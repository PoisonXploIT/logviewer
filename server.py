#!/usr/bin/env python3
"""
Visor de Logs Unificado - servidor local (solo stdlib de Python).

- Sirve una unica pagina web en el navegador (static/index.html).
- Carga archivos de logs por drag & drop o file picker (POST /upload).
  Admite varios archivos a la vez (cola de carga) y archivos comprimidos
  (.gz, .bz2, .xz, .zip).
- Detecta el formato automaticamente: apache/NCS, W3C (IIS), JSON Lines,
  syslog RFC 5424, genérico (fecha + nivel + mensaje) o RAW.
- Detecta el encoding: utf-8-sig, utf-8, cp1252, latin-1.
- El estado es una "sesion" con varios datasets; cada endpoint acepta
  opcionalmente ?name= para indicar el dataset (por defecto el activo).
- Todo el filtrado se hace en el servidor; el navegador solo muestra
  la pagina pedida (nunca se embebe el log completo en el HTML).

Uso:
  python server.py [puerto]     (puerto por defecto: 8765)

Luego abrir en el navegador: http://127.0.0.1:8765/
"""
import argparse
import bz2
import codecs
import csv
import gzip
import io
import json
import lzma
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
MAX_SIZE = 500 * 1024 * 1024       # 500 MB: limite por archivo subido
TOTAL_MAX = 1024 * 1024 * 1024     # 1 GB: limite total por peticion de upload
MAX_DECOMP_SIZE = 2 * 1024 ** 3    # 2 GB: limite tras descomprimir
PAGE_SIZE = 500                    # filas por pagina en la tabla
PAGE_MAX = 5000                    # tope de size por peticion
TRUNC = 600                        # longitud maxima de mensaje en la UI
PROGRESS_STEP = 10000              # cada N lineas se actualiza el progreso
TAIL_POLL = 0.5                    # s: intervalo del watcher
TAIL_BUFFER_MAX = 10000            # lineas nuevas max. en el buffer
TAIL_MAX = 5000                    # tope de last por peticion a /api/tail

# Token anti-CSRF por proceso: lo sirve GET /api/csrf y lo exige en todo
# POST (header X-CSRF-Token). No es un secreto: demuestra que la peticion
# sale de una pagina que este proceso sirvio (un sitio ajeno no puede leerlo
# por CORS ni anadir el header sin preflight).
CSRF_TOKEN = secrets.token_hex(16)

# Tope de subidas concurrentes (cada una puede leer hasta 1 GB del cuerpo):
# sin este limite, unas pocas peticiones a la vez agotan la memoria.
UPLOAD_SEM = threading.BoundedSemaphore(2)

# Cabecera CSP de la pagina HTML (sin inline: todo el JS esta en app.js).
CSP_HTML = ("default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'")

# Con LOGVIEWER_REQUIRE_CF=1 se rechaza el acceso directo al origen
# (peticiones sin el header de Cloudflare Access). Mitiga el caso "el
# origen Railway es alcanzable sin pasar por Access"; no valida el JWT
# (eso lo hace Access en el borde).
REQUIRE_CF = os.environ.get("LOGVIEWER_REQUIRE_CF") == "1"
def _valid_sqlite_threshold():
    try:
        v = int(os.environ.get("LOGVIEWER_SQLITE_THRESHOLD", "200000"))
        if v >= 1000:
            return v
    except (ValueError, TypeError):
        pass
    return 200000

SQLITE_THRESHOLD = _valid_sqlite_threshold()
PARSE_CHUNK = 50000                # lineas por lote al parsear en streaming
ENC_PEEK = 65536                   # bytes para detectar el encoding en streaming

# Extensiones soportadas (la deteccion real es por contenido/magico)
SUPPORTED_EXTS = (".log", ".txt", ".csv", ".json",
                  ".gz", ".bz2", ".xz", ".zip")

# ---------------------------------------------------------------------------
# Regex de formatos (reutilizadas de ver_log_navegador.py)
# ---------------------------------------------------------------------------
# Apache/NCS (CLF). La request puede contener comillas escapadas (ataques),
# por eso method/path/proto se capturan con un patron flexible.
RE_APACHE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<code>\d{3})\s+(?P<bytes>\d+|-)'
)

# Respaldo para lineas malformadas que la estricta no captura:
# - 2 o 3 campos antes de [fecha] (falta ident o user)
# - request sin protocolo ("GET /x" o "GET /x 1350.0")
# - code/bytes opcionales
RE_APACHE_LOOSE = re.compile(
    r'^(?P<ip>\S+)\s+\S+(?:\s+\S+)?\s+\[(?P<date>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>[^\s"]+)(?:\s+(?P<proto>[^"]*))?"\s*'
    r'(?P<code>\d{3})?(?:\s+(?P<bytes>\d+|-))?'
)

# Variante sin comilla de cierre: "METHOD PATH CODE BYTES (fin de linea)
RE_APACHE_NOQUOTE = re.compile(
    r'^(?P<ip>\S+)\s+\S+(?:\s+\S+)?\s+\[(?P<date>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<code>\d{3})\s+(?P<bytes>\d+|-)\s*$'
)


def match_apache(line):
    """Intenta la regex estricta y luego las laxas. Devuelve Match o None."""
    m = RE_APACHE.match(line)
    if m:
        return m
    m = RE_APACHE_LOOSE.match(line)
    if m:
        return m
    return RE_APACHE_NOQUOTE.match(line)

# Genérico: fecha + hora(+tz opcional) + [pid:tid] opcional + NIVEL + mensaje
RE_LEVEL = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
    r'(?:\([^)]*\))?'
    r'(?:\[[^\]]*\])?'
    r'\s+(?P<level>INF|WRN|ERR|DBG|CRIT|FATAL|INFO|WARN|WARNING|ERROR|DEBUG|TRACE)'
    r'\s+(?P<msg>.*)$',
    re.IGNORECASE
)

# Syslog RFC 5424: VERSION SPIS TIMESTAMP HOSTNAME APP[PID] MSG
RE_SYSLOG = re.compile(
    r'^(?:<\d+>)?(?P<version>\d+)\s+'
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>\S+?)(?:\[(?P<pid>\d+)\])?:?\s+'
    r'(?P<msg>.*)$'
)

# Primera IPv4 de una linea (para extraer IPs en formatos genericos)
RE_IP = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')

# Normaliza niveles a categorias estandar
LEVEL_MAP = {
    "INF": "INF", "INFO": "INF",
    "WRN": "WRN", "WARN": "WRN", "WARNING": "WRN",
    "ERR": "ERR", "ERROR": "ERR", "CRIT": "CRIT", "FATAL": "CRIT",
    "DBG": "DBG", "DEBUG": "DBG", "TRACE": "DBG",
}

# Campos tipicos de logs JSON (primera coincidencia gana)
TS_KEYS = ("ts", "time", "timestamp", "@timestamp", "datetime", "date")
LEVEL_KEYS = ("level", "lvl", "log_level", "severity")
MSG_KEYS = ("msg", "message", "text", "log", "msg_text")
IP_KEYS = ("ip", "client_ip", "ip_addr", "src_ip", "remote_addr", "source_ip")

# ---------------------------------------------------------------------------
# Estado global: sesion con varios datasets
# ---------------------------------------------------------------------------
# Aislamiento por usuario (Fase 6): todo el estado se clavea por usuario
# (el header Cf-Access-Authenticated-User-Email de Cloudflare Access o
# "local"). Un usuario solo ve, exporta
# y borra sus propios datasets; las copias temporales van en
# sessions/<usuario>/ para que dos usuarios con el mismo nombre de archivo
# no se pisen.
SESSIONS = {}   # user -> {name -> dataset (dict)}
ACTIVE = {}     # user -> nombre del dataset activo
LOCK = threading.Lock()

# Progreso de carga por archivo: user -> {name -> {phase, pct, ...}}
PROGRESS = {}

# Watchers de tail en vivo: user -> {name -> Watcher}
WATCHERS = {}


def _user_state(user, state):
    """Devuelve (y crea si hace falta) el dict de estado de un usuario."""
    return state.setdefault(user, {})


def _norm_level(lv):
    """Normaliza un nivel a su categoria estandar."""
    return LEVEL_MAP.get(lv.upper(), lv)


_SEARCH_KEYS = ["ts", "level", "ip", "host", "app", "pid",
                "method", "path", "code", "bytes", "msg"]


def _make_search(r):
    """Construye la cadena de busqueda lowercased para una fila."""
    return " ".join(str(r.get(k, "")) for k in _SEARCH_KEYS).lower()


def _trunc(s, n=TRUNC):
    """Trunca cadenas muy largas (las lineas de Zscaler llegan a 4095 chars)."""
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + " ..."


# ---------------------------------------------------------------------------
# Compresion y encoding
# ---------------------------------------------------------------------------
def open_log_file(path):
    """Abre un archivo de log (posiblemente comprimido).

    Devuelve (bytes, etiqueta_compresion, nombre_interno).
    La deteccion es por magico (primera linea de bytes) y el nombre
    interno solo se usa en .zip (el fichero elegido dentro del zip).
    """
    # Previa: sin esto un archivo enorme ya agota la memoria antes de
    # llegar a la comprobacion post-descompresion (zip bomb).
    if os.path.getsize(path) > MAX_DECOMP_SIZE:
        raise ValueError("archivo demasiado grande (max 2 GB)")
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) > MAX_DECOMP_SIZE:
        raise ValueError("archivo demasiado grande tras descomprimir "
                         "(max 2 GB)")
    label, inner = "", ""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
        label = "gzip"
    elif raw[:3] == b"BZh":
        raw = bz2.decompress(raw)
        label = "bzip2"
    elif raw[:6] == b"\xfd7zXZ\x00":
        raw = lzma.decompress(raw)
        label = "xz"
    elif raw[:4] == b"PK\x03\x04":
        label = "zip"
        zf = zipfile.ZipFile(io.BytesIO(raw))
        names = [n for n in zf.namelist()
                 if not n.endswith("/") and not n.startswith("__MACOSX")]
        if not names:
            raise ValueError("el archivo .zip no contiene ficheros")
        # Prefiere extensiones de log; si no, el primero
        pick = next((n for n in names
                     if n.lower().endswith((".log", ".txt", ".csv", ".json"))),
                    names[0])
        inner = os.path.basename(pick)
        raw = zf.read(pick)
    if len(raw) > MAX_DECOMP_SIZE:
        raise ValueError("archivo demasiado grande tras descomprimir "
                         "(max 2 GB)")
    return raw, label, inner


ENCODINGS = ("utf-8-sig", "utf-8", "cp1252", "latin-1")


def decode_text(raw):
    """Prueba encodings en orden. Devuelve (texto, encoding).
    latin-1 nunca falla, asi que siempre hay un resultado."""
    for enc in ENCODINGS:
        try:
            return raw.decode(enc), enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8 (reemplazo)"


def is_supported_name(name):
    """True si la extension del nombre es soportada."""
    return os.path.splitext(name)[1].lower() in SUPPORTED_EXTS


def safe_session_name(name, existing=None):
    """Devuelve un nombre seguro para usar como clave de sesion, fichero
    temporal y nombre de base de datos SQLite."""
    base = os.path.basename(name)
    safe = re.sub(r'[^A-Za-z0-9.\-_]', '_', base)
    safe = safe.replace('..', '')
    if not safe:
        safe = "subido"
    if existing is not None:
        existing = set(existing)
        if safe in existing:
            n = 1
            while "%s_%d" % (safe, n) in existing:
                n += 1
            safe = "%s_%d" % (safe, n)
    return safe


# ---------------------------------------------------------------------------
# Lectura en streaming (Fase 4): no carga el archivo entero en memoria
# ---------------------------------------------------------------------------
def open_log_stream(path):
    """Abre un lector binario en streaming (admite compresion por magico).

    Devuelve (lector_binario, etiqueta_compresion, nombre_interno).
    El lector soporta .read(n) y se cierra con .close()."""
    with open(path, "rb") as f:
        head = f.read(8)
    if head[:2] == b"\x1f\x8b":
        return gzip.open(path, "rb"), "gzip", ""
    if head[:3] == b"BZh":
        return bz2.open(path, "rb"), "bzip2", ""
    if head[:6] == b"\xfd7zXZ\x00":
        return lzma.open(path, "rb"), "xz", ""
    if head[:4] == b"PK\x03\x04":
        zf = zipfile.ZipFile(path)
        names = [n for n in zf.namelist()
                 if not n.endswith("/") and not n.startswith("__MACOSX")]
        if not names:
            zf.close()
            raise ValueError("el archivo .zip no contiene ficheros")
        pick = next((n for n in names
                     if n.lower().endswith((".log", ".txt", ".csv", ".json"))),
                    names[0])
        inner = os.path.basename(pick)
        return zf.open(pick), "zip", inner
    return open(path, "rb"), "", ""


def detect_encoding(chunk):
    """Detecta el encoding de un log a partir de los primeros bytes."""
    for enc in ENCODINGS:
        try:
            chunk.decode(enc)
            return enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return "latin-1"  # nunca falla


def iter_lines(binary, encoding):
    """Itera lineas de texto de un lector binario, decodificando en streaming.

    Devuelve un generador de lineas (sin el \n final). Los errores de
    decodificacion se reemplazan (no interrumpen la carga)."""
    decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
    buf = ""
    while True:
        chunk = binary.read(1 << 16)
        if not chunk:
            break
        buf += decoder.decode(chunk)
        parts = buf.split("\n")
        buf = parts.pop()  # el ultimo fragmento puede ser incompleto
        for l in parts:
            yield l.rstrip("\r")
    tail = decoder.decode(b"", True)  # flush del decodificador
    if buf:
        buf += tail
        for l in buf.split("\n"):
            yield l.rstrip("\r")


class PrefixedBinaryStream:
    """Stream binario: primero rinde el prefijo ya leido y luego el resto.

    Permite detectar el encoding con los primeros bytes sin perderlos."""

    def __init__(self, prefix, rest):
        self._prefix = io.BytesIO(prefix)
        self._rest = rest

    def read(self, n=-1):
        if n is None or n < 0:
            return self._prefix.read() + self._rest.read()
        data = self._prefix.read(n)
        if len(data) < n:
            data += self._rest.read(n - len(data))
        return data

    def close(self):
        self._rest.close()

    def readable(self):
        return True

    def seekable(self):
        return False


class SizeLimitedStream:
    """Envuelve un stream binario y limita los bytes descomprimidos."""

    def __init__(self, stream, limit):
        self._stream = stream
        self._limit = limit
        self._read = 0

    def read(self, n=-1):
        data = self._stream.read(n)
        self._read += len(data)
        if self._read > self._limit:
            self.close()
            raise ValueError("archivo descomprimido demasiado grande (max 2 GB)")
        return data

    def close(self):
        self._stream.close()


# ---------------------------------------------------------------------------
# Backend de datasets (Fase 4): memoria o SQLite segun el tamano
# ---------------------------------------------------------------------------
class MemStore:
    """Backend en memoria: lista de filas + contadores (datasets pequenos).

    Es el comportamiento original: rapido y sin dependencias."""

    def __init__(self, rows=None, counters=None):
        self.rows = rows if rows is not None else []
        self.counters = counters if counters is not None else {}
        self.top_cache = {}

    def add_rows(self, rows, counters):
        """Anade filas (usado por el tail en vivo)."""
        self.rows.extend(rows)
        for key, cnt in counters.items():
            if key in self.counters:
                self.counters[key].update(cnt)
            else:
                self.counters[key] = Counter(cnt)
        self.top_cache.clear()

    def count_filtered(self, q):
        return len(apply_filters(self.rows, q))

    def page_filtered(self, q, start, size):
        rows = apply_filters(self.rows, q)
        out = []
        for r in rows[start:start + size]:
            r = dict(r)
            r.pop("_search", None)
            out.append(r)
        return out

    def iter_filtered(self, q):
        return iter(apply_filters(self.rows, q))

    def top(self, field, limit):
        key = (field, limit)
        if key in self.top_cache:
            return self.top_cache[key]
        c = Counter()
        for r in self.rows:
            v = r.get(field, "")
            if v:
                c[v] += 1
        res = c.most_common(limit)
        self.top_cache[key] = res
        return res

    def kpis(self):
        """Contadores unicos para los KPIs (ips, paths, codes, levels)."""
        out = {}
        for key in ("ips", "paths", "codes", "levels"):
            if key in self.counters:
                out[key] = len(self.counters[key])
        return out

    def total_rows(self):
        return len(self.rows)

    def close(self):
        pass


class SqlStore:
    """Backend SQLite (datasets grandes, por encima del umbral).

    Las filas se guardan en una tabla; el filtrado, el top N y los KPIs
    se hacen con SQL. No se mantiene la lista de filas en memoria."""

    COLUMNS = ("ts", "level", "ip", "host", "app", "pid",
               "method", "path", "code", "bytes", "msg", "raw")

    def __init__(self, db_path):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._create_schema()

    def _create_schema(self):
        cols = ", ".join("%s TEXT" % c for c in self.COLUMNS)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS rows (%s, search TEXT)" % cols)
        # Indices para los filtros mas usados
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_level ON rows(level)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_code ON rows(code)")
        self.conn.commit()

    def _insert_rows(self, rows):
        self.conn.executemany(
            "INSERT INTO rows (%s, search) VALUES (%s)" % (
                ", ".join(self.COLUMNS), ", ".join("?" * (len(self.COLUMNS) + 1))),
            [tuple(r.get(c, "") for c in self.COLUMNS) + (r.get("_search", ""),)
             for r in rows])
        self.conn.commit()

    def add_rows(self, rows, counters):
        """Anade filas (usado por el tail en vivo)."""
        with self.lock:
            self._insert_rows(rows)

    def _where(self, q):
        """Construye la clausula WHERE a partir de los filtros."""
        clauses = []
        params = []
        level = q.get("level", [""])[0].strip()
        code = q.get("code", [""])[0].strip()
        ip = q.get("ip", [""])[0].strip().lower()
        path = q.get("path", [""])[0].strip().lower()
        txt = q.get("q", [""])[0].strip().lower()
        dt = q.get("dt", [""])[0].strip()
        if level:
            clauses.append("level = ?")
            params.append(level)
        if code:
            clauses.append("code = ?")
            params.append(code)
        if ip:
            clauses.append("instr(lower(ip), ?) > 0")
            params.append(ip)
        if path:
            clauses.append("instr(lower(path), ?) > 0")
            params.append(path)
        if dt:
            clauses.append("instr(ts, ?) > 0")
            params.append(dt)
        if txt:
            clauses.append("instr(search, ?) > 0")
            params.append(txt)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def count_filtered(self, q):
        where, params = self._where(q)
        with self.lock:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM rows %s" % where, params)
            return cur.fetchone()[0]

    def page_filtered(self, q, start, size):
        where, params = self._where(q)
        with self.lock:
            cur = self.conn.execute(
                "SELECT %s FROM rows %s LIMIT ? OFFSET ?" % (
                    ", ".join(self.COLUMNS), where),
                params + [size, start])
            cols = self.COLUMNS
            out = []
            for row in cur.fetchall():
                out.append(dict(zip(cols, row)))
            return out

    def iter_filtered(self, q):
        where, params = self._where(q)
        with self.lock:
            cur = self.conn.execute(
                "SELECT %s FROM rows %s" % (
                    ", ".join(self.COLUMNS), where), params)
            cols = self.COLUMNS
            for row in cur:
                yield dict(zip(cols, row))

    def top(self, field, limit):
        if field not in self.COLUMNS:
            return []
        with self.lock:
            cur = self.conn.execute(
                "SELECT %s, COUNT(*) AS n FROM rows WHERE %s != '' "
                "GROUP BY %s ORDER BY n DESC, %s ASC LIMIT ?" % (
                    field, field, field, field), [limit])
            return [(v, n) for v, n in cur.fetchall() if v]

    def kpis(self):
        """Contadores unicos para los KPIs (ips, paths, codes, levels)."""
        out = {}
        for key in ("ips", "paths", "codes", "levels"):
            col = {"ips": "ip", "paths": "path", "codes": "code",
                   "levels": "level"}[key]
            with self.lock:
                cur = self.conn.execute(
                    "SELECT COUNT(DISTINCT %s) FROM rows WHERE %s != ''" % (col, col))
                out[key] = cur.fetchone()[0]
        return out

    def total_rows(self):
        with self.lock:
            cur = self.conn.execute("SELECT COUNT(*) FROM rows")
            return cur.fetchone()[0]

    def close(self):
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass
            # Borra el archivo de la BD (y sus WAL/SHM)
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(self.db_path + suffix)
                except OSError:
                    pass


def make_store(db_dir, rows=None, counters=None):
    """Crea un MemStore (por defecto) o un SqlStore."""
    return MemStore(rows=rows, counters=counters)


def migrate_to_sqlite(mem_store, db_dir, name):
    """Migra un MemStore a un SqlStore (cuando se supera el umbral).

    Devuelve el nuevo SqlStore. El MemStore queda vaciado."""
    safe = safe_session_name(name)
    db_path = os.path.join(db_dir, safe + ".db")
    sql = SqlStore(db_path)
    rows = mem_store.rows
    # Inserta por lotes para no saturar la memoria
    for i in range(0, len(rows), PARSE_CHUNK):
        sql._insert_rows(rows[i:i + PARSE_CHUNK])
    mem_store.rows = []
    return sql


# ---------------------------------------------------------------------------
# Parsers: cada uno devuelve (rows, counters)
# ---------------------------------------------------------------------------
def parse_apache(lines, progress=None):
    """Apache/NCS CLF. Campos: ip, date, method, path, code, bytes.
    Usa regex estricta + respaldos laxos para lineas malformadas."""
    rows = []
    ips, paths, codes, methods = Counter(), Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        m = match_apache(l)
        if not m:
            pass
        else:
            ip, date = m.group("ip"), m.group("date")
            method, path = m.group("method"), m.group("path")
            code = m.group("code") or ""
            byts = m.group("bytes") or ""
            ips[ip] += 1
            paths[path] += 1
            if code:
                codes[code] += 1
            methods[method] += 1
            rows.append({
                "ts": date, "level": "", "ip": ip, "method": method,
                "path": path, "code": code, "bytes": byts,
                "msg": _trunc("%s %s" % (method, path)),
                "raw": _trunc(l),
            })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"ips": ips, "paths": paths, "codes": codes, "methods": methods}


def w3c_fields(lines):
    """Extrae la lista de columnas de la linea #Fields de un log W3C."""
    for l in lines:
        if l.startswith("#Fields"):
            rest = l[len("#Fields"):].strip()
            if rest.startswith(":"):
                rest = rest[1:]
            return rest.split()
    return []


def parse_w3c(lines, progress=None, fields=None):
    """W3C Extended Log Format. La primera linea #Fields define las columnas."""
    if fields is None:
        fields = w3c_fields(lines)
    if not fields:
        return [], {}
    # Mapeo de columnas W3C a campos internos
    def col(*names):
        for n in names:
            if n in fields:
                return fields.index(n)
        return -1
    i_date, i_time = col("date"), col("time")
    i_ip = col("c-ip")
    i_method = col("cs-method")
    i_path = col("cs-uri-stem", "cs-uri", "cs-uri-query")
    i_code = col("sc-status")
    i_bytes = col("sc-bytes")

    rows = []
    ips, paths, codes, methods = Counter(), Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        if not l.strip() or l.startswith("#"):
            continue
        parts = l.split()
        if len(parts) < len(fields):
            continue
        def g(i):
            return parts[i] if 0 <= i < len(parts) else ""
        ip = g(i_ip) if i_ip >= 0 else ""
        method = g(i_method) if i_method >= 0 else ""
        path = g(i_path) if i_path >= 0 else ""
        code = g(i_code) if i_code >= 0 else ""
        byts = g(i_bytes) if i_bytes >= 0 else ""
        date, t = g(i_date), g(i_time)
        ts = (date + " " + t).strip() if (i_date >= 0 or i_time >= 0) else ""
        if code.isdigit():
            codes[code] += 1
        if ip:
            ips[ip] += 1
        if path:
            paths[path] += 1
        if method:
            methods[method] += 1
        rows.append({
            "ts": ts, "level": "", "ip": ip, "method": method,
            "path": path, "code": code, "bytes": byts,
            "msg": _trunc("%s %s" % (method, path)),
            "raw": _trunc(l),
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"ips": ips, "paths": paths, "codes": codes, "methods": methods}


def parse_json(lines, progress=None):
    """JSON Lines. Una linea JSON por registro."""
    rows = []
    ips, levels = Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        l = l.strip()
        if l:
            try:
                obj = json.loads(l)
            except Exception:
                obj = None
            if obj is not None and isinstance(obj, dict):
                ts = ""
                for k in TS_KEYS:
                    if k in obj and obj[k]:
                        ts = str(obj[k])
                        break
                level = ""
                for k in LEVEL_KEYS:
                    if k in obj and obj[k]:
                        level = _norm_level(str(obj[k]).upper())
                        break
                msg = ""
                for k in MSG_KEYS:
                    if k in obj and obj[k]:
                        msg = str(obj[k])
                        break
                ip = ""
                for k in IP_KEYS:
                    if k in obj and obj[k]:
                        ip = str(obj[k])
                        break
                if not msg:
                    # Sin mensaje: el JSON entero es el mensaje
                    msg = json.dumps(obj, ensure_ascii=False)
                if ip:
                    ips[ip] += 1
                if level:
                    levels[level] += 1
                rows.append({
                    "ts": ts, "level": level, "ip": ip, "method": "",
                    "path": "", "code": "", "bytes": "",
                    "msg": _trunc(msg),
                    "raw": _trunc(l),
                })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"ips": ips, "levels": levels}


def parse_syslog(lines, progress=None):
    """Syslog RFC 5424: VERSION SPIS TIMESTAMP HOSTNAME APP[PID] MSG."""
    rows = []
    hosts, apps, ips = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        m = RE_SYSLOG.match(l)
        if m:
            host, app = m.group("host"), m.group("app")
            hosts[host] += 1
            apps[app] += 1
            mi = RE_IP.search(l)
            ip = mi.group(1) if mi else ""
            if ip:
                ips[ip] += 1
            rows.append({
                "ts": m.group("ts"), "level": "", "ip": ip, "method": "",
                "path": "", "code": "", "bytes": "",
                "msg": _trunc(m.group("msg")),
                "host": host, "app": app, "pid": m.group("pid") or "",
                "raw": _trunc(l),
            })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"hosts": hosts, "apps": apps, "ips": ips}


def parse_generic(lines, progress=None):
    """Genérico: fecha + hora + nivel + mensaje. Lo que no matchea va como RAW.
    Se extrae la primera IPv4 de cada linea para poder filtrar por IP."""
    rows = []
    levels, ips = Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        m = RE_LEVEL.match(l)
        if m:
            lv = _norm_level(m.group("level"))
            ts = m.group("date") + " " + m.group("time")
            msg = m.group("msg")
        else:
            lv, ts, msg = "RAW", "", l
        levels[lv] += 1
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        rows.append({
            "ts": ts, "level": lv, "ip": ip, "method": "",
            "path": "", "code": "", "bytes": "",
            "msg": _trunc(msg),
            "raw": _trunc(l),
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips}


def parse_raw(lines, progress=None):
    """RAW: lineas tal cual, sin parsear."""
    rows = [{"ts": "", "level": "RAW", "ip": "", "method": "",
             "path": "", "code": "", "bytes": "", "msg": _trunc(l),
             "raw": _trunc(l)}
            for l in lines]
    return rows, {"levels": Counter({"RAW": len(rows)})}


PARSERS = {
    "apache": parse_apache,
    "w3c": parse_w3c,
    "json": parse_json,
    "syslog": parse_syslog,
    "generic": parse_generic,
    "raw": parse_raw,
}


# ---------------------------------------------------------------------------
# Deteccion de formato (heuristicas sobre las primeras lineas no vacias)
# ---------------------------------------------------------------------------
def detect_format(lines):
    sample = [l for l in lines if l.strip()][:100]
    if not sample:
        return "raw"
    n = len(sample)
    if sum(1 for l in sample if match_apache(l)) > n * 0.7:
        return "apache"
    # W3C: alguna de las primeras lineas es #Fields (antes pueden ir
    # lineas de metadatos #Software, #Reason, etc.)
    if any(l.startswith("#Fields") for l in sample):
        return "w3c"
    ok = 0
    for l in sample:
        s = l.strip()
        if s.startswith("{"):
            try:
                json.loads(s)
                ok += 1
            except Exception:
                pass
    if ok > n * 0.7:
        return "json"
    if sum(1 for l in sample if RE_LEVEL.match(l)) > n * 0.7:
        return "generic"
    if sum(1 for l in sample if RE_SYSLOG.match(l)) > n * 0.7:
        return "syslog"
    return "raw"


# ---------------------------------------------------------------------------
# Carga y parseo de un archivo (devuelve un dataset, sin mutar globales)
# ---------------------------------------------------------------------------
def load_file(path, progress=None, user="local"):
    """Lee, detecta formato y encoding, parsea. Devuelve el dataset.

    Lee en streaming (no carga el archivo entero en memoria). Si el numero
    de filas supera SQLITE_THRESHOLD, migra a un backend SQLite (en la
    carpeta sqlite/<usuario>/ para no pisar la BD de otro usuario)."""
    t0 = time.time()

    def _report(phase, pct, msg=""):
        if progress:
            progress(phase, pct, msg)

    binary, compressed, inner = open_log_stream(path)
    if compressed:
        binary = SizeLimitedStream(binary, MAX_DECOMP_SIZE)
    _report("reading", 15, "leyendo archivo")
    first = binary.read(ENC_PEEK)
    encoding = detect_encoding(first)
    stream = PrefixedBinaryStream(first, binary)
    _report("reading", 30, "decodificando (%s)" % encoding)

    name = os.path.basename(path)
    db_dir = os.path.join(tempfile.gettempdir(), "logviewer", "sqlite",
                         safe_session_name(user))
    store = MemStore()
    try:
        line_iter = iter_lines(stream, encoding)

        # Cabecera: primeras lineas no vacias para detectar el formato
        head = []
        nonempty = 0
        for line in line_iter:
            head.append(line)
            if line.strip():
                nonempty += 1
                if nonempty >= 100:
                    break
        if nonempty == 0:
            raise ValueError("el archivo esta vacio o solo tiene lineas vacias")
        fmt = detect_format(head)
        w3c_f = w3c_fields(head) if fmt == "w3c" else None
        meta = [l for l in head if l.startswith("#")] if fmt == "w3c" else []

        # Fuente de lineas: cabecera + resto del stream
        def lines():
            for l in head:
                yield l
            for l in line_iter:
                yield l

        # Parseo en lotes; migra a SQLite si se supera el umbral
        parser = PARSERS[fmt]
        total_lines = 0
        chunk = []
        lines_processed = 0

        def _flush(chunk):
            nonlocal store, lines_processed
            if fmt == "w3c":
                rows, counters = parse_w3c(chunk, fields=w3c_f)
            else:
                rows, counters = parser(chunk)
            for r in rows:
                r["_search"] = _make_search(r)
            store.add_rows(rows, counters)
            lines_processed += len(chunk)
            # Migra a SQLite si se supera el umbral
            if isinstance(store, MemStore) and store.total_rows() > SQLITE_THRESHOLD:
                os.makedirs(db_dir, exist_ok=True)
                store = migrate_to_sqlite(store, db_dir, name)
            pct = 30 + int(65 * min(1.0, lines_processed / SQLITE_THRESHOLD))
            _report("parsing", pct, "parseando (%d lineas)" % lines_processed)

        for line in lines():
            chunk.append(line)
            total_lines += 1
            if len(chunk) >= PARSE_CHUNK:
                _flush(chunk)
                chunk = []
        if chunk:
            _flush(chunk)
        _report("parsing", 95, "parseando")
    finally:
        stream.close()

    return {
        "store": store,
        "format": fmt,
        "name": name,
        "size": os.path.getsize(path),
        "total": total_lines,
        "meta": meta[:20],
        "encoding": encoding,
        "compressed": compressed,
        "inner": inner,
        "load_seconds": round(time.time() - t0, 3),
        "w3c_fields": w3c_f,
    }


# Claves de KPIs por formato (las que el parser de ese formato rellena).
# Se usa para que MemStore y SqlStore devuelvan los mismos KPIs.
KPI_KEYS_BY_FORMAT = {
    "apache": ("ips", "paths", "codes"),
    "w3c": ("ips", "paths", "codes"),
    "json": ("ips", "levels"),
    "syslog": ("ips",),
    "generic": ("ips", "levels"),
    "raw": ("levels",),
}


def summary(ds):
    """KPIs de un dataset."""
    store = ds["store"]
    s = {
        "format": ds["format"],
        "name": ds["name"],
        "size": ds["size"],
        "total": ds["total"],
        "parsed": store.total_rows(),
        "encoding": ds.get("encoding", ""),
        "compressed": ds.get("compressed", ""),
        "backend": "sqlite" if isinstance(store, SqlStore) else "mem",
    }
    kpis = store.kpis()
    for key in KPI_KEYS_BY_FORMAT.get(ds["format"], ("ips", "levels")):
        if key in kpis:
            s[key] = kpis[key]
    return s


def sessions_list(user):
    """Lista de datasets de la sesion del usuario (para la UI)."""
    mine = _user_state(user, SESSIONS)
    watchers = _user_state(user, WATCHERS)
    out = []
    for name, ds in mine.items():
        w = watchers.get(name)
        out.append({
            "name": name,
            "format": ds["format"],
            "size": ds["size"],
            "total": ds["total"],
            "encoding": ds.get("encoding", ""),
            "compressed": ds.get("compressed", ""),
            "active": name == ACTIVE.get(user, ""),
            "watching": bool(w and w.enabled),
        })
    return out


def dataset(user, name):
    """Devuelve el dataset del usuario indicado o su activo. None si no
    existe o no es suyo (aislamiento por usuario)."""
    mine = _user_state(user, SESSIONS)
    if name:
        return mine.get(name)
    active = ACTIVE.get(user, "")
    return mine.get(active) if active else None


def top_n(ds, field, limit):
    """Top N por campo (ip, path, code, level, method, host, app)."""
    return ds["store"].top(field, limit)


# ---------------------------------------------------------------------------
# Filtrado en el servidor
# ---------------------------------------------------------------------------
def apply_filters(rows, q):
    """Aplica todos los filtros combinables. Devuelve la lista filtrada."""
    level = q.get("level", [""])[0].strip()
    code = q.get("code", [""])[0].strip()
    ip = q.get("ip", [""])[0].strip().lower()
    path = q.get("path", [""])[0].strip().lower()
    txt = q.get("q", [""])[0].strip().lower()
    dt = q.get("dt", [""])[0].strip()

    out = []
    for r in rows:
        if level and r["level"] != level:
            continue
        if code and r["code"] != code:
            continue
        if ip and ip not in r["ip"].lower():
            continue
        if path and path not in r["path"].lower():
            continue
        if dt and dt not in r["ts"]:
            continue
        if txt and txt not in r.get("_search", ""):
            continue
        out.append(r)
    return out


def parse_multipart_all(data, boundary):
    """Extrae todas las partes (nombre, bytes) de un multipart.
    Devuelve una lista (puede estar vacia)."""
    delim = b"--" + boundary
    parts = []
    pos = data.find(delim)
    while pos >= 0:
        rest = data[pos + len(delim):]
        end = rest.find(delim)
        if end < 0:
            break
        part = rest[:end]
        m = re.search(rb'\r?\n\r?\n', part)
        if m:
            headers = part[:m.start()].decode("utf-8", "replace")
            body = part[m.end():]
            if body.endswith(b"\r\n"):
                body = body[:-2]
            mname = re.search(r'filename="([^"]*)"', headers)
            name = os.path.basename(mname.group(1)) if mname else None
            if name is not None:
                parts.append((name, body))
        pos = data.find(delim, pos + len(delim))
    return parts


# ---------------------------------------------------------------------------
# Tail en vivo (Fase 3): watcher por dataset sobre la copia temporal
# ---------------------------------------------------------------------------
class Watcher:
    """Watcher de un dataset: lee lineas nuevas de la copia temporal.

    - Hilo daemon que sondea el archivo cada TAIL_POLL segundos.
    - Buffer de lineas nuevas (con tope) hasta que el cliente las lea.
    - Detecta truncamiento (tamano < offset) y relee desde 0.
    """

    def __init__(self, name, path, encoding="utf-8"):
        self.name = name
        self.path = path
        self.encoding = encoding
        self.lock = threading.Lock()
        self.enabled = False
        self.offset = 0
        self.pending = b""          # linea incompleta (sin \n final)
        self.buffer = deque(maxlen=TAIL_BUFFER_MAX)
        self.truncated = False
        self.last_read = 0
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self):
        self.enabled = False
        self._stop.set()

    def reset(self, seek_end=True):
        """Reinicia tras re-subida: vacia el buffer y posiciona el offset."""
        with self.lock:
            self.buffer.clear()
            self.pending = b""
            self.truncated = False
            try:
                self.offset = os.path.getsize(self.path) if seek_end else 0
            except OSError:
                self.offset = 0

    def _loop(self):
        while not self._stop.is_set():
            time.sleep(TAIL_POLL)
            if self.enabled:
                self._poll_once()

    def _poll_once(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        with self.lock:
            if size < self.offset:
                # Truncado o re-subido: se relee desde 0
                self.offset = 0
                self.pending = b""
                self.buffer.clear()
                self.truncated = True
            try:
                with open(self.path, "rb") as f:
                    f.seek(self.offset)
                    chunk = f.read()
            except OSError:
                return
            self.offset += len(chunk)
            data = self.pending + chunk
            self.pending = b""
            if data and not data.endswith(b"\n"):
                idx = data.rfind(b"\n")
                if idx >= 0:
                    data, self.pending = data[:idx + 1], data[idx + 1:]
                else:
                    data, self.pending = b"", data
            if data:
                for l in data.split(b"\n")[:-1]:
                    self.buffer.append(l.decode(self.encoding, "replace"))
            self.last_read = time.time()


def tail_parse(ds, lines):
    """Parsea lineas nuevas con el formato del dataset (incremental)."""
    if ds["format"] == "w3c":
        return parse_w3c(lines, fields=ds.get("w3c_fields"))
    return PARSERS[ds["format"]](lines)


# ---------------------------------------------------------------------------
# Carga en segundo plano (progreso por polling)
# ---------------------------------------------------------------------------
def _load_worker(name, path, user="local", ip=None):
    """Hilo: carga un archivo y lo registra en la sesion del usuario."""
    def _progress(phase, pct, msg=""):
        _user_state(user, PROGRESS)[name] = {"phase": phase, "pct": pct,
                                             "message": msg}

    try:
        ds = load_file(path, _progress, user=user)
        with LOCK:
            mine = _user_state(user, SESSIONS)
            old = mine.get(name)
            if old is not None:
                old["store"].close()
            mine[name] = ds
            if not ACTIVE.get(user, ""):
                ACTIVE[user] = name
        audit("loaded", user=user, ip=ip, file=name,
              format=ds["format"], total=ds["total"],
              backend="sqlite" if isinstance(ds["store"], SqlStore) else "mem")
        _user_state(user, PROGRESS)[name] = {"phase": "done", "pct": 100,
                                             "message": "completado"}
    except Exception as e:
        _user_state(user, PROGRESS)[name] = {"phase": "error", "pct": 0,
                                             "message": str(e),
                                             "error": str(e)}


# ---------------------------------------------------------------------------
# Servidor HTTP
# ---------------------------------------------------------------------------
def resolve_static(base, path):
    """Resuelve una ruta relativa (p. ej. 'vendor/chart.min.js') a un
    archivo dentro de <base>/static/. Devuelve la ruta absoluta o None si
    la ruta intenta salir de la carpeta static/ (path traversal)."""
    static_root = os.path.abspath(os.path.join(base, "static"))
    fp = os.path.abspath(os.path.join(static_root, path.lstrip("/")))
    if not (fp == static_root or fp.startswith(static_root + os.sep)):
        return None
    return fp


LOG_FILE = os.path.join(tempfile.gettempdir(), "logviewer", "requests.log")

# ---------------------------------------------------------------------------
# Auditoria (Fase 5): registro de acciones relevantes (memoria + archivo)
# ---------------------------------------------------------------------------
AUDIT_FILE = os.path.join(tempfile.gettempdir(), "logviewer", "audit.log")
AUDIT_MAX = 500  # tope de entradas en memoria
AUDIT = []  # lista de entradas (la mas reciente al final)
AUDIT_LOCK = threading.Lock()


def audit(action, user="local", ip=None, **details):
    """Registra una accion en la auditoria (memoria + archivo JSON Lines).

    user: quien la hizo. Detras de Cloudflare Access llega en el header
    Cf-Access-Authenticated-User-Email (spoofeable: solo atribucion, no autenticacion);
    en local (o sin ese header) es "local".
    ip: direccion remota de la peticion (forensica: si el header esta
    falseado, la IP ayuda a rastrear de donde sale)."""
    entry = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "action": action,
             "user": user or "local"}
    if ip:
        entry["ip"] = ip
    entry.update(details)
    with AUDIT_LOCK:
        AUDIT.append(entry)
        if len(AUDIT) > AUDIT_MAX:
            del AUDIT[:len(AUDIT) - AUDIT_MAX]
        try:
            os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass
    return entry


def audit_list():
    """Entradas de la auditoria (la mas reciente primero)."""
    with AUDIT_LOCK:
        return list(reversed(AUDIT))


def audit_for_user(user):
    """Solo las entradas de auditoria del usuario indicado.

    Aislamiento por usuario (Fase 6): detras de Cloudflare Access cada
    peticion lleva el header Cf-Access-Authenticated-User-Email, que se guarda en el
    campo "user" de cada entrada. Este filtro hace que cada usuario vea
    solo sus propias acciones y no las de los demas."""
    return [e for e in audit_list() if e.get("user") == user]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Log a archivo (no a consola) para poder diagnosticar fallos
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(time.strftime("%H:%M:%S ") + self.address_string() + " " + fmt % args + "\n")
        except Exception:
            pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionError, BrokenPipeError):
            pass  # el cliente se fue: nada mas que hacer

    def _error(self, msg, code=400):
        self._json({"error": msg}, code)

    def _static(self, path):
        """Sirve archivos de static/ (incluye subcarpetas como vendor/).
        Proteccion contra path traversal: resuelve a abspath y verifica
        que el resultado sigue dentro de la carpeta static/."""
        base = os.path.dirname(os.path.abspath(__file__))
        fp = resolve_static(base, path)
        if fp is None:
            self._error("ruta no permitida", 403)
            return
        if not os.path.isfile(fp):
            self._error("no encontrado", 404)
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".woff2": "font/woff2",
        }.get(os.path.splitext(fp)[1].lower(), "application/octet-stream")
        with open(fp, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        if fp.endswith(".html"):
            self.send_header("Content-Security-Policy", CSP_HTML)
            self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _user(self):
        """Usuario de la peticion: el header que inyecta Cloudflare Access
        (Cf-Access-Authenticated-User-Email) o "local" si no esta (acceso
        directo). Se mantiene Cf-Access-Login-User como fallback por
        compatibilidad con configuraciones antiguas de Access.

        AVISO: el header es spoofeable (cualquier cliente puede enviarlo).
        Solo se usa para atribuir la auditoria y aislar los datasets;
        la autenticacion real la hace Cloudflare Access en el borde."""
        return (self.headers.get("Cf-Access-Authenticated-User-Email")
                or self.headers.get("Cf-Access-Login-User") or "local")

    def _cf_ok(self):
        """Con LOGVIEWER_REQUIRE_CF=1 se rechaza el acceso anonimo al
        origen (peticiones sin el header de Cloudflare Access). No cierra
        la URL abierta (un atacante puede enviar el header el mismo),
        pero elimina el uso anonimo y deja cada accion rastroable por IP.
        La defensa real contra la URL abierta es cerrarla en Railway."""
        if not REQUIRE_CF:
            return True
        return bool(self.headers.get("Cf-Access-Authenticated-User-Email")
                    or self.headers.get("Cf-Access-Login-User"))

    def _read_json_body(self):
        """Lee un cuerpo JSON pequeno (para /api/activate, /api/remove,
        /api/watch). Devuelve el dict, o None si el cuerpo no es JSON
        valido (el llamador debe responder 400)."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > 65536:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def do_GET(self):
        if not self._cf_ok():
            self._error("acceso directo no permitido (requiere Cloudflare Access)", 403)
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        user = self._user()
        if u.path == "/":
            self._static("index.html")
        elif u.path.startswith("/static/"):
            self._static(u.path[len("/static/"):])
        elif u.path == "/api/csrf":
            # Token anti-CSRF del proceso (lo mete la pagina en los POST).
            self._json({"token": CSRF_TOKEN})
        elif u.path == "/api/summary":
            name = q.get("name", [""])[0]
            with LOCK:
                ds = dataset(user, name)
            self._json(summary(ds) if ds else None)
        elif u.path == "/api/sessions":
            with LOCK:
                sl = sessions_list(user)
                act = ACTIVE.get(user, "")
            self._json({"sessions": sl, "active": act})
        elif u.path == "/api/progress":
            name = q.get("name", [""])[0]
            self._json(_user_state(user, PROGRESS).get(name)
                       or {"phase": "idle", "pct": 0})
        elif u.path == "/api/tail":
            self._tail(q, user)
        elif u.path == "/api/rows":
            self._rows(q, user)
        elif u.path == "/api/top":
            self._top(q, user)
        elif u.path == "/api/export":
            self._export(q, user)
        elif u.path == "/api/audit":
            # Aislamiento por usuario: cada usuario ve solo sus propias
            # entradas (campo "user" = header de Cloudflare Access).
            self._json({"audit": audit_for_user(user)})
        else:
            self._error("ruta no conocida", 404)

    def _rows(self, q, user):
        name = q.get("name", [""])[0]
        # Solo se toma el dataset bajo LOCK; la consulta (que puede ser
        # lenta en SQLite) ya no bloquea el resto del servidor.
        with LOCK:
            ds = dataset(user, name)
        if ds is None:
            self._error("no hay archivo cargado", 404)
            return
        store = ds["store"]
        try:
            page = max(1, int(q.get("page", ["1"])[0]))
            size = min(PAGE_MAX, max(1, int(q.get("size", [str(PAGE_SIZE)])[0])))
        except ValueError:
            page, size = 1, PAGE_SIZE
        start = (page - 1) * size
        total = store.count_filtered(q)
        chunk = store.page_filtered(q, start, size)
        self._json({
            "total": total,
            "page": page,
            "size": size,
            "rows": chunk,
            "format": ds["format"],
            "name": ds["name"],
        })

    def _tail(self, q, user):
        name = q.get("name", [""])[0]
        with LOCK:
            ds = dataset(user, name)
            w = _user_state(user, WATCHERS).get(name)
        if ds is None:
            self._error("no hay archivo cargado", 404)
            return
        if w is None or not w.enabled:
            self._json({"watching": False, "rows": [], "total_new": 0})
            return
        try:
            last = min(TAIL_MAX, max(1, int(q.get("last", ["500"])[0])))
        except ValueError:
            last = 500
        with w.lock:
            lines = list(w.buffer)[:last]
            for _ in range(len(lines)):
                w.buffer.popleft()
            truncated = w.truncated
            w.truncated = False
        rows, counters = tail_parse(ds, lines)
        for r in rows:
            r["_search"] = _make_search(r)
        ds["store"].add_rows(rows, counters)
        with LOCK:
            ds["total"] += len(lines)
            total = ds["total"]
        self._json({
            "watching": True,
            "rows": [{k: v for k, v in r.items() if k != "_search"}
                     for r in rows],
            "total_new": len(rows),
            "total": total,
            "truncated": truncated,
        })

    def _top(self, q, user):
        name = q.get("name", [""])[0]
        with LOCK:
            ds = dataset(user, name)
        if ds is None:
            self._error("no hay archivo cargado", 404)
            return
        field = q.get("field", ["ip"])[0]
        try:
            limit = min(100, max(1, int(q.get("limit", ["30"])[0])))
        except ValueError:
            limit = 30
        self._json({"field": field, "top": top_n(ds, field, limit)})

    EXPORT_BATCH = 5000  # filas por lote al exportar en streaming

    def _write_chunk(self, data):
        """Escribe un trozo en codificacion chunked (hex size + CRLF + data)."""
        self.wfile.write(("%x\r\n" % len(data)).encode("ascii"))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")

    def _csv_cell(self, v):
        """Sanea una celda CSV contra inyeccion de formulas en Excel.

        El contenido de los logs lo controla el emisor (paths, user-agents,
        mensajes): una celda que empieza por =, +, -, @ (o con tab/salto
        de linea) se interpreta como formula al abrir el CSV en
        Excel/LibreOffice. Se prefija con ' para forzar texto."""
        s = "" if v is None else str(v)
        if s[:1] in ("=", "+", "-", "@", "\t", "\r", "\n"):
            return "'" + s
        return s

    def _export(self, q, user):
        """Exporta las filas filtradas en streaming (Transfer-Encoding:
        chunked). Se pagina por lotes de EXPORT_BATCH para no construir
        el cuerpo entero en memoria (un dataset SQLite de millones de
        filas no debe OOM ni bloquear la BD durante todo el export)."""
        name = q.get("name", [""])[0]
        fmt = q.get("format", ["csv"])[0].strip().lower()
        if fmt not in ("csv", "json"):
            self._error("formato de export no soportado (csv o json)", 400)
            return
        with LOCK:
            ds = dataset(user, name)
        if ds is None:
            self._error("no hay archivo cargado", 404)
            return
        store = ds["store"]
        cols = ["ts", "level", "ip", "host", "app", "pid",
                "method", "path", "code", "bytes", "msg"]
        ctype = ("application/x-ndjson; charset=utf-8" if fmt == "json"
                 else "text/csv; charset=utf-8")
        fname = "export.ndjson" if fmt == "json" else "export.csv"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition",
                         'attachment; filename="%s"' % fname)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        out = io.StringIO()

        def flush():
            nonlocal out
            if out.tell() > 0:
                self._write_chunk(out.getvalue().encode("utf-8"))
                out = io.StringIO()

        def clean(r):
            return {k: r.get(k, "") for k in cols}

        w = None
        if fmt == "csv":
            w = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore",
                               lineterminator="\n")
            w.writeheader()
        n = 0
        start = 0
        try:
            while True:
                batch = store.page_filtered(q, start, self.EXPORT_BATCH)
                if not batch:
                    break
                for r in batch:
                    if fmt == "json":
                        c = clean(r)
                        c["raw"] = r.get("raw", "")
                        out.write(json.dumps(c, ensure_ascii=False) + "\n")
                    else:
                        w.writerow({k: self._csv_cell(v)
                                    for k, v in clean(r).items()})
                    n += 1
                if out.tell() > 65536:
                    flush()
                start += self.EXPORT_BATCH
            flush()
            self._write_chunk(b"")  # chunk final
        except (ConnectionError, BrokenPipeError):
            return  # el cliente se fue: nada mas que hacer
        audit("export", user=self._user(), ip=self.client_address[0],
              file=ds["name"], format=fmt, rows=n)

    def do_POST(self):
        if not self._cf_ok():
            self._error("acceso directo no permitido (requiere Cloudflare Access)", 403)
            return
        # Anti-CSRF: la pagina (servida por este proceso) mete el token en
        # todos los POST. Un fetch cross-origin no puede anadir el header
        # sin preflight (y el preflight falla: no hay CORS), y un POST
        # "simple" (text/plain, multipart) sin el header se rechaza.
        if self.headers.get("X-CSRF-Token", "") != CSRF_TOKEN:
            self._error("token CSRF invalido", 403)
            return
        u = urlparse(self.path)
        if u.path == "/upload":
            self._upload()
        elif u.path == "/api/activate":
            self._activate()
        elif u.path == "/api/remove":
            self._remove()
        elif u.path == "/api/watch":
            self._watch()
        else:
            self._error("ruta no conocida", 404)

    def _upload(self):
        # Tope de subidas concurrentes: cada una puede leer hasta 1 GB del
        # cuerpo en RAM; sin este limite unas pocas peticiones a la vez
        # agotan la memoria (ThreadingHTTPServer no limita hilos).
        if not UPLOAD_SEM.acquire(timeout=15):
            self._error("servidor ocupado con otras cargas; reintenta en unos segundos",
                        503)
            return
        try:
            try:
                ctype = self.headers.get("Content-Type", "")
                if "multipart/form-data" not in ctype:
                    self._error("se espera multipart/form-data")
                    return
                # Lee el cuerpo completo: exactamente Content-Length bytes
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self._error("Content-Length invalido")
                    return
                if length > TOTAL_MAX:
                    self._error("peticion demasiado grande (max 1 GB por lote)", 413)
                    return
                data = self.rfile.read(length)
                # Extrae el boundary y localiza las partes de archivo
                m = re.search(r'boundary="?([^";]+)"?', ctype)
                if not m:
                    self._error("multipart sin boundary")
                    return
                parts = parse_multipart_all(data, m.group(1).encode())
                if not parts:
                    self._error("no se encontro ninguna parte de archivo")
                    return

                # Validaciones previas (antes de guardar nada)
                bad = []
                for name, body in parts:
                    if len(body) > MAX_SIZE:
                        bad.append("%s: supera el maximo de 500 MB" % name)
                    elif not is_supported_name(name):
                        bad.append("%s: extension no soportada (se aceptan %s)"
                                   % (name, ", ".join(SUPPORTED_EXTS)))
                if bad:
                    self._error("archivos no validos: " + " | ".join(bad), 400)
                    return

                # Guarda en el temp dir de la sesion (carpeta por usuario:
                # dos usuarios con el mismo nombre de archivo no se pisan)
                # y lanza los hilos de carga
                user = self._user()
                tmpdir = os.path.join(tempfile.gettempdir(), "logviewer",
                                      "sessions", safe_session_name(user))
                os.makedirs(tmpdir, exist_ok=True)
                started = []
                existing_names = []
                for name, body in parts:
                    safe_name = safe_session_name(name, existing_names)
                    existing_names.append(safe_name)
                    dest = os.path.join(tmpdir, safe_name)
                    with open(dest, "wb") as f:
                        f.write(body)
                    # Si hay watcher activo, reiniciarlo sobre la nueva copia
                    w = _user_state(user, WATCHERS).get(safe_name)
                    if w is not None:
                        w.reset(seek_end=True)
                    _user_state(user, PROGRESS)[safe_name] = {
                        "phase": "queued", "pct": 0, "message": "en cola"}
                    started.append(safe_name)
                    audit("upload", user=user, ip=self.client_address[0],
                          file=safe_name, size=len(body))
                    threading.Thread(target=_load_worker,
                                     args=(safe_name, dest, user,
                                           self.client_address[0]),
                                     daemon=True).start()
                with LOCK:
                    sl = sessions_list(user)
                    act = ACTIVE.get(user, "")
                self._json({
                    "started": started,
                    "sessions": sl,
                    "active": act,
                })
            except Exception as e:
                # La excepcion cruda puede llevar rutas internas del
                # servidor: se loguea y al cliente se le dice poco.
                self.log_message("upload error: %r" % (e,))
                self._error("error al cargar", 500)
        finally:
            UPLOAD_SEM.release()


    def _activate(self):
        body = self._read_json_body()
        if body is None:
            self._error("cuerpo JSON invalido", 400)
            return
        user = self._user()
        name = safe_session_name(body.get("name", ""))
        with LOCK:
            mine = _user_state(user, SESSIONS)
            if name not in mine:
                self._error("dataset no encontrado: %s" % name, 404)
                return
            ACTIVE[user] = name
            sl = sessions_list(user)
            act = ACTIVE[user]
        audit("activate", user=user, ip=self.client_address[0], file=name)
        self._json({"active": act, "sessions": sl})

    def _watch(self):
        body = self._read_json_body()
        if body is None:
            self._error("cuerpo JSON invalido", 400)
            return
        user = self._user()
        name = safe_session_name(body.get("name", ""))
        enabled = bool(body.get("enabled", False))
        with LOCK:
            ds = _user_state(user, SESSIONS).get(name)
            if ds is None:
                self._error("dataset no encontrado: %s" % name, 404)
                return
            path = os.path.join(
                tempfile.gettempdir(), "logviewer", "sessions",
                safe_session_name(user), name)
            watchers = _user_state(user, WATCHERS)
            w = watchers.get(name)
            if w is None:
                w = Watcher(name, path, ds.get("encoding") or "utf-8")
                watchers[name] = w
            if enabled:
                w.reset(seek_end=True)
                w.enabled = True
                w.start()
            else:
                w.stop()
            now_enabled = w.enabled
        self._json({"name": name, "enabled": now_enabled})

    def _remove(self):
        body = self._read_json_body()
        if body is None:
            self._error("cuerpo JSON invalido", 400)
            return
        user = self._user()
        name = safe_session_name(body.get("name", ""))
        with LOCK:
            mine = _user_state(user, SESSIONS)
            if name not in mine:
                # 404 generico: no se filtra el dataset de otro usuario
                self._error("dataset no encontrado: %s" % name, 404)
                return
            mine[name]["store"].close()
            del mine[name]
            _user_state(user, PROGRESS).pop(name, None)
            # Para y borra su watcher
            w = _user_state(user, WATCHERS).pop(name, None)
            if w is not None:
                w.stop()
            if ACTIVE.get(user, "") == name:
                # Pasa a otro dataset o queda vacio
                ACTIVE[user] = next(iter(mine), "")
            sl = sessions_list(user)
            act = ACTIVE.get(user, "")
        # Borra la copia temporal (carpeta del usuario)
        try:
            os.remove(os.path.join(
                tempfile.gettempdir(), "logviewer", "sessions",
                safe_session_name(user), name))
        except OSError:
            pass
        audit("remove", user=user, ip=self.client_address[0], file=name)
        self._json({"removed": name, "active": act, "sessions": sl})


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def resolve_bind(port_arg, host_arg, env_port):
    """Resuelve (host, puerto) de escucha.

    - Con argumento de puerto: ese puerto, host 127.0.0.1 (local).
    - Con $PORT (Railway lo inyecta): ese puerto, host 0.0.0.0.
    - Sin nada: 127.0.0.1:8765.
    --host (host_arg) fuerza la direccion en cualquier caso.
    Lanza ValueError si el puerto no es numerico."""
    if port_arg is not None:
        return (host_arg or "127.0.0.1"), int(port_arg)
    if env_port:
        return (host_arg or "0.0.0.0"), int(env_port)
    return (host_arg or "127.0.0.1"), 8765


def main():
    ap = argparse.ArgumentParser(description="Visor de Logs Unificado")
    ap.add_argument("port", nargs="?", default=None,
                    help="puerto (por defecto: 8765, o $PORT si esta)")
    ap.add_argument("--host", default=None,
                    help="direccion de escucha (por defecto 127.0.0.1;"
                         " 0.0.0.0 si hay $PORT, p. ej. en Railway)")
    args = ap.parse_args()
    try:
        host, port = resolve_bind(args.port, args.host,
                                  os.environ.get("PORT"))
    except ValueError:
        print("Puerto invalido: %s" % args.port)
        sys.exit(1)

    # Limpia las carpetas de sesiones y SQLite al arrancar
    tmpdir = os.path.join(tempfile.gettempdir(), "logviewer")
    sessions_dir = os.path.join(tmpdir, "sessions")
    sqlite_dir = os.path.join(tmpdir, "sqlite")
    for d in (sessions_dir, sqlite_dir):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)

    class Server(ThreadingHTTPServer):
        # Reutilizar la direccion para poder reiniciar rapidamente
        allow_reuse_address = True

    server = Server((host, port), Handler)
    print("Visor de Logs Unificado", flush=True)
    print("  http://%s:%d/" % (host, port), flush=True)
    print("  Temp dir: %s" % tmpdir, flush=True)
    print("  (Ctrl+C para parar)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAdios.")
        server.server_close()


if __name__ == "__main__":
    main()
