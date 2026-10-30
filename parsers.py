"""parsers.py - deteccion de formato, parsers y filtros de filas.

P5.1 (2026-10-30): separado de server.py. Solo stdlib.
"""
import argparse
import base64
import bz2
import fnmatch
import hashlib
import codecs
import csv
import gzip
import hmac
import io
import json
import lzma
import os
import re
import secrets
import shutil
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
import socket
import urllib.request

import config
from config import *

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

# OperVanta/piloop: 'YYYY-MM-DD HH:MM:SS componente: mensaje', SIN nivel explicito.
# El componente es opcional (hay lineas tipo 'DIGEST s01 -> memoria.md').
# Las lineas que no matchean (stack traces, continuaciones) se quedan como RAW.
RE_PILOOP = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
    r'(?:(?P<comp>[^\n:]{1,80}):\s+)?'
    r'(?P<msg>.*)$'
)

# SOC triage (buzon/soc/triage.log):
#   'HH:MM:SS [fuente] FIRMA -> verdict conf 0.8 sev 2.0 accion yes | ESCALADA t4f87df76'
#   o '... | sin tarea'. La hora va SIN fecha: ts se completa con la fecha del
#   archivo si la hay. Los valores pueden venir como 'None' (el triage no siempre
#   puntua) y la parte del '|' es opcional.
RE_TRIAGE = re.compile(
    r'^(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<fuente>[^\]]*)\]\s+'
    r'(?P<firma>.*?)\s*->\s*'
    r'(?P<verdict>\S+)\s+'
    r'conf\s+(?P<conf>None|\d+(?:\.\d+)?)\s+'
    r'sev\s+(?P<sev>None|\d+(?:\.\d+)?)\s+'
    r'accion\s+(?P<accion>None|\S+)'
    r'(?:\s*\|\s*(?:ESCALADA\s+(?P<tarea>\S+)|sin\s+tarea))?\s*$'
)

# Heuristica de nivel para el formato piloop (no hay nivel en la linea)
PILOOP_ERR_HINTS = ("except", "error", "traceback", "permissionerror", "epipe", "denied")
PILOOP_WRN_HINTS = ("warn", "aviso")
PILOOP_INF_HINTS = ("ok", "completado", "rotado", "iniciado")

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
# P0.3 (OperVanta): los JSON Lines del SOC traen el nivel en 'sev' como texto
# ('baja', 'media', 'alta', 'critica') o como numero (0..3, como el triage).
SEV_KEYS = ("sev", "criticality", "impacto")
MSG_KEYS = ("msg", "message", "text", "log", "msg_text", "mensaje")
IP_KEYS = ("ip", "client_ip", "ip_addr", "src_ip", "remote_addr", "source_ip",
           "src", "dst")
SEV_MAP = {
    "baja": "WRN", "low": "WRN", "minor": "WRN", "warn": "WRN", "warning": "WRN",
    "media": "INF", "medium": "INF", "mid": "INF", "info": "INF",
    "alta": "ERR", "high": "ERR", "error": "ERR",
    "critica": "CRIT", "critical": "CRIT", "fatal": "CRIT",
}

# P4.2: orden de severidad de menor a mayor riesgo, para el dashboard SOC
SEV_ORDER = ("CRIT", "ERR", "WRN", "INF")
RE_SEV_NUM = re.compile(r"\d+(?:\.\d+)?")


def norm_sev(v):
    """Normaliza una severidad a CRIT/ERR/WRN/INF (P4.2).

    Acepta texto ('alta', 'critica', 'baja', 'media', 'err', 'CRIT'...) y
    numero (0..3, como el triage SOC: sev 0.2 = baja, sev 2.0 = alta).
    Lo desconocido se queda como INF (no se inventa riesgo)."""
    if v is None:
        return "INF"
    if isinstance(v, (int, float)):
        n = float(v)
    else:
        s = str(v).strip()
        if not s:
            return "INF"
        up = s.upper()
        if up in SEV_ORDER:
            return up
        low = s.lower()
        if low in SEV_MAP:
            return SEV_MAP[low]
        if not RE_SEV_NUM.fullmatch(low):
            return "INF"
        n = float(low)
    if not n == n:      # NaN
        return "INF"
    if n >= 3.0:
        return "CRIT"
    if n >= 2.0:
        return "ERR"
    if n >= 1.0:
        return "WRN"
    return "INF"
# Columnas de OperVanta que antes se perdian al parsear JSON Lines.
# P0.4: 'sev', 'src' y 'dst' se conservan tal cual (ademas de usarse para
# level e ip) para que el export no pierda la firma ni la severidad original.
JSON_EXTRA_KEYS = ("fuente", "firma", "tenant", "tarea", "dedupe",
                   "evidencia", "riesgo", "url", "sev", "src", "dst")
# Claves que envuelven el registro real en dataset.jsonl / triage-dataset.jsonl
JSON_NESTED_KEYS = ("datos", "alerta", "data", "event", "payload", "detail")


def _norm_level(lv):
    """Normaliza un nivel a su categoria estandar."""
    return LEVEL_MAP.get(lv.upper(), lv)


# Fase 7A: normalizacion de timestamps a ISO canónico (campo ts_norm).
# Se usa para el rango dt_from/dt_to (comparacion lexicografica). Los
# valores con zona horaria se convierten a UTC; los sin zona se dejan en
# su hora local. Si no se parsea, norm_ts devuelve "".
RE_CLF_TS = re.compile(
    r'(\d{1,2})/([A-Za-z]{3,4})/(\d{4}):(\d{2}):(\d{2}):(\d{2})'
    r'(?:\s*([+-]\d{2})(\d{2}))?')
_CLF_MONTHS = {}
for _i, _m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun",
                         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")):
    _CLF_MONTHS[_m.lower()] = _i + 1


def norm_ts(ts):
    """Normaliza un timestamp a ISO (Fase 7A).

    Acepta CLF (21/Ago/2026:13:00:00 +0000), ISO 8601 (con T o espacio,
    fraccion opcional, Z u offset) y epoch (segundos o ms). Devuelve ""
    si no se parsea. Con zona horaria -> UTC; sin zona -> hora local.
    """
    if not ts:
        return ""
    s = str(ts).strip()
    dt = None
    m = RE_CLF_TS.match(s)
    if m and m.group(2)[:3].lower() in _CLF_MONTHS:
        mon = _CLF_MONTHS[m.group(2)[:3].lower()]
        tz = None
        if m.group(7):
            sign = 1 if m.group(7)[0] == "+" else -1
            tz = timezone(sign * timedelta(hours=int(m.group(7)[1:]),
                                           minutes=int(m.group(8))))
        dt = datetime(int(m.group(3)), mon, int(m.group(1)),
                      int(m.group(4)), int(m.group(5)), int(m.group(6)),
                      tzinfo=tz)
    elif s.isdigit():
        v = int(s)
        if len(s) >= 13:
            v /= 1000.0
        dt = datetime.fromtimestamp(v, timezone.utc)
    else:
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return ""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    out = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        out += ".%06d" % dt.microsecond
    return out


def _dt_bound(v):
    """Normaliza un extremo de rango dt_from/dt_to (Fase 7A)."""
    v = v.strip()
    if not v:
        return ""
    return norm_ts(v) or v


_SEARCH_KEYS = ["ts", "level", "ip", "host", "app", "pid",
                "method", "path", "code", "bytes", "msg",
                "fuente", "firma", "tenant", "tarea", "dedupe", "url"]


def _make_search(r):
    """Construye la cadena de busqueda lowercased para una fila."""
    return " ".join(str(r.get(k, "")) for k in _SEARCH_KEYS).lower()


# Fase 9A: normalizacion a plantilla (en el parseo, no en SQL)
RE_TPL_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_TPL_HEX = re.compile(r"\b[0-9a-fA-F]{8,}\b")
RE_TPL_NUM = re.compile(r"\b\d+\b")


def make_template(text):
    """Normaliza una linea a plantilla: IPs, hex largo y numeros -> '*'.

    Se calcula EN EL PARSING (no sobre la marcha en SQL): asi agrupa
    lineas que solo difieren en valores variables sin coste por consulta.
    """
    if text is None:
        return ""
    t = RE_TPL_IP.sub("*", str(text))
    t = RE_TPL_HEX.sub("*", t)
    t = RE_TPL_NUM.sub("*", t)
    return t


def _clean(v):
    """Cadena normalizada (strip) de un valor que puede venir como None."""
    return "" if v is None else str(v).strip()

def _trunc(s, n=TRUNC):
    """Trunca cadenas muy largas (las lineas de Zscaler llegan a 4095 chars).

    P1.1 (bug B3): SOLO se usa en la capa de serializacion hacia la UI y en la
    auditoria. El parseo ya no trunca: el contenido completo vive en la fila."""
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + " ..."


def _ui_columns(store):
    """P3.1: columnas que la tabla puede mostrar para este dataset.

    Usa store.columns() (union real de claves, sin internas) y deja solo las
    que se pueden pintar en la tabla: 'msg' primero si existe, y el resto en
    el orden natural del parseo. No devuelve 'raw' ni 'ts_norm'.
    """
    try:
        cols = store.columns()
    except Exception:
        cols = []
    out = []
    for c in cols:
        if c in EXPORT_SKIP_KEYS or c in out:
            continue
        if c in ("msg_len", "msg_truncated", "line", "search"):
            continue
        out.append(c)
    return out


def ui_row(r):
    """Fila tal y como la sirve la UI (P1.1, bug B3).

    El parseo guarda el contenido COMPLETO; el recorte se aplica aqui, en la
    capa que sirve la lista de filas, para no inflar el JSON de la tabla.
    'raw' se sirve entero: el drawer y el export necesitan la linea completa.
    Se anaden msg_len y msg_truncated para que la UI pueda indicar el recorte.
    La fila interna (con _search) no se modifica: el store sigue teniendo el
    texto completo.
    """
    out = dict(r)
    out.pop("_search", None)
    msg = out.get("msg", "") or ""
    if len(msg) > TRUNC:
        out["msg_len"] = len(msg)
        out["msg_truncated"] = True
        out["msg"] = _trunc(msg, TRUNC)
    return out



# ---------------------------------------------------------------------------
# Compresion y encoding
# ---------------------------------------------------------------------------
# Bug B12 (2026-10-30): se eliminó open_log_file, una version muerta que
# cargaba el archivo entero en RAM. La ruta viva es open_log_stream (abajo),
# que ya lee en streaming y detecta la compresion por magico.

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
                "msg": "%s %s" % (method, path),
                "raw": l, "_line": i,
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
            "msg": "%s %s" % (method, path),
            "raw": l, "_line": i,
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"ips": ips, "paths": paths, "codes": codes, "methods": methods}


def _json_scalar(v):
    """Convierte un valor JSON (escalar, lista o dict) en texto de columna."""
    if v is None or v == "":
        return ""
    if isinstance(v, bool):
        return "si" if v else "no"
    if isinstance(v, (list, tuple)):
        return ", ".join(_json_scalar(x) for x in v if x not in (None, ""))
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _flatten_json(obj):
    """Aplana las claves relevantes de un dict anidado ('datos', 'alerta'...).

    Las claves de nivel superior mandan; las anidadas solo se usan si arriba
    no hay valor (dataset.jsonl y triage-dataset.jsonl)."""
    flat = dict(obj)
    for key in JSON_NESTED_KEYS:
        nested = obj.get(key)
        if isinstance(nested, dict):
            for k, v in nested.items():
                if not flat.get(k) and v:
                    flat[k] = v
    return flat


def _norm_sev(v):
    """'sev' de OperVanta -> nivel estandar.

    Regla P0.3: baja->WRN, media->INF, alta->ERR, critica->CRIT. También acepta
    niveles textuales ya normalizados y severidades numericas (umbral del
    triage SOC: >=2 ERR, >=1 WRN)."""
    if v is None:
        return ""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if v >= TRIAGE_ERR_SEV:
            return "ERR"
        if v >= TRIAGE_WRN_SEV:
            return "WRN"
        return "INF" if v > 0 else ""
    s = str(v).strip().lower()
    if not s:
        return ""
    if s in SEV_MAP:
        return SEV_MAP[s]
    try:
        f = float(s)
    except ValueError:
        return _norm_level(s)
    if f >= TRIAGE_ERR_SEV:
        return "ERR"
    if f >= TRIAGE_WRN_SEV:
        return "WRN"
    return "INF" if f > 0 else ""


def parse_json(lines, progress=None):
    """JSON Lines. Una linea JSON por registro.

    Mapeos OperVanta (P0.3): 'sev' -> level (baja->WRN, media->INF, alta->ERR,
    critica->CRIT), 'mensaje'/'message' -> msg, 'src'/'dst' -> ip (dst si src
    esta vacio) y columnas fuente/firma/tenant/tarea/dedupe/evidencia/riesgo.
    Si el registro envuelve el dato en 'datos'/'alerta', se aplana."""
    rows = []
    ips, levels = Counter(), Counter()
    fuentes, firmas, tareas = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        l = l.strip()
        if l:
            try:
                obj = json.loads(l)
            except Exception:
                obj = None
            if obj is not None and isinstance(obj, dict):
                obj = _flatten_json(obj)
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
                if not level:
                    for k in SEV_KEYS:
                        if k in obj and obj[k]:
                            level = _norm_sev(obj[k])
                            break
                msg = ""
                for k in MSG_KEYS:
                    if k in obj and obj[k]:
                        msg = _json_scalar(obj[k])
                        break
                ip = ""
                for k in IP_KEYS:
                    if k in obj and obj[k]:
                        ip = _json_scalar(obj[k])
                        break
                if not msg:
                    # Sin mensaje: el JSON entero es el mensaje
                    msg = json.dumps(obj, ensure_ascii=False)
                # P1.1: sin truncado en el parseo (el export pierde datos si
                # se recorta aqui; la UI ya acota al serializar)
                extra = {k: _json_scalar(obj.get(k, ""))
                         for k in JSON_EXTRA_KEYS}
                if ip:
                    ips[ip] += 1
                if level:
                    levels[level] += 1
                if extra["fuente"]:
                    fuentes[extra["fuente"]] += 1
                if extra["firma"]:
                    firmas[extra["firma"]] += 1
                if extra["tarea"]:
                    tareas[extra["tarea"]] += 1
                rows.append({
                    "ts": ts, "level": level, "ip": ip, "method": "",
                    "path": "", "code": "", "bytes": "",
                    "msg": msg,
                    "fuente": extra["fuente"], "firma": extra["firma"],
                    "tenant": extra["tenant"], "tarea": extra["tarea"],
                    "dedupe": extra["dedupe"], "evidencia": extra["evidencia"],
                    "riesgo": extra["riesgo"], "url": extra["url"],
                    # P0.4: severidad y extremos originales, sin transformar
                    "sev": extra["sev"], "src": extra["src"],
                    "dst": extra["dst"],
                    "raw": l, "_line": i,
                })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"ips": ips, "levels": levels,
                  "fuentes": fuentes, "firmas": firmas, "tareas": tareas}


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
                "msg": m.group("msg"),
                "host": host, "app": app, "pid": m.group("pid") or "",
                "raw": l, "_line": i,
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
            "msg": msg,
            "raw": l, "_line": i,
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips}


def _infer_level_piloop(msg):
    """Infiere el nivel de una linea de OperVanta a partir del mensaje.
    Sin pistas -> INF (es texto normal del buzon)."""
    low = msg.lower()
    if any(h in low for h in PILOOP_ERR_HINTS):
        return "ERR"
    if any(h in low for h in PILOOP_WRN_HINTS):
        return "WRN"
    if any(h in low for h in PILOOP_INF_HINTS):
        return "INF"
    return "INF"


def parse_piloop(lines, progress=None):
    """Formato OperVanta/piloop: 'YYYY-MM-DD HH:MM:SS componente: mensaje'.
    El nivel se infiere por heuristica. Lo que no matchea va como RAW.
    Se extrae la primera IPv4 de cada linea, igual que parse_generic."""
    rows = []
    levels, ips, comps = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        m = RE_PILOOP.match(l)
        if m:
            ts = m.group("date") + " " + m.group("time")
            comp = m.group("comp") or ""
            msg = m.group("msg")
            lv = _infer_level_piloop(comp + " " + msg) if comp else _infer_level_piloop(msg)
            if comp:
                comps[comp] += 1
        else:
            lv, ts, comp, msg = "RAW", "", "", l
        levels[lv] += 1
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        rows.append({
            "ts": ts, "level": lv, "ip": ip, "method": "",
            "path": "", "code": "", "bytes": "",
            "msg": msg,
            "raw": l, "_line": i,
            "comp": comp,
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "comps": comps}


def _triage_num(v):
    """Devuelve float(v) o None si el valor es 'None'/vacio/no numerico."""
    if v is None or v == "" or str(v).lower() == "none":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None

# Umbrales de severidad/confianza para inferir el nivel en el formato triage.
TRIAGE_ERR_SEV = 2.0
TRIAGE_WRN_SEV = 1.0
TRIAGE_HIGH_CONF = 0.7
TRIAGE_INCIDENT_VERDICTS = ("real_incident", "true_positive", "incident",
                            "breach", "malware", "intrusion")


def _infer_level_triage(verdict, conf, sev, accion):
    """Infiere el nivel de una linea de triage (no hay nivel en la linea).

    ERR  si sev >= 2.0 o la accion es 'yes' (se actuo sobre el evento).
    WRN  si sev >= 1.0, o si la confianza es alta y el veredicto es de incidente.
    INF  en el resto (sev baja y veredicto benigno, o sin puntuacion).
    """
    if sev is not None and sev >= TRIAGE_ERR_SEV:
        return "ERR"
    if accion and accion.lower() == "yes":
        return "ERR"
    if sev is not None and sev >= TRIAGE_WRN_SEV:
        return "WRN"
    if (conf is not None and conf >= TRIAGE_HIGH_CONF and
            verdict and verdict.lower() in TRIAGE_INCIDENT_VERDICTS):
        return "WRN"
    return "INF"


def parse_triage(lines, progress=None, file_date=None):
    """Formato SOC triage: 'HH:MM:SS [fuente] FIRMA -> verdict conf X sev Y accion Z | ESCALADA tid'.

    Columnas extra: fuente, firma, verdict, conf, sev, accion, tarea.
    ts = '<fecha del archivo> HH:MM:SS' si se conoce la fecha; si no, solo la
    hora (vacio si la linea no matchea, que se queda como RAW).
    """
    rows = []
    levels, ips = Counter(), Counter()
    fuentes, firmas, verdicts = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        m = RE_TRIAGE.match(l)
        if m:
            hora = m.group("time")
            ts = (file_date + " " + hora) if file_date else hora
            fuente = m.group("fuente").strip()
            firma = m.group("firma").strip()
            verdict = m.group("verdict")
            conf = _triage_num(m.group("conf"))
            sev = _triage_num(m.group("sev"))
            accion = m.group("accion") or ""
            tarea = m.group("tarea") or ""
            lv = _infer_level_triage(verdict, conf, sev, accion)
            msg = l[m.start("firma"):].strip()
            fuentes[fuente] += 1
            firmas[firma] += 1
            verdicts[verdict] += 1
        else:
            lv, ts, fuente, firma, verdict, conf, sev, accion, tarea = (
                "RAW", "", "", "", "", None, None, "", "")
            msg = l
        levels[lv] += 1
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        rows.append({
            "ts": ts, "level": lv, "ip": ip, "method": "",
            "path": "", "code": "", "bytes": "",
            "msg": msg,
            "raw": l, "_line": i,
            "fuente": fuente, "firma": firma, "verdict": verdict,
            "conf": conf, "sev": sev, "accion": accion, "tarea": tarea,
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "fuente": fuentes,
                  "firma": firmas, "verdict": verdicts}


def parse_raw(lines, progress=None):
    """RAW: lineas tal cual, sin parsear."""
    rows = []
    for i, l in enumerate(lines):
        rows.append({
            "ts": "", "level": "RAW", "ip": "", "method": "",
            "path": "", "code": "", "bytes": "", "msg": l,
            "raw": l, "_line": i,
        })
    return rows, {"levels": Counter({"RAW": len(rows)})}


PARSERS = {
    "apache": parse_apache,
    "w3c": parse_w3c,
    "json": parse_json,
    "syslog": parse_syslog,
    "generic": parse_generic,
    "piloop": parse_piloop,
    "triage": parse_triage,
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
    # triage (SOC): umbral 40% porque puede haber lineas de continuation
    # o cabeceras que no siguen el patron
    if sum(1 for l in sample if RE_TRIAGE.match(l)) >= n * 0.4:
        return "triage"
    # piloop: umbral bajo (40%) porque los stack traces y las continuaciones
    # de linea no llevan timestamp y se quedan como RAW solo en esas lineas
    if sum(1 for l in sample if RE_PILOOP.match(l)) >= n * 0.4:
        return "piloop"
    return "raw"



# ---------------------------------------------------------------------------
# Filtrado en el servidor
# ---------------------------------------------------------------------------
def parse_terms(val):
    """Fase 7D: parser de filtros con exclusion y multivalor.

    Acepta coma para multivalor ("200,301") y prefijo "!" por termino
    ("!10.0.0.5"). Devuelve una lista de tuplas (negado, termino) o None
    si no hay terminos validos.
    """
    if val is None:
        return None
    # Acepta forma CGI (lista) o cadena plana
    if isinstance(val, (list, tuple)):
        val = val[0] if val else ""
    terms = []
    for part in str(val).split(","):
        t = part.strip()
        if not t:
            continue
        neg = t.startswith("!")
        if neg:
            t = t[1:]
        if t:
            terms.append((neg, t))
    return terms or None


def _first(val, default=""):
    """Primer valor de un parametro tipo CGI (lista) o cadena plana."""
    if isinstance(val, (list, tuple)):
        val = val[0] if val else default
    return default if val is None else val


def filter_plan(q):
    """P1.1 (bug B5): contrato UNICO de filtrado para MemStore y SqlStore.

    Normaliza el query de la UI una sola vez: terminos parseados (positivos y
    negativos), plantilla, fecha y rango. Los dos backendos consumen este plan
    y comparten la semantica:
      - q / ip / path: subcadena case-insensitive (OR de positivos, AND de
        negativos)
      - level / code: igualdad exacta
      - tpl: igualdad exacta; dt: subcadena de ts; dt_from/dt_to: ts_norm
    Si cambia la semantica se cambia aqui y ambos stores siguen devolviendo
    las mismas filas para el mismo 'q'.
    """
    if not q:
        q = {}
    return {
        "level": parse_terms(_first(q.get("level"))),
        "code": parse_terms(_first(q.get("code"))),
        "ip": parse_terms(_first(q.get("ip"))),
        "path": parse_terms(_first(q.get("path"))),
        "q": parse_terms(_first(q.get("q"))),
        "tpl": str(_first(q.get("tpl"))).strip(),
        "dt": str(_first(q.get("dt"))).strip(),
        "dt_from": _dt_bound(_first(q.get("dt_from"))),
        "dt_to": _dt_bound(_first(q.get("dt_to"))),
    }


def terms_pass(value, terms, exact=False):
    """Fase 7D: OR de los positivos AND NOT de los negativos.

    Sin positivos, la condicion positiva se cumple siempre (solo
    aplican las exclusiones). Con exact=True el match es de igualdad
    (level/code); si no, subcadena sin distinguir mayusculas.
    """
    value = value or ""
    pos = [t for n, t in terms if not n]
    neg = [t for n, t in terms if n]
    if pos and not any(
            (value == p if exact else p.lower() in value.lower())
            for p in pos):
        return False
    for g in neg:
        if exact:
            if value == g:
                return False
        elif g.lower() in value.lower():
            return False
    return True


def _row_match(r, plan):
    """P1.2: predicado de UNA fila (cuerpo de _rows_match).

    Se separa para poder recorrer el dataset en un solo paso sin construir la
    lista filtrada entera (keyset pagination en MemStore, bug B8)."""
    level_t, code_t = plan["level"], plan["code"]
    ip_t, path_t, txt_t = plan["ip"], plan["path"], plan["q"]
    tpl, dt = plan["tpl"], plan["dt"]
    dt_from, dt_to = plan["dt_from"], plan["dt_to"]
    if level_t and not terms_pass(r.get("level", ""), level_t, exact=True):
        return False
    if code_t and not terms_pass(r.get("code", ""), code_t, exact=True):
        return False
    if ip_t and not terms_pass(r.get("ip", ""), ip_t):
        return False
    if path_t and not terms_pass(r.get("path", ""), path_t):
        return False
    if dt and dt not in (r.get("ts", "") or ""):
        return False
    if txt_t and not terms_pass(r.get("_search", ""), txt_t):
        return False
    # Fase 9B: filtro exacto por plantilla (vino de la vista agrupada)
    if tpl and r.get("template", "") != tpl:
        return False
    ts_n = r.get("ts_norm", "")
    if dt_from and ts_n < dt_from:
        return False
    if dt_to and ts_n > dt_to:
        return False
    return True


def _rows_match(rows, plan):
    """Capa unica de filtrado (P1.1): filas que cumplen el plan.

    Es la referencia de la semantica que SqlStore debe replicar en SQL.
    """
    return [r for r in rows if _row_match(r, plan)]


def apply_filters(rows, q):
    """Aplica todos los filtros combinables. Devuelve la lista filtrada.

    P1.1: el query se normaliza con filter_plan(), el mismo plan que usa
    SqlStore. Se admite tanto el query crudo de la UI como un plan ya
    construido (filter_plan es idempotente con un plan)."""
    return _rows_match(rows, filter_plan(q))



