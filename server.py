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
import base64
import bz2
import fnmatch
import hashlib
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
                "method", "path", "code", "bytes", "msg"]


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


def _trunc(s, n=TRUNC):
    """Trunca cadenas muy largas (las lineas de Zscaler llegan a 4095 chars)."""
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + " ..."


# ---------------------------------------------------------------------------
# Fase 10A: runbooks (patron -> explicacion/causa/solucion/referencia)
#
# BD persistente en %TEMP\logviewer\runbooks.db: NO se borra al arrancar
# el servidor ni al quitar un dataset (a diferencia de los datasets).
class RunbookStore:
    """BD local de runbooks (patrones sobre msg y su explicacion)."""

    FIELDS = ("id", "pattern", "kind", "explicacion", "causa",
              "solucion", "ref", "created_at")

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS runbooks ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " pattern TEXT NOT NULL,"
            " kind TEXT NOT NULL DEFAULT 'regex',"
            " explicacion TEXT DEFAULT '',"
            " causa TEXT DEFAULT '',"
            " solucion TEXT DEFAULT '',"
            " ref TEXT DEFAULT '',"
            " created_at TEXT)")
        # Idempotencia por patron (Fase 10C: re-ejecutable sin duplicar)
        self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_rb_pattern"
            " ON runbooks(pattern)")
        self.conn.commit()

    def add(self, pattern, kind="regex", explicacion="", causa="",
            solucion="", ref=""):
        """Crea un runbook. Devuelve la fila; lanza ValueError si el
        patron ya existe (indice unico)."""
        if kind not in ("regex", "glob"):
            kind = "regex"
        try:
            with self.lock:
                cur = self.conn.execute(
                    "INSERT INTO runbooks (pattern, kind, explicacion,"
                    " causa, solucion, ref, created_at) VALUES (?,?,?,?,?,?,?)",
                    [pattern, kind, explicacion, causa, solucion, ref,
                     time.strftime("%Y-%m-%d %H:%M:%S")])
                self.conn.commit()
                rowid = cur.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError("el patron ya existe")
        return self.get(rowid)

    def get(self, rowid):
        with self.lock:
            r = self.conn.execute(
                "SELECT id, pattern, kind, explicacion, causa, solucion,"
                " ref, created_at FROM runbooks WHERE id = ?",
                [rowid]).fetchone()
        return dict(zip(self.FIELDS, r)) if r else None

    def update(self, rowid, pattern, kind, explicacion, causa,
               solucion, ref):
        """Edit los campos de un runbook. Devuelve la fila actualizada;
        None si no existe; ValueError si el patron choca con otro."""
        if kind not in ("regex", "glob"):
            kind = "regex"
        try:
            with self.lock:
                cur = self.conn.execute(
                    "UPDATE runbooks SET pattern=?, kind=?, explicacion=?,"
                    " causa=?, solucion=?, ref=? WHERE id=?",
                    [pattern, kind, explicacion, causa, solucion, ref,
                     rowid])
                self.conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError("el patron ya existe")
        if cur.rowcount == 0:
            return None
        return self.get(rowid)

    def all(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT id, pattern, kind, explicacion, causa, solucion,"
                " ref, created_at FROM runbooks ORDER BY id").fetchall()
        return [dict(zip(self.FIELDS, r)) for r in rows]

    def delete(self, rowid):
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM runbooks WHERE id = ?", [rowid])
            self.conn.commit()
            return cur.rowcount > 0


RUNBOOKS = None  # singleton perezoso (no se crea al importar)


def runbooks_store():
    global RUNBOOKS
    if RUNBOOKS is None:
        d = os.path.join(tempfile.gettempdir(), "logviewer")
        os.makedirs(d, exist_ok=True)
        RUNBOOKS = RunbookStore(os.path.join(d, "runbooks.db"))
    return RUNBOOKS


@lru_cache(maxsize=512)
def _rb_compile(pattern):
    """Compila (con cache) un patron regex de runbook; None si invalido."""
    try:
        return re.compile(pattern)
    except re.error:
        return None


def match_runbooks(msg, runbooks):
    """Devuelve los runbooks cuyo patron coincide con msg.

    kind 'regex': re.search (sin anclas; el patron va donde toque).
    kind 'glob': fnmatch sobre el msg entero. Un patron invalido
    (regex mal formada) NUNCA coincide: no rompe la lista."""
    out = []
    if msg is None:
        return out
    m = str(msg)
    for rb in runbooks:
        pat = rb.get("pattern") or ""
        if not pat:
            continue
        if rb.get("kind", "regex") == "glob":
            ok = fnmatch.fnmatch(m, pat)
        else:
            rx = _rb_compile(pat)
            ok = rx is not None and rx.search(m) is not None
        if ok:
            out.append(rb)
    return out


# ---------------------------------------------------------------------------
# Fase 12A: LLM local (API OpenAI-compatible) para el boton "Analizar"
# ---------------------------------------------------------------------------
# LOGVIEWER_LLM_URL: base del endpoint (p. ej. http://127.0.0.1:8080/v1 de
# LM Studio, o http://127.0.0.1:11434/v1 de Ollama). Si no esta definida,
# el boton "Analizar" NO aparece en la UI y /api/analyze responde 404.
LLM_URL = os.environ.get("LOGVIEWER_LLM_URL", "").strip()
LLM_MODEL = os.environ.get("LOGVIEWER_LLM_MODEL", "").strip() or "local"
LLM_TIMEOUT = int(os.environ.get("LOGVIEWER_LLM_TIMEOUT", "10").strip() or 10)
LLM_MAX_TOKENS = 4096    # generoso: los modelos de razonamiento gastan
                        # tokens en reasoning_content antes del content
LLM_SYSTEM_PROMPT = (
    "Eres un analista experto de logs de sistemas. Te dan UNA linea de log."
    " Explica que pasa, indica la causa probable y da pasos concretos de"
    " solucion. Responde breve y accionable.")

# Fase 12B: idioma de la respuesta del LLM (llm_lang en los ajustes).
# "auto" -> el idioma de la linea; "es"/"en" -> fijo.
LLM_LANGS = ("auto", "es", "en")
LLM_LANG_PROMPTS = {
    "auto": " Responde en el idioma de la linea.",
    "es": " Responde SIEMPRE en espanol, aunque la linea este en otro idioma.",
    "en": " Always respond in English, even if the line is in another language.",
}


def _norm_llm_lang(v):
    """Valida un idioma de respuesta del LLM: auto/es/en (lo demas -> auto)."""
    v = str(v or "").strip().lower()
    return v if v in LLM_LANGS else "auto"


def llm_system_prompt(lang):
    """Prompt del sistema segun el idioma configurado (Fase 12B).

    La instruccion de idioma se anade al prompt base: asi un cambio de
    idioma en los ajustes cambia el prompt sin tocar codigo."""
    return LLM_SYSTEM_PROMPT + LLM_LANG_PROMPTS[_norm_llm_lang(lang)]

LLM_CACHE = None  # singleton perezoso (no se crea al importar)


class SettingsStore:
    """Ajustes persistentes del visor (p. ej. config del LLM local).

    Se guardan en %TEMP%\\logviewer\\settings.json para que sobrevivan a
    reinicios. La primera vez se inicializan desde las variables de
    entorno (LOGVIEWER_LLM_URL/MODEL/TIMEOUT), que actuan como valor
    inicial por defecto; despues la UI puede cambiarlos con
    GET/POST /api/settings sin reiniciar el servidor."""

    KEYS = ("llm_url", "llm_model", "llm_timeout", "llm_lang")

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = self._load()

    def _load(self):
        d = {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {}
        # Valores por defecto desde env var (solo si aun no hay guardado)
        defaults = {
            "llm_url": LLM_URL,
            "llm_model": LLM_MODEL,
            "llm_timeout": LLM_TIMEOUT,
            "llm_lang": "auto",
        }
        for k in self.KEYS:
            if k not in d or d[k] in (None, ""):
                d[k] = defaults.get(k, "" if k != "llm_timeout" else 10)
        return d

    def get(self):
        with self.lock:
            return dict(self.data)

    def set(self, url=None, model=None, timeout=None, lang=None):
        with self.lock:
            if url is not None:
                self.data["llm_url"] = str(url).strip()
            if model is not None:
                self.data["llm_model"] = str(model).strip() or "local"
            if lang is not None:
                # Valor invalido cae a "auto" (nunca se guarda un idioma
                # que el prompt no entiende)
                self.data["llm_lang"] = _norm_llm_lang(lang)
            if timeout is not None:
                try:
                    self.data["llm_timeout"] = max(1, int(timeout))
                except (TypeError, ValueError):
                    self.data["llm_timeout"] = LLM_TIMEOUT
            try:
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.data, f, ensure_ascii=False, indent=2)
            except OSError:
                pass  # si no se puede escribir, la config sigue en memoria
            return dict(self.data)


SETTINGS = None  # singleton perezoso


def settings_store():
    global SETTINGS
    if SETTINGS is None:
        d = os.path.join(tempfile.gettempdir(), "logviewer")
        os.makedirs(d, exist_ok=True)
        SETTINGS = SettingsStore(os.path.join(d, "settings.json"))
    return SETTINGS


# URL publica del repo de GitHub (opcional): enlace de descarga de la
# version local en los avisos de funciones SOLO local (LLM, Splunk).
# Si no esta definida, el aviso se muestra sin enlace.
REPO_URL = os.environ.get("LOGVIEWER_REPO_URL", "").strip()


def llm_config():
    """Config actual del LLM desde los ajustes (URL, modelo, timeout, lang)."""
    s = settings_store().get()
    return {
        "url": s.get("llm_url", "") or LLM_URL,
        "model": s.get("llm_model", "") or LLM_MODEL,
        "timeout": s.get("llm_timeout", LLM_TIMEOUT),
        "lang": _norm_llm_lang(s.get("llm_lang")),
    }


def public_config():
    """Config de solo lectura para la UI (GET /api/config).

    Fase 12A: "llm" decide si aparece el boton Analizar; Fase 13:
    "splunk" decide si aparece la seccion de Splunk. repo_url (opcional):
    URL publica del repo para los avisos de funciones SOLO local; si no
    esta, el aviso se muestra sin enlace."""
    cfg = llm_config()
    return {"llm": bool(cfg["url"]), "url": cfg["url"],
            "model": cfg["model"], "timeout": cfg["timeout"],
            "splunk": splunk_enabled(), "repo_url": REPO_URL}


class LlmCacheStore:
    """Cache de respuestas del LLM por hash del mensaje (Fase 12A).

    Persistente como la BD de runbooks: sobrevive a cambios de dataset y a
    reinicios. Solo se cachean los exitos; un fallo NUNCA se guarda, asi
    el siguiente intento vuelve a preguntar al LLM."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS llm_cache ("
            "hash TEXT PRIMARY KEY,"
            " line TEXT NOT NULL,"
            " answer TEXT NOT NULL,"
            " created_at TEXT)")
        self.conn.commit()

    def get(self, key):
        with self.lock:
            r = self.conn.execute(
                "SELECT answer FROM llm_cache WHERE hash = ?", [key]).fetchone()
        return r[0] if r else None

    def put(self, key, line, answer):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO llm_cache (hash, line, answer,"
                " created_at) VALUES (?,?,?,?)",
                [key, line, answer,
                 time.strftime("%Y-%m-%d %H:%M:%S")])
            self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()


def llm_cache():
    global LLM_CACHE
    if LLM_CACHE is None:
        d = os.path.join(tempfile.gettempdir(), "logviewer")
        os.makedirs(d, exist_ok=True)
        LLM_CACHE = LlmCacheStore(os.path.join(d, "llm_cache.db"))
    return LLM_CACHE


def llm_key(line, model=None, lang="auto"):
    """Hash del mensaje (+ modelo + idioma): si cambia el modelo o el
    idioma, no se sirve una respuesta cacheada de otra config."""
    m = (model if model is not None else LLM_MODEL) or "local"
    l = _norm_llm_lang(lang)
    h = hashlib.sha256()
    h.update(str(m).encode("utf-8"))
    h.update(b"\x00")
    h.update(l.encode("utf-8"))
    h.update(b"\x00")
    h.update(str(line).encode("utf-8"))
    return h.hexdigest()


def _llm_url_host(url):
    """Host (hostname o IP) de una URL de LLM, o None si es invalida.

    Solo se permiten URL http/https. El host se extrae sin resolver DNS
    (solo el literal de la URL): asi un atacante no puede apuntar a una
    IP interna via nombre ni a una URL arbitraria."""
    if not url:
        return None
    try:
        u = urllib.parse.urlparse(url)
    except ValueError:
        return None
    if u.scheme not in ("http", "https"):
        return None
    if u.hostname is None:
        return None
    return u.hostname.lower()


def _is_loopback(host):
    """True si host es loopback (localhost, 127.0.0.0/8 o ::1).

    Es lo unico permitido como destino del LLM: los modelos locales corren
    en la propia maquina (LM Studio/Ollama/llama.cpp). Rechazar cualquier
    otra URL evita que el servidor se use como SSRF hacia la red interna
    (p. ej. metadata de cloud o servicios internos)."""
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    # 127.0.0.0/8 (cualquier 127.x.y.z) es loopback
    if host.startswith("127."):
        return True
    return False


class _LoopbackRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Rechaza redirecciones HTTP cuyo destino no sea loopback.

    urllib sigue redirecciones 3xx por defecto sin revalidar el host; un
    servicio en loopback que devolviera un 302 a una IP interna haria que
    el servidor disparara una peticion "ciega" a esa IP (SSRF ciego).
    Este handler intercepta cada salto y solo deja seguir los que apuntan
    a loopback (localhost/127.x). No resuelve DNS: compara el literal."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = _llm_url_host(newurl)
        if host is None or not _is_loopback(host):
            raise urllib.error.HTTPError(
                newurl, code, "redirect a destino no-loopback no permitido",
                headers, fp)
        return super().redirect_request(
            req, fp, code, msg, headers, newurl)


_LLM_OPENER = urllib.request.build_opener(_LoopbackRedirectHandler)


def ask_llm(line, url=None, model=None, timeout=LLM_TIMEOUT, lang="auto"):
    """Pide a un LLM OpenAI-compatible que explique UNA linea.

    Devuelve (ok, texto): ok True con el contenido; ok False con un mensaje
    amigable. PUNTOS CRITICOS:
    - Los modelos de RAZONAMIENTO devuelven "reasoning_content" y un
      "content" que puede quedar VACIO si el presupuesto de tokens se gasta
      en razonar: eso NUNCA es un exito (max_tokens generoso para evitarlo,
      pero si aun asi llega vacio, sale como error amigable).
    - Si el LLM no responde (503, timeout, conexion negada) falla limpio:
      timeout corto, mensaje amigable, nunca cuelga la peticion."""
    base = url if url is not None else LLM_URL
    m = model if model is not None else LLM_MODEL
    # SSRF: el destino del LLM SOLO puede ser loopback (localhost/127.x).
    # Si alguien edita settings.json o la env var a mano con una URL
    # arbitraria, se rechaza aqui antes de hacer la peticion: el servidor
    # no se usa como proxy hacia la red interna.
    host = _llm_url_host(base)
    if host is None or not _is_loopback(host):
        return False, ("destino del LLM no permitido: solo se acepta"
                       " localhost/127.0.0.1 (loopback)")
    payload = json.dumps({
        "model": m,
        "max_tokens": LLM_MAX_TOKENS,
        "messages": [
            {"role": "system", "content": llm_system_prompt(lang)},
            {"role": "user", "content": str(line)},
        ]}).encode("utf-8")
    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions",
        data=payload, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with _LLM_OPENER.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                # El codigo queda en el detalle tecnico; el mensaje
                # principal va en lenguaje humano
                return False, ("el modelo local respondio con un error"
                              " (HTTP %d); comprueba la URL y el modelo"
                              " en Ajustes" % resp.status)
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except HTTPError as e:
        # 503 y otros codigos de error del LLM: el codigo va en el detalle
        return False, ("el modelo local respondio con un error"
                      " (HTTP %d); comprueba la URL y el modelo en"
                      " Ajustes" % e.code)
    except (URLError, socket.timeout, TimeoutError, ConnectionError,
            OSError):
        # Sin respuesta del LLM: lenguaje humano, sin codigo HTTP a
        # la vista (el 503 queda como estado tecnico de la peticion)
        return False, ("no se pudo contactar con el modelo local:"
                      " comprueba que esta arrancado y que la URL en"
                      " Ajustes es correcta. Si no funciona, puede que"
                      " esta version web no tenga acceso a tu modelo"
                      " local")
    except ValueError:
        return False, "el LLM devolvio una respuesta no JSON"
    try:
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        return False, ("la respuesta del LLM no tenia el formato OpenAI"
                      " esperado")
    content = str(msg.get("content") or "").strip()
    reasoning = str(msg.get("reasoning_content") or "").strip()
    if not content:
        # Prespuesto gastado en razonar (o salida vacia): NUNCA es un exito.
        return False, ("el LLM no devolvio texto"
                      + (" (todo el presupuesto se fue en razonar)"
                         if reasoning else ""))
    return True, content


# ---------------------------------------------------------------------------
# Fase 12C: diagnostico rapido (el LLM local resume TODAS las lineas de
# error del dataset activo a traves de sus plantillas unicas)
# ---------------------------------------------------------------------------
# NUNCA se mandan miles de lineas al LLM: solo las plantillas unicas (mismo
# computo que /api/templates, filtrado por nivel) con su count y una linea
# de ejemplo. Maximo DIAGNOSE_MAX_PER_CALL plantillas por llamada; si hay
# mas, loteo en pila (fold): llamadas secuenciales de a lotes, cada una
# lleva el resumen acumulado de los lotes anteriores y la ultima produce la
# conclusion final (p. ej. 60 plantillas -> 2 llamadas: 50 + [resumen+10]).
# Todo contra 127.0.0.1 (mismo ask_llm, config LOGVIEWER_LLM_URL): nada
# sale a internet.
DIAGNOSE_MAX_PER_CALL = 50   # plantillas por llamada al LLM
DIAGNOSE_TOTAL_MAX = 200    # tope de plantillas analizadas (como /api/templates)


def _diag_item(t):
    """Una plantilla en texto plano para el prompt."""
    return ("PLANTILLA (%d ocurrencias):\n%s\nEjemplo: %s"
            % (t["count"], t["template"], t.get("example", "")))


def diagnose_key(name, level, lang, model, templates):
    """Clave de cache del diagnostico: hash de dataset+level+lang(+modelo)
    y del contenido exacto de las plantillas analizadas. Reusa llm_key:
    mismo modelo o idioma que /api/analyze -> si cambia, no se sirve una
    conclusion cacheada de otra config."""
    canon = "\x01".join([name, level]
                        + [_diag_item(t) for t in templates])
    return llm_key(canon, model=model, lang=lang)


def run_diagnose(templates, ask, level="ERR"):
    """Orquesta las llamadas del diagnostico rapido.

    templates: lista de dicts {template,count,example} ordenadas por count
      descendente (la que salga de store.templates()).
    ask: callable(prompt) -> (ok, text); normalmente ask_llm ya configurado
      con la URL/modelo/timeout/lang del visor.
    Devuelve (ok, conclusion, analyzed).

    Loteo: si hay mas de DIAGNOSE_MAX_PER_CALL plantillas se hace en
    llamadas secuenciales; cada una lleva el resumen acumulado de los lotes
    anteriores y la ultima genera la conclusion final unica. Un fallo de
    cualquier llamada es (False, mensaje): el llamador NUNCA lo cachea."""
    n = len(templates)
    if n == 0:
        return True, "No hay lineas de este nivel en el dataset.", 0
    chunks = [templates[i:i + DIAGNOSE_MAX_PER_CALL]
              for i in range(0, n, DIAGNOSE_MAX_PER_CALL)]
    acc = None
    for k, chunk in enumerate(chunks):
        last = (k == len(chunks) - 1)
        parts = []
        if acc:
            parts.append("RESUMEN de los lotes anteriores:\n" + acc)
        parts.append(
            "A continuacion van %d plantillas unicas de lineas de log de"
            " nivel %s (de un total de %d analizadas). Cada una con su"
            " numero de ocurrencias y una linea de ejemplo:\n\n%s"
            % (len(chunk), level, n, "\n\n".join(_diag_item(t) for t in chunk)))
        if last:
            parts.append(
                "Devuelve UNA conclusion final unica, breve y accionable:"
                " que esta pasando en el sistema, la(s) plantilla(s) mas"
                " importante(s) (las de MAYOR numero de ocurrencias) citando"
                " su texto exacto y su linea de ejemplo, la causa probable y"
                " los proximos pasos concretos.")
        else:
            parts.append(
                "Devuelve un resumen breve y fiel SOLO de este lote (no es"
                " la ultima llamada): los patrones mas frecuentes, sus"
                " recuentos y que indican. Sera el contexto de la"
                " conclusion global.")
        ok, text = ask("\n\n".join(parts))
        if not ok:
            return False, text, 0
        acc = text
    return True, acc, n


# ---------------------------------------------------------------------------
# Fase 13: ingesta desde Splunk local (REST API)
# ---------------------------------------------------------------------------
# La conexion es SOLO a Splunk local (https://localhost:8089 por defecto):
# nada sale a internet. El self-signed de Splunk no se verifica (ssl
# CERT_NONE), igual que el curl -k del script de referencia
# scripts/splunk_search.sh, pero replicado en stdlib (urllib). Peculiaridad
# de este Splunk 10.4: el SPL debe empezar con un comando explicito
# ("search index=..."); si falta, se fuerza el prefijo "search ".
SPLUNK_URL = os.environ.get("SPLUNK_URL", "").strip() or "https://localhost:8089"
SPLUNK_USER = os.environ.get("SPLUNK_USER", "").strip() or "Sammi"
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "").strip()
try:
    SPLUNK_TIMEOUT = int(os.environ.get("SPLUNK_TIMEOUT", "120").strip() or 120)
except ValueError:
    SPLUNK_TIMEOUT = 120
SPLUNK_TIMEOUT = max(5, SPLUNK_TIMEOUT)
SPLUNK_MAX_ROWS = 5000   # tope duro de filas por dataset (no traer 2M)


def splunk_enabled():
    """Si hay contrasena configurada: aparece la opcion de ingesta Splunk."""
    return bool(SPLUNK_PASS)


def _splunk_ssl():
    """Contexto TLS sin verificacion (self-signed local, como curl -k)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _splunk_open(path, data=None, timeout=SPLUNK_TIMEOUT):
    """Peticion a la REST de Splunk local (basic auth). Devuelve la resp.

    Los fallos salen como ValueError con mensaje amigable (el llamador
    lo convierte en 502/404 para la UI)."""
    req = urllib.request.Request(SPLUNK_URL.rstrip("/") + path,
                                 data=data, method="POST" if data else "GET")
    req.add_header("Authorization", "Basic " + base64.b64encode(
        (SPLUNK_USER + ":" + SPLUNK_PASS).encode("utf-8")).decode("ascii"))
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        return urllib.request.urlopen(req, timeout=timeout,
                                      context=_splunk_ssl())
    except HTTPError as e:
        raise ValueError("Splunk devolvio HTTP %d; revisa el SPL o el"
                         " indice" % e.code)
    except (URLError, socket.timeout, TimeoutError, ConnectionError,
            OSError):
        # Lenguaje humano: el usuario final no gestiona la conexion
        raise ValueError("El Splunk no responde: contacta con el"
                         " operador del servidor para que revise la"
                         " conexion")


def splunk_query(spl, count=1000):
    """Ejecuta un SPL contra Splunk local (POST /services/search/jobs,
    oneshot, output_mode=json, earliest_time=0) y devuelve la lista de
    dicts de resultados. Fuerza el prefijo "search " si falta (Splunk 10.4).
    count acota filas (tope SPLUNK_MAX_ROWS): el SPL filtra y agrega."""
    q = str(spl or "").strip()
    if not q:
        raise ValueError("el SPL esta vacio")
    if not (q.startswith("search ") or q.startswith("|")):
        q = "search " + q
    n = max(1, min(int(count), SPLUNK_MAX_ROWS))
    body = urlencode({
        "search": q,
        "exec_mode": "oneshot",
        "output_mode": "json",
        "earliest_time": "0",
        "count": str(n),
    }).encode("utf-8")
    with _splunk_open("/services/search/jobs", data=body) as resp:
        raw = resp.read().decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("Splunk devolvio una respuesta no JSON")
    rows = data.get("results") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError("la respuesta de Splunk no traia resultados")
    return rows


def splunk_indexes():
    """Indices disponibles (GET /services/data/2.0/indexes). Recon ligero:
    sin lanzar searches sobre el indice de 2M+ eventos. Puede fallar
    (404) si el usuario no tiene permiso para listar: el llamador lo
    trata como informativo, no como fallo duro."""
    with _splunk_open("/services/data/2.0/indexes") as resp:
        raw = resp.read().decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("Splunk devolvio una respuesta no JSON")
    out = []
    for e in (data.get("entry") or []) if isinstance(data, dict) else []:
        name = str(e.get("name", "") or "").strip()
        if name and not name.startswith("_"):
            out.append(name)
    return sorted(out)


def splunk_rows_to_dataset_rows(results):
    """Convierte filas de resultado de Splunk (dicts) en filas del visor.

    ts = _time (epoch -> ISO via norm_ts); msg = campo "line" si existe,
    si no, los campos como k=v; raw = JSON de los campos (para drawer y
    LLM). level queda vacio: un dataset Splunk no tiene niveles syslog y
    el diagnostico rapido lo trata aparte (ver _diagnose/_templates)."""
    out = []
    for r in results:
        if not isinstance(r, dict):
            continue
        t = str(r.get("_time", "") or "").strip()
        try:
            t = str(int(float(t)))   # epoch seg (norm_ts lo parsea)
        except (TypeError, ValueError):
            t = ""
        fields = {k: v for k, v in r.items() if not k.startswith("_")}
        line = str(fields.get("line", "") or "").strip()
        msg = line or " ".join("%s=%s" % (k, v)
                               for k, v in sorted(fields.items()))
        if not msg:
            continue
        ip = ""
        for key in ("src_ip", "ip", "src", "clientip", "source_ip"):
            if key in fields:
                ip = str(fields[key])
                break
        raw = json.dumps(fields, ensure_ascii=False) if fields else msg
        out.append({
            "ts": t, "ts_norm": norm_ts(t), "level": "",
            "ip": ip, "host": str(fields.get("host", "") or ""),
            "app": str(fields.get("sourcetype", "") or ""),
            "pid": "", "method": "", "path": "", "code": "",
            "bytes": "", "msg": msg, "raw": raw,
        })
    for row in out:
        row["_search"] = _make_search(row)
        # Plantilla sobre el msg (leible para el LLM), no sobre el JSON
        row["template"] = make_template(row["msg"])
    return out


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
        self._reindex()

    def _reindex(self):
        """Fase 7B: posicion de cada fila en la lista (rowid de MemStore)."""
        for i, r in enumerate(self.rows):
            r["_idx"] = i

    def add_rows(self, rows, counters):
        """Anade filas (usado por el tail en vivo)."""
        base = len(self.rows)
        for i, r in enumerate(rows):
            r["_idx"] = base + i
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
            # Fase 7B: rowid = indice en la lista de filas del dataset
            r["rowid"] = r.get("_idx", -1)
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

    def templates(self, min_count=1, limit=200, level=None):
        """Fase 9B: agregacion por plantilla (calculada en el parseo).

        level (opcional): solo filas de ese nivel exacto (Fase 12C)."""
        agg = {}
        for r in self.rows:
            if level is not None and r.get("level", "") != level:
                continue
            t = r.get("template", "")
            if not t:
                continue
            e = agg.get(t)
            ts = r.get("ts_norm", "")
            if e is None:
                e = agg[t] = {"count": 0, "first": ts, "last": ts,
                              "example": r.get("raw", "")}
            e["count"] += 1
            if ts:
                if not e["first"] or ts < e["first"]:
                    e["first"] = ts
                if not e["last"] or ts > e["last"]:
                    e["last"] = ts
        out = [dict(template=t, **e) for t, e in agg.items()
              if e["count"] >= min_count]
        out.sort(key=lambda e: (-e["count"], e["first"]))
        return out[:limit]

    def histogram(self, q, gran="min"):
        """Fase 9C: distribucion temporal de las filas filtradas."""
        n = 16 if gran == "min" else 13
        out = Counter()
        for r in apply_filters(self.rows, q):
            t = (r.get("ts_norm") or "")[:n]
            if t:
                out[t] += 1
        return [{"t": t, "count": c} for t, c in sorted(out.items())]

    def total_rows(self):
        return len(self.rows)

    def close(self):
        pass


class SqlStore:
    """Backend SQLite (datasets grandes, por encima del umbral).

    Las filas se guardan en una tabla; el filtrado, el top N y los KPIs
    se hacen con SQL. No se mantiene la lista de filas en memoria."""

    COLUMNS = ("ts", "ts_norm", "level", "ip", "host", "app", "pid",
               "method", "path", "code", "bytes", "msg", "raw",
               # Fase 9A: plantilla normalizada, calculada en el parseo
               "template")

    def __init__(self, db_path):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._create_schema()

    def _create_schema(self):
        cols = ", ".join("%s TEXT" % c for c in self.COLUMNS)
        # line: numero de linea (0-based) en el archivo original (Fase 7B)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS rows (%s, search TEXT, "
            "line INTEGER)" % cols)
        # Indices para los filtros mas usados
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_level ON rows(level)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_code ON rows(code)")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ts_norm ON rows(ts_norm)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON rows(ip)")
        # Fase 8A: FTS5 external-content sobre la columna search existente
        # (no duplica datos: el contenido se lee de rows por rowid)
        self.conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5("
            "search, content='rows', content_rowid='rowid')")
        # Si la BD venia de una version anterior sin FTS, reindexa desde
        # rows (external-content: rebuild solo relée el contenido)
        n_rows = self.conn.execute("SELECT COUNT(*) FROM rows").fetchone()[0]
        n_fts = self.conn.execute("SELECT COUNT(*) FROM fts").fetchone()[0]
        if n_rows != n_fts:
            self.conn.execute(
                "INSERT INTO fts(fts) VALUES('rebuild')")
        self.conn.commit()

    def _insert_rows(self, rows):
        cur = self.conn.execute("SELECT COALESCE(MAX(rowid), 0) FROM rows")
        first = cur.fetchone()[0] + 1
        self.conn.executemany(
            "INSERT INTO rows (%s, search, line) VALUES (%s)" % (
                ", ".join(self.COLUMNS),
                ", ".join("?" * (len(self.COLUMNS) + 2))),
            [tuple(r.get(c, "") for c in self.COLUMNS)
             + (r.get("_search", ""), int(r.get("_line", -1)))
             for r in rows])
        # Fase 8A: alimentar el indice FTS con los mismos rowids
        self.conn.executemany(
            "INSERT INTO fts(rowid, search) VALUES (?, ?)",
            [(first + i, r.get("_search", ""))
             for i, r in enumerate(rows)])
        self.conn.commit()

    def add_rows(self, rows, counters):
        """Anade filas (usado por el tail en vivo)."""
        with self.lock:
            self._insert_rows(rows)

    def _fts_clause(self, terms):
        """Fase 8B: traduce el filtro q a FTS5 MATCH sobre search.

        - Positivos (multivalor de la Fase 7D): OR entre frases FTS.
        - Negativos (prefijo "!"): operador NOT de FTS5.
        - Sin positivos no hay forma de decir "todo menos X" con MATCH:
          se cae a clausulas SQL instr(lower(search), lower(?)) = 0.
        Las frases van entre comas dobles (literal de FTS5); un termino
        de varios tokens es una frase, aproximacion del antiguo match por
        subcadena cuando el termino no coincide con token completo.
        """
        pos = [t for n, t in terms if not n]
        neg = [t for n, t in terms if n]

        def fts_phrase(t):
            return '"%s"' % t.replace('"', '""')

        if not pos:
            clauses = []
            params = []
            for g in neg:
                clauses.append("instr(lower(search), lower(?)) = 0")
                params.append(g)
            return "(" + " AND ".join(clauses) + ")", params
        query = " OR ".join(fts_phrase(p) for p in pos)
        for g in neg:
            query += " NOT " + fts_phrase(g)
        # MATCH no se puede evaluar directo en el WHERE de rows: se usa
        # la subconsulta por rowid (FTS5 external-content)
        return ("rowid IN (SELECT rowid FROM fts WHERE fts MATCH ?)"), [query]

    def _field_clause(self, col, terms, exact=False):
        """Fase 7D: clausula SQL equivalente a terms_pass()."""
        pos = [t for n, t in terms if not n]
        neg = [t for n, t in terms if n]
        clauses = []
        params = []
        if exact:
            if pos:
                clauses.append(
                    "%s IN (%s)" % (col, ", ".join("?" * len(pos))))
                params.extend(pos)
            for g in neg:
                clauses.append("%s != ?" % col)
                params.append(g)
        else:
            if pos:
                ors = []
                for p in pos:
                    ors.append("instr(lower(%s), lower(?)) > 0" % col)
                    params.append(p)
                clauses.append("(" + " OR ".join(ors) + ")")
            for g in neg:
                clauses.append("instr(lower(%s), lower(?)) = 0" % col)
                params.append(g)
        if not clauses:
            return None, []
        return "(" + " AND ".join(clauses) + ")", params

    def _where(self, q):
        """Construye la clausula WHERE a partir de los filtros."""
        clauses = []
        params = []
        level_t = parse_terms(q.get("level", [""]))
        code_t = parse_terms(q.get("code", [""]))
        ip_t = parse_terms(q.get("ip", [""]))
        path_t = parse_terms(q.get("path", [""]))
        txt_t = parse_terms(q.get("q", [""]))
        # Fase 9B: filtro exacto por plantilla (vino de la vista agrupada)
        tpl = q.get("tpl", [""])[0].strip()
        dt = q.get("dt", [""])[0].strip()
        dt_from = _dt_bound(q.get("dt_from", [""])[0])
        dt_to = _dt_bound(q.get("dt_to", [""])[0])
        for col, terms, exact in (
                ("level", level_t, True), ("code", code_t, True),
                ("ip", ip_t, False), ("path", path_t, False)):
            if terms:
                c, p = self._field_clause(col, terms, exact)
                if c:
                    clauses.append(c)
                    params.extend(p)
        # Fase 8B: q usa FTS5 MATCH en SQLite; MemStore sigue por subcadena
        if txt_t:
            c, p = self._fts_clause(txt_t)
            clauses.append(c)
            params.extend(p)
        if tpl:
            clauses.append("template = ?")
            params.append(tpl)
        if dt:
            clauses.append("instr(ts, ?) > 0")
            params.append(dt)
        if dt_from:
            clauses.append("ts_norm >= ?")
            params.append(dt_from)
        if dt_to:
            clauses.append("ts_norm <= ?")
            params.append(dt_to)
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
                "SELECT rowid, %s FROM rows %s LIMIT ? OFFSET ?" % (
                    ", ".join(self.COLUMNS), where),
                params + [size, start])
            cols = self.COLUMNS
            out = []
            for row in cur.fetchall():
                d = dict(zip(cols, row[1:]))
                # Fase 7B: rowid de SQLite (identificador estable de fila)
                d["rowid"] = row[0]
                out.append(d)
            return out

    def histogram(self, q, gran="min"):
        """Fase 9C: distribucion temporal de las filas filtradas."""
        n = 16 if gran == "min" else 13
        where, params = self._where(q)
        sql = ("SELECT substr(ts_norm, 1, %d) t, COUNT(*) c FROM rows "
               "WHERE ts_norm != '' %s GROUP BY t ORDER BY t" % (n, where))
        with self.lock:
            cur = self.conn.execute(sql, params)
            return [{"t": t, "count": c} for t, c in cur.fetchall()]

    def line_of(self, rowid):
        """Fase 7B: numero de linea (0-based) en el archivo de una fila."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT line FROM rows WHERE rowid = ?", [rowid])
            r = cur.fetchone()
        return r[0] if r else None

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

    def templates(self, min_count=1, limit=200, level=None):
        """Fase 9B: GROUP BY sobre la columna template.

        level (opcional): solo filas de ese nivel exacto (Fase 12C)."""
        with self.lock:
            sql = ("SELECT template, COUNT(*) c, MIN(ts_norm), MAX(ts_norm), "
                   "MIN(rowid) FROM rows WHERE template != '' ")
            params = []
            if level is not None:
                sql += "AND level = ? "
                params.append(level)
            sql += ("GROUP BY template HAVING c >= ? ORDER BY c DESC LIMIT ?")
            cur = self.conn.execute(
                sql, params + [min_count, limit])
            groups = cur.fetchall()
            if not groups:
                return []
            ids = [g[4] for g in groups]
            ph = ", ".join("?" * len(ids))
            cur = self.conn.execute(
                "SELECT rowid, raw FROM rows WHERE rowid IN (%s)" % ph, ids)
            ex = {rowid: raw for rowid, raw in cur.fetchall()}
        return [{"template": g[0], "count": g[1], "first": g[2],
                 "last": g[3], "example": ex.get(g[4], "")}
                for g in groups]

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
                "raw": _trunc(l), "_line": i,
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
            "raw": _trunc(l), "_line": i,
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
                    "raw": _trunc(l), "_line": i,
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
                "raw": _trunc(l), "_line": i,
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
            "raw": _trunc(l), "_line": i,
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips}


def parse_raw(lines, progress=None):
    """RAW: lineas tal cual, sin parsear."""
    rows = []
    for i, l in enumerate(lines):
        rows.append({
            "ts": "", "level": "RAW", "ip": "", "method": "",
            "path": "", "code": "", "bytes": "", "msg": _trunc(l),
            "raw": _trunc(l), "_line": i,
        })
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
    # Una carga anterior con el mismo nombre puede haber dejado una BD:
    # se borra para que la migracion no apile filas sobre la vieja
    _old_db = os.path.join(db_dir, safe_session_name(name) + ".db")
    for _suf in ("", "-wal", "-shm"):
        try:
            os.remove(_old_db + _suf)
        except OSError:
            pass
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
            base_line = lines_processed
            if fmt == "w3c":
                rows, counters = parse_w3c(chunk, fields=w3c_f)
            else:
                rows, counters = parser(chunk)
            for r in rows:
                r["_search"] = _make_search(r)
                # Fase 9A: plantilla calculada en el parseo
                r["template"] = make_template(r.get("raw", ""))
                r["ts_norm"] = norm_ts(r.get("ts", ""))
                # Fase 7B: numero de linea (0-based) en el archivo original
                r["_line"] = base_line + r.pop("_line", 0)
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


def apply_filters(rows, q):
    """Aplica todos los filtros combinables. Devuelve la lista filtrada."""
    level_t = parse_terms(q.get("level", [""]))
    code_t = parse_terms(q.get("code", [""]))
    ip_t = parse_terms(q.get("ip", [""]))
    path_t = parse_terms(q.get("path", [""]))
    txt_t = parse_terms(q.get("q", [""]))
    tpl = q.get("tpl", [""])[0].strip()
    dt = q.get("dt", [""])[0].strip()
    # Rango de fechas real (Fase 7A): comparacion lexicografica sobre
    # ts_norm. El filtro "dt" por subcadena queda como fallback.
    dt_from = _dt_bound(q.get("dt_from", [""])[0])
    dt_to = _dt_bound(q.get("dt_to", [""])[0])

    out = []
    for r in rows:
        if level_t and not terms_pass(r["level"], level_t, exact=True):
            continue
        if code_t and not terms_pass(r["code"], code_t, exact=True):
            continue
        if ip_t and not terms_pass(r.get("ip", ""), ip_t):
            continue
        if path_t and not terms_pass(r.get("path", ""), path_t):
            continue
        if dt and dt not in r["ts"]:
            continue
        if txt_t and not terms_pass(r.get("_search", ""), txt_t):
            continue
        # Fase 9B: filtro exacto por plantilla (vino de la vista agrupada)
        if tpl and r.get("template", "") != tpl:
            continue
        ts_n = r.get("ts_norm", "")
        if dt_from and ts_n < dt_from:
            continue
        if dt_to and ts_n > dt_to:
            continue
        out.append(r)
    return out


def read_context_lines(path, line, n, encoding="utf-8"):
    """Fase 7B: contexto tipo grep -C alrededor de una linea (0-based).

    Lee el archivo por streaming y devuelve {"before": [...],
    "current": str, "after": [...]} con las n lineas anteriores y
    posteriores de la linea pedida.
    """
    lo = max(0, line - n)
    hi = line + n
    before, after, current = [], [], ""
    with open(path, "r", encoding=encoding, errors="replace") as f:
        for i, l in enumerate(f):
            if i < lo or i > hi:
                continue
            t = l.rstrip("\n")
            if i < line:
                before.append(t)
            elif i == line:
                current = t
            else:
                after.append(t)
    return {"before": before, "current": current, "after": after}


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
        # Carga anterior con el mismo nombre: cerrala (su close borra la
        # BD) antes de parsear para que la migracion no apile filas
        with LOCK:
            old = _user_state(user, SESSIONS).get(name)
        if old is not None:
            old["store"].close()
        ds = load_file(path, _progress, user=user)
        with LOCK:
            mine = _user_state(user, SESSIONS)
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

    def do_PUT(self):
        if not self._cf_ok():
            self._error("acceso directo no permitido (requiere Cloudflare Access)", 403)
            return
        if self.headers.get("X-CSRF-Token", "") != CSRF_TOKEN:
            self._error("token CSRF invalido", 403)
            return
        u = urlparse(self.path)
        if u.path == "/api/runbooks":
            self._runbooks_update()
        else:
            self._error("ruta no conocida", 404)

    def do_DELETE(self):
        if not self._cf_ok():
            self._error("acceso directo no permitido (requiere Cloudflare Access)", 403)
            return
        if self.headers.get("X-CSRF-Token", "") != CSRF_TOKEN:
            self._error("token CSRF invalido", 403)
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        user = self._user()
        if u.path == "/api/runbooks":
            try:
                rid = int(q.get("id", ["0"])[0])
            except ValueError:
                self._error("id invalido", 400)
                return
            gone = runbooks_store().delete(rid)
            if not gone:
                self._error("no existe", 404)
                return
            audit("runbook_del", user, id=rid)
            self._json({"ok": True})
        else:
            self._error("ruta no conocida", 404)

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
        elif u.path == "/api/templates":
            self._templates(q, user)
        elif u.path == "/api/histogram":
            self._histogram(q, user)
        elif u.path == "/api/config":
            # Config de solo lectura para la UI (Fase 12A: si hay LLM,
            # aparece el boton Analizar en el drawer; Fase 13: si hay
            # Splunk configurado, aparece la seccion "Importar de Splunk";
            # repo_url: enlace de descarga de la version local)
            self._json(public_config())
        elif u.path == "/api/splunk/sources":
            self._splunk_sources()
        elif u.path == "/api/settings":
            # Config editable del LLM desde la UI (persistente)
            self._settings_get()
        elif u.path == "/api/runbooks":
            self._runbooks_list()
        elif u.path == "/api/runbooks/match":
            self._runbooks_match(q)
        elif u.path == "/api/context":
            self._context(q, user)
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

    def _splunk_sources(self):
        """Fase 13: GET /api/splunk/sources -> indices disponibles."""
        if not splunk_enabled():
            self._error("Splunk no esta configurado (falta la contrasena)",
                        404)
            return
        # Listar indices es INFORMATIVO: si el usuario no tiene permiso
        # (REST 404 en este entorno), no bloquea la ingesta
        try:
            indexes = splunk_indexes()
        except ValueError as e:
            audit("splunk_sources", user=self._user(), error=str(e))
            self._json({"indexes": [], "primary": "botsv3",
                        "note": ("Este usuario de Splunk no puede listar"
                                 " indices; usa index=botsv3."),
                        "hint": ("El SPL debe empezar con 'search' y"
                                " acotar filas (tope %d)." % SPLUNK_MAX_ROWS)})
            return
        audit("splunk_sources", user=self._user(), count=len(indexes))
        # El indice principal de este entorno (documentado, no se asume):
        self._json({"indexes": indexes,
                    "primary": "botsv3",
                    "hint": ("El SPL debe empezar con 'search' y acotar"
                            " filas (el servidor limita a %d)."
                            % SPLUNK_MAX_ROWS)})

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

    def _templates(self, q, user):
        """Fase 9B: vista 'Errores agrupados' por plantilla."""
        name = q.get("name", [""])[0]
        with LOCK:
            ds = dataset(user, name)
        if ds is None:
            self._error("no hay archivo cargado", 404)
            return
        try:
            min_count = max(1, int(q.get("min", ["1"])[0]))
        except ValueError:
            min_count = 1
        level = q.get("level", [""])[0].strip() or None  # Fase 12C
        # Fase 13: los datasets Splunk no tienen niveles syslog; el nivel
        # no filtra (mismo tratamiento que _diagnose)
        if ds.get("format") == "splunk":
            level = None
        store = ds["store"]
        items = store.templates(min_count=min_count, limit=200,
                                level=level)
        self._json({"name": name, "total": len(items), "templates": items})

    def _runbooks_list(self):
        """Fase 10A: lista de runbooks (BD persistente)."""
        self._json({"runbooks": runbooks_store().all()})

    def _runbooks_match(self, q):
        """Fase 10A: runbooks cuyo patron coincide con el msg dado."""
        msg = q.get("msg", [""])[0]
        rbs = runbooks_store().all()
        self._json({"msg": _trunc(msg, 500),
                    "matches": match_runbooks(msg, rbs)})

    def _runbooks_update(self):
        """Fase 10B: edicion de runbook (PUT /api/runbooks?id=)."""
        user = self._user()
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            rid = int(q.get("id", ["0"])[0])
        except ValueError:
            self._error("id invalido", 400)
            return
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._error("cuerpo JSON invalido", 400)
            return
        pattern = str(body.get("pattern") or "").strip()
        kind = str(body.get("kind") or "regex").strip() or "regex"
        if not pattern:
            self._error("falta el patron", 400)
            return
        if kind == "regex" and _rb_compile(pattern) is None:
            self._error("el regex no compila", 400)
            return
        try:
            rb = runbooks_store().update(
                rid, pattern, kind,
                str(body.get("explicacion") or ""),
                str(body.get("causa") or ""),
                str(body.get("solucion") or ""),
                str(body.get("ref") or ""))
        except ValueError as e:
            self._error(str(e), 409)
            return
        if rb is None:
            self._error("no existe", 404)
            return
        audit("runbook_edit", user, id=rid, pattern=pattern)
        self._json(rb)

    def _runbooks_create(self):
        """Fase 10A: alta de runbook desde la UI/CLI."""
        user = self._user()
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._error("cuerpo JSON invalido", 400)
            return
        pattern = str(body.get("pattern") or "").strip()
        kind = str(body.get("kind") or "regex").strip() or "regex"
        if not pattern:
            self._error("falta el patron", 400)
            return
        if kind == "regex" and _rb_compile(pattern) is None:
            self._error("el regex no compila", 400)
            return
        try:
            rb = runbooks_store().add(
                pattern, kind=kind,
                explicacion=str(body.get("explicacion") or ""),
                causa=str(body.get("causa") or ""),
                solucion=str(body.get("solucion") or ""),
                ref=str(body.get("ref") or ""))
        except ValueError as e:
            self._error(str(e), 409)
            return
        audit("runbook_add", user, pattern=pattern, kind=kind,
              id=rb["id"])
        self._json(rb)

    def _settings_get(self):
        """GET /api/settings: config editable del LLM (persistente)."""
        cfg = llm_config()
        self._json({"llm": bool(cfg["url"]), "url": cfg["url"],
                    "model": cfg["model"], "timeout": cfg["timeout"],
                    "lang": cfg["lang"]})

    def _settings_post(self):
        """POST /api/settings: guarda la config del LLM desde la UI.

        URL/modelo/timeout; persiste en settings.json (sobrevive a
        reinicios). Se valida la URL (http/https) y el timeout (>=1 s).
        La env var actua solo como valor inicial; lo que se guarda aqui
        manda hasta que se cambie o se borre settings.json."""
        user = self._user()
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._error("cuerpo JSON invalido", 400)
            return
        st = settings_store()
        url = body.get("url")
        if url is not None:
            url = str(url).strip()
            if url and not url.startswith(("http://", "https://")):
                self._error("la URL debe empezar por http:// o https://", 400)
                return
            if url:
                # SSRF: el destino del LLM SOLO puede ser loopback. No se
                # permite apuntar a IPs internas/metadata de cloud, o el
                # visor desplegado podria usarse como proxy.
                host = _llm_url_host(url)
                if host is None or not _is_loopback(host):
                    self._error(
                        "destino del LLM no permitido: solo loopback"
                        " (localhost/127.0.0.1). Los modelos locales corren"
                        " en tu propia maquina.", 400)
                    return
        model = body.get("model")
        if model is not None:
            model = str(model).strip()
        timeout = body.get("timeout")
        if timeout is not None:
            try:
                if int(timeout) < 1:
                    raise ValueError
            except (TypeError, ValueError):
                self._error("el timeout debe ser un entero >= 1", 400)
                return
        lang = body.get("lang")
        st.set(url=url, model=model, timeout=timeout,
               lang=(None if lang is None else str(lang)))
        cfg = llm_config()
        audit("settings_update", user,
              llm_url=(cfg["url"] or ""), llm_model=cfg["model"],
              llm_timeout=cfg["timeout"], llm_lang=cfg["lang"])
        self._json({"llm": bool(cfg["url"]), "url": cfg["url"],
                    "model": cfg["model"], "timeout": cfg["timeout"],
                    "lang": cfg["lang"]})

    def _analyze(self):
        """Fase 12A: analiza UNA linea con el LLM local (cache por hash)."""
        user = self._user()
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._error("cuerpo JSON invalido", 400)
            return
        line = str(body.get("line") or "").strip()
        if not line:
            self._error("falta la linea a analizar", 400)
            return
        cfg = llm_config()
        if not cfg["url"]:
            self._error("el LLM no esta configurado", 404)
            return
        key = llm_key(line, model=cfg["model"], lang=cfg["lang"])
        cached = llm_cache().get(key)
        if cached is not None:
            audit("analyze", user, line=_trunc(line, 200), cached=True)
            self._json({"cached": True, "answer": cached})
            return
        ok, text = ask_llm(line, url=cfg["url"], model=cfg["model"],
                           timeout=cfg["timeout"], lang=cfg["lang"])
        if not ok:
            # NUNCA se cachea un fallo: el proximo intento vuelve a preguntar
            audit("analyze", user, line=_trunc(line, 200), error=text)
            self._json({"error": text}, 503)
            return
        llm_cache().put(key, line, text)
        audit("analyze", user, line=_trunc(line, 200))
        self._json({"cached": False, "answer": text})

    def _diagnose(self):
        """Fase 12C: POST /api/diagnose {name, level?}.

        El LLM local resume TODAS las lineas del nivel (por defecto ERR)
        del dataset activo a traves de sus plantillas unicas (mismo
        computo que /api/templates). Devuelve {cached, conclusion,
        top:[{template,count,linea}], analyzed}. Cache por hash de
        dataset+level+lang(+modelo) en llm_cache.db; los fallos NUNCA se
        cachean. Maximo DIAGNOSE_MAX_PER_CALL plantillas por llamada:
        si hay mas, loteo en pila (ver run_diagnose)."""
        user = self._user()
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._error("cuerpo JSON invalido", 400)
            return
        name = str(body.get("name") or "").strip()
        level = str(body.get("level") or "ERR").strip().upper() or "ERR"
        with LOCK:
            ds = dataset(user, name)
        if ds is None:
            self._error("no hay archivo cargado", 404)
            return
        cfg = llm_config()
        if not cfg["url"]:
            self._error("el LLM no esta configurado", 404)
            return
        items = ds["store"].templates(min_count=1,
                                      limit=DIAGNOSE_TOTAL_MAX,
                                      level=level)
        if not items and ds.get("format") == "splunk":
            # Fase 13: dataset de Splunk sin niveles syslog: se diagnostica
            # sobre TODAS las plantillas (las filas son hallazgos del SPL)
            items = ds["store"].templates(min_count=1,
                                         limit=DIAGNOSE_TOTAL_MAX)
        if not items:
            audit("diagnose", user, name=name, level=level, analyzed=0)
            self._json({"cached": False,
                        "conclusion": ("No hay lineas de nivel %s en el"
                                       " dataset.") % level,
                        "top": [], "analyzed": 0})
            return
        key = diagnose_key(name, level, cfg["lang"], cfg["model"], items)
        cached = llm_cache().get(key)
        if cached is not None:
            audit("diagnose", user, name=name, level=level,
                  analyzed=len(items), cached=True)
            self._json({"cached": True, "conclusion": cached,
                        "top": [{"template": t["template"],
                                 "count": t["count"],
                                 "linea": t.get("example", "")}
                                for t in items[:10]],
                        "analyzed": len(items)})
            return

        def ask(prompt):
            return ask_llm(prompt, url=cfg["url"], model=cfg["model"],
                           timeout=cfg["timeout"], lang=cfg["lang"])

        ok, conclusion, analyzed = run_diagnose(items, ask, level=level)
        if not ok:
            # NUNCA se cachea un fallo: el proximo intento vuelve a preguntar
            audit("diagnose", user, name=name, level=level, error=conclusion)
            self._json({"error": conclusion}, 503)
            return
        llm_cache().put(key, "diagnose %s/%s (%d plantillas)"
                        % (name, level, analyzed), conclusion)
        audit("diagnose", user, name=name, level=level, analyzed=analyzed)
        self._json({"cached": False, "conclusion": conclusion,
                    "top": [{"template": t["template"],
                             "count": t["count"],
                             "linea": t.get("example", "")}
                            for t in items[:10]],
                    "analyzed": analyzed})

    def _splunk_search(self):
        """Fase 13: POST /api/splunk/search {search, name?, count?}.

        Ejecuta un SPL contra Splunk local y crea un dataset del visor
        con las filas devueltas (MemStore: el tope de filas lo pone el
        count; el SPL es quien filtra y agrega). El dataset queda activo:
        se puede filtrar, exportar y diagnosticar. El contexto de linea
        no aplica (no hay archivo original). Auditoria: splunk_search."""
        user = self._user()
        if not splunk_enabled():
            self._error("Splunk no esta configurado (falta la contrasena)",
                        404)
            return
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._error("cuerpo JSON invalido", 400)
            return
        spl = str(body.get("search") or "").strip()
        if not spl:
            self._error("falta el SPL (campo 'search')", 400)
            return
        try:
            count = int(body.get("count", 1000))
        except (TypeError, ValueError):
            count = 1000
        count = max(1, min(count, SPLUNK_MAX_ROWS))
        try:
            results = splunk_query(spl, count=count)
        except ValueError as e:
            audit("splunk_search", user, error=str(e),
                  spl=_trunc(spl, 200))
            self._json({"error": str(e)}, 502)
            return
        rows = splunk_rows_to_dataset_rows(results)
        if not rows:
            audit("splunk_search", user, rows=0, spl=_trunc(spl, 200))
            self._json({"error": "la query no devolvio filas"}, 404)
            return
        with LOCK:
            mine = _user_state(user, SESSIONS)
            name = safe_session_name(
                str(body.get("name") or "").strip()
                or ("splunk_" + time.strftime("%Y%m%d_%H%M%S")),
                existing=list(mine))
            store = MemStore(rows=rows, counters={})
            ds = {
                "store": store,
                "format": "splunk",
                "name": name,
                "size": 0,
                "total": len(rows),
                "encoding": "",
                "compressed": "",
                "meta": ["Splunk: " + spl],
            }
            mine[name] = ds
            ACTIVE[user] = name
        audit("splunk_search", user, name=name, rows=len(rows),
              spl=_trunc(spl, 200))
        self._json({"name": name, "rows": len(rows)})

    def _histogram(self, q, user):
        """Fase 9C: histograma temporal de las filas filtradas."""
        name = q.get("name", [""])[0]
        gran = q.get("gran", ["min"])[0]
        if gran not in ("min", "h"):
            gran = "min"
        with LOCK:
            ds = dataset(user, name)
        if ds is None:
            self._error("no hay archivo cargado", 404)
            return
        buckets = ds["store"].histogram(q, gran="h" if gran == "h" else "min")
        self._json({"name": name, "gran": gran,
                    "total": sum(b["count"] for b in buckets),
                    "buckets": buckets})

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
        base_line = ds["total"]
        for r in rows:
            r["_search"] = _make_search(r)
            # Fase 9A: plantilla calculada en el parseo
            r["template"] = make_template(r.get("raw", ""))
            r["ts_norm"] = norm_ts(r.get("ts", ""))
            r["_line"] = base_line + r.pop("_line", 0)
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

    def _context(self, q, user):
        """Fase 7B: lineas del log original alrededor de una fila."""
        # Fase 13: el contexto necesita el archivo original; un dataset
        # traido de Splunk no lo tiene
        with LOCK:
            ds0 = dataset(user, q.get("name", [""])[0])
        if ds0 is not None and ds0.get("format") == "splunk":
            self._error("el contexto no aplica a un dataset de Splunk",
                        404)
            return
        name = q.get("name", [""])[0]
        with LOCK:
            ds = dataset(user, name)
        if ds is None:
            self._error("no hay archivo cargado", 404)
            return
        try:
            row = int(q.get("row", ["-1"])[0])
            n = min(50, max(0, int(q.get("n", ["5"])[0])))
        except ValueError:
            self._error("parametros invalidos (row, n)", 400)
            return
        store = ds["store"]
        if isinstance(store, SqlStore):
            line = store.line_of(row)
            if line is None or line < 0:
                self._error("fila no encontrada", 404)
                return
        else:
            rows = store.rows
            if not (0 <= row < len(rows)):
                self._error("fila no encontrada", 404)
                return
            line = rows[row].get("_line", -1)
            if line is None or line < 0:
                self._error("la fila no tiene linea de origen", 404)
                return
        path = os.path.join(
            tempfile.gettempdir(), "logviewer", "sessions",
            safe_session_name(user), name)
        try:
            ctx = read_context_lines(path, line, n,
                                      ds.get("encoding") or "utf-8")
        except OSError:
            self._error("no se puede leer el archivo original", 503)
            return
        out = {"name": name, "row": row, "line": line + 1}
        out.update(ctx)
        self._json(out)

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
        elif u.path == "/api/runbooks":
            self._runbooks_create()
        elif u.path == "/api/settings":
            self._settings_post()
        elif u.path == "/api/analyze":
            self._analyze()
        elif u.path == "/api/diagnose":
            self._diagnose()
        elif u.path == "/api/splunk/search":
            self._splunk_search()
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
