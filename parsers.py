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
# ---------------------------------------------------------------------------
# U0.1 (2026-10-30): parser universal 'auto' (extraccion best-effort).
# Sirve para cualquier log que no matchee un formato concreto: saca fecha,
# nivel, primera IPv4 y pares clave=valor (logfmt) sin exigir estructura.
# ---------------------------------------------------------------------------
RE_TS_ISO = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?'
    r'(?:Z|[+-]\d{2}(?::?\d{2})?)?'
)
# Epoch en segundos (10 digitos) o milisegundos (11-13 digitos).
RE_TS_EPOCH = re.compile(r'(?<![\d.])(1\d{9,12})(?![\d.])')
RE_TS_YMD_SLASH = re.compile(r'(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{2}:\d{2}:\d{2})')
RE_TS_DMY = re.compile(r'(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{2}:\d{2}:\d{2})')
# RFC 3164 / syslog BSD: 'Oct 30 10:00:00' (sin anio: se pone el anio actual).
RE_TS_RFC3164 = re.compile(r'\b([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b')
# Hora suelta al inicio de la linea ('10:11:12 mensaje'): no lleva fecha, pero
# es estructura (parse_triage la completa con la fecha del fichero).
RE_TS_TIME_ONLY = re.compile(r'^(?:<\d+>)?\s*(\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)(?:\s|$)')

AUTO_LEVEL_WORDS = ("FATAL", "CRITICAL", "CRIT", "ALERT", "ERROR", "WARNING",
                    "WARN", "NOTICE", "DEBUG", "TRACE", "INFO", "ERR")
RE_LEVEL_BRACKET = re.compile(r'\[(' + "|".join(AUTO_LEVEL_WORDS) + r')\]',
                              re.IGNORECASE)
RE_LEVEL_WORD = re.compile(r'\b(' + "|".join(AUTO_LEVEL_WORDS) + r')\b',
                           re.IGNORECASE)
AUTO_LEVEL_MAP = dict(LEVEL_MAP)
AUTO_LEVEL_MAP["ALERT"] = "CRIT"
AUTO_LEVEL_MAP["NOTICE"] = "INF"

# Pares clave=valor (logfmt): key=value, key="value" o key='valor'.
RE_KV = re.compile(r'([A-Za-z_][A-Za-z0-9_]{0,24})='
                   r'(?:"([^"]*)"|' + "'" + r"([^']*)'" + r'|([^\s,;]+))')
# Claves que no se copian de logfmt: las pone el propio parser.
AUTO_RESERVED = ("ts", "ts_norm", "level", "ip", "msg", "raw", "_line")

# Columnas de OperVanta que antes se perdian al parsear JSON Lines.
# P0.4: 'sev', 'src' y 'dst' se conservan tal cual (ademas de usarse para
# level e ip) para que el export no pierda la firma ni la severidad original.
JSON_EXTRA_KEYS = ("fuente", "firma", "tenant", "tarea", "dedupe",
                   "evidencia", "riesgo", "url", "sev", "src", "dst")
# Claves que envuelven el registro real en dataset.jsonl / triage-dataset.jsonl
JSON_NESTED_KEYS = ("datos", "alerta", "data", "event", "payload", "detail")

# ---------------------------------------------------------------------------
# U0.2 (2026-10-30): formatos concretos que antes caian a 'raw' o 'auto'.
# Python logging, syslog RFC 3164, logfmt, CSV/TSV y nginx error_log.
# ---------------------------------------------------------------------------
# Niveles extra que LEVEL_MAP no cubre (nginx, syslog, python NOTSET).
EXTRA_LEVEL_MAP = {
    "CRITICAL": "CRIT", "ALERT": "CRIT", "EMERG": "CRIT", "PANIC": "CRIT",
    "SEVERE": "ERR", "NOTICE": "INF", "NOTSET": "INF", "NONE": "",
}


def _norm_level_any(lv):
    """Normaliza niveles de cualquier formato a CRIT/ERR/WRN/INF/DBG."""
    lv = (lv or "").strip().upper()
    if not lv:
        return ""
    if lv in EXTRA_LEVEL_MAP:
        return EXTRA_LEVEL_MAP[lv]
    return _norm_level(lv)


# Python logging: '2026-10-30 10:11:50,123 - app.logger - INFO - mensaje'.
# La parte ',mmm - logger -' es opcional, asi que '2026-10-30 10:11:50 - INFO - x'
# tambien matchea. El separador antes del nivel es un guion.
PY_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "WARN", "ERROR", "CRITICAL",
                 "CRIT", "FATAL", "NOTICE", "ALERT", "TRACE", "NOTSET")
RE_PYTHON_LOG = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)'
    r'(?:\s*-\s*(?P<logger>[^-\n]*?))?'
    r'\s*-\s*'
    r'(?P<level>' + "|".join(PY_LOG_LEVELS) + r')'
    r'\s*[-:]\s*(?P<msg>.*)$',
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# J1 (2026-10-30): Java / log4j. Primera linea de una entrada:
#   'YYYY-MM-DD HH:MM:SS,mmm LEVEL [thread] logger - mensaje'
# (pattern log4j2 %d{yyyy-MM-dd HH:mm:ss,SSS} %p %t %c - %m). [thread] y
# logger son opcionales; la coma de milisegundos puede faltar (se admite
# tambien el punto) y el separador fecha/hora puede ser espacio o 'T'.
# Los frames del stack trace ('    at ...', 'Caused by:', tabulacion) los
# agrupa la continuacion multilinea U0.3: aqui solo se detecta la PRIMERA
# linea, que antes caia a 'piloop'/'auto'/'raw'.
# ---------------------------------------------------------------------------
JAVA_LEVELS = ("FATAL", "CRITICAL", "CRIT", "ALERT", "ERROR", "ERR",
               "WARNING", "WARN", "WRN", "SEVERE", "NOTICE", "INFO",
               "DEBUG", "DBG", "TRACE")
RE_JAVA = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})[ T]\s*'
    r'(?P<time>\d{2}:\d{2}:\d{2})(?P<ms>[,.]\d{1,6})?'
    r'\s+(?P<level>' + "|".join(JAVA_LEVELS) + r')\b'
    r'(?:\s+\[(?P<thread>[^\]]*)\])?'
    r'(?:\s+(?P<logger>[A-Za-z][A-Za-z0-9_.$\-]{1,120})\s*[-:])?'
    r'\s*(?P<msg>.*)$',
    re.IGNORECASE
)

# Syslog RFC 3164 (BSD): 'Oct 30 10:00:00 host app[1234]: mensaje'.
# Sin anio: se pone el anio actual, igual que hace extract_ts con RE_TS_RFC3164.
# El prefijo de prioridad '<14>' es opcional.
RE_SYSLOG3164 = re.compile(
    r'^(?:<(?P<pri>\d{1,2})>)?'
    r'(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>[A-Za-z0-9._-]+)\s+'
    r'(?P<app>[^\s:\[\]]+)(?:\[(?P<pid>\d+)])?:?\s*'
    r'(?P<msg>.*)$'
)

# Severidad RFC 3164 (pri % 8): 0 emerg ... 7 debug.
SYSLOG_SEV_MAP = {0: "CRIT", 1: "CRIT", 2: "CRIT", 3: "ERR",
                  4: "WRN", 5: "INF", 6: "INF", 7: "DBG"}

# nginx error_log: '2026/10/30 10:11:50 [error] 1234#5678: mensaje'.
# El pid#tid es opcional (algunos logs de nginx solo traen '[error] mensaje').
RE_NGINX_ERROR = re.compile(
    r'^(?P<date>\d{4})/(\d{1,2})/(\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>[^\]]+)\]\s*'
    r'(?:(?P<pid>\d+)(?:#(?P<tid>\d+))?:\s*)?'
    r'(?P<msg>.*)$'
)

# Claves de logfmt/CSV que se mapean a las columnas estandar del visor.
LOGFMT_TS_KEYS = ("ts", "time", "timestamp", "datetime", "date", "_time")
LOGFMT_LEVEL_KEYS = ("level", "severity", "lvl", "log_level", "sev", "priority")
LOGFMT_MSG_KEYS = ("msg", "message", "text", "log", "mensaje")
CSV_DATE_KEYS = ("date", "fecha", "timestamp", "ts", "datetime", "time", "hora",
                 "_time", "tiempo")
CSV_LEVEL_KEYS = ("level", "nivel", "severity", "sev", "lvl", "log_level",
                  "priority", "status")
CSV_MSG_KEYS = ("message", "msg", "mensaje", "text", "texto", "log", "detail",
                "description")


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

    U2.1 (2026-10-30): se descartan las columnas vacias en TODAS las filas
    (el parser auto declara method/path/code/bytes aunque el log no los traiga),
    para que el selector y la tabla no ofrezcan huecos sin datos. 'msg' se
    conserva siempre: una fila legitima puede ser solo un timestamp.
    """
    try:
        cols = store.columns()
    except Exception:
        cols = []
    try:
        filled = store.nonempty_columns()
    except Exception:
        filled = set(cols)
    out = []
    for c in cols:
        if c in EXPORT_SKIP_KEYS or c in out:
            continue
        if c in ("msg_len", "msg_truncated", "line", "search"):
            continue
        if c != "msg" and c not in filled:
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


def count_file_lines(path, chunk=1 << 20):
    """Numero de lineas de un fichero de texto sin comprimir.

    Una pasada en bloques binarios (no carga el fichero en memoria). La ultima
    linea cuenta aunque no termine con salto de linea."""
    total = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            total += block.count(b"\n")
        f.seek(os.path.getsize(path) - 1)
        if f.read(1) not in (b"\n", b"\r", b""):   # ultima linea sin \n
            total += 1
    return total


def tail_lines_from_file(path, lines=5000, encoding="utf-8", chunk=8192):
    """Ultimas `lines` lineas de un fichero de texto, leyendo desde el final.

    Version robusta de `tail_lines` (server.py): lee bloques desde el final con
    seek y NO devuelve una primera linea cortada a mitad (descarta el bloque
    parcial cuando el seek cae en medio de una linea). Devuelve una tupla
    (lineas, linea_inicial) donde `linea_inicial` es el numero de linea
    (0-based) de la primera linea devuelta dentro del fichero original, para
    que `_line` siga apuntando al archivo real.
    """
    want = max(1, int(lines))
    size = os.path.getsize(path)
    if size == 0:
        return [], 0
    total = count_file_lines(path)
    want = min(want, total)
    tail = b""
    offset = size
    # Se pide una linea mas de la necesaria: la primera del bloque acumulado
    # puede empezar a mitad de linea y se descarta al tomar las ultimas 'want'.
    while offset > 0 and tail.count(b"\n") < want + 1:
        start = max(0, offset - chunk)
        with open(path, "rb") as f:
            f.seek(start)
            tail = f.read(offset - start) + tail
        offset = start
    out = tail.decode(encoding, errors="replace").splitlines()
    out = out[-want:]
    # La primera linea devuelta es la numero (total - want) del fichero,
    # 0-based. Si el fichero tiene menos lineas que 'want', es la 0.
    return out, max(0, total - want)


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


def _fix_iso_offset(s):
    # Convierte el offset '+0200' en '+02:00' para que norm_ts lo parsee.
    m = re.search(r'([+-])(\d{2})(\d{2})$', s)
    if m and ":" not in m.group(0):
        # s[:-4] deja el signo: solo hay que insertar el separador.
        return s[:-4] + m.group(2) + ":" + m.group(3)
    return s


def extract_ts(line):
    # Devuelve (ts_crudo, ts_norm) de la primera fecha reconocible.
    # Orden: ISO 8601, epoch (s o ms), yyyy/MM/dd, dd/MM/yyyy o MM/dd/yyyy,
    # RFC3164 ('Oct 30 10:00:00'). Devuelve ("", "") si no la hay.
    m = RE_TS_ISO.search(line)
    if m:
        raw = m.group(0)
        return raw, norm_ts(_fix_iso_offset(raw))
    m = RE_TS_EPOCH.search(line)
    if m:
        raw = m.group(1)
        return raw, norm_ts(raw)
    m = RE_TS_YMD_SLASH.search(line)
    if m:
        raw = "%s-%02d-%02d %s" % (m.group(1), int(m.group(2)),
                                   int(m.group(3)), m.group(4))
        return m.group(0), norm_ts(raw)
    m = RE_TS_DMY.search(line)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a <= 12 and b > 12:          # MM/dd/yyyy
            day, mon = b, a
        else:                           # dd/MM/yyyy (por defecto, europeo)
            day, mon = a, b
        raw = "%s-%02d-%02d %s" % (m.group(3), mon, day, m.group(4))
        return m.group(0), norm_ts(raw)
    m = RE_TS_RFC3164.search(line)
    if m and m.group(1).lower()[:3] in _CLF_MONTHS:
        raw = "%d-%02d-%02d %s" % (datetime.now().year,
                                   _CLF_MONTHS[m.group(1).lower()[:3]],
                                   int(m.group(2)), m.group(3))
        return m.group(0), norm_ts(raw)
    m = RE_TS_TIME_ONLY.match(line)
    if m:
        # Hora suelta: se devuelve tal cual; no se puede normalizar sin fecha.
        return m.group(1), ""
    return "", ""


def extract_level(line):
    # Nivel normalizado (CRIT/ERR/WRN/INF/DBG) en CUALQUIER posicion.
    # Primero busca '[ERROR]'; si no, la primera palabra de la lista con
    # word boundary (case-insensitive). Devuelve "" si no lo encuentra.
    m = RE_LEVEL_BRACKET.search(line)
    if not m:
        m = RE_LEVEL_WORD.search(line)
    if not m:
        return ""
    return AUTO_LEVEL_MAP.get(m.group(1).upper(), m.group(1).upper())


def extract_kv(line):
    # Pares clave=valor (logfmt) como dict. La primera ocurrencia gana.
    out = {}
    for m in RE_KV.finditer(line):
        key = m.group(1).lower()
        if key in AUTO_RESERVED or key in out:
            continue
        val = m.group(2)
        if val is None:
            val = m.group(3)
        if val is None:
            val = m.group(4)
        out[key] = val
    return out


def _auto_score(line):
    # True si la linea tiene al menos una sena aprovechable.
    return bool(extract_ts(line)[0] or extract_level(line) or RE_KV.search(line))


def parse_auto(lines, progress=None):
    # Parser universal 'auto' (U0.1): best-effort sobre cualquier linea.
    # Orden: timestamp -> nivel -> primera IPv4 -> pares clave=valor a
    # columnas dinamicas. Si no hay fecha, ni nivel ni clave=valor, la fila
    # queda 'RAW'. El ts se normaliza con norm_ts y se guarda en ts_norm.
    rows = []
    levels, ips, keys = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        ts, ts_norm = extract_ts(l)
        lv = extract_level(l)
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        kv = extract_kv(l)
        if not ts and not lv and not kv:
            lv = "RAW"
        msg = l.strip()
        if ts:
            msg = msg.replace(ts, "", 1).strip()
        if not msg:
            msg = l.strip()
        row = {"ts": ts, "ts_norm": ts_norm, "level": lv, "ip": ip,
               "method": "", "path": "", "code": "", "bytes": "",
               "msg": msg, "raw": l, "_line": i}
        for k, v in kv.items():
            if k in row:
                if not row[k]:
                    row[k] = v
            else:
                row[k] = v
        levels[lv] += 1
        if ip:
            ips[ip] += 1
        for k in kv:
            keys[k] += 1
        rows.append(row)
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "keys": keys}

def parse_python_logging(lines, progress=None):
    """Python logging: 'YYYY-MM-DD HH:MM:SS,mmm - logger - LEVEL - mensaje'.

    La parte ',mmm - logger -' es opcional. Lo que no matchea se queda RAW.
    Columnas extra: logger.
    """
    rows = []
    levels, ips, loggers = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        m = RE_PYTHON_LOG.match(l)
        if m:
            ts = m.group("date") + " " + m.group("time")
            lv = _norm_level_any(m.group("level"))
            logger = (m.group("logger") or "").strip()
            msg = m.group("msg")
            if logger:
                loggers[logger] += 1
        else:
            lv, ts, logger, msg = "RAW", "", "", l
        levels[lv] += 1
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        rows.append({
            "ts": ts, "ts_norm": norm_ts(ts), "level": lv, "ip": ip,
            "method": "", "path": "", "code": "", "bytes": "",
            "msg": msg, "raw": l, "_line": i, "logger": logger,
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "logger": loggers}


def parse_java(lines, progress=None):
    """Java/log4j: 'YYYY-MM-DD HH:MM:SS,mmm LEVEL [thread] logger - mensaje'.

    [thread] y logger son opcionales; la coma de milisegundos puede faltar.
    Lo que no matchea (frames del stack trace, continuaciones) se queda RAW
    y se anexa a la fila anterior gracias a la continuacion U0.3.
    Columnas extra: thread y logger.
    """
    rows = []
    levels, ips, threads, loggers = Counter(), Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        m = RE_JAVA.match(l)
        if m:
            ts = m.group("date") + " " + m.group("time")
            lv = _norm_level_any(m.group("level"))
            thread = (m.group("thread") or "").strip()
            logger = (m.group("logger") or "").strip()
            msg = (m.group("msg") or "").strip()
            # Sin logger queda 'ERROR - mensaje': el guion se queda en msg.
            if msg[:1] in "-:" and (len(msg) == 1 or msg[1] in " \t"):
                msg = msg[1:].strip()
            if thread:
                threads[thread] += 1
            if logger:
                loggers[logger] += 1
        else:
            lv, ts, thread, logger, msg = "RAW", "", "", "", l
        levels[lv] += 1
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        rows.append({
            "ts": ts, "ts_norm": norm_ts(ts), "level": lv, "ip": ip,
            "method": "", "path": "", "code": "", "bytes": "",
            "msg": msg, "raw": l, "_line": i,
            "thread": thread, "logger": logger,
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "thread": threads,
                  "logger": loggers}


def parse_syslog3164(lines, progress=None):
    """Syslog RFC 3164: 'MMM d HH:MM:SS host app[pid]: mensaje' (sin anio).

    El anio se pone el actual (el formato no lo lleva). Si la linea trae
    prioridad '<N>', el nivel sale de pri % 8; si no, se intenta adivinar
    del mensaje. Lo que no matchea se queda RAW.
    """
    rows = []
    levels, ips, hosts, apps = Counter(), Counter(), Counter(), Counter()
    year = datetime.now().year
    n = len(lines)
    for i, l in enumerate(lines):
        m = RE_SYSLOG3164.match(l)
        if m:
            mon = m.group("mon").lower()[:3]
            if mon in _CLF_MONTHS:
                ts = "%d-%02d-%02d %s" % (year, _CLF_MONTHS[mon],
                                          int(m.group("day")), m.group("time"))
            else:
                ts = m.group(0)
            lv = SYSLOG_SEV_MAP.get(int(m.group("pri")) % 8, "") if m.group("pri") else ""
            if not lv:
                lv = extract_level(l) or "INF"
            host = m.group("host")
            app = m.group("app")
            msg = m.group("msg")
            levels[lv] += 1
            hosts[host] += 1
            apps[app] += 1
        else:
            lv, ts, host, app, msg = "RAW", "", "", "", l
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        rows.append({
            "ts": ts, "ts_norm": norm_ts(ts), "level": lv, "ip": ip,
            "method": "", "path": "", "code": "", "bytes": "",
            "msg": msg, "raw": l, "_line": i,
            "host": host, "app": app, "pid": (m.group("pid") or "") if m else "",
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "hosts": hosts, "apps": apps}


def _kv_pairs(line):
    """Pares clave=valor de una linea logfmt, sin descartar las claves reservadas."""
    out = {}
    for m in RE_KV.finditer(line):
        key = m.group(1).lower()
        val = m.group(2)
        if val is None:
            val = m.group(3)
        if val is None:
            val = m.group(4)
        if key not in out:
            out[key] = val if val is not None else ""
    return out


def parse_logfmt(lines, progress=None):
    """Logfmt: 'clave=valor clave2="valor 2' ...' con comillas opcionales.

    ts/time/timestamp -> ts, level/severity/lvl -> level, msg/message -> msg.
    El resto de claves se queda como columnas dinamicas. Las lineas sin
    pares clave=valor se guardan como RAW.
    """
    rows = []
    levels, ips, keys = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        kv = _kv_pairs(l)
        if not kv:
            rows.append({
                "ts": "", "ts_norm": "", "level": "RAW", "ip": "",
                "method": "", "path": "", "code": "", "bytes": "",
                "msg": l, "raw": l, "_line": i,
            })
            levels["RAW"] += 1
            if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
                progress(i + 1, n)
            continue
        ts = next((kv[k] for k in LOGFMT_TS_KEYS if kv.get(k)), "")
        # U3.2 (2026-10-30): el timestamp puede ir suelto al principio de la
        # linea ('2026-10-30T09:12:03.481Z level=info msg=...'), no como par
        # clave=valor. Sin eso la fila se queda sin fecha y la histograma vacia.
        if not ts:
            ts, _ = extract_ts(l)
        lv = next((_norm_level_any(kv[k]) for k in LOGFMT_LEVEL_KEYS if kv.get(k)), "")
        if not lv:
            lv = extract_level(l)
        msg = next((kv[k] for k in LOGFMT_MSG_KEYS if kv.get(k)), "")
        if not msg:
            msg = l.strip()
            # U3.2: si la fecha iba suelta al principio, no la deja en el msg.
            if ts and msg.startswith(ts):
                msg = msg[len(ts):].strip()
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        levels[lv] += 1
        row = {"ts": ts, "ts_norm": norm_ts(ts), "level": lv, "ip": ip,
               "method": "", "path": "", "code": "", "bytes": "",
               "msg": msg, "raw": l, "_line": i}
        for k, v in kv.items():
            if k in LOGFMT_TS_KEYS or k in LOGFMT_LEVEL_KEYS or k in LOGFMT_MSG_KEYS:
                continue
            if k in row:
                if not row[k]:
                    row[k] = v
            else:
                row[k] = v
            keys[k] += 1
        rows.append(row)
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "keys": keys}


def _csv_delim(header):
    """Delimitador de una cabecera CSV: coma, punto y coma o tabulador."""
    for d in (",", ";", "\t", "|"):
        if d in header:
            return d
    return ","


RE_CSV_DATA_FIELD = re.compile(r'^(?:\d+|\d{4}-\d{2}-\d{2}\b|\d{1,2}:\d{2}:\d{2})')
RE_CSV_DATE_ONLY = re.compile(r'^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?$')


def _looks_header(head):
    """True si la primera linea son nombres de columna, no una linea de datos.

    Un campo que es solo numero, una fecha o una hora indica que la primera
    linea ya es dato (CSV sin cabecera)."""
    if not head:
        return False
    return all(h and not RE_CSV_DATA_FIELD.match(h) for h in head)


def _csv_fields(line, delim):
    try:
        return next(csv.reader([line], delimiter=delim))
    except Exception:
        return [line]


def parse_csv(lines, progress=None):
    """CSV/TSV: la primera linea no vacia es la cabecera.

    Se mapean fecha/nivel/mensaje a ts/level/msg si existen; el resto de
    columnas se conserva como columnas dinamicas. Si la primera linea no
    parece una cabecera (empieza con una fecha o todos los campos son
    numericos) se generan nombres c0, c1, ... y esa linea se parsea como dato.
    """
    rows = []
    levels, ips, keys = Counter(), Counter(), Counter()
    first = next((l for l in lines if l.strip()), "")
    if not first:
        return rows, {"levels": levels, "ips": ips, "keys": keys}
    delim = _csv_delim(first)
    head = [h.strip() for h in _csv_fields(first, delim)]
    looks_header = _looks_header(head)
    if looks_header:
        header = head or ["c%d" % i for i in range(len(head))]
        start = lines.index(first)
    else:
        header = ["c%d" % i for i in range(len(head))]
        start = -1  # la primera linea es dato
    n = len(lines)
    for i, l in enumerate(lines):
        if i == start or not l.strip():
            continue
        fields = _csv_fields(l, delim)
        rec = {}
        for j, name in enumerate(header):
            rec[name] = fields[j].strip() if j < len(fields) else ""
        ts = next((rec[k] for k in CSV_DATE_KEYS if rec.get(k)), "")
        if not ts:
            # CSV sin cabecera o con columna de fecha no reconocida: se saca
            # de la linea (primer campo que parece una fecha) o del extractor
            # universal de U0.1.
            ts = next((f.strip() for f in fields
                       if RE_CSV_DATE_ONLY.match(f.strip())), "")
            if not ts:
                ts = extract_ts(l)[0]
        lv = next((_norm_level_any(rec[k]) for k in CSV_LEVEL_KEYS if rec.get(k)), "")
        if not lv:
            lv = extract_level(l)
        msg = next((rec[k] for k in CSV_MSG_KEYS if rec.get(k)), "")
        if not msg:
            msg = " ".join(f for f in fields if f)
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        levels[lv] += 1
        row = {"ts": ts, "ts_norm": norm_ts(ts), "level": lv, "ip": ip,
               "method": "", "path": "", "code": "", "bytes": "",
               "msg": msg, "raw": l, "_line": i}
        for k, v in rec.items():
            if k in CSV_DATE_KEYS or k in CSV_LEVEL_KEYS or k in CSV_MSG_KEYS:
                continue
            if k in row:
                if not row[k]:
                    row[k] = v
            else:
                row[k] = v
            keys[k] += 1
        rows.append(row)
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "keys": keys}


def parse_nginx_error(lines, progress=None):
    """nginx error_log: 'YYYY/MM/DD HH:MM:SS [level] pid#tid: mensaje'.

    Columnas extra: pid y tid. Lo que no matchea se queda RAW.
    """
    rows = []
    levels, ips, pids = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        m = RE_NGINX_ERROR.match(l)
        if m:
            ts = "%s-%02d-%02d %s" % (m.group("date"), int(m.group(2)),
                                      int(m.group(3)), m.group("time"))
            lv = _norm_level_any(m.group("level"))
            pid = m.group("pid") or ""
            tid = m.group("tid") or ""
            msg = m.group("msg")
            levels[lv] += 1
            if pid:
                pids[pid] += 1
        else:
            lv, ts, pid, tid, msg = "RAW", "", "", "", l
        mi = RE_IP.search(l)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        rows.append({
            "ts": ts, "ts_norm": norm_ts(ts), "level": lv, "ip": ip,
            "method": "", "path": "", "code": "", "bytes": "",
            "msg": msg, "raw": l, "_line": i, "pid": pid, "tid": tid,
        })
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "pid": pids}


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


# ---------------------------------------------------------------------------
# U0.3: continuaciones multilineas (stack traces) - post-proceso generico
# ---------------------------------------------------------------------------
# Las lineas que no matchean el formato activo y van justo detras de una linea
# ya parseada (traceback de Python, stack trace de Java, continuation de un
# mensaje) se anexan al 'raw' y al 'msg' de la fila anterior en vez de crear
# filas RAW sueltas. Se aplica a TODOS los parsers desde el bucle de carga
# (api.load_file y el tail), no parser por parser.
MAX_CONTINUATION_LINES = 40

# Prefijos tipicos de una continuacion de trace (Java, Python, JS, C#).
CONTINUATION_PREFIXES = ("at ", "caused by", "traceback", "file ",
                         "stack trace", "suppressed", "during handling of")

# Columnas estandar de una fila; lo demas son columnas dinamicas.
STANDARD_ROW_KEYS = frozenset(("ts", "ts_norm", "level", "ip", "method",
                               "path", "code", "bytes", "msg", "raw",
                               "_line", "template", "_search"))


def _line_has_ts(line):
    """True si la linea lleva un timestamp reconocible."""
    return bool(extract_ts(line or "")[0])


def is_continuation_line(line, prev_line=None, in_trace=False):
    """True si `line` es continuacion de la linea anterior (stack trace).

    Reglas (U0.3): empieza por espacio o tab, o por 'at ', 'Caused by',
    'Traceback', 'File '; o no tiene timestamp y la anterior si lo tiene.
    Una linea vacia solo continua un trace ya abierto (no lo abre), para no
    pegar los saltos de linea entre entradas de log independientes.
    """
    if line is None:
        return False
    s = line.rstrip("\r")
    if not s.strip():
        return bool(in_trace)
    if s[0] in " \t":
        return True
    low = s.lstrip().lower()
    if low.startswith(CONTINUATION_PREFIXES):
        return True
    if not _line_has_ts(s):
        # Dentro de un trace ya abierto, cualquier linea sin fecha es parte
        # del trace (p. ej. 'ValueError: x' tras el 'raise'). Fuera de un
        # trace, solo se anexa si la linea anterior si tenia fecha: eso evita
        # pegar filas de CSV o logfmt que van legítimamente sin timestamp.
        if in_trace:
            return True
        return bool(prev_line) and _line_has_ts(prev_line)
    return False


def _uncount_row(counters, row):
    """Descuenta de los contadores una fila que se absorbe en la anterior."""
    if not counters:
        return
    lv = row.get("level")
    if lv and counters.get("levels") is not None:
        counters["levels"][lv] -= 1
    ip = row.get("ip")
    if ip and counters.get("ips") is not None:
        counters["ips"][ip] -= 1
    keys = counters.get("keys")
    if keys is not None:
        for k in row:
            if k not in STANDARD_ROW_KEYS and k in keys:
                keys[k] -= 1
    # Los demas contadores (logger, host, pid, method...) no se ven
    # afectados: una linea de continuacion no matchea el formato, así que
    # esos campos van vacios en la fila absorbida.
    for name, c in counters.items():
        if isinstance(c, Counter):
            for k, v in list(c.items()):
                if v <= 0:
                    del c[k]


def attach_continuations(rows, counters=None, max_lines=MAX_CONTINUATION_LINES):
    """Anexa las lineas de continuacion a la fila anterior.

    Post-proceso del bucle de carga: agrupa un stack trace en UNA fila. Solo
    se anexa si existe fila anterior, la linea no tiene timestamp propio y
    cumple una de las reglas de continuacion; como mucho `max_lines` lineas
    seguidas (40 por defecto). Devuelve las filas agrupadas y deja los
    contadores coherentes.
    """
    if not rows:
        return rows
    out = []
    run = 0
    for row in rows:
        raw = row.get("raw") or ""
        if out and run < max_lines and not row.get("ts"):
            prev_raw = out[-1].get("raw") or ""
            prev_last = prev_raw.split("\n")[-1] if prev_raw else ""
            if is_continuation_line(raw, prev_last, run > 0):
                prev = out[-1]
                prev["raw"] = (prev.get("raw") or "") + "\n" + raw
                msg = (row.get("msg") or "").strip()
                if msg:
                    prev["msg"] = ((prev.get("msg") or "") + "\n" + msg)
                _uncount_row(counters, row)
                run += 1
                continue
        out.append(row)
        run = 0
    return out


# ---------------------------------------------------------------------------
# Volcado de stack traces sin fecha (U3.2, 2026-10-30)
# ---------------------------------------------------------------------------
TRACE_PATTERNS = (
    re.compile(r"^\s*at\s+\S"),
    re.compile(r"^Traceback \(most recent call last\):"),
    re.compile(r"^\s*File \"[^\"]+\", line \d+"),
    re.compile(r"^\s*Caused by:"),
    re.compile(r"^\s*\^$"),
    re.compile(r"^(?:Error|Exception|Fatal)[A-Za-z]*:"),
    re.compile(r"^\s*(?:errno|syscall):"),
    re.compile(r"^\s*code: '[A-Z0-9_]+'"),
    re.compile(r"^node:[A-Za-z]+:\d+"),
    re.compile(r"^Emitted 'error' event"),
    re.compile(r"^Node\.js v\d"),
)


def _trace_shapes(line):
    """Formas de stack trace que aparecen en la linea (node, Java, Python).

    Se exige mas de una forma distinta para que una repeticion suelta de
    'Traceback (most recent call last):' no convierta un log sin estructura
    en 'trace': eso seguiria siendo 'raw'.
    """
    return {i for i, rx in enumerate(TRACE_PATTERNS) if rx.match(line)}


def _is_trace_line(line):
    """True si la linea es parte de un stack trace (node, Java o Python)."""
    return bool(_trace_shapes(line))


def parse_trace(lines, progress=None):
    """Volcado de stack traces sin timestamps (p. ej. orquestador.log).

    No hay fecha: 'ts' queda vacio. Nivel ERR si la linea trae
    Error/Exception/Fatal; si no, se usa extract_level y, en su defecto, ERR
    porque dentro de un volcado de traces todo es parte del error. Las lineas
    se anexan a la fila anterior en attach_continuations, asi que un trace
    completo es una sola fila.
    """
    rows = []
    levels, ips, keys = Counter(), Counter(), Counter()
    n = len(lines)
    for i, l in enumerate(lines):
        s = l.rstrip("\r")
        if not s.strip():
            continue
        lv = extract_level(s) or "ERR"
        mi = RE_IP.search(s)
        ip = mi.group(1) if mi else ""
        if ip:
            ips[ip] += 1
        levels[lv] += 1
        rows.append({"ts": "", "ts_norm": "", "level": lv, "ip": ip,
                     "method": "", "path": "", "code": "", "bytes": "",
                     "msg": s.strip(), "raw": s, "_line": i})
        if progress is not None and (i % PROGRESS_STEP == 0 or i == n - 1):
            progress(i + 1, n)
    return rows, {"levels": levels, "ips": ips, "keys": keys}


PARSERS = {
    "apache": parse_apache,
    "w3c": parse_w3c,
    "json": parse_json,
    "syslog": parse_syslog,
    "generic": parse_generic,
    "piloop": parse_piloop,
    "triage": parse_triage,
    "auto": parse_auto,
    "raw": parse_raw,
    "python": parse_python_logging,
    "java": parse_java,
    "syslog3164": parse_syslog3164,
    "logfmt": parse_logfmt,
    "trace": parse_trace,
    "csv": parse_csv,
    "nginx_error": parse_nginx_error,
}


# ---------------------------------------------------------------------------
# Deteccion de formato (heuristicas sobre las primeras lineas no vacias)
# ---------------------------------------------------------------------------
def _looks_csv(sample):
    """Heuristica U0.2: cabecera con nombres y numero de columnas estable.

    No vale con que haya comas: hay que parecer una tabla (>=3 columnas en
    la cabecera y el mismo numero en la mayor parte de las lineas). Los
    JSON y los logs con fecha en la primera columna no cuentan.
    """
    first = sample[0]
    delim = _csv_delim(first)
    if delim not in first:
        return False
    head = [h.strip() for h in _csv_fields(first, delim)]
    if len(head) < 3:
        return False
    if not _looks_header(head):
        return False
    if not all(re.match(r'^[A-Za-z0-9_ .-]{1,40}$', h) for h in head):
        return False
    base = len(head)
    same = sum(1 for l in sample[1:] if len(_csv_fields(l, delim)) == base)
    return same >= (len(sample) - 1) * 0.7


def _is_java_line(line):
    """True si la linea es java/log4j y trae firma propia del formato.

    RE_JAVA es laxo (thread y logger opcionales, sin milisegundos), así que
    una linea tipo '2026-10-30 10:00:00 INFO arranque' tambien la matchea y
    es mas honesta como 'generic'. Solo se apunta a 'java' si aparece al menos
    una marca del pattern log4j: milisegundos, [thread] o logger con separador.
    """
    m = RE_JAVA.match(line)
    if not m:
        return False
    return bool(m.group("ms") or m.group("thread") or m.group("logger"))


def _is_trace_continuation(line):
    """True si la linea parece un frame de stack trace (U0.3, sin contexto)."""
    s = (line or "").rstrip("\r")
    if not s.strip():
        return False
    if s[0] in " \t":
        return True
    return s.lstrip().lower().startswith(CONTINUATION_PREFIXES)


def _is_json_line(line):
    """True si la linea, suelta, es un objeto JSON completo (JSON Lines)."""
    s = line.strip()
    if not s.startswith("{"):
        return False
    try:
        json.loads(s)
    except Exception:
        return False
    return True


def detect_format(lines):
    """Deteccion de formato por orden de especificidad (U1.1, 2026-10-30).

    El orden es determinista y va de lo mas estructurado a lo mas laxo:
    csv, w3c, json, syslog RFC5424, syslog RFC3164, python logging, apache
    (access), nginx error, logfmt, piloop, triage, generic. Cada formato
    exige su umbral sobre las primeras 100 lineas no vacias.

    Si NINGUN formato alcanza su umbral no se devuelve 'raw' a la primera:
    se cae a 'auto' (parser universal) cuando hay estructura aprovechable,
    es decir un timestamp reconocible en mas del 40% de las lineas, o un
    nivel/clave=valor en esa proporcion. 'raw' queda solo para lo que de
    verdad no tiene estructura (ni fecha, ni nivel, ni clave=valor).
    """
    sample = [l for l in lines if l.strip()][:100]
    if not sample:
        return "raw"
    n = len(sample)

    def share(pred):
        return sum(1 for l in sample if pred(l))

    # 1. CSV/TSV: la primera linea no vacia es una cabecera de columnas.
    if _looks_csv(sample):
        return "csv"
    # 2. W3C: '#Fields' (puede ir tras metadatos #Software, #Reason...).
    if any(l.startswith("#Fields") for l in sample):
        return "w3c"
    # 3. JSON Lines (>70% de lineas que son un objeto JSON completo).
    if share(_is_json_line) > n * 0.7:
        return "json"
    # 4. syslog RFC 5424: '1 2026-10-30T10:00:00.000Z host app[1]: msg' (>70%).
    if share(RE_SYSLOG.match) > n * 0.7:
        return "syslog"
    # 5. syslog RFC 3164: 'Oct 30 10:00:00 host app[123]: msg' (>40%).
    if share(RE_SYSLOG3164.match) >= n * 0.4:
        return "syslog3164"
    # 6. python logging: '... - logger - LEVEL - msg' (>40%; los trazos de
    #    traceback no llevan el prefijo, por eso el umbral es bajo).
    if share(RE_PYTHON_LOG.match) >= n * 0.4:
        return "python"
    # 6.5 java/log4j: 'YYYY-MM-DD HH:MM:SS,mmm LEVEL [thread] logger - msg'
    #     (>40%). Va antes de piloop y generic: la coma de milisegundos rompe
    #     RE_LEVEL y, sin esta regla, la linea se iba a 'piloop' o 'auto'.
    java_hits = share(_is_java_line)
    if java_hits >= n * 0.4:
        return "java"
    # Muestra corta (una linea de error + los frames del stack): si todo lo
    # demas es continuacion de trace, el formato es java aunque el umbral
    # no se cumpla sobre 3 lineas.
    if java_hits and all(_is_java_line(l) or _is_trace_continuation(l)
                         for l in sample):
        return "java"
    # 7. apache/nginx access (>40%).
    if share(match_apache) >= n * 0.4:
        return "apache"
    # 8. nginx error_log: '2026/10/30 10:11:50 [error] 1234#5678: msg' (>40%).
    if share(RE_NGINX_ERROR.match) >= n * 0.4:
        return "nginx_error"
    # 9. logfmt: dos o mas pares clave=valor por linea (>40%).
    if share(lambda l: len(_kv_pairs(l)) >= 2) >= n * 0.4:
        return "logfmt"
    # 10. piloop: 'YYYY-MM-DD HH:MM:SS componente: msg' SIN nivel explicito.
    #     Si la linea ademas lleva nivel, es 'generic' (mas abajo): el orden
    #     exige que generic no se lo robe a piloop cuando solo hay fecha.
    if share(lambda l: RE_PILOOP.match(l) and not RE_LEVEL.match(l)) >= n * 0.4:
        return "piloop"
    # 11. triage SOC: 'HH:MM:SS [fuente] FIRMA -> verdict conf ... sev ...' (>40%).
    if share(RE_TRIAGE.match) >= n * 0.4:
        return "triage"
    # 12. generic: fecha + hora + nivel (>40%).
    if share(RE_LEVEL.match) >= n * 0.4:
        return "generic"
    # 13. trace: volcado de stack traces sin fecha (node, Java, Python). Va
    #     antes del fallback 'auto' porque aqui no hay timestamp que aprovechar.
    #     Exige >=40% de lineas de trace y al menos 3 formas distintas (una
    #     repeticion de 'Traceback' suelta sigue siendo 'raw').
    shapes = set()
    trace_lines = 0
    for l in sample:
        s = _trace_shapes(l)
        if s:
            trace_lines += 1
            shapes |= s
    if trace_lines >= n * 0.4 and len(shapes) >= 3:
        return "trace"
    # Fallback 'auto' (U1.1): hay estructura pero ningun formato concreto.
    if share(lambda l: extract_ts(l)[0]) >= n * 0.4:
        return "auto"
    # Nada con timestamp, pero si con nivel o clave=valor: 'auto' tambien
    # saca eso (fecha vacia, nivel y columnas dinamicas).
    if share(_auto_score) >= n * 0.4:
        return "auto"
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



