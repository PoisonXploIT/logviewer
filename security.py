"""security.py - cookie de sesion firmada, cabeceras, CSRF y rate limit.

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

# Token anti-CSRF por proceso: lo sirve GET /api/csrf y lo exige en todo
# POST (header X-CSRF-Token). No es un secreto: demuestra que la peticion
# sale de una pagina que este proceso sirvio (un sitio ajeno no puede leerlo
# por CORS ni anadir el header sin preflight).
CSRF_TOKEN = secrets.token_hex(16)

# Tope de subidas concurrentes. Desde la correccion de B9 el cuerpo se lee en
# bloques y se escribe a disco, asi que cada subida usa unos pocos MB de RAM;
# el semaphore sigue acotando el numero de lecturas simultaneas del socket.
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

# ---------------------------------------------------------------------------
# P2.1 (2026-10-30): identidad por cookie firmada con HMAC, rate limit,
# cabeceras de seguridad y tope de hilos. Todo con stdlib (hmac + hashlib).
# ---------------------------------------------------------------------------
# PENDIENTE, decision humana: validar el JWT de Cloudflare Access (Ed25519)
# exigiría la librería 'cryptography', que rompe la regla de solo stdlib.
# Mientras no se decida, la identidad se firma aqui con HMAC y el header
# Cf-Access-Authenticated-User-Email se usa solo como valor inicial NO confiable.
SESSION_COOKIE = "lv_session"
SESSION_SECRET = os.environ.get("LOGVIEWER_SESSION_SECRET") or secrets.token_hex(32)
SESSION_MAX_AGE = 8 * 3600  # 8 h; la sesion es efimera (se limpia al arrancar)

# Cabeceras de seguridad que se envian en TODA respuesta.
SECURITY_HEADERS = (
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
)

# Rate limit simple por IP (ventana deslizante con deque).
RATE_WINDOW = 60.0                       # segundos
RATE_LIMITS = {                          # peticiones por ventana y endpoint
    "/upload": 30,
    "/api/analyze": 20,
    "/api/diagnose": 20,
}
RATE_BUCKETS = {}                        # (path, ip) -> deque de timestamps
RATE_LOCK = threading.Lock()

# Tope de hilos y de conexiones concurrentes del servidor.
MAX_THREADS = max(1, int(os.environ.get("LOGVIEWER_MAX_THREADS", "32")))
MAX_CONNECTIONS = max(1, int(os.environ.get("LOGVIEWER_MAX_CONNECTIONS",
                                           str(MAX_THREADS))))


def _session_sign(payload):
    """Firma un payload de cookie con HMAC-SHA256 y el secreto de arranque."""
    return hmac.new(SESSION_SECRET.encode("utf-8"),
                    payload.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_cookie(user):
    """Devuelve el valor de la cookie de sesion firmada para un usuario."""
    payload = base64.urlsafe_b64encode(json.dumps(
        {"u": user, "exp": int(time.time()) + SESSION_MAX_AGE}
    ).encode("utf-8")).decode("ascii")
    return "%s.%s" % (payload, _session_sign(payload))


def verify_session_cookie(raw):
    """Devuelve el usuario si la cookie esta bien firmada y no caducada.

    None en cualquier otro caso (firma manipulada, payload corrupto,
    caducada). La comparacion es en tiempo constante (hmac.compare_digest)."""
    if not raw or "." not in raw:
        return None
    payload, sig = raw.rsplit(".", 1)
    if not payload or not sig:
        return None
    if not hmac.compare_digest(sig, _session_sign(payload)):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii"))
                          .decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if int(data.get("exp", 0)) < time.time():
        return None
    user = str(data.get("u") or "").strip()
    return user or None


def cookie_value(header, name=SESSION_COOKIE):
    """Extrae el valor de una cookie del header Cookie ("a=1; b=2")."""
    for part in (header or "").split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return None


def check_rate_limit(ip, path):
    """True si la IP puede hacer una peticion mas en ese endpoint.

    Ventana deslizante de RATE_WINDOW segundos con un deque por (path, ip).
    Devuelve (permitido, retry_after)."""
    limit = RATE_LIMITS.get(path)
    if not limit:
        return True, 0
    now = time.time()
    key = (path, ip or "local")
    with RATE_LOCK:
        bucket = RATE_BUCKETS.setdefault(key, deque(maxlen=limit))
        while bucket and bucket[0] < now - RATE_WINDOW:
            bucket.popleft()
        if len(bucket) >= limit:
            retry = max(1, int(RATE_WINDOW - (now - bucket[0])) + 1)
            return False, retry
        bucket.append(now)
        return True, 0


def reset_rate_limits():
    """Vacía las buckets (lo usan los tests y el reinicio del proceso)."""
    with RATE_LOCK:
        RATE_BUCKETS.clear()


