"""security.py - cookie de sesion firmada, cabeceras, CSRF y rate limit.

P5.1 (2026-10-30): separado de server.py. Solo stdlib.
S1 (2026-10-30): se autoriza 'cryptography' para validar el JWT de
Cloudflare Access (Ed25519). El import va en try/except: si la libreria no
esta, el visor arranca igual y se mantiene el comportamiento anterior.
"""
import argparse
import base64
import bz2
import fnmatch
import hashlib
import binascii
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
# style-src lleva 'unsafe-inline': app.js genera barras (spark/KPI/progreso)
# con style="height:...px"/style="width:...%" dinamicos via innerHTML, y sin
# unsafe-inline el navegador los bloquea (CSP) y no se ven. script-src sigue
# estricto 'self' (sin inline JS), que es lo que importa para seguridad.
CSP_HTML = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'")

# Con LOGVIEWER_REQUIRE_CF=1 se rechaza el acceso directo al origen
# (peticiones sin el header de Cloudflare Access). Mitiga el caso "el
# origen Railway es alcanzable sin pasar por Access"; no valida el JWT
# (eso lo hace Access en el borde).
REQUIRE_CF = os.environ.get("LOGVIEWER_REQUIRE_CF") == "1"

# ---------------------------------------------------------------------------
# S1 (2026-10-30): validacion REAL del JWT de Cloudflare Access (Ed25519).
# ---------------------------------------------------------------------------
# Cloudflare Access firma la cabecera Cf-Access-Jwt-Assertion con Ed25519 y
# publica las claves publicas en https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
# (JSON: {"keys": [{"kid": "...", "cert": "<hex 32 bytes>"}], "max_age": 86400}).
# Con esto la identidad deja de depender del header spoofeable
# Cf-Access-Authenticated-User-Email.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAS_CRYPTOGRAPHY = True
except ImportError:      # la libreria no esta: se mantiene el fallback HMAC
    Ed25519PublicKey = None
    HAS_CRYPTOGRAPHY = False

# CF_ACCESS_TEAM puede venir como "sammideblas" o "sammideblas.cloudflareaccess.com".
CF_ACCESS_TEAM = os.environ.get("CF_ACCESS_TEAM", "").strip()
CF_ACCESS_AUD = os.environ.get("CF_ACCESS_AUD", "").strip()
CF_JWT_HEADER = "Cf-Access-Jwt-Assertion"
CF_ACCESS_TIMEOUT = max(1, int(os.environ.get("CF_ACCESS_TIMEOUT", "10")))
CF_CERTS_TTL = max(60, int(os.environ.get("CF_ACCESS_CERTS_TTL", "3600")))

# Cache de claves Ed25519: kid -> Ed25519PublicKey. Se re-fetch si falta el kid.
CF_CERTS = {}
CF_CERTS_FETCHED_AT = 0.0
CF_CERTS_LOCK = threading.Lock()
CF_ACCESS_WARNED = False


def cf_access_enabled():
    """True si la validacion del JWT de Access esta operativa (team + AUD + lib)."""
    return bool(HAS_CRYPTOGRAPHY and CF_ACCESS_TEAM and CF_ACCESS_AUD)


def cf_certs_url(team=None):
    """URL publica de los certs del equipo de Access. '' si no hay team."""
    team = (team if team is not None else CF_ACCESS_TEAM).strip()
    if not team:
        return ""
    if not team.endswith(".cloudflareaccess.com"):
        team = team + ".cloudflareaccess.com"
    if not team.startswith("http://") and not team.startswith("https://"):
        team = "https://" + team
    return team + "/cdn-cgi/access/certs"


def _fetch_cf_certs(url=None):
    """Descarga los certs Ed25519 del equipo. Devuelve {} si la red falla.
    La red esta cerrada en este entorno: la funcion debe ser tolerante."""
    url = url or cf_certs_url()
    if not url or not HAS_CRYPTOGRAPHY:
        return {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "logviewer/1.0"})
        with urllib.request.urlopen(req, timeout=CF_ACCESS_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError, TimeoutError):
        return {}
    out = {}
    for item in (data.get("keys") or []):
        if not isinstance(item, dict):
            continue
        kid = str(item.get("kid") or "").strip()
        cert = str(item.get("cert") or "").strip()
        if not kid or not cert:
            continue
        try:
            out[kid] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cert))
        except (ValueError, TypeError, OSError):
            continue
    return out


def load_cf_certs(force=False, certs=None, url=None):
    """Devuelve el cache de claves kid -> Ed25519PublicKey.

    `certs` permite inyectar claves (los tests) sin tocar la red. Si el cache
    esta vacío o caducado, descarga los certs del equipo."""
    global CF_CERTS, CF_CERTS_FETCHED_AT
    if certs is not None:
        with CF_CERTS_LOCK:
            CF_CERTS = dict(certs)
            CF_CERTS_FETCHED_AT = time.time()
            return CF_CERTS
    with CF_CERTS_LOCK:
        if CF_CERTS and not force and (time.time() - CF_CERTS_FETCHED_AT) < CF_CERTS_TTL:
            return CF_CERTS
    fetched = _fetch_cf_certs(url)
    with CF_CERTS_LOCK:
        if fetched:
            CF_CERTS.update(fetched)
            CF_CERTS_FETCHED_AT = time.time()
        return CF_CERTS


def _b64url_decode(part):
    """Decodifica un segmento base64url de un JWT (sin relleno)."""
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def verify_cf_access_jwt(token, now=None):
    """Verifica el JWT de Cloudflare Access: firma Ed25519, aud y exp.

    Devuelve {"ok": bool, "user": str|None, "reason": str}. Nunca lanza: un
    JWT raro (mal formado, kid desconocido, red caída) es un rechazo."""
    if not HAS_CRYPTOGRAPHY:
        return {"ok": False, "user": None,
                "reason": "cryptography no instalado: no se puede validar el JWT"}
    if not CF_ACCESS_TEAM or not CF_ACCESS_AUD:
        return {"ok": False, "user": None,
                "reason": "CF_ACCESS_TEAM o CF_ACCESS_AUD no definidos"}
    token = (token or "").strip()
    if not token:
        return {"ok": False, "user": None, "reason": "sin cabecera Cf-Access-Jwt-Assertion"}
    parts = token.split(".")
    if len(parts) != 3:
        return {"ok": False, "user": None, "reason": "JWT sin 3 partes"}
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        signature = _b64url_decode(parts[2])
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return {"ok": False, "user": None, "reason": "JWT mal formado"}
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return {"ok": False, "user": None, "reason": "JWT mal formado"}
    kid = str(header.get("kid") or "").strip()
    certs = load_cf_certs()
    key = certs.get(kid)
    if key is None:
        # el kid puede ser de una rotacion de claves: re-fetch una vez
        certs = load_cf_certs(force=True)
        key = certs.get(kid)
    if key is None:
        return {"ok": False, "user": None,
                "reason": "kid %s no esta entre los certs del equipo" % (kid or "(sin kid)")}
    try:
        key.verify(signature, (parts[0] + "." + parts[1]).encode("utf-8"))
    except Exception:
        return {"ok": False, "user": None, "reason": "firma Ed25519 invalida"}
    aud = claims.get("aud")
    aud_list = aud if isinstance(aud, list) else [aud]
    if CF_ACCESS_AUD not in aud_list:
        return {"ok": False, "user": None,
                "reason": "aud no coincide con CF_ACCESS_AUD"}
    try:
        exp = int(claims.get("exp", 0))
    except (TypeError, ValueError):
        return {"ok": False, "user": None, "reason": "claim exp invalido"}
    if exp <= (time.time() if now is None else now):
        return {"ok": False, "user": None, "reason": "JWT caducado (exp)"}
    email = str(claims.get("email") or "").strip()
    if not email:
        return {"ok": False, "user": None, "reason": "JWT sin claim email"}
    return {"ok": True, "user": email, "reason": "ok"}


def cf_access_status():
    """Estado de la validacion de Access, para el arranque y la auditoria."""
    if HAS_CRYPTOGRAPHY and CF_ACCESS_TEAM and CF_ACCESS_AUD:
        msg = "JWT de Access validado (team %s, %d claves en cache)" % (
            cf_certs_url(), len(CF_CERTS))
    elif HAS_CRYPTOGRAPHY and (CF_ACCESS_TEAM or CF_ACCESS_AUD):
        msg = "cryptography instalado pero faltan CF_ACCESS_TEAM/CF_ACCESS_AUD: " \
             "se usa la cookie HMAC y el header NO es confiable"
    elif CF_ACCESS_TEAM or CF_ACCESS_AUD:
        msg = "CF_ACCESS_TEAM/CF_ACCESS_AUD definidos pero 'cryptography' no " \
             "instalado: no se puede validar el JWT"
    else:
        msg = "sin Cloudflare Access: cookie HMAC y header como valor no confiable"
    return {"enabled": cf_access_enabled(), "team": CF_ACCESS_TEAM,
            "aud": CF_ACCESS_AUD, "cryptography": HAS_CRYPTOGRAPHY,
            "certs": len(CF_CERTS), "message": msg}


# ---------------------------------------------------------------------------
# P2.1 (2026-10-30): identidad por cookie firmada con HMAC, rate limit,
# cabeceras de seguridad y tope de hilos. Todo con stdlib (hmac + hashlib).
# ---------------------------------------------------------------------------
# PENDIENTE, decision humana: validar el JWT de Cloudflare Access (Ed25519)
# exigiría la librería 'cryptography', que rompe la regla de solo stdlib.
# Mientras no se decida, la identidad se firma aqui con HMAC y el header
# Cf-Access-Authenticated-User-Email se usa solo como valor inicial NO confiable.
SESSION_COOKIE = "lv_session"

# Residual de P2.1 (2026-10-30): antes el secreto se generaba con
# secrets.token_hex() en cada arranque, y con --persist las cookies firmadas
# de la sesion anterior quedaban invalidadas al reiniciar. Ahora el secreto
# se persiste en %TEMP%\logviewer\session_secret (0600) para que la
# identidad de la cookie sobreviva entre arranques.
SESSION_SECRET_DIR = os.path.join(tempfile.gettempdir(), "logviewer")
SESSION_SECRET_PATH = os.path.join(SESSION_SECRET_DIR, "session_secret")
SESSION_MAX_AGE = 8 * 3600  # 8 h; la sesion es efimera (se limpia al arrancar)


def _read_persisted_secret(path):
    """Lee el secreto persistido. '' si no existe o tiene un formato dudoso."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
    except OSError:
        return ""
    if len(value) >= 32 and re.fullmatch(r"[0-9a-fA-F]+", value):
        return value
    return ""


def _write_persisted_secret(path, secret):
    """Escribe el secreto con permisos 0600. True si se pudo escribir."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(secret + "\n")
        try:
            os.chmod(path, 0o600)   # Windows: refuerza el modo (no es estricto)
        except OSError:
            pass
        return True
    except OSError:
        return False


def load_session_secret(path=None):
    """Resuelve el secreto de sesion y de donde viene.

    Orden: 1) LOGVIEWER_SESSION_SECRET (manda), 2) el fichero persistido,
    3) se genera uno nuevo y se persiste. Devuelve (secreto, origen)."""
    path = path or SESSION_SECRET_PATH
    env = os.environ.get("LOGVIEWER_SESSION_SECRET")
    if env:
        return env, "env LOGVIEWER_SESSION_SECRET"
    persisted = _read_persisted_secret(path)
    if persisted:
        return persisted, "persistido en %s" % path
    secret = secrets.token_hex(32)
    if _write_persisted_secret(path, secret):
        return secret, "generado y persistido en %s" % path
    return secret, "generado al arrancar (no se pudo persistir)"


SESSION_SECRET, SESSION_SECRET_SOURCE = load_session_secret()

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


