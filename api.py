"""api.py - Handler HTTP, rutas, LLM, Splunk, tail, auditoria y servidor.

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
import security
from config import *
from security import *
from parsers import *
from stores import *
# Ayudas privadas: el star-import no arrastra nombres con underscore.
from config import _norm_llm_lang
from parsers import _clean, _first, _make_search, _trunc, _ui_columns
from stores import _rb_compile, _user_state



def llm_config():
    """Config actual del LLM desde los ajustes (URL, modelo, timeout, lang)."""
    s = settings_store().get()
    return {
        "url": s.get("llm_url", "") or LLM_URL,
        "model": s.get("llm_model", "") or config.LLM_MODEL,
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
            "splunk": splunk_enabled(), "repo_url": config.REPO_URL,
            # P3.2: 'follow' = modo 'seguir archivo' disponible. Solo si
            # LOGVIEWER_TAIL_DIRS esta definido; la UI oculta el panel si no.
            "follow": bool(tail_allowlist())}


def health_payload(user="local"):
    """Estado del servicio para GET /api/health (P5.1, 2026-10-30).

    version : version del visor (config.APP_VERSION).
    backend : 'sqlite' si el dataset activo usa SqlStore, 'mem' en caso
              contrario (MemStore) o si no hay ningun dataset cargado.
    uptime  : segundos desde el arranque del proceso.
    """
    with LOCK:
        ds = dataset(user, "")
        backend = "mem"
        if ds is not None and isinstance(ds.get("store"), SqlStore):
            backend = "sqlite"
    return {"status": "ok",
            "version": APP_VERSION,
            "backend": backend,
            "uptime": round(time.time() - START_TIME, 2),
            "datasets": len(_user_state(user, SESSIONS)),
            "sqlite_threshold": config.SQLITE_THRESHOLD}



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
    m = model if model is not None else config.LLM_MODEL
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





def splunk_enabled():
    """Si hay contrasena configurada: aparece la opcion de ingesta Splunk."""
    return bool(config.SPLUNK_PASS)


def _env_flag(name, default=True):
    """Flag de entorno: 1/true/yes/on activan, 0/false/no/off desactivan.

    Sin variable definida se usa `default` (True: la opcion segura)."""
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v not in ("0", "false", "no", "off", "n")


def splunk_verify_enabled():
    """Verificacion TLS de Splunk: ON por defecto (default seguro).

    LOGVIEWER_SPLUNK_VERIFY=1 la fuerza; =0 la desactiva de forma explicita
    (solo para un Splunk local con certificado self-signed sin CA)."""
    return _env_flag("LOGVIEWER_SPLUNK_VERIFY", True)


def _splunk_ssl():
    """Contexto TLS. Verificado por defecto; CERT_NONE solo si se desactiva
    expresamente con LOGVIEWER_SPLUNK_VERIFY=0."""
    ctx = ssl.create_default_context()
    if splunk_verify_enabled():
        cafile = os.environ.get("LOGVIEWER_SPLUNK_CAFILE", "").strip()
        if cafile and os.path.isfile(cafile):
            try:
                ctx.load_verify_locations(cafile=cafile)
            except (ssl.SSLError, OSError, ValueError):
                # CA ilegible: NO se desactiva la verificacion, se sigue
                # verificando contra la CA del sistema (default seguro).
                pass
        return ctx
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _splunk_open(path, data=None, timeout=config.SPLUNK_TIMEOUT):
    """Peticion a la REST de Splunk local (basic auth). Devuelve la resp.

    Los fallos salen como ValueError con mensaje amigable (el llamador
    lo convierte en 502/404 para la UI)."""
    req = urllib.request.Request(config.SPLUNK_URL.rstrip("/") + path,
                                 data=data, method="POST" if data else "GET")
    req.add_header("Authorization", "Basic " + base64.b64encode(
        (config.SPLUNK_USER + ":" + config.SPLUNK_PASS).encode("utf-8")).decode("ascii"))
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
    count acota filas (tope config.SPLUNK_MAX_ROWS): el SPL filtra y agrega."""
    q = str(spl or "").strip()
    if not q:
        raise ValueError("el SPL esta vacio")
    if not (q.startswith("search ") or q.startswith("|")):
        q = "search " + q
    n = max(1, min(int(count), config.SPLUNK_MAX_ROWS))
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
# Carga y parseo de un archivo (devuelve un dataset, sin mutar globales)
# ---------------------------------------------------------------------------
def load_file(path, progress=None, user="local"):
    """Lee, detecta formato y encoding, parsea. Devuelve el dataset.

    Lee en streaming (no carga el archivo entero en memoria). Si el numero
    de filas supera config.SQLITE_THRESHOLD, migra a un backend SQLite (en la
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
        # triage: la hora va sin fecha; se completa con la fecha del archivo
        file_date = ""
        if fmt == "triage":
            try:
                file_date = datetime.fromtimestamp(
                    os.path.getmtime(path)).strftime("%Y-%m-%d")
            except OSError:
                file_date = ""
        total_lines = 0
        chunk = []
        lines_processed = 0

        def _flush(chunk):
            nonlocal store, lines_processed
            base_line = lines_processed
            if fmt == "w3c":
                rows, counters = parse_w3c(chunk, fields=w3c_f)
            elif fmt == "triage":
                rows, counters = parse_triage(chunk, file_date=file_date)
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
            if isinstance(store, MemStore) and store.total_rows() > config.SQLITE_THRESHOLD:
                os.makedirs(db_dir, exist_ok=True)
                store = migrate_to_sqlite(store, db_dir, name)
            pct = 30 + int(65 * min(1.0, lines_processed / config.SQLITE_THRESHOLD))
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
        "file_date": file_date,
    }


# Claves de KPIs por formato (las que el parser de ese formato rellena).
# Se usa para que MemStore y SqlStore devuelvan los mismos KPIs.
KPI_KEYS_BY_FORMAT = {
    "apache": ("ips", "paths", "codes"),
    "w3c": ("ips", "paths", "codes"),
    "json": ("ips", "levels"),
    "syslog": ("ips",),
    "generic": ("ips", "levels"),
    "piloop": ("ips", "levels"),
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
# P4.1 (2026-10-30): correlacion alertas <-> triage por firma
# ---------------------------------------------------------------------------
# alertas.jsonl (SOC) trae 'firma', 'tarea' y 'dedupe'; triage.log trae la
# decision del triaje: 'HH:MM:SS [fuente] FIRMA -> verdict conf X sev Y
# accion Z | ESCALADA tid' o '| sin tarea'. Cruzarlos por firma responde a
# que hizo el triaje con cada alerta.
TRIAGE_FP_VERDICTS = ("false_positive", "fp", "descartada", "descartado",
                      "falso_positivo")
CORRELATE_STATUSES = ("escalada", "encolada", "descartada", "sin_triage")
CORRELATE_LIMIT_MAX = 500



def triage_index(triage_rows):
    """Indexa las filas del triage por firma y por tarea.

    Las lineas RAW (no parseables) no tienen firma ni tarea y se descartan.
    Devuelve (por_firma, por_tarea)."""
    by_firma, by_tarea = {}, {}
    for r in triage_rows:
        firma = _clean(r.get("firma"))
        tarea = _clean(r.get("tarea"))
        if not firma and not tarea:
            continue
        if firma:
            by_firma.setdefault(firma, []).append(r)
        if tarea:
            by_tarea.setdefault(tarea, []).append(r)
    return by_firma, by_tarea


def correlate(alert_rows, triage_rows, firma_q="", status_q="", limit=200):
    """Correlacion alertas <-> triage por firma (y por tarea si coincide).

    Estado de cada alerta:
      escalada    - el triage la escal6a a una tarea (ESCALADA tid) o la
                    propia alerta ya trae 'tarea'
      encolada    - sin tarea y 'dedupe' == 'encolada' (pendiente en cola)
      descartada - el triage dice false_positive o dice 'sin tarea'
      sin_triage  - no hay ninguna linea de triage para esa firma
    El filtrado por firma y por estado se hace aqui, en el servidor.
    """
    limit = max(1, min(CORRELATE_LIMIT_MAX, int(limit)))
    firma_q = _clean(firma_q).lower()
    status_q = _clean(status_q).lower()
    by_firma, by_tarea = triage_index(triage_rows)
    items = []
    counts = Counter()
    matched = 0
    for a in alert_rows:
        firma = _clean(a.get("firma"))
        tarea_alerta = _clean(a.get("tarea"))
        dedupe = _clean(a.get("dedupe")).lower()
        tri = list(by_firma.get(firma, [])) if firma else []
        match_by = "firma" if tri else ""
        if not tri and tarea_alerta and by_tarea.get(tarea_alerta):
            tri = list(by_tarea[tarea_alerta])
            match_by = "tarea"
        if tri:
            matched += 1
            tarea_triage = next((_clean(t.get("tarea")) for t in tri
                                 if _clean(t.get("tarea"))), "")
            verdicts = {_clean(t.get("verdict")).lower() for t in tri}
            if tarea_alerta or tarea_triage:
                status = "escalada"
                motivo = "ESCALADA" if tarea_triage else "tarea en la alerta"
            elif any(v in TRIAGE_FP_VERDICTS for v in verdicts):
                status = "descartada"
                motivo = "false_positive"
            else:
                status = "descartada"
                motivo = "sin tarea"
        else:
            tarea_triage = ""
            if tarea_alerta:
                status, motivo = "escalada", "tarea en la alerta"
            elif dedupe == "encolada":
                status, motivo = "encolada", "dedupe encolada"
            else:
                status, motivo = "sin_triage", "sin evidencia de triaje"
        counts[status] += 1
        if status_q and status != status_q:
            continue
        if firma_q and firma_q not in firma.lower():
            continue
        if len(items) < limit:
            items.append({
                "firma": firma,
                "ts": _clean(a.get("ts")),
                "fuente": _clean(a.get("fuente")),
                "sev": _clean(a.get("sev")),
                "tarea": tarea_alerta or tarea_triage,
                "dedupe": dedupe,
                "status": status,
                "motivo": motivo,
                "match_by": match_by,
                "triage": [{
                    "ts": _clean(t.get("ts")),
                    "fuente": _clean(t.get("fuente")),
                    "verdict": _clean(t.get("verdict")),
                    "conf": t.get("conf"),
                    "sev": t.get("sev"),
                    "accion": _clean(t.get("accion")),
                    "tarea": _clean(t.get("tarea")),
                } for t in tri[:5]],
            })
    total_status = sum(counts.values())
    return {
        "alerts_total": len(alert_rows),
        "triage_total": len(triage_rows),
        "matched": matched,
        "counts": dict(counts),
        "total_status": total_status,
        "items": items,
        "limit": limit,
        "truncated": total_status > limit,
    }


# ---------------------------------------------------------------------------
# P4.2 (2026-10-30): dashboard SOC - reparto por severidad, fuente y tarea
# ---------------------------------------------------------------------------
# Usa las columnas ya mapeadas en P0.3/P0.4: 'sev', 'fuente', 'dedupe' y
# 'tarea'. Todo el agregado se hace en el SERVIDOR: la UI solo pinta lo que
# devuelve /api/soc/dashboard (no se embebe el log en el HTML).
SOC_TASK_STATUSES = ("abierta", "encolada", "descartada", "sin_dato")
SOC_LIMIT_MAX = 500
SOC_NO_TASK_TOKENS = ("sin tarea", "no crea tarea", "descartada")


def task_status(alert, tri_hits):
    """Estado de trabajo de una alerta del SOC (P4.2).

      abierta    - tiene tarea asignada (en la propia alerta o en el triaje)
      encolada   - sin tarea y dedupe == 'encolada' (pendiente en la cola)
      descartada - el triaje la cierra sin tarea (false_positive / 'sin tarea')
      sin_dato   - no hay evidencia de tarea ni de triaje
    Devuelve (estado, tarea, motivo)."""
    tarea = _clean(alert.get("tarea"))
    dedupe = _clean(alert.get("dedupe")).lower()
    tri_tarea = next((_clean(t.get("tarea")) for t in tri_hits
                      if _clean(t.get("tarea"))), "")
    if tarea or tri_tarea:
        return "abierta", tarea or tri_tarea, "ESCALADA" if tri_tarea else "tarea en la alerta"
    verdicts = {_clean(t.get("verdict")).lower() for t in tri_hits}
    if any(v in TRIAGE_FP_VERDICTS for v in verdicts):
        return "descartada", "", "false_positive en el triaje"
    if tri_hits:
        return "descartada", "", "sin tarea en el triaje"
    if dedupe == "encolada":
        return "encolada", "", "dedupe encolada"
    return "sin_dato", "", "sin evidencia de tarea"


def soc_dashboard(alert_rows, triage_rows=None, sev_q="", fuente_q="",
                  tarea_q="", limit=100):
    """Agregado del dashboard SOC (filtrado en el servidor).

    Devuelve el reparto por severidad (CRIT/ERR/WRN/INF, y la severidad
    original de OperVanta: critica/alta/media/baja), por fuente y por estado
    de tarea (abierta/encolada/descartada/sin_dato), mas una lista de filas
    filtrada por sev/fuente/tarea."""
    triage_rows = triage_rows or []
    by_firma, by_tarea = triage_index(triage_rows)
    limit = max(1, min(SOC_LIMIT_MAX, int(limit)))
    sev_q = _clean(sev_q).upper()
    fuente_q = _clean(fuente_q).lower()
    tarea_q = _clean(tarea_q).lower()

    sev_counts = Counter()
    sev_raw = Counter()
    fuente_counts = Counter()
    fuente_sev = {}
    tarea_counts = Counter()
    dedupe_counts = Counter()
    tareas_abiertas = Counter()
    verdicts = Counter()
    items = []
    for a in alert_rows:
        sev_raw_val = a.get("sev")
        sev = norm_sev(sev_raw_val if sev_raw_val not in (None, "")
                       else a.get("level"))
        fuente = _clean(a.get("fuente")) or _clean(a.get("app")) or "(sin fuente)"
        tri_hits = list(by_firma.get(_clean(a.get("firma")), []))
        if not tri_hits:
            t = _clean(a.get("tarea"))
            if t and by_tarea.get(t):
                tri_hits = list(by_tarea[t])
        status, tarea, motivo = task_status(a, tri_hits)
        # Los veredictos se cuentan UNA vez por alerta (el triaje repite la
        # misma firma cientos de veces; contarlos por linea inflaria el total)
        for v in {_clean(t.get("verdict")).lower() for t in tri_hits if _clean(t.get("verdict"))}:
            verdicts[v] += 1
        dedupe = _clean(a.get("dedupe")).lower() or "sin_dato"
        dedupe_counts[dedupe] += 1
        sev_counts[sev] += 1
        sev_raw[_clean(sev_raw_val) or sev.lower()] += 1
        fuente_counts[fuente] += 1
        fuente_sev.setdefault(fuente, Counter())[sev] += 1
        tarea_counts[status] += 1
        if tarea:
            tareas_abiertas[tarea] += 1
        if sev_q and sev != sev_q:
            continue
        if fuente_q and fuente_q not in fuente.lower():
            continue
        if tarea_q and tarea_q != status:
            continue
        if len(items) < limit:
            items.append({
                "ts": _clean(a.get("ts")),
                "fuente": fuente,
                "firma": _clean(a.get("firma")),
                "sev": sev,
                "sev_raw": _clean(sev_raw_val),
                "tarea": tarea,
                "dedupe": _clean(a.get("dedupe")),
                "status": status,
                "motivo": motivo,
                "msg": _trunc(a.get("msg") or a.get("mensaje") or "", 160),
            })
    return {
        "alerts_total": len(alert_rows),
        "triage_total": len(triage_rows),
        "sev": {k: sev_counts.get(k, 0) for k in SEV_ORDER},
        "sev_raw": dict(sev_raw),
        "fuente": [{"fuente": f, "count": c,
                    "sev": {k: fuente_sev[f].get(k, 0) for k in SEV_ORDER}}
                   for f, c in fuente_counts.most_common()],
        "tarea": {k: tarea_counts.get(k, 0) for k in SOC_TASK_STATUSES},
        "dedupe": dict(dedupe_counts),
        "tareas_abiertas": [{"tarea": t, "alertas": c}
                            for t, c in tareas_abiertas.most_common(20)],
        "verdicts": dict(verdicts),
        "items": items,
        "limit": limit,
        "truncated": sum(tarea_counts.values()) > limit,
    }



# ---------------------------------------------------------------------------
# Indice de posiciones de linea para el contexto (P1.2, bug B7)
# ---------------------------------------------------------------------------
CONTEXT_STEP = 512          # checkpoint cada 512 lineas
_CONTEXT_INDEX = {}         # (path, encoding) -> {marks, scanned, offset, eof}
_CONTEXT_INDEX_LOCK = threading.Lock()


def _line_index(path, encoding, upto_line=0):
    """Posiciones (en bytes) de cada CONTEXT_STEP-esima linea del archivo.

    marks[j] es el offset de la linea j*CONTEXT_STEP. Se construye de forma
    perezosa: solo se recorre hasta la linea que se pide (upto_line) y se
    PROLONGA cuando el tail anade lineas o cuando se pide una linea mas alta.
    El coste total del indice es O(linea maxima pedida), no O(N) por clic. Si
    el archivo se trunca o se re-sube (tamano < offset) se reinicia.
    """
    key = (path, encoding)
    with _CONTEXT_INDEX_LOCK:
        idx = _CONTEXT_INDEX.get(key)
        if idx is None:
            idx = {"marks": [0], "scanned": 0, "offset": 0, "eof": False}
            _CONTEXT_INDEX[key] = idx
        try:
            size = os.path.getsize(path)
        except OSError:
            return idx
        if idx["offset"] > size:
            idx["marks"] = [0]
            idx["scanned"] = 0
            idx["offset"] = 0
            idx["eof"] = False
        if size > idx["offset"]:
            idx["eof"] = False
        if idx["eof"] or idx["scanned"] >= upto_line:
            return idx
        # Lectura binaria por bloques: contar lineas con tell() en modo texto
        # (flush de buffer cada linea) es mas lento que split() en C. Los
        # offsets marcados son posiciones de inicio de linea, alineadas con lo
        # que veria una lectura en modo texto.
        with open(path, "rb") as f:
            f.seek(idx["offset"])
            line = idx["scanned"]
            start = idx["offset"]
            while line < upto_line:
                chunk = f.read(131072)
                if not chunk:
                    if start < size:
                        line += 1  # ultima linea sin \n final
                    idx["offset"] = start
                    idx["eof"] = True
                    break
                parts = chunk.split(b"\n")
                for part in parts[:-1]:
                    start += len(part) + 1
                    line += 1
                    if line % CONTEXT_STEP == 0:
                        idx["marks"].append(start)
                idx["offset"] = start
                start += len(parts[-1])
            idx["scanned"] = line
        return idx


def read_context_lines(path, line, n, encoding="utf-8"):
    """Fase 7B: contexto tipo grep -C alrededor de una linea (0-based).

    P1.2 (bug B7): en vez de recorrer el archivo desde la linea 0 cada vez
    (O(N) por clic), se posiciona con seek en el checkpoint mas cercano a la
    linea pedida y lee el entorno. El resultado es identico: los offsets del
    indice son tell() en modo texto, o sea alineados con las lineas que veria
    una lectura desde el principio.
    """
    lo = max(0, line - n)
    hi = line + n
    before, after, current = [], [], ""
    idx = _line_index(path, encoding, lo)
    j = lo // CONTEXT_STEP
    start = 0
    if j > 0 and j < len(idx["marks"]):
        start = j * CONTEXT_STEP
        with open(path, "r", encoding=encoding, errors="replace") as f:
            f.seek(idx["marks"][j])
            for i, l in enumerate(f, start):
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


class UploadError(Exception):
    """Error de upload detectado mientras se lee el cuerpo por bloques."""


def stream_multipart_to_disk(fp, boundary, length, dest_dir,
                             max_part_size=MAX_SIZE, max_total=TOTAL_MAX,
                             chunk_size=UPLOAD_CHUNK, existing_names=None):
    """Lee un multipart por bloques y escribe cada parte a disco (Bug B9).

    No acumula el cuerpo en RAM: copia bloques de chunk_size y mantiene un
    buffer acotado (un bloque + el delimitador) para localizar el boundary.
    Devuelve (parts, written_paths) con parts = [(nombre, ruta, bytes)].
    Lanza UploadError si se rebasa un limite o el multipart esta mal formado;
    deja escritas las partes completadas (el llamador las borra si aborta).
    """
    delim = b"--" + boundary
    header_max = 8192
    parts = []
    written_paths = []
    existing = list(existing_names or [])
    buf = b""
    remaining = length
    total = 0
    f = None
    path = None
    name = None
    written = 0
    tail = b""

    def read_more():
        nonlocal buf, remaining, total
        n = min(chunk_size, remaining)
        if n <= 0:
            return False
        data = fp.read(n)
        if not data:
            remaining = 0
            return False
        buf += data
        remaining -= len(data)
        total += len(data)
        if total > max_total:
            raise UploadError("peticion demasiado grande (max %d bytes)" % max_total)
        return True

    def write_body(data):
        nonlocal written, tail
        if not data:
            return
        if written + len(data) > max_part_size:
            raise UploadError("archivo demasiado grande (max %d bytes por archivo)"
                              % max_part_size)
        f.write(data)
        written += len(data)
        tail = (tail + data)[-2:]

    def close_part():
        nonlocal f, written, tail
        if f is None:
            return
        # El cuerpo termina con el CRLF previo al delimitador: se quita.
        if tail == b"\r\n":
            written -= 2
            f.seek(written)
            f.truncate()
        f.close()
        if name is not None:
            # El nombre devuelto es el saneado (el que esta en el disco).
            parts.append((os.path.basename(path), path, written))
        f = None
        tail = b""

    # Preamble: lo que hay antes del primer delimitador se descarta.
    while True:
        idx = buf.find(delim)
        if idx >= 0:
            buf = buf[idx + len(delim):]
            break
        if len(buf) > header_max:
            raise UploadError("multipart mal formado")
        if not read_more():
            raise UploadError("multipart sin delimitador")

    while True:
        while len(buf) < 2 and read_more():
            pass
        if buf[:2] == b"--":
            break
        if buf[:2] == b"\r\n":
            buf = buf[2:]
        while True:
            h = buf.find(b"\r\n\r\n")
            if h >= 0:
                break
            if len(buf) > header_max:
                raise UploadError("cabecera de parte demasiado grande")
            if not read_more():
                raise UploadError("multipart mal formado")
        headers = buf[:h].decode("utf-8", "replace")
        buf = buf[h + 4:]
        mname = re.search(r'filename="([^"]*)"', headers)
        name = os.path.basename(mname.group(1)) if mname else None
        written = 0
        tail = b""
        if name is not None:
            safe_name = safe_session_name(name, existing)
            existing.append(safe_name)
            path = os.path.join(dest_dir, safe_name)
            f = open(path, "wb")
            written_paths.append(path)
        else:
            f = None
            path = None
        while True:
            idx = buf.find(delim)
            if idx >= 0:
                if f is not None:
                    write_body(buf[:idx])
                buf = buf[idx + len(delim):]
                close_part()
                break
            keep = len(delim) - 1
            if len(buf) > keep:
                if f is not None:
                    write_body(buf[:len(buf) - keep])
                buf = buf[len(buf) - keep:]
            if not read_more():
                raise UploadError("multipart truncado")
    return parts, written_paths


# ---------------------------------------------------------------------------
# Tail en vivo (Fase 3): watcher por dataset sobre la copia temporal
# ---------------------------------------------------------------------------
def tail_allowlist():
    """Directorios permitidos para el modo 'seguir archivo' (P3.2).

    DESACTIVADO por defecto: si LOGVIEWER_TAIL_DIRS no esta definido (o
    esta vacio) la lista esta vacia y el modo no funciona. Se aceptan
    varios directorios separados por coma o punto y coma. Las rutas se
    normalizan y se comparan en minusculas (Windows no es sensible a
    mayusculas). La lista de produccion la decide un humano; aqui solo se
    usan las rutas de prueba del plan.
    """
    raw = (os.environ.get("LOGVIEWER_TAIL_DIRS", "") or "").strip()
    if not raw:
        return []
    dirs = []
    for part in raw.replace(";", ",").split(","):
        p = part.strip().strip('"').strip("'")
        if not p:
            continue
        d = os.path.normcase(os.path.abspath(os.path.expanduser(p)))
        if d not in dirs:
            dirs.append(d)
    return dirs


def tail_path_ok(path):
    """True si `path` cae dentro de uno de los directorios de la allowlist.

    Sin LOGVIEWER_TAIL_DIRS no hay allowlist: cualquier ruta se rechaza.
    La comparacion es de prefijo de directorio tras abspath, de modo que
    las rutas relativas y los '../' no permiten salir de la allowlist.
    """
    dirs = tail_allowlist()
    if not dirs:
        return False
    ap = os.path.normcase(os.path.abspath(os.path.expanduser(str(path))))
    for d in dirs:
        if ap == d or ap.startswith(d + os.sep):
            return True
    return False


class Watcher:
    """Watcher de un dataset: lee lineas nuevas de la copia temporal.

    - Hilo daemon que sondea el archivo cada config.TAIL_POLL segundos.
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
            time.sleep(config.TAIL_POLL)
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
    if ds["format"] == "triage":
        return parse_triage(lines, file_date=ds.get("file_date", ""))
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


def rotate_log(path, max_bytes=None):
    """Rota un log cuando supera max_bytes (Bug B11).

    Patron igual que el resto del sistema: el fichero activo pasa a
    `<path>.1` (la copia anterior se pierde) y se crea uno nuevo vacio.
    max_bytes es None usa config.LOG_MAX_BYTES (5 MB). Devuelve True si se rotó.
    No lanza excepciones: un log no puede tumbar una peticion.
    """
    if max_bytes is None:
        max_bytes = config.LOG_MAX_BYTES
    try:
        if os.path.getsize(path) <= max_bytes:
            return False
        backup = path + ".1"
        try:
            os.replace(path, backup)
        except OSError:
            return False
        # Dejar el fichero activo vacio para que exista siempre.
        try:
            with open(path, "a", encoding="utf-8"):
                pass
        except OSError:
            pass
        return True
    except OSError:
        return False

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
                size = f.tell()
            # Bug B11: audit.log no puede crecer sin limite en %TEMP%.
            if size > config.LOG_MAX_BYTES:
                rotate_log(AUDIT_FILE)
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
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(time.strftime("%H:%M:%S ") + self.address_string() + " " + fmt % args + "\n")
                size = f.tell()
            # Bug B11: requests.log no puede crecer sin limite en %TEMP%.
            if size > config.LOG_MAX_BYTES:
                rotate_log(LOG_FILE)
        except Exception:
            pass

    def send_response(self, code, message=None):
        """Respuesta sin el header 'Server' (no se revela la version de Python)
        y con las cabeceras de seguridad de P2.1 en todas las respuestas."""
        if self.request_version != "HTTP/0.9":
            self.send_response_only(code, message)
            self.send_header("Date", self.date_time_string())
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)

    def _session_cookie_header(self):
        """Set-Cookie de la sesion firmada, si la peticion no traia una valida."""
        pending = getattr(self, "_pending_session_cookie", None)
        if pending:
            self._pending_session_cookie = None
            return (SESSION_COOKIE + "=" + pending +
                    "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" +
                    str(SESSION_MAX_AGE))
        return None

    def _json(self, obj, code=200, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            cookie = self._session_cookie_header()
            if cookie:
                self.send_header("Set-Cookie", cookie)
            if extra_headers:
                for name, value in extra_headers.items():
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionError, BrokenPipeError):
            pass  # el cliente se fue: nada mas que hacer

    def _error(self, msg, code=400, extra_headers=None):
        self._json({"error": msg}, code, extra_headers)

    def _static(self, path, head_only=False):
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
        # Cache-Control en estaticos (P2.1): el HTML nunca se cachea; el
        # resto de assets, 5 minutos (se renombra con cada version).
        if fp.endswith(".html"):
            self.send_header("Content-Security-Policy", CSP_HTML)
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
        else:
            self.send_header("Cache-Control", "public, max-age=300")
        cookie = self._session_cookie_header()
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_HEAD(self):
        """P2.1: HEAD sin cuerpo, para que `curl -I` muestre las cabeceras
        de seguridad en lugar de un 501 del BaseHTTPRequestHandler."""
        if not self._cf_ok():
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._user()  # emite la cookie firmada tambien en HEAD
        u = urlparse(self.path)
        if u.path == "/":
            self._static("index.html", head_only=True)
        elif u.path.startswith("/static/"):
            self._static(u.path[len("/static/"):], head_only=True)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _user(self):
        """Identidad de la peticion (P2.1: cookie de sesion firmada con HMAC).

        1. Si la peticion trae la cookie 'lv_session' y la firma HMAC cuadra,
           esa es la identidad: el cliente no puede cambiar el usuario sin
           el secreto del proceso.
        2. Si la cookie esta manipulada, se ignora (se audita) y se vuelve a
           la atribucion del header.
        3. Si no hay cookie, el header Cf-Access-Authenticated-User-Email de
           Cloudflare Access (o el antiguo Cf-Access-Login-User) se usa solo
           como VALOR INICIAL NO CONFIABLE: sirve para dar una identidad de
           arranque y para emitir la cookie firmada en la respuesta.

        PENDIENTE (decision humana): validar el JWT de Access (Ed25519) exigir
        'cryptography' y rompe la regla de solo stdlib. Mientras no se decida,
        el header sigue siendo spoofeable en el primer contacto; la cookie
        firmada evita que ese valor se mantenga indefinidamente."""
        raw = cookie_value(self.headers.get("Cookie", ""), SESSION_COOKIE)
        if raw:
            user = verify_session_cookie(raw)
            if user:
                return user
            audit("session_cookie_invalid",
                  user="local", ip=self.client_address[0])
        header_user = (self.headers.get("Cf-Access-Authenticated-User-Email")
                       or self.headers.get("Cf-Access-Login-User") or "local")
        self._pending_session_cookie = make_session_cookie(header_user)
        return header_user

    def _rate_ok(self, path):
        """Rate limit por IP (P2.1) para /upload, /api/analyze y /api/diagnose.
        Responde 429 con Retry-After si la IP supera el limite de la ventana."""
        allowed, retry_after = check_rate_limit(self.client_address[0], path)
        if allowed:
            return True
        audit("rate_limited", user=self._user(), ip=self.client_address[0],
              path=path, retry_after=retry_after)
        self._json({"error": "demasiadas peticiones; reintenta en %d s"
                              % retry_after}, 429,
                   {"Retry-After": str(retry_after)})
        return False

    def _cf_ok(self):
        """Con LOGVIEWER_REQUIRE_CF=1 se rechaza el acceso anonimo al
        origen (peticiones sin el header de Cloudflare Access). No cierra
        la URL abierta (un atacante puede enviar el header el mismo),
        pero elimina el uso anonimo y deja cada accion rastroable por IP.
        La defensa real contra la URL abierta es cerrarla en Railway."""
        if not security.REQUIRE_CF:
            return True
        # P2.1: una cookie de sesion firmada por este proceso tambien vale
        # (es una identidad que el cliente no puede forjar).
        if verify_session_cookie(cookie_value(self.headers.get("Cookie", ""),
                                             SESSION_COOKIE)):
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
        elif u.path == "/api/health":
            # P5.1 (2026-10-30): version, backend (mem/sqlite) y uptime.
            self._json(health_payload(user))
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
        elif u.path == "/api/views":
            # P3.1: vistas de filtros guardadas (persistentes)
            self._views_list()
        elif u.path == "/api/runbooks":
            self._runbooks_list()
        elif u.path == "/api/runbooks/match":
            self._runbooks_match(q)
        elif u.path == "/api/context":
            self._context(q, user)
        elif u.path == "/api/top":
            self._top(q, user)
        elif u.path == "/api/correlate":
            # P4.1: cruce alertas.jsonl <-> triage.log por firma
            self._correlate(q, user)
        elif u.path == "/api/soc/dashboard":
            # P4.2: reparto por severidad, fuente y tarea (agregado aqui)
            self._soc_dashboard(q, user)
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
                                " acotar filas (tope %d)." % config.SPLUNK_MAX_ROWS)})
            return
        audit("splunk_sources", user=self._user(), count=len(indexes))
        # El indice principal de este entorno (documentado, no se asume):
        self._json({"indexes": indexes,
                    "primary": "botsv3",
                    "hint": ("El SPL debe empezar con 'search' y acotar"
                            " filas (el servidor limita a %d)."
                            % config.SPLUNK_MAX_ROWS)})

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
        # P1.1 (bug B3): el recorte de msg se hace AQUI, en la serializacion
        # de la lista; el store conserva el contenido completo para el drawer
        # (raw entero) y para el export.
        self._json({
            "total": total,
            "page": page,
            "size": size,
            "rows": [ui_row(r) for r in chunk],
            "format": ds["format"],
            "name": ds["name"],
            # P3.1: columnas reales del dataset (sin claves internas) para que
            # el selector de columnas sepa que puede ofrecer.
            "columns": _ui_columns(store),
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
                str(body.get("ref") or ""),
                nombre=str(body.get("nombre") or ""),
                severidad=str(body.get("severidad") or ""),
                accion=str(body.get("accion") or ""))
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
                ref=str(body.get("ref") or ""),
                nombre=str(body.get("nombre") or ""),
                severidad=str(body.get("severidad") or ""),
                accion=str(body.get("accion") or ""))
        except ValueError as e:
            self._error(str(e), 409)
            return
        audit("runbook_add", user, pattern=pattern, kind=kind,
              id=rb["id"])
        self._json(rb)

    def _views_list(self):
        """P3.1: GET /api/views: vistas de filtros guardadas (persistentes)."""
        self._json({"views": views_store().all()})

    def _views_save(self):
        """P3.1: POST /api/views: guarda la query de filtros con un nombre.

        Cuerpo: {"name": "...", "query": "q=err&level=ERR"} (la query admite
        tambien un dict). La vista se queda en views.json: sobrevive a
        reinicios y no depende del navegador."""
        user = self._user()
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._error("cuerpo JSON invalido", 400)
            return
        try:
            view = views_store().save(body.get("name"),
                                      body.get("query") or "", user)
        except ValueError as e:
            self._error(str(e), 400)
            return
        audit("view_save", user, name=view["name"])
        self._json({"ok": True, "view": view})

    def _views_delete(self):
        """P3.1: POST /api/views/delete: borra una vista por nombre."""
        user = self._user()
        body = self._read_json_body()
        name = str(body.get("name") or "").strip() if isinstance(body, dict) else ""
        if not name:
            self._error("falta el nombre de la vista", 400)
            return
        if not views_store().delete(name):
            self._error("no existe esa vista", 404)
            return
        audit("view_delete", user, name=name)
        self._json({"ok": True, "name": name})

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
        count = max(1, min(count, config.SPLUNK_MAX_ROWS))
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
        # P1.2 (bug B6): la escritura al store y la actualizacion de ds['total']
        # van en el MISIMO LOCK. Antes add_rows se ejecutaba fuera: una lectura
        # (/rows, /search, export) podia ver las filas ya insertadas con un
        # ds['total'] viejo (o al reves), dando conteos incoherentes.
        with LOCK:
            base_line = ds["total"]
            for r in rows:
                r["_search"] = _make_search(r)
                # Fase 9A: plantilla calculada en el parseo
                r["template"] = make_template(r.get("raw", ""))
                r["ts_norm"] = norm_ts(r.get("ts", ""))
                r["_line"] = base_line + r.pop("_line", 0)
            ds["store"].add_rows(rows, counters)
            ds["total"] += len(lines)
            total = ds["total"]
        self._json({
            "watching": True,
            "rows": [ui_row(r) for r in rows],
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

    def _correlate(self, q, user):
        """P4.1: GET /api/correlate -> cruce alertas <-> triage por firma.

        ?alerts=<nombre> y ?triage=<nombre> seleccionan los datasets; si no
        se indican, se auto-detectan por el nombre (uno con 'alerta' y otro
        con 'triage'). ?firma= substring, ?status= escalada|encolada|
        descartada|sin_triage, ?limit= filas (tope 500). El filtrado se hace
        en el servidor, no en el navegador."""
        def pick(explicit, keywords):
            if explicit:
                return explicit
            with LOCK:
                for s in sessions_list(user):
                    low = s["name"].lower()
                    if any(k in low for k in keywords):
                        return s["name"]
            return ""
        alerts_name = pick(_first(q.get("alerts")), ("alerta",))
        triage_name = pick(_first(q.get("triage")), ("triage",))
        if not alerts_name or not triage_name:
            self._error("hacen falta dos datasets cargados (alertas y "
                        "triage): usa ?alerts=<nombre>&triage=<nombre>", 400)
            return
        with LOCK:
            ads = dataset(user, alerts_name)
            tds = dataset(user, triage_name)
        if ads is None or tds is None:
            self._error("dataset de alertas o de triage no encontrado", 404)
            return
        try:
            limit = int(_first(q.get("limit"), "200"))
        except ValueError:
            limit = 200
        res = correlate(list(ads["store"].iter_filtered({})),
                        list(tds["store"].iter_filtered({})),
                        firma_q=_first(q.get("firma")),
                        status_q=_first(q.get("status")),
                        limit=limit)
        res["alerts_name"] = alerts_name
        res["triage_name"] = triage_name
        self._json(res)

    def _soc_dashboard(self, q, user):
        """P4.2: GET /api/soc/dashboard -> reparto SOC por severidad, fuente
        y tarea.

        ?alerts=<nombre> (o ?dataset=<nombre>) elige el dataset de alertas;
        si no se indica, se auto-detecta por el nombre ('alerta').
        ?triage=<nombre> es OPCIONAL: sin el, el estado de tarea sale solo de
        'tarea'/'dedupe'. ?sev=CRIT|ERR|WRN|INF, ?fuente=substring,
        ?tarea=abierta|encolada|descartada|sin_dato, ?limit= filas (tope 500).
        El agregado se hace en el servidor; la UI solo pinta el JSON."""
        def pick(explicit, keywords):
            if explicit:
                return explicit
            with LOCK:
                for s in sessions_list(user):
                    low = s["name"].lower()
                    if any(k in low for k in keywords):
                        return s["name"]
            return ""
        alerts_name = pick(_first(q.get("alerts")) or _first(q.get("dataset")),
                           ("alerta", "alertas"))
        if not alerts_name:
            self._error("no hay dataset de alertas cargado: usa "
                        "?alerts=<nombre>", 400)
            return
        triage_name = pick(_first(q.get("triage")), ("triage",))
        with LOCK:
            ads = dataset(user, alerts_name)
            tds = dataset(user, triage_name) if triage_name else None
        if ads is None:
            self._error("dataset de alertas no encontrado", 404)
            return
        try:
            limit = int(_first(q.get("limit"), "100"))
        except ValueError:
            limit = 100
        res = soc_dashboard(list(ads["store"].iter_filtered({})),
                           list(tds["store"].iter_filtered({})) if tds else [],
                           sev_q=_first(q.get("sev")),
                           fuente_q=_first(q.get("fuente")),
                           tarea_q=_first(q.get("tarea")),
                           limit=limit)
        res["alerts_name"] = alerts_name
        res["triage_name"] = triage_name
        self._json(res)

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
        # P0.4: la cabecera NO es fija: se descubren las columnas que realmente
        # tiene el dataset (claves de las filas + columnas extra de OperVanta).
        cols = export_columns(store)
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
            nonlocal out, w
            if out.tell() > 0:
                self._write_chunk(out.getvalue().encode("utf-8"))
                out = io.StringIO()
                # P1.2 (bug B8, detectado en el smoke de 250k filas): el
                # DictWriter guarda referencia al StringIO cerrado, asi que al
                # vaciar hay que recrearlo; si no, las filas del segundo lote
                # se escriben en un buffer que nunca se envia (el export se
                # truncaba a EXPORT_BATCH filas).
                if fmt == "csv":
                    w = csv.DictWriter(out, fieldnames=cols,
                                       extrasaction="ignore",
                                       lineterminator="\n")

        def clean(r):
            return {k: r.get(k, "") for k in cols}

        w = None
        if fmt == "csv":
            w = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore",
                               lineterminator="\n")
            w.writeheader()
        n = 0
        # P1.2 (bug B8): keyset pagination. 'last_rowid' es el rowid de la ultima
        # fila emitida; el siguiente lote empieza WHERE rowid > last_rowid.
        # Con OFFSET creciente el export era O(N^2) en un dataset SQLite grande.
        last_rowid = -1
        try:
            while True:
                batch = store.page_filtered_keyset(q, last_rowid,
                                                  self.EXPORT_BATCH)
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
                last_rowid = max(last_rowid, batch[-1].get("rowid", last_rowid))
                if out.tell() > 65536:
                    flush()
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
        if u.path in RATE_LIMITS and not self._rate_ok(u.path):
            return
        if u.path == "/upload":
            self._upload()
        elif u.path == "/api/activate":
            self._activate()
        elif u.path == "/api/remove":
            self._remove()
        elif u.path == "/api/watch":
            self._watch()
        elif u.path == "/api/open-file":
            # P3.2: modo 'seguir archivo' (off por defecto, allowlist)
            self._open_file()
        elif u.path == "/api/runbooks":
            self._runbooks_create()
        elif u.path == "/api/settings":
            self._settings_post()
        elif u.path == "/api/views":
            # P3.1: guardar/actualizar una vista de filtros
            self._views_save()
        elif u.path == "/api/views/delete":
            # P3.1: borrar una vista de filtros
            self._views_delete()
        elif u.path == "/api/analyze":
            self._analyze()
        elif u.path == "/api/diagnose":
            self._diagnose()
        elif u.path == "/api/splunk/search":
            self._splunk_search()
        else:
            self._error("ruta no conocida", 404)

    def _upload(self):
        # Tope de subidas concurrentes: sin el limite, unas pocas peticiones a
        # la vez siguen saturando el socket (ThreadingHTTPServer no limita
        # hilos). El cuerpo ya NO se carga en RAM: se copia a disco por bloques.
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
                # Extrae el boundary: el cuerpo se va copiando a disco por
                # bloques de UPLOAD_CHUNK, sin leerlo entero (Bug B9).
                m = re.search(r'boundary="?([^";]+)"?', ctype)
                if not m:
                    self._error("multipart sin boundary")
                    return

                # Guarda en el temp dir de la sesion (carpeta por usuario:
                # dos usuarios con el mismo nombre de archivo no se pisan)
                # y lanza los hilos de carga
                user = self._user()
                tmpdir = os.path.join(tempfile.gettempdir(), "logviewer",
                                      "sessions", safe_session_name(user))
                os.makedirs(tmpdir, exist_ok=True)
                try:
                    parts, written_paths = stream_multipart_to_disk(
                        self.rfile, m.group(1).encode(), length, tmpdir)
                except UploadError as e:
                    # El limite se detecta leyendo: se borra lo ya escrito.
                    for p in written_paths:
                        try:
                            os.remove(p)
                        except OSError:
                            pass
                    self._error(str(e), 413)
                    return
                if not parts:
                    self._error("no se encontro ninguna parte de archivo")
                    return
                bad = [n for n, _, _ in parts if not is_supported_name(n)]
                if bad:
                    for p in written_paths:
                        try:
                            os.remove(p)
                        except OSError:
                            pass
                    self._error("archivos no validos: " + " | ".join(
                        "%s: extension no soportada (se aceptan %s)"
                        % (n, ", ".join(SUPPORTED_EXTS)) for n in bad), 400)
                    return

                started = []
                for safe_name, dest, size in parts:
                    # Si hay watcher activo, reiniciarlo sobre la nueva copia
                    w = _user_state(user, WATCHERS).get(safe_name)
                    if w is not None:
                        w.reset(seek_end=True)
                    _user_state(user, PROGRESS)[safe_name] = {
                        "phase": "queued", "pct": 0, "message": "en cola"}
                    started.append(safe_name)
                    audit("upload", user=user, ip=self.client_address[0],
                          file=safe_name, size=size)
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
            path = ds.get("orig_path") or os.path.join(
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

    def _open_file(self):
        """P3.2: modo 'seguir archivo' (open-file por ruta, con allowlist).

        Off por defecto: sin LOGVIEWER_TAIL_DIRS la peticion da 403. La
        ruta debe estar dentro de uno de los directorios allowlist; fuera,
        403. El dataset se crea sobre el ORIGINAL (no sobre una copia
        temporal), de modo que el tail en vivo ve las lineas nuevas del
        archivo real.
        """
        body = self._read_json_body()
        if body is None:
            self._error("cuerpo JSON invalido", 400)
            return
        path = str(body.get("path", "")).strip()
        user = self._user()
        if not path:
            self._error("falta la ruta del archivo", 400)
            return
        if not tail_allowlist():
            self._error("modo 'seguir archivo' desactivado: define la "
                        "variable de entorno LOGVIEWER_TAIL_DIRS con los "
                        "directorios permitidos", 403)
            return
        if not tail_path_ok(path):
            self._error("ruta fuera de la allowlist de directorios "
                        "permitidos", 403)
            return
        ap = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(ap):
            self._error("el archivo no existe", 404)
            return
        if not is_supported_name(ap):
            self._error("extension no soportada (se aceptan %s)"
                        % ", ".join(SUPPORTED_EXTS), 400)
            return
        try:
            size = os.path.getsize(ap)
        except OSError:
            self._error("el archivo no existe", 404)
            return
        if size > MAX_SIZE:
            self._error("archivo demasiado grande para seguirlo en vivo "
                       "(limite %d MB)" % (MAX_SIZE // (1024 * 1024)), 413)
            return
        try:
            with LOCK:
                old = _user_state(user, SESSIONS).get(  # noqa: F841
                    safe_session_name(os.path.basename(ap)))
            if old is not None:
                old["store"].close()
            ds = load_file(ap, None, user=user)
        except Exception as e:
            self.log_message("open-file error: %r" % (e,))
            self._error("no se pudo leer el archivo", 500)
            return
        name = safe_session_name(os.path.basename(ap),
                                 existing=list(_user_state(user, SESSIONS)))
        ds["follow"] = True
        ds["orig_path"] = ap
        with LOCK:
            mine = _user_state(user, SESSIONS)
            mine[name] = ds
            ACTIVE[user] = name
            watchers = _user_state(user, WATCHERS)
            w = watchers.get(name)
            if w is None or w.path != ap:
                if w is not None:
                    w.stop()
                w = Watcher(name, ap, ds.get("encoding") or "utf-8")
                watchers[name] = w
            # El archivo ya esta cargado entero: el tail solo recoge lo nuevo
            w.reset(seek_end=True)
            w.enabled = True
            w.start()
            sl = sessions_list(user)
        audit("follow_open", user=user, ip=self.client_address[0],
              file=name, format=ds["format"], total=ds["total"])
        self._json({"name": name, "total": ds["total"],
                    "format": ds["format"], "watching": True,
                    "sessions": sl, "active": ACTIVE.get(user, "")})

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


class LogViewerServer(ThreadingHTTPServer):
    """ThreadingHTTPServer con pool de hilos y conexiones acotado (P2.1).

    ThreadingHTTPServer abre un hilo por conexion sin limite: unas decenas de
    peticiones simultaneas saturan el host. Aqui un semaphore de MAX_CONNECTIONS
    (por defecto 32) corta las conexiones que exceden el pool con un 503 y
    Connection: close, asi que el servidor responde siempre y no acumula hilos.
    """
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_connections = MAX_CONNECTIONS
        self._pool = threading.BoundedSemaphore(self.max_connections)
        self.active_connections = 0
        self.rejected_connections = 0

    def process_request(self, request, client_address):
        if not self._pool.acquire(timeout=5):
            self.rejected_connections += 1
            self._reject_overload(request)
            return
        self.active_connections += 1
        t = threading.Thread(target=self._handle_and_release,
                            args=(request, client_address), daemon=True)
        t.start()

    def _handle_and_release(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            self.active_connections -= 1
            self._pool.release()

    def _reject_overload(self, request):
        body = json.dumps({"error": "demasiadas conexiones concurrentes",
                           "retry_after": 5}).encode("utf-8")
        head = ("HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                "Retry-After: 5\r\n"
                "Connection: close\r\n"
                "Content-Length: " + str(len(body)) + "\r\n\r\n")
        try:
            request.sendall(head.encode("ascii") + body)
        except OSError:
            pass
        self.shutdown_request(request)


def startup_dirs(tmpdir=None):
    """Rutas de trabajo: (tmpdir, sessions/, sqlite/)."""
    tmpdir = tmpdir or os.path.join(tempfile.gettempdir(), "logviewer")
    return (tmpdir, os.path.join(tmpdir, "sessions"),
            os.path.join(tmpdir, "sqlite"))


def startup_cleanup(persist, tmpdir=None):
    """P4.1 (bug B14): limpia sessions/ y sqlite/ al arrancar.

    Con persist=True NO borra nada: los datasets y las bases SQLite de la
    sesion anterior sobreviven al reinicio. Devuelve (tmpdir, sessions,
    sqlite) para que el llamador pueda reconstruir las sesiones."""
    tmpdir, sessions_dir, sqlite_dir = startup_dirs(tmpdir)
    for d in (sessions_dir, sqlite_dir):
        if os.path.isdir(d) and not persist:
            shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
    return tmpdir, sessions_dir, sqlite_dir


def restore_sessions_from_disk(sessions_dir):
    """P4.1 (--persist): re-carga los archivos de sesion que quedaron en disco.

    Las sesiones viven en memoria; sin esta reconstruccion, --persist solo
    conservaria los archivos sueltos. Devuelve el numero de datasets recargados."""
    if not os.path.isdir(sessions_dir):
        return 0
    n = 0
    for user_dir in sorted(os.listdir(sessions_dir)):
        udir = os.path.join(sessions_dir, user_dir)
        if not os.path.isdir(udir):
            continue
        for fname in sorted(os.listdir(udir)):
            path = os.path.join(udir, fname)
            if not os.path.isfile(path) or not is_supported_name(fname):
                continue
            _load_worker(fname, path, user=user_dir)
            n += 1
    return n

