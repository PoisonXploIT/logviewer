"""stores.py - estado global y backend de datasets (MemStore/SqlStore).

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
from parsers import *
from config import _norm_llm_lang
from parsers import _clean, _row_match

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



# ---------------------------------------------------------------------------
# Fase 10A: runbooks (patron -> explicacion/causa/solucion/referencia)
#
# BD persistente en %TEMP\logviewer\runbooks.db: NO se borra al arrancar
# el servidor ni al quitar un dataset (a diferencia de los datasets).
class RunbookStore:
    """BD local de runbooks (patrones sobre msg y su explicacion).

    P4.2 (2026-10-30): cada runbook lleva ADEMAS nombre, severidad sugerida
    (CRIT/ERR/WRN/INF) y accion recomendada. Las BD creadas antes de P4.2 se
    migran con ALTER TABLE (no se pierden los runbooks ya existentes).
    """

    FIELDS = ("id", "pattern", "nombre", "kind", "severidad", "explicacion",
              "causa", "solucion", "accion", "ref", "created_at")
    # Columnas anadidas en P4.2: se agregan a las BD antiguas si faltan
    EXTRA_COLS = ("nombre", "severidad", "accion")

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
        self._migrate()

    def _migrate(self):
        """Anade nombre/severidad/accion a una BD previa a P4.2."""
        have = {r[1] for r in self.conn.execute(
            "PRAGMA table_info(runbooks)").fetchall()}
        for col in self.EXTRA_COLS:
            if col not in have:
                self.conn.execute(
                    "ALTER TABLE runbooks ADD COLUMN %s TEXT DEFAULT ''"
                    % col)
        self.conn.commit()

    def add(self, pattern, kind="regex", explicacion="", causa="",
            solucion="", ref="", nombre="", severidad="", accion=""):
        """Crea un runbook. Devuelve la fila; lanza ValueError si el
        patron ya existe (indice unico)."""
        if kind not in ("regex", "glob"):
            kind = "regex"
        try:
            with self.lock:
                cur = self.conn.execute(
                    "INSERT INTO runbooks (pattern, kind, explicacion,"
                    " causa, solucion, ref, created_at, nombre, severidad,"
                    " accion) VALUES (?,?,?,?,?,?,?, ?,?,?)",
                    [pattern, kind, explicacion, causa, solucion, ref,
                     time.strftime("%Y-%m-%d %H:%M:%S"),
                     _clean(nombre), norm_sev(severidad), _clean(accion)])
                self.conn.commit()
                rowid = cur.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError("el patron ya existe")
        return self.get(rowid)

    def get(self, rowid):
        with self.lock:
            r = self.conn.execute(
                "SELECT id, pattern, nombre, kind, severidad, explicacion,"
                " causa, solucion, accion, ref, created_at"
                " FROM runbooks WHERE id = ?",
                [rowid]).fetchone()
        return dict(zip(self.FIELDS, r)) if r else None

    def update(self, rowid, pattern, kind, explicacion, causa,
               solucion, ref, nombre=None, severidad=None, accion=None):
        """Edit los campos de un runbook. Devuelve la fila actualizada;
        None si no existe; ValueError si el patron choca con otro.
        nombre/severidad/accion: None = no tocar el valor guardado."""
        if kind not in ("regex", "glob"):
            kind = "regex"
        cur_rb = self.get(rowid)
        if cur_rb is None:
            return None
        if nombre is None:
            nombre = cur_rb.get("nombre") or ""
        if severidad is None:
            severidad = cur_rb.get("severidad") or ""
        if accion is None:
            accion = cur_rb.get("accion") or ""
        try:
            with self.lock:
                cur = self.conn.execute(
                    "UPDATE runbooks SET pattern=?, kind=?, explicacion=?,"
                    " causa=?, solucion=?, ref=?, nombre=?, severidad=?,"
                    " accion=? WHERE id=?",
                    [pattern, kind, explicacion, causa, solucion, ref,
                     _clean(nombre), norm_sev(severidad), _clean(accion),
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
                "SELECT id, pattern, nombre, kind, severidad, explicacion,"
                " causa, solucion, accion, ref, created_at"
                " FROM runbooks ORDER BY id").fetchall()
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
            "llm_model": config.LLM_MODEL,
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



# ---------------------------------------------------------------------------
# P3.1: vistas guardadas de filtros (persistentes, no solo localStorage)
# ---------------------------------------------------------------------------
# Claves que una vista puede guardar: son exactamente las que se reflejan en
# la URL de la UI. Una vista NO guarda el log, solo los filtros.
VIEW_KEYS = ("q", "level", "code", "ip", "path", "dt", "tpl",
             "dt_from", "dt_to", "name", "page", "cols")


def normalize_view_query(query):
    """Normaliza la query de una vista a un dict con solo claves conocidas.

    Acepta una query string ('q=err&level=ERR') o el dict de listas de
    parse_qs. Descarta lo vacio y cualquier parametro que no sea un filtro:
    una vista no puede arrastrar rutas ni parametros raros.
    """
    if query is None:
        return {}
    if isinstance(query, str):
        q = parse_qs(query)
    elif isinstance(query, dict):
        q = query
    else:
        return {}
    out = {}
    for k in VIEW_KEYS:
        v = q.get(k)
        if isinstance(v, (list, tuple)):
            v = v[0] if v else ""
        v = str(v if v is not None else "").strip()
        if v:
            out[k] = v
    return out


class SavedViewsStore:
    """Vistas de filtros guardadas en %TEMP%\\logviewer\\views.json.

    Sobreviven a reinicios del servidor y cambian de navegador: la vista es
    recuperable pegando su URL (los filtros van en la query string). No se
    guarda el contenido del log, solo la query de filtros.
    """

    MAX_VIEWS = 50
    MAX_NAME = 80

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {}
        views = d.get("views") if isinstance(d, dict) else None
        if not isinstance(views, list):
            views = []
        return [v for v in views
                if isinstance(v, dict) and str(v.get("name") or "")]

    def _flush(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"views": self.data}, f, ensure_ascii=False, indent=2)
        except OSError:
            pass  # si no se puede escribir, la vista sigue en memoria

    def all(self):
        with self.lock:
            return [dict(v) for v in self.data]

    def get(self, name):
        with self.lock:
            for v in self.data:
                if v["name"] == name:
                    return dict(v)
        return None

    def save(self, name, query, user="local"):
        """Guarda (o actualiza) una vista por nombre. Devuelve la entrada."""
        name = str(name or "").strip()
        if not name:
            raise ValueError("el nombre de la vista esta vacio")
        if len(name) > self.MAX_NAME:
            raise ValueError("nombre demasiado largo (max %d)" % self.MAX_NAME)
        q = normalize_view_query(query)
        with self.lock:
            idx = None
            for i, v in enumerate(self.data):
                if v["name"] == name:
                    idx = i
                    break
            entry = {"name": name, "query": q, "user": user or "local",
                     "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
            if idx is None:
                if len(self.data) >= self.MAX_VIEWS:
                    raise ValueError(
                        "demasiadas vistas guardadas (max %d)" % self.MAX_VIEWS)
                self.data.append(entry)
            else:
                self.data[idx] = entry
            self._flush()
            return dict(entry)

    def delete(self, name):
        with self.lock:
            before = len(self.data)
            self.data = [v for v in self.data if v["name"] != name]
            if len(self.data) == before:
                return False
            self._flush()
            return True


VIEWS = None  # singleton perezoso


def views_store():
    global VIEWS
    if VIEWS is None:
        d = os.path.join(tempfile.gettempdir(), "logviewer")
        os.makedirs(d, exist_ok=True)
        VIEWS = SavedViewsStore(os.path.join(d, "views.json"))
    return VIEWS



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
    m = (model if model is not None else config.LLM_MODEL) or "local"
    l = _norm_llm_lang(lang)
    h = hashlib.sha256()
    h.update(str(m).encode("utf-8"))
    h.update(b"\x00")
    h.update(l.encode("utf-8"))
    h.update(b"\x00")
    h.update(str(line).encode("utf-8"))
    return h.hexdigest()



# ---------------------------------------------------------------------------
# Backend de datasets (Fase 4): memoria o SQLite segun el tamano
# ---------------------------------------------------------------------------
def _line_buckets(rows, gran="min", line_of=None):
    """U3.2 (2026-10-30): bucketas por numero de linea cuando no hay fecha.

    Un volcado de stack traces (orquestador.log) no tiene ni un timestamp: la
    histograma temporal queda vacia y la UI muestra 'Sin datos con fecha'. Para
    que el panel siga siendo util, se agrupa por bloques de lineas.
    """
    step = 100 if gran == "min" else 500
    out = Counter()
    for i, r in enumerate(rows):
        line = r.get("_line") if line_of is None else line_of(r, i)
        try:
            line = int(line)
        except (TypeError, ValueError):
            line = i
        if line < 0:
            line = i
        b = (line // step) * step
        out["linea %05d-%05d" % (b + 1, b + step)] += 1
    return out


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

    def columns(self):
        """P0.4: columnas realmente presentes en el dataset (union de claves).

        Sin tocar la cabecera: las filas de un mismo dataset pueden traer claves
        distintas (piloop trae 'comp', triage trae 'sev'). Se devuelven en el
        orden de primera aparicion, sin duplicados y sin claves internas."""
        seen = []
        known = set()
        for r in self.rows:
            for k in r:
                if k not in known and k not in EXPORT_SKIP_KEYS:
                    known.add(k)
                    seen.append(k)
        return seen

    def nonempty_columns(self):
        """U2.1 (2026-10-30): claves con al menos un valor no vacio.

        Sirve para no ofrecer columnas sin datos (el parser auto arranca con
        method/path/code/bytes vacios). Sin claves internas."""
        out = set()
        for r in self.rows:
            for k, v in r.items():
                if v and k not in EXPORT_SKIP_KEYS:
                    out.add(k)
        return out

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

    def page_filtered_keyset(self, q, after_rowid, size):
        """P1.2 (bug B8): paginacion por clave, no por OFFSET.

        En MemStore el rowid es la posicion en la lista (_idx), de modo que
        'despues de after_rowid' es un recorrido que empieza donde termino el
        lote anterior: cada fila se mira una sola vez en todo el export, O(N)
        en total (con OFFSET era O(N^2)). El orden es el mismo que
        page_filtered, asi que el resultado es identico."""
        plan = filter_plan(q)
        rows = self.rows
        out = []
        i = max(0, after_rowid + 1)
        n = len(rows)
        while i < n and len(out) < size:
            r = rows[i]
            if _row_match(r, plan):
                r = dict(r)
                r.pop("_search", None)
                r["rowid"] = r.get("_idx", i)
                out.append(r)
            i += 1
        return out

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
        """Fase 9C: distribucion temporal de las filas filtradas.

        U3.2 (2026-10-30): si NINGUNA fila tiene timestamp se bucketea por
        numero de linea (volcados de stack traces) en vez de devolver vacio.
        Si al menos una fila tiene fecha, el comportamiento es el de siempre.
        """
        n = 16 if gran == "min" else 13
        out = Counter()
        rows = list(apply_filters(self.rows, q))
        for r in rows:
            t = (r.get("ts_norm") or "")[:n]
            if t:
                out[t] += 1
        if not out:
            out = _line_buckets(rows, gran)
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
               "template",
               # P0.3: columnas de los JSON Lines de OperVanta
               "fuente", "firma", "tenant", "tarea", "dedupe",
               "evidencia", "riesgo", "url",
               # P0.4: columnas del triage SOC y del formato piloop
               "verdict", "conf", "sev", "accion", "comp",
               "src", "dst")

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
        # Migracion: las BD creadas con una version anterior no tienen las
        # columnas nuevas (fuente, firma, tenant...). ALTER TABLE las anade.
        existing = {r[1] for r in self.conn.execute("PRAGMA table_info(rows)")}
        for c in self.COLUMNS:
            if c not in existing:
                self.conn.execute("ALTER TABLE rows ADD COLUMN %s TEXT" % c)
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
        """Construye la clausula WHERE a partir del plan de filtrado.

        P1.1 (bug B5): el plan lo genera filter_plan(), la misma capa que usa
        MemStore, y cada condicion se traduce a SQL con la semantica canonica
        de _field_clause. El texto libre (q) se resuelve por subcadena, no por
        FTS5: MATCH tokeniza y no coincide con subcadenas, lo que daba filas
        distintas al mismo 'q' en MemStore y en SQLite."""
        plan = filter_plan(q)
        clauses = []
        params = []
        for col, terms, exact in (
                ("level", plan["level"], True), ("code", plan["code"], True),
                ("ip", plan["ip"], False), ("path", plan["path"], False),
                ("search", plan["q"], False)):
            if terms:
                c, p = self._field_clause(col, terms, exact)
                if c:
                    clauses.append(c)
                    params.extend(p)
        if plan["tpl"]:
            clauses.append("template = ?")
            params.append(plan["tpl"])
        if plan["dt"]:
            clauses.append("instr(ts, ?) > 0")
            params.append(plan["dt"])
        if plan["dt_from"]:
            clauses.append("ts_norm >= ?")
            params.append(plan["dt_from"])
        if plan["dt_to"]:
            clauses.append("ts_norm <= ?")
            params.append(plan["dt_to"])
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

    def page_filtered_keyset(self, q, after_rowid, size):
        """P1.2 (bug B8): paginacion por clave (keyset) en SQLite.

        page_filtered usa LIMIT/OFFSET: para el lote k, SQLite recorre y
        descarta 'start' filas, de modo que un export de N filas en lotes de
        B cuesta O(N^2/B). Con 'rowid > ultimo_rowid' el lote siguiente arranca
        donde termino el anterior: O(N) en total (el rowid es la PK, hay indice).
        El orden (rowid ascendente) es el mismo que page_filtered, por eso el
        resultado es identico.
        """
        where, params = self._where(q)
        where = (where + " AND rowid > ?") if where else "WHERE rowid > ?"
        params = params + [after_rowid]
        with self.lock:
            cur = self.conn.execute(
                "SELECT rowid, %s FROM rows %s ORDER BY rowid LIMIT ?" % (
                    ", ".join(self.COLUMNS), where),
                params + [size])
            cols = self.COLUMNS
            out = []
            for row in cur.fetchall():
                d = dict(zip(cols, row[1:]))
                d["rowid"] = row[0]
                out.append(d)
            return out

    def histogram(self, q, gran="min"):
        """Fase 9C: distribucion temporal de las filas filtradas.

        P1.1: el WHERE de _where ya trae su propio 'WHERE', se combina con AND
        (antes se concatenaban dos WHERE y la consulta era invalida)."""
        n = 16 if gran == "min" else 13
        where, params = self._where(q)
        conds = ["ts_norm != ''"]
        if where:
            conds.append(where[len("WHERE "):])
        sql = ("SELECT substr(ts_norm, 1, %d) t, COUNT(*) c FROM rows "
               "WHERE %s GROUP BY t ORDER BY t" % (n, " AND ".join(conds)))
        with self.lock:
            cur = self.conn.execute(sql, params)
            buckets = [{"t": t, "count": c} for t, c in cur.fetchall()]
        if buckets:
            return buckets
        # U3.2 (2026-10-30): ninguna fila tiene fecha; se bucketea por numero
        # de linea, igual que MemStore, para que la histograma no quede vacia.
        step = 100 if gran == "min" else 500
        fwhere = where[len("WHERE "):] if where else "1=1"
        sql = ("SELECT (line / %d) * %d AS b, COUNT(*) AS c FROM rows "
               "WHERE %s GROUP BY b ORDER BY b" % (step, step, fwhere))
        with self.lock:
            cur = self.conn.execute(sql, params)
            return [{"t": "linea %05d-%05d" % (b + 1, b + step), "count": c}
                    for b, c in cur.fetchall()]

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

    def columns(self):
        """P0.4: columnas reales de la tabla (incluye las anadidas por migracion).

        Se lee PRAGMA table_info, no la lista de clase: una BD antigua migra con
        ALTER TABLE y aqui salen exactamente las columnas que tiene."""
        with self.lock:
            cur = self.conn.execute("PRAGMA table_info(rows)")
            return [r[1] for r in cur.fetchall()
                    if r[1] not in EXPORT_SKIP_KEYS]

    def nonempty_columns(self):
        """U2.1 (2026-10-30): columnas de la tabla con algun valor no vacio.

        Un 'SELECT 1 ... LIMIT 1' por columna: se para a la primera coincidencia.
        Los nombres salen de PRAGMA table_info, no del usuario."""
        out = set()
        with self.lock:
            for col in self.columns():
                try:
                    cur = self.conn.execute(
                        'SELECT 1 FROM rows WHERE "%s" != \'\' LIMIT 1' % col)
                    if cur.fetchone():
                        out.add(col)
                except Exception:
                    continue
        return out

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


def export_columns(store):
    """P0.4: cabecera dinamica del export, descubierta en el propio dataset.

    Devuelve las columnas canonicas que existen (en orden canonico) y, detras,
    las claves adicionales que aparezcan en las filas. Si el store no expone
    columnas (dataset vacio o backend sin soporte), cae a las 11 basicas."""
    try:
        present = list(store.columns())
    except Exception:
        present = []
    if not present:
        return list(EXPORT_BASE_COLS)
    have = set(present)
    ordered = [c for c in EXPORT_BASE_COLS + EXPORT_OPERVANTA_COLS if c in have]
    extra = [c for c in present if c not in set(ordered)]
    return ordered + extra


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



