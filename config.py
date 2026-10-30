"""config.py - constantes y configuracion por variables de entorno.

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
UPLOAD_CHUNK = 1024 * 1024         # 1 MB: bloque de lectura del upload (Bug B9)

# P5.1 (2026-10-30): identificacion del servicio para /api/health.
APP_VERSION = "1.2"
START_TIME = time.time()           # momento de arranque del proceso
LOG_MAX_BYTES = 5 * 1024 * 1024    # 5 MB: tope de requests.log y audit.log (Bug B11)

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
SUPPORTED_EXTS = (".log", ".txt", ".csv", ".json", ".jsonl",
                  ".gz", ".bz2", ".xz", ".zip")


# ---------------------------------------------------------------------------
# P0.4: cabecera dinamica del export CSV/NDJSON
# ---------------------------------------------------------------------------
# Orden canonico de las columnas del export. La cabecera real se DESCUBRE en el
# dataset (union de las claves de las filas + las columnas extra de OperVanta);
# estas son solo las canonicas, para que el orden sea estable y predecible.
EXPORT_BASE_COLS = ("ts", "level", "ip", "host", "app", "pid",
                    "method", "path", "code", "bytes", "msg")
EXPORT_OPERVANTA_COLS = ("fuente", "firma", "tenant", "tarea", "dedupe",
                         "evidencia", "riesgo", "url",
                         # severidad y extremos de OperVanta (alertas.jsonl)
                         "sev", "src", "dst",
                         # triage SOC (parse_triage) y piloop (parse_piloop)
                         "verdict", "conf", "accion")
# Claves internas que NO se exportan (derivadas o de control interno)
EXPORT_SKIP_KEYS = frozenset(("raw", "ts_norm", "template", "_line",
                              "_idx", "_search", "rowid"))


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



# URL publica del repo de GitHub (opcional): enlace de descarga de la
# version local en los avisos de funciones SOLO local (LLM, Splunk).
# Si no esta definida, el aviso se muestra sin enlace.
REPO_URL = os.environ.get("LOGVIEWER_REPO_URL", "").strip()

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

# ---------------------------------------------------------------------------
# Fase 13: ingesta desde Splunk local (REST API)
# ---------------------------------------------------------------------------
# La conexion es SOLO a Splunk local (https://localhost:8089 por defecto):
# nada sale a internet. TLS con DEFAULT SEGURO: se verifica el certificado
# (create_default_context: CERT_REQUIRED + check_hostname). Solo se desactiva
# de forma EXPLICITA con LOGVIEWER_SPLUNK_VERIFY=0, para un Splunk local con
# self-signed sin CA accesible; nunca por defecto (bug B13: antes CERT_NONE
# fijo, susceptible a MITM). Si el operador aporta la CA del Splunk, se puede
# verificar sin desactivar nada: LOGVIEWER_SPLUNK_CAFILE=/ruta/ca.pem.
# Peculiaridad de este Splunk 10.4: el SPL debe empezar con un comando
# explicito ("search index=..."); si falta, se fuerza el prefijo "search ".
SPLUNK_URL = os.environ.get("SPLUNK_URL", "").strip() or "https://localhost:8089"
# Bug B13: SIN default "admin". Si no se define SPLUNK_USER, queda vacio
# (la ingesta ademas exige SPLUNK_PASS, asi que la seccion no aparece).
SPLUNK_USER = os.environ.get("SPLUNK_USER", "").strip()
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "").strip()
try:
    SPLUNK_TIMEOUT = int(os.environ.get("SPLUNK_TIMEOUT", "120").strip() or 120)
except ValueError:
    SPLUNK_TIMEOUT = 120
SPLUNK_TIMEOUT = max(5, SPLUNK_TIMEOUT)
SPLUNK_MAX_ROWS = 5000   # tope duro de filas por dataset (no traer 2M)

