#!/usr/bin/env python3
"""
Visor de Logs Unificado - servidor local (solo stdlib de Python).

P5.1 (2026-10-30): server.py queda como PUNTO DE ENTRADA. La logica esta
repartida en modulos:

  - config.py    : constantes y configuracion por variables de entorno
  - security.py  : cookie de sesion firmada, cabeceras, CSRF y rate limit
  - parsers.py   : deteccion de formato, parsers y filtros de filas
  - stores.py    : estado global y backend de datasets (MemStore/SqlStore)
  - api.py       : Handler HTTP, rutas, LLM, Splunk, tail, auditoria y servidor

Comandos:
  python server.py [puerto]        levanta el visor (por defecto 8765)
  python server.py --tail <ruta>   muestra por terminal las ultimas lineas
                                   de un fichero (NO levanta el HTTP)

Endpoints nuevos:
  GET /api/health  -> {"status":"ok","version":...,"backend":"mem|sqlite",
                       "uptime":...}
"""
import argparse
import os
import sys
import time

import config
import security
import parsers
import stores
import api
from config import *          # noqa: F401  (re-export para compatibilidad)
from security import *        # noqa: F401
from parsers import *         # noqa: F401
from stores import *          # noqa: F401
from api import *             # noqa: F401

# Nombres privados que los tests usan como server.<nombre>: se re-exportan
# de forma explicita para no romper la compatibilidad.
from config import _valid_sqlite_threshold          # noqa: F401
from parsers import _json_scalar, _make_search, _norm_sev, _ui_columns  # noqa: F401
from security import _session_sign                  # noqa: F401
from stores import _user_state                      # noqa: F401
from api import _CONTEXT_INDEX, _splunk_ssl         # noqa: F401


def tail_lines(path, lines=20, encoding="utf-8"):
    """Devuelve las ultimas `lines` lineas de `path` (lista de cadenas).

    Lee desde el final en bloques (no carga el fichero entero) y respeta
    CRLF. Devuelve [] si el fichero no existe o esta vacio.
    """
    if not os.path.isfile(path):
        print("No existe el fichero: %s" % path, file=sys.stderr)
        return []
    lines = max(1, int(lines))
    chunk = 8192
    tail = b""
    offset = os.path.getsize(path)
    # Acumula bloques desde el final hasta tener 'lines' saltos de linea
    while offset > 0 and tail.count(b"\n") < lines:
        start = max(0, offset - chunk)
        with open(path, "rb") as f:
            f.seek(start)
            tail = f.read(offset - start) + tail
        offset = start
    out = tail.decode(encoding, errors="replace").splitlines()
    return out[-lines:]


def tail_file(path, lines=20, encoding="utf-8"):
    """Imprime por terminal las ultimas `lines` lineas de `path`."""
    out = tail_lines(path, lines, encoding)
    for line in out:
        print(line)
    return len(out)


def run_tail(path, lines):
    """Modo tail: muestra el final de un fichero y termina (sin HTTP)."""
    n = tail_file(path, lines)
    if n == 0:
        print("(el fichero esta vacio o no tiene lineas)", file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description="Visor de Logs Unificado")
    ap.add_argument("port", nargs="?", default=None,
                    help="puerto (por defecto: 8765, o $PORT si esta)")
    ap.add_argument("--host", default=None,
                    help="direccion de escucha (por defecto 127.0.0.1;"
                         " 0.0.0.0 si hay $PORT, p. ej. en Railway)")
    # P4.1 (bug B14): por defecto el visor es efimero y limpia sessions/ y
    # sqlite/ al arrancar. --persist conserva lo cargado en arrancos previos.
    ap.add_argument("--persist", action="store_true",
                    help="no borra sessions/ ni sqlite/ al arrancar"
                         " (por defecto se limpian: la naturaleza efimera"
                         " es una feature)")
    # P5.1: modo tail por terminal, sin levantar el servidor.
    ap.add_argument("--tail", metavar="RUTA",
                    help="imprime por terminal las ultimas lineas de un"
                         " fichero de log y termina (no arranca el HTTP)")
    ap.add_argument("--lines", type=int, default=20,
                    help="numero de lineas del --tail (por defecto 20)")
    args = ap.parse_args()

    if args.tail:
        sys.exit(run_tail(args.tail, args.lines))

    try:
        host, port = resolve_bind(args.port, args.host,
                                  os.environ.get("PORT"))
    except ValueError:
        print("Puerto invalido: %s" % args.port)
        sys.exit(1)

    # Limpia las carpetas de sesiones y SQLite al arrancar (B14). Con
    # --persist NO se borran: las sesiones y los datasets sobreviven.
    tmpdir, sessions_dir, sqlite_dir = startup_cleanup(args.persist)
    restored = restore_sessions_from_disk(sessions_dir) if args.persist else 0

    server = LogViewerServer((host, port), Handler)
    print("Visor de Logs Unificado", flush=True)
    print("  http://%s:%d/" % (host, port), flush=True)
    print("  Pool de hilos: max %d conexiones concurrentes" % MAX_CONNECTIONS,
          flush=True)
    print("  Secreto de sesion: %s" % ("env LOGVIEWER_SESSION_SECRET"
                                       if os.environ.get("LOGVIEWER_SESSION_SECRET")
                                       else "generado al arrancar (no persistido)"),
          flush=True)
    print("  Temp dir: %s" % tmpdir, flush=True)
    print("  Persistencia: %s" % ("activa (--persist)"
                                  if args.persist else
                                  "efimera: se borran sessions/ y sqlite/"),
          flush=True)
    if args.persist:
        print("  Sesiones recargadas desde disco: %d" % restored, flush=True)
    print("  (Ctrl+C para parar)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAdios.")
        server.server_close()


if __name__ == "__main__":
    main()
