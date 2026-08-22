#!/usr/bin/env python3
"""Benchmark Fase 8C: busqueda q= con instr (antes) vs FTS5 MATCH (despues).

Genera un set determinista de ~2M lineas (el mismo volumen verificado en
la Fase 4), lo carga con server.load_file (migracion a SqlStore por el
umbral) y mide:
- Coste de construir el indice FTS5 (rebuild desde rows).
- Busqueda "antes": SELECT COUNT(*) ... WHERE instr(search, ?) > 0
  (escaneo completo; no existe indice posible sobre search).
- Busqueda "despues": rowid IN (SELECT rowid FROM fts WHERE fts MATCH ?).
Escribe el resumen en stdout con la marca BENCHMARK para copiar a
ESTADO.md. No sube nada por red: es un ejercicio del backend local.
"""
import os
import random
import tempfile
import time

import server

N = 2_000_000
HERE = os.path.dirname(os.path.abspath(__file__))


def build_file(path):
    """~2M lineas genericas deterministas (seed fija)."""
    rnd = random.Random(20260821)
    words = ["ok", "warn", "timeout", "retry", "cache", "db", "auth",
             "session", "token", "query", "slow", "error", "reset"]
    with open(path, "w", encoding="utf-8") as f:
        for i in range(N):
            w = words[rnd.randrange(len(words))]
            f.write("2023-10-10 %02d:%02d:%02d INFO linea %s unica%07d "
                    "de prueba\n" % (i // 3600 % 24, i // 60 % 60,
                                    i % 60, w, i))


def main():
    tmpdir = tempfile.mkdtemp(prefix="lvbench8")
    path = os.path.join(tmpdir, "bench.log")
    build_file(path)
    print("Archivo: %.1f MB, %d lineas"
          % (os.path.getsize(path) / 1e6, N))

    t0 = time.time()
    ds = server.load_file(path)
    t_load = time.time() - t0
    store = ds["store"]
    assert isinstance(store, server.SqlStore), type(store)
    print("Carga + parseo + FTS: %.1f s (backend=%s)"
          % (t_load, "sqlite"))

    with store.lock:
        # Coste de construir el indice FTS5 desde rows (rebuild)
        t0 = time.time()
        store.conn.execute("INSERT INTO fts(fts) VALUES('rebuild')")
        t_rebuild = time.time() - t0
        print("FTS rebuild (2M filas): %.1f s" % t_rebuild)

        # "Antes": instr sobre search (escaneo completo, sin indice)
        terms = ["de prueba", "unica1234567", "timeout"]
        for term in terms:
            q_old = ("SELECT COUNT(*) FROM rows WHERE instr(search, ?) > 0")
            t0 = time.time()
            cur = store.conn.execute(q_old, [term])
            n_old = cur.fetchone()[0]
            t_old = time.time() - t0
            # "Despues": FTS5 MATCH por token exacto
            q_new = ("SELECT COUNT(*) FROM rows WHERE rowid IN "
                     "(SELECT rowid FROM fts WHERE fts MATCH ?)")
            phrase = '"%s"' % term.replace('"', '""')
            t0 = time.time()
            cur = store.conn.execute(q_new, [phrase])
            n_new = cur.fetchone()[0]
            t_new = time.time() - t0
            print("BENCHMARK term=%r antes_instr=%.3fs(n=%d) "
                  "despues_fts=%.4fs(n=%d)"
                  % (term, t_old, n_old, t_new, n_new))

    # Limpieza
    store.close()  # borra la BD (y sus WAL/SHM)
    try:
        os.remove(path)
    except OSError:
        pass
    os.rmdir(tmpdir)
    print("OK benchmark terminado")


if __name__ == "__main__":
    main()
