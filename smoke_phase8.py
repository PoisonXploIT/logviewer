#!/usr/bin/env python3
"""Smoke test de la Fase 8: FTS5 en el backend SQLite.

Arranca el servidor en su propio puerto (8794) con un umbral bajo
(LOGVIEWER_SQLITE_THRESHOLD=1000, el minimo que acepta server.py), sube un log de 1200 lineas que fuerza
la migracion a SqlStore y verifica:
- /api/summary dice backend "sqlite".
- /api/rows con q responde usando FTS5 MATCH (tokens exactos).
- Multivalor (coma) y exclusion (!) tambien por FTS.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import quote

PORT = 8794
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))


def build_log(n=1200):
    """Log generico con un token unico por linea (unicaNNNN)."""
    lines = []
    for i in range(n):
        lines.append("2023-10-10 10:%02d:%02d INFO linea unica%04d de "
                     "prueba\n" % (i // 60, i % 60, i))
    return "".join(lines).encode("utf-8")


def multipart(files):
    boundary = "----smoke8boundary"
    body = b""
    for name, data in files:
        body += ("--%s\r\n" % boundary).encode()
        body += ('Content-Disposition: form-data; filename="%s"\r\n\r\n'
                % name).encode()
        body += data
        body += b"\r\n"
    body += ("--%s--\r\n" % boundary).encode()
    return body, "multipart/form-data; boundary=" + boundary


CSRF = {"token": ""}


def csrf_token():
    if not CSRF["token"]:
        CSRF["token"] = get("/api/csrf")["token"]
    return CSRF["token"]


def post(path, body, ctype):
    req = urllib.request.Request(BASE + path, data=body,
                                 headers={"Content-Type": ctype,
                                          "X-CSRF-Token": csrf_token()},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=60) as r:
        return json.loads(r.read())


def wait_progress(name, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = get("/api/progress?name=" + name)
        if p["phase"] in ("done", "error"):
            return p
        time.sleep(0.3)
    raise TimeoutError("progreso no termino: " + name)


def main():
    server = None
    try:
        env = dict(os.environ, LOGVIEWER_SQLITE_THRESHOLD="1000")
        server = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "server.py"), str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        time.sleep(1.2)

        # 1. Subida de 1200 lineas: por encima del umbral -> SqlStore
        body, ct = multipart([("p8.log", build_log())])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("p8.log")
        assert p["phase"] == "done", p
        print("OK subida: p8.log (1200 lineas)")

        # 2. El backend debe decir sqlite
        s = get("/api/summary?name=p8.log")
        assert s["backend"] == "sqlite", s
        assert s["total"] == 1200, s["total"]
        print("OK /api/summary: backend=sqlite, total=1200")

        # 3. q por token exacto -> FTS5 MATCH (una sola linea)
        res = get("/api/rows?name=p8.log&q=" + quote("unica0042")
                  + "&page=1&size=50")
        assert res["total"] == 1, res["total"]
        assert "unica0042" in res["rows"][0]["msg"], res["rows"][0]
        print("OK q por FTS: token unico -> 1 fila")

        # 4. Multivalor (coma): OR entre frases FTS
        res = get("/api/rows?name=p8.log&q="
                  + quote("unica0001,unica0002") + "&page=1&size=50")
        assert res["total"] == 2, res["total"]
        print("OK q multivalor: 2 tokens -> 2 filas")

        # 5. Exclusion (!): sin positivos, clausulas SQL (documentado)
        res = get("/api/rows?name=p8.log&q=" + quote("!unica0005")
                  + "&page=1&size=50")
        assert res["total"] == 1199, res["total"]
        print("OK q exclusion: 1200 - 1 = 1199 filas")

        # 6. Sin filtros: todo el dataset por SQLite
        res = get("/api/rows?name=p8.log&page=1&size=5")
        assert res["total"] == 1200, res["total"]
        print("OK sin filtros: total=1200 por SQLite")

        # 7. Quitar el dataset
        code, res = post("/api/remove",
                        json.dumps({"name": "p8.log"}).encode(),
                        "application/json")
        assert code == 200, (code, res)
        print("OK dataset quitado")

        print("\nSMOKE FASE 8: TODO OK")
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    main()
