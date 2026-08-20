#!/usr/bin/env python3
"""Smoke test de la Fase 2: servidor + subidas + compresion + sesiones."""
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
import io

PORT = 8799
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))

APACHE = """192.168.1.10 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326
192.168.1.11 - - [10/Oct/2023:13:55:37 +0000] "POST /api/login HTTP/1.1" 401 512
192.168.1.12 - - [10/Oct/2023:13:55:38 +0000] "GET /static/app.js HTTP/1.1" 200 1024
192.168.1.10 - - [10/Oct/2023:13:55:39 +0000] "GET /nope HTTP/1.1" 404 123
"""

GENERIC = "2023-10-10 13:55:36 info linea uno\n2023-10-10 13:55:37 error linea dos\n"


def multipart(files):
    """files: list of (name, bytes). Devuelve (body, content_type)."""
    boundary = "----smokeboundary"
    body = b""
    for name, data in files:
        body += ("--%s\r\n" % boundary).encode()
        body += ('Content-Disposition: form-data; filename="%s"\r\n\r\n' % name).encode()
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
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return json.loads(r.read())


def wait_progress(name, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = get("/api/progress?name=" + name)
        if p["phase"] in ("done", "error"):
            return p
        time.sleep(0.3)
    raise TimeoutError("progreso no termino: " + name)


def main():
    tmp = tempfile.mkdtemp(prefix="smoke2_")
    server = None
    try:
        server = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "server.py"), str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1.2)

        # 1. Subida simple (apache plano)
        body, ct = multipart([("a.log", APACHE.encode())])
        code, res = post("/upload", body, ct)
        assert code == 200 and "a.log" in res["started"], (code, res)
        p = wait_progress("a.log")
        assert p["phase"] == "done", p
        s = get("/api/summary?name=a.log")
        assert s["format"] == "apache" and s["total"] == 4, s
        assert s["encoding"] in ("utf-8-sig", "utf-8"), s
        print("OK subida simple + formato + encoding:", s["format"], s["encoding"])

        # 2. Subida multi (gzip + zip + generic) en un solo lote
        gz = gzip.compress(GENERIC.encode())
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("notas.md", "no es el log")
            z.writestr("inner.log", APACHE.encode())
        body, ct = multipart([
            ("b.log.gz", gz),
            ("c.zip", buf.getvalue()),
            ("d.txt", GENERIC.encode()),
        ])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        assert set(res["started"]) == {"b.log.gz", "c.zip", "d.txt"}, res
        for n in ("b.log.gz", "c.zip", "d.txt"):
            p = wait_progress(n)
            assert p["phase"] == "done", (n, p)
        sb = get("/api/summary?name=b.log.gz")
        assert sb["format"] == "generic" and sb["compressed"] == "gzip", sb
        sc = get("/api/summary?name=c.zip")
        assert sc["format"] == "apache" and sc["compressed"] == "zip", sc
        print("OK multi-subida + compresion: gzip, zip (elige inner.log)")

        # 3. Sesiones: lista, activar, quitar
        sess = get("/api/sessions")
        names = [s["name"] for s in sess["sessions"]]
        assert set(names) == {"a.log", "b.log.gz", "c.zip", "d.txt"}, names
        assert sess["active"] == "a.log", sess
        code, res = post("/api/activate",
                         json.dumps({"name": "c.zip"}).encode(),
                         "application/json")
        assert code == 200 and res["active"] == "c.zip", res
        rows = get("/api/rows?name=c.zip&page=1&size=10")
        assert rows["format"] == "apache" and rows["total"] == 4, rows
        code, res = post("/api/remove",
                         json.dumps({"name": "d.txt"}).encode(),
                         "application/json")
        assert code == 200, (code, res)
        sess = get("/api/sessions")
        assert "d.txt" not in [s["name"] for s in sess["sessions"]]
        print("OK sesiones: lista, activar, quitar")

        # 4. Extension no soportada
        body, ct = multipart([("e.pdf", b"%PDF-1.4 fake")])
        code, res = post("/upload", body, ct)
        assert code == 400 and "no soportada" in res.get("error", ""), (code, res)
        print("OK rechaza extension no soportada:", res["error"])

        # 5. Archivo vacio
        body, ct = multipart([("empty.log", b"")])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("empty.log")
        assert p["phase"] == "error" and "vacio" in p["message"], p
        print("OK archivo vacio -> error amigable:", p["message"])

        # 6. Encoding cp1252
        raw = b"2023-10-10 13:55:36 info caf\xe9 \x93prueba\x94\n"
        body, ct = multipart([("enc.log", raw)])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("enc.log")
        assert p["phase"] == "done", p
        s = get("/api/summary?name=enc.log")
        assert s["encoding"] == "cp1252", s
        rows = get("/api/rows?name=enc.log&page=1&size=10")
        assert "caf" in rows["rows"][0]["msg"], rows["rows"][0]
        print("OK encoding cp1252 detectado y decodificado")

        # 7. Export sigue funcionando con name
        with urllib.request.urlopen(
                BASE + "/api/export?name=a.log&code=404", timeout=30) as r:
            csv = r.read().decode()
        assert "404" in csv and "/nope" in csv, csv
        print("OK export con name + filtro")

        # 8. Filtro combinado en dataset no activo
        rows = get("/api/rows?name=a.log&ip=192.168.1.10&code=200")
        assert rows["total"] == 1, rows
        rows = get("/api/rows?name=a.log&ip=192.168.1.10")
        assert rows["total"] == 2, rows
        print("OK filtro combinado en dataset no activo")

        print("\nSMOKE FASE 2: TODO OK")
    finally:
        if server:
            server.terminate()
            server.wait()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
