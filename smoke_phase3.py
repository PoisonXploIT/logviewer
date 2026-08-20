#!/usr/bin/env python3
"""Smoke test de la Fase 3: tail en vivo (watcher + /api/tail).

Sube un archivo, activa el watcher, anade lineas a la copia temporal y
verifica que /api/tail las devuelve parseadas, que el dataset se actualiza
(filtros y KPIs), que detecta truncamiento y que al quitar el dataset el
watcher se para.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

PORT = 8798
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))

GENERIC = ("2023-10-10 13:55:36 info linea uno\n"
           "2023-10-10 13:55:37 error linea dos\n")


def multipart(files):
    boundary = "----smoke3boundary"
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
    server = None
    try:
        server = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "server.py"), str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1.2)

        # 1. Subida base (generic)
        body, ct = multipart([("t.log", GENERIC.encode())])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("t.log")
        assert p["phase"] == "done", p
        s = get("/api/summary?name=t.log")
        assert s["format"] == "generic" and s["total"] == 2, s
        print("OK subida base:", s["format"], s["total"])

        # 2. Activar watch
        code, res = post("/api/watch",
                         json.dumps({"name": "t.log", "enabled": True}).encode(),
                         "application/json")
        assert code == 200 and res["enabled"], (code, res)
        print("OK watch activado")

        # 3. Anadir lineas a la copia temporal y leerlas por /api/tail
        # Carpeta por usuario: sin header Cf-Access-Login-User es "local"
        tmp = os.path.join(tempfile.gettempdir(), "logviewer", "sessions",
                           "local", "t.log")
        assert os.path.isfile(tmp), tmp
        with open(tmp, "ab") as f:
            f.write(b"2023-10-10 13:55:38 error fallo nuevo en vivo\n")
        deadline = time.time() + 10
        t = {}
        while time.time() < deadline:
            t = get("/api/tail?name=t.log&last=500")
            if t.get("total_new", 0) > 0:
                break
            time.sleep(0.3)
        assert t["watching"] and t["total_new"] == 1, t
        r = t["rows"][0]
        assert r["level"] == "ERR" and "fallo nuevo" in r["msg"], r
        assert t["total"] == 3, t
        print("OK tail: linea nueva parseada y anadida al dataset")

        # 4. El dataset se actualizo: filtro por nivel y KPIs
        rows = get("/api/rows?name=t.log&level=ERR")
        assert rows["total"] == 2, rows
        s = get("/api/summary?name=t.log")
        assert s["total"] == 3, s
        assert s["levels"] == 2, s
        print("OK dataset actualizado: filtros y KPIs reflejan las lineas nuevas")

        # 5. Sin watcher: /api/tail responde watching=false
        code, res = post("/api/watch",
                         json.dumps({"name": "t.log", "enabled": False}).encode(),
                         "application/json")
        assert code == 200 and not res["enabled"], (code, res)
        t = get("/api/tail?name=t.log&last=500")
        assert t["watching"] is False and t["rows"] == [], t
        print("OK watch desactivado: /api/tail sin lineas")

        # 6. Truncamiento: reescribir la copia mas corta se relee desde 0
        code, res = post("/api/watch",
                         json.dumps({"name": "t.log", "enabled": True}).encode(),
                         "application/json")
        assert code == 200, (code, res)
        with open(tmp, "wb") as f:
            f.write(b"2023-10-10 14:00:00 info linea tras truncar\n")
        deadline = time.time() + 10
        t = {}
        while time.time() < deadline:
            t = get("/api/tail?name=t.log&last=500")
            if t.get("total_new", 0) > 0:
                break
            time.sleep(0.3)
        assert t["total_new"] == 1 and t["truncated"], t
        assert "tras truncar" in t["rows"][0]["msg"], t
        print("OK truncamiento: relee desde 0 y avisa a la UI")

        # 7. Re-subida con watcher activo: no duplica lineas
        body, ct = multipart([("t.log", GENERIC.encode())])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("t.log")
        assert p["phase"] == "done", p
        s = get("/api/summary?name=t.log")
        assert s["total"] == 2, s
        t = get("/api/tail?name=t.log&last=500")
        assert t["total_new"] == 0, t
        print("OK re-subida: watcher reiniciado sin duplicar")

        # 8. Quitar el dataset para el watcher
        code, res = post("/api/remove",
                         json.dumps({"name": "t.log"}).encode(),
                         "application/json")
        assert code == 200, (code, res)
        try:
            get("/api/tail?name=t.log&last=500")
            raise AssertionError("deberia dar 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404, e
        print("OK quitar dataset: watcher parado")

        print("\nSMOKE FASE 3: TODO OK")
    finally:
        if server:
            server.terminate()
            server.wait()


if __name__ == "__main__":
    main()
