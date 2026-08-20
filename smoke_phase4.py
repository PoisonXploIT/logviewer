#!/usr/bin/env python3
"""Smoke test de la Fase 4: backend SQLite hibrido (umbral por tamano).

Arranca el servidor con LOGVIEWER_SQLITE_THRESHOLD bajo, sube un archivo que
supera el umbral (migra a SQLite) y verifica que el filtrado, el top N, los
KPIs, el tail en vivo y el export funcionan sobre el backend SQLite.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

PORT = 8797
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))
THRESHOLD = 1000


def build_log(n_inf=100, n_err=50):
    """Genera un log generic con n_inf INF + n_err ERR lineas."""
    lines = []
    for i in range(n_inf):
        lines.append("2023-10-10 13:55:%02d info linea inf %d ip 1.1.1.1\n"
                     % (i % 60, i))
    for i in range(n_err):
        lines.append("2023-10-10 14:55:%02d error linea err %d ip 2.2.2.2\n"
                     % (i % 60, i))
    return "".join(lines).encode("utf-8")


def multipart(files):
    boundary = "----smoke4boundary"
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


def get_raw(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return r.read().decode("utf-8")


def wait_progress(name, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = get("/api/progress?name=" + name)
        if p["phase"] in ("done", "error"):
            return p
        time.sleep(0.3)
    raise TimeoutError("progreso no termino: " + name)


def main():
    env = dict(os.environ)
    env["LOGVIEWER_SQLITE_THRESHOLD"] = str(THRESHOLD)
    server = None
    try:
        server = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "server.py"), str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        time.sleep(1.2)

        # 0. Un archivo pequeno (bajo el umbral) queda en memoria
        body, ct = multipart([("small.log", build_log(n_inf=30, n_err=20))])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("small.log")
        assert p["phase"] == "done", p
        s_small = get("/api/summary?name=small.log")
        assert s_small["backend"] == "mem", s_small
        assert s_small["total"] == 50, s_small
        print("OK archivo pequeno: backend=mem, total=%d" % s_small["total"])
        # Quitarlo para no interferir
        post("/api/remove", json.dumps({"name": "small.log"}).encode(),
             "application/json")

        # 1. Subida de un archivo que supera el umbral (migra a SQLite)
        body, ct = multipart([("big.log", build_log(n_inf=1100, n_err=500))])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("big.log")
        assert p["phase"] == "done", p
        s = get("/api/summary?name=big.log")
        assert s["backend"] == "sqlite", s
        assert s["total"] == 1600, s
        assert s["parsed"] == 1600, s
        print("OK migracion a SQLite: backend=sqlite, total=%d" % s["total"])

        # 2. KPIs sobre SQLite
        assert s["levels"] == 2, s
        assert s["ips"] == 2, s
        print("OK KPIs SQLite: levels=%d ips=%d" % (s["levels"], s["ips"]))

        # 3. Filtrado por nivel sobre SQLite
        rows = get("/api/rows?name=big.log&level=ERR")
        assert rows["total"] == 500, rows
        assert all(r["level"] == "ERR" for r in rows["rows"]), rows
        print("OK filtro por nivel (ERR): %d filas" % rows["total"])

        # 4. Filtrado por IP (subcadena) sobre SQLite
        rows = get("/api/rows?name=big.log&ip=2.2.2")
        assert rows["total"] == 500, rows
        print("OK filtro por IP (2.2.2): %d filas" % rows["total"])

        # 5. Filtrado por texto libre sobre SQLite ("err" esta en level+msg)
        rows = get("/api/rows?name=big.log&q=err")
        assert rows["total"] == 500, rows
        print("OK filtro por texto (err): %d filas" % rows["total"])

        # 6. Filtro combinado (nivel + IP) sobre SQLite
        rows = get("/api/rows?name=big.log&level=ERR&ip=2.2.2")
        assert rows["total"] == 500, rows
        rows = get("/api/rows?name=big.log&level=ERR&ip=1.1.1")
        assert rows["total"] == 0, rows
        print("OK filtro combinado (nivel + IP)")

        # 7. Top N sobre SQLite
        top = get("/api/top?name=big.log&field=ip&limit=10")
        d = dict(top["top"])
        assert d.get("1.1.1.1") == 1100, top
        assert d.get("2.2.2.2") == 500, top
        print("OK top N SQLite: 1.1.1.1=%d 2.2.2.2=%d" % (
            d.get("1.1.1.1"), d.get("2.2.2.2")))

        # 8. Tail en vivo sobre SQLite (anadir lineas)
        code, res = post("/api/watch",
                         json.dumps({"name": "big.log", "enabled": True}).encode(),
                         "application/json")
        assert code == 200 and res["enabled"], (code, res)
        # Carpeta por usuario: sin header Cf-Access-Login-User es "local"
        tmp = os.path.join(tempfile.gettempdir(), "logviewer", "sessions",
                           "local", "big.log")
        assert os.path.isfile(tmp), tmp
        with open(tmp, "ab") as f:
            f.write(b"2023-10-10 15:00:00 error fallo nuevo en vivo\n")
        deadline = time.time() + 10
        t = {}
        while time.time() < deadline:
            t = get("/api/tail?name=big.log&last=500")
            if t.get("total_new", 0) > 0:
                break
            time.sleep(0.3)
        assert t["watching"] and t["total_new"] == 1, t
        assert t["total"] == 1601, t
        s2 = get("/api/summary?name=big.log")
        assert s2["total"] == 1601 and s2["backend"] == "sqlite", s2
        print("OK tail sobre SQLite: linea anadida, total=%d" % s2["total"])

        # 9. Export CSV sobre SQLite (con filtro; incluye la linea del tail)
        csv = get_raw("/api/export?name=big.log&level=ERR")
        lines = [l for l in csv.splitlines() if l.strip()]
        # Cabecera + 500 filas ERR + 1 del tail = 502
        assert len(lines) == 502, len(lines)
        assert "fallo nuevo" in csv, "la linea del tail debe estar en el export"
        print("OK export CSV SQLite: %d lineas (con cabecera)" % len(lines))

        # 10. Quitar el dataset (cierra la BD)
        code, res = post("/api/remove",
                         json.dumps({"name": "big.log"}).encode(),
                         "application/json")
        assert code == 200, (code, res)
        db = os.path.join(tempfile.gettempdir(), "logviewer", "sqlite",
                          "local", "big.log.db")
        assert not os.path.exists(db), "la BD deberia borrarse: " + db
        print("OK quitar dataset: BD de SQLite borrada")

        print("\nSMOKE FASE 4: TODO OK")
    finally:
        if server:
            server.terminate()
            server.wait()


if __name__ == "__main__":
    main()
