#!/usr/bin/env python3
"""Smoke test de la Fase 5: export JSON Lines y auditoria.

Arranca el servidor, sube un archivo y verifica:
- Export JSON Lines (una linea JSON por fila, valida).
- Export CSV (cabecera + filas).
- Export en streaming (Transfer-Encoding: chunked, sin cuerpo en memoria).
- Cuerpos JSON invalidos en activate/remove -> 400.
- Auditoria: las acciones (upload, loaded, export, remove) quedan registradas.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

PORT = 8796
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))


def build_log(n=100):
    """Genera un log apache con n lineas (codes 200/404 alternos)."""
    lines = []
    for i in range(n):
        code = 200 if i % 2 else 404
        lines.append('10.0.%d.%d - - [10/Oct/2023:13:55:%02d +0000] '
                     '"GET /path%d HTTP/1.1" %d 1234\n'
                     % (i % 256, (i // 256) % 256, i % 60, i % 1000, code))
    return "".join(lines).encode("utf-8")


def multipart(files):
    boundary = "----smoke5boundary"
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
    server = None
    try:
        server = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "server.py"), str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1.2)

        # 1. Subida de un archivo
        body, ct = multipart([("p5.log", build_log(100))])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("p5.log")
        assert p["phase"] == "done", p
        print("OK subida: p5.log (100 lineas)")

        # 2. Export JSON Lines (todas las filas)
        ndjson = get_raw("/api/export?name=p5.log&format=json")
        lines = [l for l in ndjson.splitlines() if l.strip()]
        assert len(lines) == 100, len(lines)
        # Cada linea es un objeto JSON valido
        for l in lines[:3]:
            obj = json.loads(l)
            assert "ip" in obj and "path" in obj and "raw" in obj, obj
        print("OK export JSON Lines: %d lineas, cada una un objeto JSON"
              % len(lines))

        # 3. Export JSON Lines con filtro (code=404 -> 50 filas)
        ndjson = get_raw("/api/export?name=p5.log&format=json&code=404")
        lines = [l for l in ndjson.splitlines() if l.strip()]
        assert len(lines) == 50, len(lines)
        assert all(json.loads(l)["code"] == "404" for l in lines)
        print("OK export JSON Lines con filtro (code=404): %d lineas"
              % len(lines))

        # 4. Export CSV (cabecera + 100 filas)
        csv = get_raw("/api/export?name=p5.log&format=csv")
        lines = [l for l in csv.splitlines() if l.strip()]
        assert len(lines) == 101, len(lines)
        assert lines[0].startswith("ts,level,ip"), lines[0]
        print("OK export CSV: %d lineas (con cabecera)" % len(lines))

        # 5. Export con formato invalido -> 400
        try:
            urllib.request.urlopen(BASE + "/api/export?name=p5.log&format=xml")
            raise AssertionError("deberia dar 400")
        except urllib.error.HTTPError as e:
            assert e.code == 400, e.code
        print("OK export formato invalido: 400")

        # 6. Auditoria: las acciones quedan registradas
        audit = get("/api/audit")["audit"]
        actions = [e["action"] for e in audit]
        assert "upload" in actions, actions
        assert "loaded" in actions, actions
        assert "export" in actions, actions
        # La entrada de export tiene el formato y el numero de filas
        exp = [e for e in audit if e["action"] == "export"]
        assert any(e.get("format") == "json" and e.get("rows") == 50
                   for e in exp), exp
        print("OK auditoria: upload/loaded/export registrados (%d entradas)"
              % len(audit))

        # 7. Cuerpos JSON invalidos -> 400 (activate/remove/watch)
        code, res = post("/api/activate", b"esto no es JSON",
                        "application/json")
        assert code == 400, (code, res)
        code, res = post("/api/remove", b"", "application/json")
        assert code == 400, (code, res)
        print("OK cuerpo JSON invalido: 400 (activate/remove)")

        # 8. Export en streaming: Transfer-Encoding chunked y contenido intacto
        with urllib.request.urlopen(
                BASE + "/api/export?name=p5.log&format=csv") as r:
            assert r.headers.get("Transfer-Encoding") == "chunked", \
                dict(r.headers)
            data = r.read().decode("utf-8")
        lines = [l for l in data.splitlines() if l.strip()]
        assert len(lines) == 101, len(lines)
        print("OK export streaming: Transfer-Encoding chunked, 101 lineas")

        # 9. Quitar el dataset (queda en la auditoria)
        code, res = post("/api/remove",
                         json.dumps({"name": "p5.log"}).encode(),
                         "application/json")
        assert code == 200, (code, res)
        audit = get("/api/audit")["audit"]
        assert "remove" in [e["action"] for e in audit]
        print("OK auditoria: remove registrado")

        print("\nSMOKE FASE 5: TODO OK")
    finally:
        if server:
            server.terminate()
            server.wait()


if __name__ == "__main__":
    main()
