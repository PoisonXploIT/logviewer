#!/usr/bin/env python3
"""Smoke test de la Fase 7: ts_norm, rango de fechas y contexto (7A+7B).

Arranca el servidor en su propio puerto (8795), sube un log pequeno
(backend en memoria) y verifica:
- Cada fila expone ts_norm (ISO canónico).
- /api/rows con dt_from/dt_to filtra por rango real.
- /api/rows expone rowid por fila.
- /api/context devuelve las lineas del log original alrededor de la fila
  (antes, actual y despues, con su numero).
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

PORT = 8795
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))


def build_log(n=10):
    """Log genérico: una linea por segundo, nivel alterno."""
    lines = []
    for i in range(n):
        level = "INFO" if i % 2 == 0 else "ERROR"
        lines.append("2023-10-10 10:00:%02d %s msg numero %d\n"
                     % (i, level, i))
    return "".join(lines).encode("utf-8")


def multipart(files):
    boundary = "----smoke7boundary"
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

        # 1. Subida de un archivo pequeno (MemStore)
        body, ct = multipart([("p7.log", build_log(10))])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("p7.log")
        assert p["phase"] == "done", p
        print("OK subida: p7.log (10 lineas)")

        # 2. ts_norm en cada fila (ISO canónico)
        rows = get("/api/rows?name=p7.log&page=1&size=50")["rows"]
        assert len(rows) == 10, len(rows)
        for i, r in enumerate(rows):
            assert r["ts_norm"] == "2023-10-10T10:00:%02d" % i, (i, r["ts_norm"])
            assert r["rowid"] == i, (i, r["rowid"])
        print("OK ts_norm: 10 filas con ISO canónico y rowid")

        # 3. Rango de fechas real: dt_from/dt_to sobre ts_norm
        res = get("/api/rows?name=p7.log&dt_from=2023-10-10T10%3A00%3A02"
                  "&dt_to=2023-10-10T10%3A00%3A04&page=1&size=50")
        assert res["total"] == 3, res["total"]
        assert [r["ts_norm"] for r in res["rows"]] == [
            "2023-10-10T10:00:02", "2023-10-10T10:00:03",
            "2023-10-10T10:00:04"]
        # Solo dt_from (sin tope)
        res = get("/api/rows?name=p7.log&dt_from=2023-10-10T10%3A00%3A08"
                  "&page=1&size=50")
        assert res["total"] == 2, res["total"]
        print("OK rango dt_from/dt_to: filtro por rango real")

        # 4. Contexto de la linea 4 (n=2): antes/actual/despues
        ctx = get("/api/context?name=p7.log&row=4&n=2")
        assert ctx["line"] == 5, ctx          # 1-based en el archivo
        assert ctx["current"] == "2023-10-10 10:00:04 INFO msg numero 4"
        assert ctx["before"] == [
            "2023-10-10 10:00:02 INFO msg numero 2",
            "2023-10-10 10:00:03 ERROR msg numero 3"], ctx["before"]
        assert ctx["after"] == [
            "2023-10-10 10:00:05 ERROR msg numero 5",
            "2023-10-10 10:00:06 INFO msg numero 6"], ctx["after"]
        print("OK contexto n=2: lineas 3-7 del original, actual resaltada")

        # 5. Contexto en la primera linea (borde inferior) y fila invalida
        ctx = get("/api/context?name=p7.log&row=0&n=3")
        assert ctx["line"] == 1 and len(ctx["before"]) == 0, ctx
        assert len(ctx["after"]) == 3, ctx
        try:
            urllib.request.urlopen(BASE + "/api/context?name=p7.log&row=999")
            raise AssertionError("deberia dar 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404, e.code
        print("OK contexto: borde inferior y fila inexistente (404)")

        # 6. Fase 7D: exclusion (!) y multivalor (coma)
        from urllib.parse import quote
        # level normalizado: INFO->INF, ERROR->ERR
        res = get("/api/rows?name=p7.log&level=" + quote("!INF")
                  + "&page=1&size=50")
        assert res["total"] == 5, res["total"]
        assert all(r["level"] == "ERR" for r in res["rows"])
        res = get("/api/rows?name=p7.log&q="
                  + quote("numero 2,numero 3") + "&page=1&size=50")
        assert res["total"] == 2, res["total"]
        # Combinado: positivo y exclusion en el mismo campo
        res = get("/api/rows?name=p7.log&q="
                  + quote("numero,!4") + "&page=1&size=50")
        assert res["total"] == 9, res["total"]
        print("OK exclusion/multivalor: !INFO, q multivalor y combinado")

        # 7. Quitar el dataset
        code, res = post("/api/remove",
                         json.dumps({"name": "p7.log"}).encode(),
                         "application/json")
        assert code == 200, (code, res)
        print("OK dataset quitado")

        print("\nSMOKE FASE 7: TODO OK")
    finally:
        if server:
            server.terminate()
            server.wait()


if __name__ == "__main__":
    main()
