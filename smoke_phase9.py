#!/usr/bin/env python3
"""Smoke test de la Fase 9: Errores agrupados + plantilla en el parseo.

Arranca el servidor en su propio puerto (8793) y verifica:
- La columna template se calcula al parsear (visible en /api/rows).
- /api/templates agrupa por plantilla con count/primera/ultima/ejemplo.
- El filtro tpl= exacto devuelve solo las filas de esa plantilla.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import quote

PORT = 8793
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))


def build_log():
    lines = []
    for i in range(4):
        lines.append("2023-10-10 10:00:%02d ERR fallo de red desde "
                     "10.0.0.%d puerto 8080\n" % (i, i))
    lines.append("2023-10-10 11:00:00 INFO aviso menor uno\n")
    lines.append("2023-10-10 11:05:00 INFO aviso menor dos\n")
    return "".join(lines).encode("utf-8")


def multipart(files):
    boundary = "----smoke9boundary"
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
        server = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "server.py"), str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1.2)

        # 1. Subida
        body, ct = multipart([("p9.log", build_log())])
        code, res = post("/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("p9.log")
        assert p["phase"] == "done", p
        print("OK subida: p9.log (6 lineas)")

        # 2. La columna template existe en las filas y normaliza valores
        res = get("/api/rows?name=p9.log&page=1&size=10")
        assert len(res["rows"]) == 6, len(res["rows"])
        t0 = res["rows"][0]["template"]
        assert "fallo de red desde *" in t0, t0
        assert "10.0.0" not in t0, t0
        print("OK columna template en /api/rows (IP y numeros normalizados)")

        # 3. /api/templates: agrupacion por plantilla
        res = get("/api/templates?name=p9.log&min=1")
        items = res["templates"]
        assert len(items) == 3, [i["template"] for i in items]
        top = items[0]
        assert top["count"] == 4, top
        assert "fallo de red desde *" in top["template"], top
        assert "fallo de red" in top["example"], top
        assert top["first"] == "2023-10-10T10:00:00", top
        assert top["last"] == "2023-10-10T10:00:03", top
        print("OK /api/templates: 3 grupos, top count=4 con ejemplo")

        # 4. min=3 descarta los grupos de una sola aparicion
        res = get("/api/templates?name=p9.log&min=3")
        assert len(res["templates"]) == 1, res
        print("OK /api/templates min=3: solo el grupo repetido")

        # 5. Filtro tpl exacto: solo las filas de esa plantilla
        tpl = top["template"]
        res = get("/api/rows?name=p9.log&tpl=" + quote(tpl)
                  + "&page=1&size=50")
        assert res["total"] == 4, res["total"]
        assert all(r["template"] == tpl for r in res["rows"]), res["rows"]
        print("OK filtro tpl: 4 filas de la plantilla elegida")

        # 6. Histograma: buckets por minuto y hora sobre las filas
        res = get("/api/histogram?name=p9.log&gran=min")
        counts = [b["count"] for b in res["buckets"]]
        assert counts == [4, 1, 1], counts
        assert res["total"] == 6, res["total"]
        res = get("/api/histogram?name=p9.log&gran=h")
        counts = [(b["t"], b["count"]) for b in res["buckets"]]
        assert counts == [("2023-10-10T10", 4), ("2023-10-10T11", 2)], counts
        print("OK /api/histogram: minutos [4,1,1] y horas [4,2]")

        # 7. Histograma respeta los filtros (tpl)
        res = get("/api/histogram?name=p9.log&gran=min&tpl=" + quote(tpl))
        assert res["total"] == 4, res["total"]
        print("OK /api/histogram filtrado por plantilla: total=4")

        # 8. Quitar el dataset
        code, res = post("/api/remove",
                        json.dumps({"name": "p9.log"}).encode(),
                        "application/json")
        assert code == 200, (code, res)
        print("OK dataset quitado")

        print("\nSMOKE FASE 9: TODO OK")
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    main()
