#!/usr/bin/env python3
"""Smoke test de la Fase 10: runbooks (errores conocidos).

Arranca el servidor en su propio puerto (8792) y verifica:
- POST /api/runbooks crea un runbook precargado (persistente).
- GET /api/runbooks/match?msg= encuentra el runbook con una linea real.
- PUT edita, DELETE borra y el match queda vacio.
- Validaciones: regex invalido 400, duplicado por patron 409.

Nota: la BD de runbooks es persistente (no muere con el dataset), asi que
el smoke limpia lo que crea al final.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import quote

PORT = 8792
BASE = "http://127.0.0.1:%d" % PORT
HERE = os.path.dirname(os.path.abspath(__file__))


def build_log():
    lines = []
    for i in range(3):
        lines.append("2023-10-10 10:00:%02d ERR timeout de red a las "
                     "10:00:%d\n" % (i, i))
    lines.append("2023-10-10 11:00:00 INFO todo bien uno\n")
    lines.append("2023-10-10 11:05:00 INFO todo bien dos\n")
    return "".join(lines).encode("utf-8")


def multipart(files):
    boundary = "----smoke10boundary"
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


def req(method, path, body=None, ctype="application/json"):
    data = None if body is None else (
        body if isinstance(body, bytes)
        else json.dumps(body).encode())
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", ctype)
    r.add_header("X-CSRF-Token", csrf_token())
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read())
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
    created_ids = []
    try:
        server = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "server.py"), str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1.2)

        # 0. Limpieza defensiva de runbooks de una corrida anterior
        for rb in get("/api/runbooks")["runbooks"]:
            code, res = req("DELETE", "/api/runbooks?id=%d" % rb["id"])
            assert code == 200, (code, res)

        # 1. Subida del log
        body, ct = multipart([("p10.log", build_log())])
        code, res = req("POST", "/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress("p10.log")
        assert p["phase"] == "done", p
        print("OK subida: p10.log (5 lineas)")

        # 2. Runbook precargado (el que veria el drawer)
        code, rb = req("POST", "/api/runbooks", {
            "pattern": r"timeout de red", "kind": "regex",
            "explicacion": "El upstream no responde a tiempo",
            "causa": "carga o servicio caido",
            "solucion": "reintentar y revisar el upstream",
            "ref": "vault/red/timeout.md"})
        assert code == 200, (code, rb)
        rid = rb["id"]
        created_ids.append(rid)

        # 3. El match sobre una linea real del log lo encuentra
        res = get("/api/rows?name=p10.log&page=1&size=50")
        rows = [r for r in res["rows"] if "timeout de red" in (r.get("msg") or "")]
        assert len(rows) == 3, len(rows)
        m = get("/api/runbooks/match?msg=" + quote(rows[0]["msg"]))
        assert len(m["matches"]) == 1, m
        hit = m["matches"][0]
        assert hit["id"] == rid and hit["solucion"].startswith("reintentar"), hit
        print("OK /api/runbooks/match: el runbook precargado aparece "
              "para la linea del log")

        # 4. Validaciones de alta
        code, res = req("POST", "/api/runbooks", {"pattern": "([",
                                                  "kind": "regex"})
        assert code == 400, (code, res)
        code, res = req("POST", "/api/runbooks",
                        {"pattern": r"timeout de red"})
        assert code == 409, (code, res)
        print("OK validaciones: regex invalido 400, duplicado 409")

        # 5. PUT edita el runbook
        code, rb2 = req("PUT", "/api/runbooks?id=%d" % rid, {
            "pattern": r"timeout de red", "kind": "regex",
            "explicacion": "EDITADO: upstream no responde a tiempo",
            "causa": "", "solucion": "", "ref": ""})
        assert code == 200, (code, rb2)
        assert rb2["explicacion"].startswith("EDITADO"), rb2
        m = get("/api/runbooks/match?msg=" + quote(rows[0]["msg"]))
        assert m["matches"][0]["explicacion"].startswith("EDITADO"), m
        print("OK PUT: edicion persistida y visible en el match")

        # 6. DELETE borra y el match queda vacio
        code, res = req("DELETE", "/api/runbooks?id=%d" % rid)
        assert code == 200, (code, res)
        created_ids.remove(rid)
        m = get("/api/runbooks/match?msg=" + quote(rows[0]["msg"]))
        assert m["matches"] == [], m
        assert get("/api/runbooks")["runbooks"] == []
        print("OK DELETE: match vacio y BD limpia")

        # 7. Quitar el dataset (los runbooks NO se borran con el)
        code, res = req("POST", "/api/remove", {"name": "p10.log"})
        assert code == 200, (code, res)
        print("OK dataset quitado")

        print("\nSMOKE FASE 10: TODO OK")
    finally:
        # Limpieza final de runbooks (la BD es persistente)
        for rid in created_ids:
            try:
                req("DELETE", "/api/runbooks?id=%d" % rid)
            except Exception:
                pass
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    main()
