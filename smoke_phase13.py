"""Smoke Fase 13: ingesta desde Splunk local contra el Splunk real.

Requisito de la fase (el mock HTTP ya esta cubierto en test_parsers.py,
TestSplunkQuery): aqui SI se consulta el Splunk real de https://localhost:8089
con una query de deteccion de password spray sobre botsv3 y se comprueba
todo el flujo del visor: dataset activo -> filas/filtros/export -> contexto
(no aplica) -> diagnostico rapido con LLM (mock local que respone "ok").

La contrasena NO esta en este codigo: se toma de SPLUNK_PASS o, si no hay,
del default del script de referencia scripts/splunk_search.sh.

Uso:  python smoke_phase13.py
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 8792
BASE = "http://127.0.0.1:%d" % PORT
SCRIPT = r"C:\Users\Sammi\scripts\splunk_search.sh"

# Query de la fase: password spray en botsv3 (IPs con >=2 fallos de
# autenticacion). Agregada y acotada: vuelve pocas filas, no 2M.
SPRAY_SPL = ('search index=botsv3 failureReason '
             '"Invalid username or password" | stats count by ipAddress,'
             ' userPrincipalName | where count >= 2 | head 10')


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_mock():
    """LLM mock: respone 'ok' con un texto fijo (analista del visor)."""

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            sysp = body.get("messages", [{}])[0].get("content", "")
            assert "analista" in sysp, \
                "el system prompt del diagnostico no llega al LLM"
            out = {"choices": [{"message": {
                "content": ("[smoke-llm] conclusion: hay un password spray"
                            " activo; revisar los fallos de autenticacion"
                            " y bloquear las IPs recurrentes."),
                "reasoning_content": ""}}]}
            data = json.dumps(out).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    port = _free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "http://127.0.0.1:%d/v1" % port, srv


def start_server(port, extra_env):
    env = dict(os.environ)
    env.update(extra_env)
    return subprocess.Popen(
        [sys.executable, os.path.join(HERE, "server.py"), str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)


def get(path, timeout=60):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return json.loads(r.read())


def req(method, path, body=None, timeout=120):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    r.add_header("X-CSRF-Token", get("/api/csrf")["token"])
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def splunk_pass():
    p = os.environ.get("SPLUNK_PASS", "").strip()
    if p:
        return p
    # Default del script de referencia (fuente autorizada por el usuario)
    with open(SCRIPT, "r", encoding="utf-8") as f:
        txt = f.read()
    m = re.search(r"SPLUNK_AUTH:-([\w:.@]+)", txt)
    if not m:
        raise SystemExit("sin SPLUNK_PASS en el entorno y sin default en"
                         " splunk_search.sh")
    return m.group(1).rsplit(":", 1)[-1]


def main():
    mock_url, mock_srv = start_mock()
    # settings.json es estado compartido en %TEMP%: se limpia al empezar
    try:
        os.remove(os.path.join(tempfile.gettempdir(), "logviewer",
                               "settings.json"))
    except OSError:
        pass
    srv = None
    try:
        srv = start_server(PORT, {
            "LOGVIEWER_LLM_URL": mock_url,
            "LOGVIEWER_LLM_MODEL": "smoke-model-13",
            "SPLUNK_URL": "https://localhost:8089",
            "SPLUNK_USER": "Sammi",
            "SPLUNK_PASS": splunk_pass(),
        })
        # Espera a que el servidor levante (el arranque carga runbooks/BD)
        for _ in range(60):
            try:
                get("/api/summary")
                break
            except urllib.error.HTTPError:
                continue
            except OSError:
                time.sleep(0.5)
        else:
            raise TimeoutError("el servidor no levanto en 30s")

        # --- config expone splunk:true (seccion visible en la UI)
        cfg = get("/api/config")
        assert cfg.get("splunk") is True, cfg
        print("OK /api/config: splunk:true con SPLUNK_PASS definido")

        # --- fuentes de Splunk (recon ligero, sin search pesado).
        # En este entorno el usuario no puede listar indices (REST 404):
        # el endpoint lo documenta y sigue sirviendo la ingesta
        idx = get("/api/splunk/sources", timeout=90)
        assert idx.get("primary") == "botsv3", idx
        print("OK /api/splunk/sources: primary=botsv3 (%d indices listados)"
              % len(idx.get("indexes", [])))

        # --- password spray contra el Splunk real -> dataset activo
        code, res = req("POST", "/api/splunk/search", {"search": SPRAY_SPL})
        assert code == 200, (code, res)
        n = res.get("rows") or 0
        assert n > 0, "la query de spray no devolvio filas"
        name = res["name"]
        print("OK /api/splunk/search: %d filas de password spray en '%s'"
              % (n, name))

        # --- el dataset usa la maquinaria normal del visor
        s = get("/api/summary?name=" + urllib.parse.quote(name))
        assert s["format"] == "splunk", s
        assert s["total"] == n, (s["total"], n)
        print("OK /api/summary: format=splunk, total=%d" % s["total"])

        rows = get("/api/rows?name=" + urllib.parse.quote(name)
                   + "&size=5")
        assert len(rows["rows"]) > 0, rows
        r0 = rows["rows"][0]
        for k in ("msg", "template", "raw"):
            assert r0.get(k), "fila sin %s" % k
        print("OK /api/rows: msg/template/raw presentes en la fila 0")

        # filtro por texto (el msg de las filas trae userPrincipalName=...)
        filt = get("/api/rows?name=" + urllib.parse.quote(name)
                   + "&q=userPrincipalName&size=5")
        assert len(filt["rows"]) > 0, "el filtro no encontro nada"
        print("OK /api/rows?q=userPrincipalName: %d filas filtradas"
              % filt["total"])

        t = get("/api/templates?name=" + urllib.parse.quote(name))
        assert len(t["templates"]) > 0, "sin plantillas"
        print("OK /api/templates: %d plantillas (base del diagnostico)"
              % t["total"])

        # export ndjson: una linea JSON por fila filtrada
        with urllib.request.urlopen(
                BASE + "/api/export?name="
                + urllib.parse.quote(name) + "&format=json", timeout=60) as r:
            data = r.read().decode("utf-8")
        lines = [ln for ln in data.splitlines() if ln.strip()]
        assert len(lines) == n, (len(lines), n)
        json.loads(lines[0])  # cada linea es JSON valido
        print("OK /api/export: %d lineas ndjson exportadas" % len(lines))

        # --- el contexto de linea NO aplica a un dataset de Splunk
        code, res = req("GET", "/api/context?name=" + urllib.parse.quote(name)
                        + "&row=0&before=5")
        assert code == 404, (code, res)
        print("OK /api/context: 404 (no aplica a Splunk, sin archivo)")

        # --- diagnostico rapido con LLM local (mock que respone ok)
        # El dataset Splunk no tiene niveles: _diagnose cae a todas las
        # plantillas (comportamiento de la Fase 13 documentado)
        code, res = req("POST", "/api/diagnose", {"name": name,
                                                  "level": "ERR"})
        assert code == 200, (code, res)
        assert res.get("cached") is False, res
        assert "[smoke-llm]" in res.get("conclusion", ""), res
        print("OK /api/diagnose: conclusion del LLM local (%d plantillas)"
              % res.get("analyzed", -1))

        # --- auditoria: la accion splunk_search queda registrada
        a = get("/api/audit")
        acts = [e.get("action") for e in a.get("audit", [])]
        assert "splunk_search" in acts, acts
        print("OK /api/audit: accion 'splunk_search' presente")

        print("\nSMOKE FASE 13 COMPLETA (Splunk real + LLM mock ok)")
    finally:
        if srv is not None:
            srv.terminate()
            try:
                srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                srv.kill()
        mock_srv.shutdown()


if __name__ == "__main__":
    main()
