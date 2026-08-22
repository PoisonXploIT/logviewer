#!/usr/bin/env python3
"""Smoke test de la Fase 12A: boton "Analizar" (LLM local OpenAI-compatible).

Arranca TRES servidores en sus propios puertos y un mock de LLM:
- A (:8790): LOGVIEWER_LLM_URL -> mock local. Verifica el flujo bueno
  (analiza, cachea, la segunda vez no vuelve a preguntar) y el caso del
  modelo de RAZONAMIENTO que devuelve "content" vacio (nunca es exito).
- B (:8789): LOGVIEWER_LLM_URL -> puerto caido. Fallo limpio y rapido:
  mensaje amigable, nunca cuelga la peticion.
- C (:8788): sin LOGVIEWER_LLM_URL. /api/config dice llm:false (el boton
  no aparece) y /api/analyze responde 404.

El mock es un http.server en hilos de este proceso, sirviendo
/v1/chat/completions con formato OpenAI. El mock devuelve el prompt del
sistema dentro del content para poder comprobar end-to-end que el idioma
configurado (llm_lang) llega al prompt.

Fase 12B: /api/settings acepta y persiste "lang" (auto/es/en; un valor
invalido cae a auto), el analyze lo pasa al prompt y llm_key distingue
idiomas (misma linea, es/en -> hashes distintos).

Fase 12C: POST /api/diagnose resume con el LLM local TODAS las lineas de
error del dataset activo via sus plantillas unicas (el mock ecoa el
prompt: se comprueba que van plantillas+count y no lineas sueltas),
devuelve conclusion + top, y la segunda vez sale de cache sin volver a
preguntar.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PORT_A = 8790   # LLM ok (mock)
PORT_B = 8789   # LLM en puerto caido
PORT_C = 8788   # sin LLM
REPO_URL = "https://github.com/sammi/logviewer"  # VERSION 1.2: aviso


# ---------------------------------------------------------------- mock LLM
MOCK = {"n": 0}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_mock():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            MOCK["n"] += 1
            # El cliente debe pedir max_tokens generoso y el prompt fijo
            assert body.get("max_tokens", 0) >= 4000, body
            sysp = body["messages"][0]["content"]
            assert "analista" in sysp.lower(), sysp
            user = body["messages"][-1]["content"]
            if "RAZON" in user:
                # Modelo de razonamiento: presupuesto gastado en razonar
                out = {"choices": [{"message": {
                    "content": "",
                    "reasoning_content": "mucho razonar sobre la linea"}}]}
            else:
                # Se ecoa el prompt del sistema para poder comprobar que
                # el idioma configurado (llm_lang) llega al prompt
                out = {"choices": [{"message": {
                    "content": ("Explicacion smoke para: " + user
                                + " || SYS: " + sysp),
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


# ------------------------------------------------------------- HTTP helpers
def start_server(port, extra_env):
    env = dict(os.environ)
    env.update(extra_env)
    return subprocess.Popen(
        [sys.executable, os.path.join(HERE, "server.py"), str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)


def req(base, method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    r.add_header("X-CSRF-Token", get(base, "/api/csrf")["token"])
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=60) as r:
        return json.loads(r.read())


def multipart(files):
    boundary = "----smoke12cboundary"
    body = b""
    for name, data in files:
        body += ("--%s\r\n" % boundary).encode()
        body += ('Content-Disposition: form-data; filename="%s"\r\n\r\n'
                % name).encode()
        body += data
        body += b"\r\n"
    body += ("--%s--\r\n" % boundary).encode()
    return body, "multipart/form-data; boundary=" + boundary


def post_raw(base, path, body, ctype):
    r = urllib.request.Request(base + path, data=body, method="POST",
                                headers={"Content-Type": ctype,
                                         "X-CSRF-Token":
                                         get(base, "/api/csrf")["token"]})
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_progress(base, name, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = get(base, "/api/progress?name=" + name)
        if p["phase"] in ("done", "error"):
            return p
        time.sleep(0.3)
    raise TimeoutError("progreso no termino: " + name)


def build_err_log():
    # 5 ERR de una plantilla, 3 de otra y 1 de una tercera (+ INFOs):
    # 3 plantillas unicas de nivel ERR con counts 5/3/1
    lines = []
    for i in range(5):
        lines.append("2023-10-10 10:00:%02d ERR fallo de red desde "
                     "10.0.0.%d puerto 8080\n" % (i, i))
    for i in range(3):
        lines.append("2023-10-10 10:05:%02d ERR disco lleno en el"
                     " volumen /var/log/%d\n" % (i, i))
    lines.append("2023-10-10 10:06:00 ERR certificado caducado del"
                " servicio TLS\n")
    for i in range(2):
        lines.append("2023-10-10 11:00:%02d INFO aviso menor %d\n" % (i, i))
    return "".join(lines).encode("utf-8")


def main():
    mock_url, mock_srv = start_mock()
    # settings.json es estado compartido en %TEMP%: se limpia al empezar
    # para que cada corrida parta del estado determinista (las env vars
    # de A/B/C son la config inicial)
    try:
        os.remove(os.path.join(tempfile.gettempdir(), "logviewer",
                               "settings.json"))
    except OSError:
        pass
    srv_a = srv_b = srv_c = None
    try:
        # A: LLM ok (mock local)
        srv_a = start_server(PORT_A, {
            "LOGVIEWER_LLM_URL": mock_url,
            "LOGVIEWER_LLM_MODEL": "smoke-model-1"})
        time.sleep(1.2)
        base_a = "http://127.0.0.1:%d" % PORT_A

        assert get(base_a, "/api/config")["llm"] is True
        print("OK /api/config: llm:true con LOGVIEWER_LLM_URL definido")

        linea = "timeout de red a las 10:00:01 (smoke %d)" % int(time.time())
        code, res = req(base_a, "POST", "/api/analyze", {"line": linea})
        assert code == 200, (code, res)
        assert res["cached"] is False and res["answer"].strip(), res
        assert "Explicacion smoke" in res["answer"], res
        n1 = MOCK["n"]
        print("OK /api/analyze: primera vez pregunta al LLM (no cache)")

        code, res2 = req(base_a, "POST", "/api/analyze", {"line": linea})
        assert code == 200 and res2["cached"] is True, (code, res2)
        assert res2["answer"] == res["answer"], res2
        assert MOCK["n"] == n1, (MOCK["n"], n1)
        print("OK cache: la segunda vez no vuelve a preguntar al LLM")

        # Modelo de razonamiento: content vacio NUNCA es un exito
        razon = "linea rara RAZON para gastar el presupuesto"
        code, res3 = req(base_a, "POST", "/api/analyze", {"line": razon})
        assert code == 503 and "no devolvio texto" in res3["error"], \
            (code, res3)
        n2 = MOCK["n"]
        # Un fallo no se cachea: el siguiente intento vuelve a preguntar
        code, res4 = req(base_a, "POST", "/api/analyze", {"line": razon})
        assert code == 503 and "no devolvio texto" in res4["error"], \
            (code, res4)
        assert MOCK["n"] == n2 + 1, (MOCK["n"], n2)
        print("OK razonamiento: content vacio sale como error amigable y "
              "no se cachea")

        # B: LLM en puerto caido -> fallo limpio y rapido
        dead = "http://127.0.0.1:%d/v1" % _free_port()
        srv_b = start_server(PORT_B, {"LOGVIEWER_LLM_URL": dead})
        time.sleep(1.2)
        base_b = "http://127.0.0.1:%d" % PORT_B
        assert get(base_b, "/api/config")["llm"] is True
        t0 = time.time()
        code, res5 = req(base_b, "POST", "/api/analyze", {"line": linea})
        dt = time.time() - t0
        assert code == 503 and res5.get("error"), (code, res5)
        assert dt < 9, dt  # timeout corto: nunca cuelga la peticion
        print("OK puerto caido: fallo limpio en %.1f s con mensaje "
              "amigable" % dt)

        # C: sin LOGVIEWER_LLM_URL -> llm:false (aviso de funcion SOLO
        # local en el drawer) y con LOGVIEWER_REPO_URL para probar el
        # enlace de descarga de la version local
        # SPLUNK_PASS forzada a vacio: la comprobacion del aviso del
        # operador no depende del entorno de quien corre el smoke
        srv_c = start_server(PORT_C, {"LOGVIEWER_REPO_URL": REPO_URL,
                                      "SPLUNK_PASS": ""})
        time.sleep(1.2)
        base_c = "http://127.0.0.1:%d" % PORT_C
        assert get(base_c, "/api/config")["llm"] is False
        code, res6 = req(base_c, "POST", "/api/analyze", {"line": linea})
        assert code == 404 and "no esta configurado" in res6.get("error", ""), \
            (code, res6)
        print("OK sin LLM: config llm:false y /api/analyze 404")

        # F (VERSION 1.2): avisos de funciones SOLO local con llm:false.
        # /api/config expone repo_url; la UI servida trae el aviso del
        # drawer ("funcion SOLO local") y el enlace apunta a repo_url;
        # la seccion Splunk trae el aviso del operador (splunk:false).
        cfg_c = get(base_c, "/api/config")
        assert cfg_c["llm"] is False
        assert cfg_c["repo_url"] == REPO_URL, cfg_c
        html = urllib.request.urlopen(
            base_c + "/").read().decode("utf-8")
        js = urllib.request.urlopen(
            base_c + "/static/app.js?v=13").read().decode("utf-8")
        assert 'id="an-local-note"' in html and "SOLO local" in html
        assert 'id="an-repo-link"' in html and 'id="an-repo-line"' in html
        # app.js liga el enlace a repo_url y lo oculta si no existe
        assert "a.href = app.repoUrl" in js
        assert "app.repoUrl = cfg.repo_url" in js
        assert 'id="splunk-local-note"' in html and "operador" in html
        assert cfg_c["splunk"] is False  # sin SPLUNK_PASS en C
        print("OK avisos SOLO local: repo_url en /api/config, aviso del"
              " drawer con enlace y aviso Splunk del operador")

        # D (Fase 12B): /api/settings acepta y persiste lang; el valor
        # invalido cae a auto; el lang llega al prompt end-to-end y
        # llm_key distingue idiomas.
        code, sres = req(base_a, "POST", "/api/settings", {"lang": "es"})
        assert code == 200 and sres["lang"] == "es", (code, sres)
        assert get(base_a, "/api/settings")["lang"] == "es"
        linea_es = "timeout de red para probar idioma es (%d)" % int(time.time())
        code, res7 = req(base_a, "POST", "/api/analyze", {"line": linea_es})
        # El mock ecoa el prompt del sistema: con lang=es debe pedir
        # responder en espanol
        assert code == 200 and "espanol" in res7["answer"], (code, res7)
        print("OK /api/settings: acepta lang=es y el analyze lo pasa al prompt")
        code, sres2 = req(base_a, "POST", "/api/settings", {"lang": "fr"})
        assert code == 200 and sres2["lang"] == "auto", (code, sres2)
        code, sres3 = req(base_a, "POST", "/api/settings", {"lang": "auto"})
        assert code == 200 and sres3["lang"] == "auto", (code, sres3)
        print("OK /api/settings: valor invalido cae a auto")

        sys.path.insert(0, HERE)
        import server as srvmod
        linea_k = "linea para probar idiomas de cache"
        assert srvmod.llm_key(linea_k, lang="es") != \
            srvmod.llm_key(linea_k, lang="en")
        print("OK llm_key: es/en distinguidos (dos hashes distintos para"
              " la misma linea)")

        # E (Fase 12C): POST /api/diagnose sobre un dataset con varias
        # plantillas ERR. El mock ecoa el prompt en el content: se
        # comprueba que al LLM van plantillas+count (no lineas sueltas)
        # y que la respuesta trae conclusion + top.
        # Nombre unico por corrida: la clave de cache del diagnose incluye
        # el nombre del dataset; un nombre fijo haria que una segunda
        # corrida en el mismo dia saliera de cache (no determinista)
        ds = "p12c_%d.log" % int(time.time())
        body, ct = multipart([(ds, build_err_log())])
        code, res = post_raw(base_a, "/upload", body, ct)
        assert code == 200, (code, res)
        p = wait_progress(base_a, ds)
        assert p["phase"] == "done", p
        code, res = req(base_a, "POST", "/api/activate",
                        {"name": ds})
        assert code == 200, (code, res)
        res = get(base_a, "/api/templates?name=%s&level=ERR" % ds)
        n_tpl = res["total"]
        assert n_tpl == 3, res
        code, d = req(base_a, "POST", "/api/diagnose",
                      {"name": ds, "level": "ERR"})
        assert code == 200, (code, d)
        assert d["cached"] is False and d["analyzed"] == n_tpl, d
        assert d["conclusion"].strip(), d
        # El mock ecoa el prompt: debe ir en plantillas con count...
        assert "PLANTILLA (5 ocurrencias):" in d["conclusion"], d
        assert "fallo de red desde *" in d["conclusion"], d
        # ...y no lineas sueltas del log (el INFO nunca va al LLM)
        assert "aviso menor" not in d["conclusion"], d
        assert len(d["top"]) == 3 and d["top"][0]["count"] == 5, d
        assert "fallo de red desde *" in d["top"][0]["template"], d
        n3 = MOCK["n"]
        print("OK /api/diagnose: conclusion + top con %d plantillas ERR"
              % n_tpl)
        # La segunda vez sale de cache (dataset+level+lang) sin preguntar
        code, d2 = req(base_a, "POST", "/api/diagnose",
                       {"name": ds, "level": "ERR"})
        assert code == 200 and d2["cached"] is True, (code, d2)
        assert d2["conclusion"] == d["conclusion"], d2
        assert MOCK["n"] == n3, (MOCK["n"], n3)
        print("OK /api/diagnose cache: la segunda vez no pregunta al LLM")

        print("\nSMOKE FASE 12A+12B+12C: TODO OK")
    finally:
        for s in (srv_a, srv_b, srv_c):
            if s is not None:
                s.terminate()
                try:
                    s.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    s.kill()
        mock_srv.shutdown()


if __name__ == "__main__":
    main()
