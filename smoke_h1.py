#!/usr/bin/env python3
"""Smoke H1 (2026-10-30): secreto de sesion persistido + UI de P1/P2/P3/P4.

Levanta el visor en 8877 con --persist, comprueba:
  1. El secreto de sesion se persiste: tras reiniciar, la cookie firmada
     antes del reinicio sigue autenticando (no se invalida).
  2. Cabeceras de seguridad en la respuesta (/).
  3. Rate limit 429 al exceder /upload.
  4. Filtros en la URL (?q=...&level=ERR) y selector de columnas.
  5. Empty state (filtro sin coincidencias).
  6. /api/soc/dashboard y /api/runbooks (runbooks de OperVanta).

Solo stdlib. No toca el servidor vivo (8765).
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.abspath(__file__))
BASE = "http://127.0.0.1:8877"
LOGS = [
    r"C:\Users\Sammi\AI\piloop-proyectos\buzon\buzon.log",
    r"C:\Users\Sammi\AI\piloop-proyectos\buzon\orquestador.log",
    r"C:\Users\Sammi\AI\piloop-proyectos\buzon\soc\triage.log",
    r"C:\Users\Sammi\AI\piloop-proyectos\buzon\soc\alertas.jsonl",
]
USER = "sammi@example.com"
results = []


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print("%s  %s  %s" % ("OK  " if ok else "FALLO", name, detail))


def req(path, method="GET", headers=None, body=None):
    r = urllib.request.Request(BASE + path, method=method,
                               headers=headers or {})
    if body is not None:
        r.data = body
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode("utf-8")


def wait_health(timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        st, _, _ = req("/api/health")
        if st == 200:
            return True
        time.sleep(0.5)
    return False


def start_server():
    p = subprocess.Popen([sys.executable, "server.py", "8877", "--persist"],
                         cwd=REPO, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    if not wait_health():
        out = p.stdout.read() if p.stdout else ""
        raise RuntimeError("El servidor no arranca: %s" % out)
    return p


def stop_server(p):
    p.terminate()
    try:
        p.wait(timeout=10)
    except Exception:
        p.kill()


def upload(name, path, csrf):
    boundary = "----h1smoke"
    with open(path, "rb") as f:
        data = f.read()
    body = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; "
             "filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n"
             % (boundary, name)).encode("utf-8") + data +
            ("\r\n--%s--\r\n" % boundary).encode("utf-8"))
    return req("/upload", "POST",
               {"Content-Type": "multipart/form-data; boundary=%s" % boundary,
                "Content-Length": str(len(body)),
                "X-CSRF-Token": csrf,
                "Cf-Access-Authenticated-User-Email": USER}, body)


def main():
    # --- Arranque 1 -----------------------------------------------------------
    srv = start_server()
    st, hdrs, body = req("/", headers={"Cf-Access-Authenticated-User-Email": USER})
    cookie = ""
    sc = hdrs.get("Set-Cookie", "")
    for part in sc.split(";"):
        if part.strip().startswith("lv_session="):
            cookie = part.strip()[len("lv_session="):]
    record("cookie de sesion emitida en /", bool(cookie), sc[:80])

    missing = [h for h in ("Strict-Transport-Security", "Referrer-Policy",
                           "Permissions-Policy", "Content-Security-Policy")
               if not hdrs.get(h)]
    record("cabeceras de seguridad en /", not missing,
           "faltan: %s" % missing if missing else
           "HSTS=%s Referrer=%s" % (hdrs.get("Strict-Transport-Security"),
                                    hdrs.get("Referrer-Policy")))

    st, _, body = req("/api/csrf")
    csrf = json.loads(body).get("token", "")
    record("token CSRF", bool(csrf), "")

    uploaded = []
    for path in LOGS:
        if not os.path.isfile(path):
            record("upload %s" % os.path.basename(path), False, "no existe")
            continue
        name = os.path.basename(path)
        st, _, body = upload(name, path, csrf)
        ok = st == 200
        uploaded.append(name)
        record("upload %s" % name, ok, "HTTP %d" % st)

    # --- Filtros en la URL (P1/P3) ------------------------------------------
    target = "triage.log" if "triage.log" in uploaded else (uploaded[0] if uploaded else "")
    if target:
        st, _, body = req("/api/rows?name=%s&q=%s&level=ERR&size=5"
                          % (target, "ESCALADA"),
                          headers={"Cf-Access-Authenticated-User-Email": USER})
        data = json.loads(body) if st == 200 else {}
        cols = data.get("columns") or []
        record("filtro q=ESCALADA&level=ERR en /api/rows",
               st == 200 and data.get("total", 0) > 0,
               "total=%d columnas=%d" % (data.get("total", 0), len(cols)))
        record("selector de columnas (columns en la respuesta)", len(cols) > 0,
              ",".join(cols[:8]))
        st, _, body = req("/api/rows?name=%s&q=%s" % (target, "zzz_no_existe_en_el_log"),
                          headers={"Cf-Access-Authenticated-User-Email": USER})
        data = json.loads(body) if st == 200 else {}
        record("empty state (filtro sin coincidencias)",
               st == 200 and data.get("total", 0) == 0 and not data.get("rows"),
               "total=%d" % data.get("total", 0))

    # --- Dashboard SOC y runbooks (P4) --------------------------------------
    st, _, body = req("/api/soc/dashboard")
    data = json.loads(body) if st == 200 else {}
    record("/api/soc/dashboard", st == 200 and bool(data),
           "claves=%s" % ",".join(list(data)[:6]))

    st, _, body = req("/api/runbooks")
    text = body.decode("utf-8", errors="replace")
    need = ["except silencioso", "PermissionError", "EPIPE", "rotado", "ESCALADA"]
    faltan = [k for k in need if k not in text]
    record("/api/runbooks con los runbooks de OperVanta",
           st == 200 and not faltan,
           "HTTP %d, %d bytes, faltan: %s" % (st, len(body), faltan))

    # --- Rate limit 429 en /upload -------------------------------------------
    tiny = os.path.join(os.environ.get("TEMP", ""), "logviewer", "_h1_tiny.log")
    os.makedirs(os.path.dirname(tiny), exist_ok=True)
    with open(tiny, "w", encoding="utf-8") as f:
        f.write("2026-10-30 11:00:00 smoke: linea de prueba\n")
    codes = []
    for i in range(35):
        st, _, _ = upload("h1_rate_%02d.log" % i, tiny, csrf)
        codes.append(st)
        if st == 429:
            break
    record("rate limit 429 al exceder /upload", 429 in codes,
           "primer 429 en la peticion %d de %d" % (codes.index(429) + 1, len(codes)))

    # --- Persistencia del secreto entre arranques ----------------------------
    secret_path = os.path.join(os.environ.get("TEMP", ""), "logviewer",
                               "session_secret")
    exists = os.path.isfile(secret_path)
    with open(secret_path, "r", encoding="utf-8") as f:
        secret = f.read().strip()
    record("fichero de secreto persistido", exists,
           "%s (%d chars)" % (secret_path, len(secret)))

    stop_server(srv)
    time.sleep(1)
    srv2 = start_server()
    st, _, body = req("/api/sessions", headers={"Cookie": "lv_session=" + cookie})
    data = json.loads(body) if st == 200 else {}
    sessions = data.get("sessions") or []
    record("la cookie de la sesion anterior sigue valida tras reiniciar",
           st == 200 and len(sessions) > 0,
           "sesiones=%d active=%s" % (len(sessions), data.get("active", "")))
    st, _, body = req("/api/health", headers={"Cookie": "lv_session=" + cookie})
    h = json.loads(body) if st == 200 else {}
    record("/api/health con la cookie antigua", st == 200,
           "user=%s backend=%s" % (h.get("user"), h.get("backend")))
    stop_server(srv2)

    fails = [r for r in results if not r[1]]
    print("\n=== %d comprobaciones, %d fallos ===" % (len(results), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
