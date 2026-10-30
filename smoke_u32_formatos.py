#!/usr/bin/env python3
"""Smoke U3.2 (2026-10-30): soporte de formato universal, verificado end-to-end.

Sube por la API (con token CSRF) los logs reales de OperVanta y dos muestras
sinteticas exoticas a un visor en marcha, y comprueba por API que cada fichero
tiene formato detectado, histograma no vacia, niveles y columnas.

Uso:
  python server.py 8877                (servidor de prueba, no el vivo)
  python smoke_u32_formatos.py         [--base http://127.0.0.1:8877]

Solo biblioteca estandar. No toca el servidor en 8765.
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from urllib.parse import urlencode

BUZON = r"C:\Users\Sammi\AI\piloop-proyectos\buzon"

SAMPLES = {
    "logfmt_exotico.log": (
        '2026-10-30T09:12:03.481Z level=info service=ingest pid=412 msg="worker started" queue=3\n'
        '2026-10-30T09:12:04.101Z level=warn service=ingest pid=412 msg="retrying after timeout" attempt=2 elapsed_ms=1500\n'
        '2026-10-30T09:12:05.999Z level=error service=ingest pid=412 msg="connection refused" host=10.0.0.5 port=5432\n'
        '2026-10-30T09:12:07.250Z level=debug service=ingest pid=412 msg="payload accepted" bytes=2048\n'
        '2026-10-30T09:12:09.000Z level=info service=ingest pid=412 msg="heartbeat" uptime_s=60\n'
    ),
    "python_logging_exotico.log": (
        "2026-10-30 09:15:01,123 - app.server - INFO - listening on 0.0.0.0:8877\n"
        "2026-10-30 09:15:02,456 - app.db - WARNING - slow query took 2.3s\n"
        "2026-10-30 09:15:03,789 - app.auth - ERROR - token expired for user 42\n"
        "Traceback (most recent call last):\n"
        '  File "app/auth.py", line 88, in validate\n'
        "    raise TokenExpired(user)\n"
        "app.auth.TokenExpired: user 42\n"
        "2026-10-30 09:15:05,000 - app.server - INFO - recovered\n"
    ),
}

TARGETS = [
    ("buzon.log", os.path.join(BUZON, "buzon.log")),
    ("orquestador.log", os.path.join(BUZON, "orquestador.log")),
    ("triage.log", os.path.join(BUZON, "soc", "triage.log")),
    ("alertas.jsonl", os.path.join(BUZON, "soc", "alertas.jsonl")),
    ("logfmt_exotico.log", "logfmt_exotico.log"),
    ("python_logging_exotico.log", "python_logging_exotico.log"),
]


def api_get(base, path, params=None):
    url = base + path
    if params:
        url += "?" + urlencode(params)
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def api_upload(base, token, filepath):
    boundary = "----smokeu32"
    with open(filepath, "rb") as f:
        data = f.read()
    body = (
        ("--" + boundary + "\r\n"
         'Content-Disposition: form-data; name="file"; filename="' +
         os.path.basename(filepath) + "\"\r\n"
         "Content-Type: application/octet-stream\r\n\r\n").encode()
        + data +
        ("\r\n--" + boundary + "--\r\n").encode()
    )
    req = urllib.request.Request(base + "/upload", data=body, method="POST")
    req.add_header("Content-Type", "multipart/form-data; boundary=" + boundary)
    req.add_header("X-CSRF-Token", token)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    ap = argparse.ArgumentParser(description="Smoke U3.2 del visor de logs")
    ap.add_argument("--base", default="http://127.0.0.1:8877",
                    help="URL del visor de prueba (por defecto 8877)")
    ap.add_argument("--out", default="smoke_u32_result.json",
                    help="ruta del JSON con la evidencia")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    here = os.path.dirname(os.path.abspath(__file__))
    for name, text in SAMPLES.items():
        with open(os.path.join(here, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    token = api_get(base, "/api/csrf")["token"]
    results = []
    for name, path in TARGETS:
        if not os.path.isabs(path):
            path = os.path.join(here, path)
        if not os.path.isfile(path):
            results.append({"file": name, "error": "no existe la fuente: " + path})
            continue
        api_upload(base, token, path)
        summary = None
        for _ in range(60):
            try:
                summary = api_get(base, "/api/summary", {"name": name})
            except Exception:
                summary = None
            if summary:
                break
            time.sleep(1)
        rows = api_get(base, "/api/rows", {"name": name, "size": 3})
        hist = api_get(base, "/api/histogram", {"name": name, "gran": "h"})
        results.append({
            "file": name,
            "source": path,
            "format": (summary or {}).get("format"),
            "total": (summary or {}).get("total", 0),
            "parsed": (summary or {}).get("parsed", 0),
            "raw_lines": (summary or {}).get("raw_lines"),
            "raw_pct": (summary or {}).get("raw_pct"),
            "levels": (summary or {}).get("levels"),
            "columns": rows.get("columns"),
            "histogram_total": hist.get("total", 0),
            "histogram_first": (hist.get("buckets") or [None])[0],
        })

    verde = all(r.get("format") and r.get("histogram_total", 0) > 0
                and r.get("columns") for r in results)
    payload = {
        "base": base,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "verde": verde,
        "results": results,
    }
    with open(args.out, "w", encoding="utf-8", newline="\r\n") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    for r in results:
        print("%-28s fmt=%-10s total=%-6s raw%%=%-5s niveles=%-3s hist=%-6s cols=%s" % (
            r["file"], r.get("format"), r.get("total"), r.get("raw_pct"),
            r.get("levels"), r.get("histogram_total"), r.get("columns")))
    print("SUITE DE SMOKE:", "VERDE" if verde else "NO VERDE")
    return 0 if verde else 1


if __name__ == "__main__":
    sys.exit(main())
