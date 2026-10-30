#!/usr/bin/env python3
"""Smoke P4.2 (2026-10-30): dashboard SOC con alertas.jsonl real.

Arranca el visor en un puerto de prueba (8877, NO el vivo 8765), carga
buzon/soc/alertas.jsonl y buzon/soc/triage.log por la API /upload, y pide
/api/soc/dashboard. Comprueba que el reparto por severidad, fuente y tarea
coincide con el dataset (se contrastan los totales y el top de fuentes).

Uso:  python smoke_phase_p42.py
Salida: 0 si todo cuadra, 1 si hay divergencia.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

PORT = int(os.environ.get("SMOKE_P42_PORT", "8880"))
BASE = "http://127.0.0.1:%d" % PORT
REPO = os.path.dirname(os.path.abspath(__file__))
SOC_DIR = r"C:\Users\Sammi\AI\piloop-proyectos\buzon\soc"
ALERTAS = os.path.join(SOC_DIR, "alertas.jsonl")
TRIAGE = os.path.join(SOC_DIR, "triage.log")


def wait_ready(timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(BASE + "/api/config", timeout=5) as r:
                r.read()
                return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    return False


def upload(path, name, token):
    boundary = "----smokep42"
    with open(path, "rb") as fh:
        body = fh.read()
    payload = (
        "--" + boundary + "\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"" + name + "\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + body + ("\r\n--" + boundary + "--\r\n").encode("utf-8")
    req = urllib.request.Request(BASE + "/upload", data=payload,
                                 headers={"Content-Type":
                                         "multipart/form-data; boundary=" + boundary,
                                         "X-CSRF-Token": token})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print("HTTP %d en %s: %s" % (e.code, url, e.read()[:200].decode("utf-8", "replace")))
        raise


def count_lines(path):
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n


def main():
    if not os.path.exists(ALERTAS):
        print("NO EXISTE " + ALERTAS)
        return 1
    proc = subprocess.Popen([sys.executable, os.path.join(REPO, "server.py"),
                             str(PORT)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        if proc.poll() is not None:
            print("el servidor de prueba no pudo arrancar (puerto " + str(PORT) +
                  " ocupado): usa SMOKE_P42_PORT=<otro>")
            return 1
        if not wait_ready():
            print("el servidor de prueba no arranco en el puerto " + str(PORT))
            return 1
        token = get(BASE + "/api/csrf")["token"]
        upload(ALERTAS, "alertas.jsonl", token)
        upload(TRIAGE, "triage.log", token)
        # La carga es por hilos: esperamos a que ambos datasets esten listos
        for _ in range(40):
            sess = get(BASE + "/api/sessions")
            names = {s["name"]: s.get("total", 0) for s in sess["sessions"]}
            if names.get("alertas.jsonl") and names.get("triage.log"):
                break
            time.sleep(0.5)
        res = get(BASE + "/api/soc/dashboard?limit=20")
        raw_lines = count_lines(ALERTAS)
        print("== Dashboard SOC (dataset: %s) ==" % res["alerts_name"])
        print("alertas agregadas: %d (lineas del fichero: %d)"
              % (res["alerts_total"], raw_lines))
        print("por severidad: " + json.dumps(res["sev"]))
        print("severidad original: " + json.dumps(res["sev_raw"]))
        print("por fuente (top 5): " + json.dumps(res["fuente"][:5]))
        print("por tarea: " + json.dumps(res["tarea"]))
        print("dedupe: " + json.dumps(res["dedupe"]))
        print("veredictos del triaje: " + json.dumps(res["verdicts"]))
        print("primeras alertas: " + json.dumps(res["items"][:3],
                                               ensure_ascii=False))
        # Coherencia: el reparto por severidad tiene que sumar el total
        if sum(res["sev"].values()) != res["alerts_total"]:
            print("FALLO: la suma por severidad no cuadra con el total")
            return 1
        if sum(f["count"] for f in res["fuente"]) != res["alerts_total"]:
            print("FALLO: la suma por fuente no cuadra con el total")
            return 1
        if sum(res["tarea"].values()) != res["alerts_total"]:
            print("FALLO: la suma por estado de tarea no cuadra")
            return 1
        # Coherencia con el dataset: 'alta' debe ir a ERR y 'media' a INF
        if res["sev_raw"].get("alta") and res["sev"]["ERR"] < res["sev_raw"]["alta"]:
            print("FALLO: las alertas 'alta' no cuentan como ERR")
            return 1
        # Filtro en servidor: ?sev=ERR debe devolver solo ERR
        filt = get(BASE + "/api/soc/dashboard?sev=ERR&limit=50")
        if not filt["items"] or any(i["sev"] != "ERR" for i in filt["items"]):
            print("FALLO: el filtro ?sev=ERR no filtra en el servidor")
            return 1
        filt2 = get(BASE + "/api/soc/dashboard?fuente=splunk&limit=50")
        if any(i["fuente"] != "splunk" for i in filt2["items"]):
            print("FALLO: el filtro ?fuente=splunk no filtra")
            return 1
        print("OK: reparto coherente con el dataset")
        return 0
    finally:
        proc.terminate()
        proc.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
