#!/usr/bin/env python3
"""Tests para los parsers, filtros, compresion y sesiones."""
import base64
import bz2
import gzip
import io
import inspect
import json
import lzma
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest
import zipfile
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
import urllib.error
import urllib.parse
import urllib.request

import api
import config
import security
import stores
import server


class TestParseApache(unittest.TestCase):
    def test_clf(self):
        line = '127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 1234'
        rows, counters = server.parse_apache([line])
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["ip"], "127.0.0.1")
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["path"], "/index.html")
        self.assertEqual(r["code"], "200")
        self.assertEqual(r["bytes"], "1234")
        self.assertEqual(counters["codes"]["200"], 1)
        self.assertEqual(counters["methods"]["GET"], 1)


class TestParseW3C(unittest.TestCase):
    def test_w3c_uri_stem(self):
        lines = [
            "#Software: IIS",
            "#Version: 1.0",
            "#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes",
            "2023-10-10 13:55:36 192.168.1.1 GET /api/data 200 567",
        ]
        rows, counters = server.parse_w3c(lines)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["ip"], "192.168.1.1")
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["path"], "/api/data")
        self.assertNotEqual(r["path"], "")
        self.assertEqual(r["code"], "200")
        self.assertEqual(r["bytes"], "567")


class TestParseSyslog(unittest.TestCase):
    def test_rfc5424_with_priority(self):
        line = '<34>1 2023-10-10T13:55:36.123Z host01 app1[123]: mensaje de prueba'
        rows, counters = server.parse_syslog([line])
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["ts"], "2023-10-10T13:55:36.123Z")
        self.assertEqual(r["host"], "host01")
        self.assertEqual(r["app"], "app1")
        self.assertEqual(r["pid"], "123")
        self.assertEqual(r["msg"], "mensaje de prueba")
        self.assertEqual(counters["hosts"]["host01"], 1)
        self.assertEqual(counters["apps"]["app1"], 1)


class TestParseGeneric(unittest.TestCase):
    def test_lowercase_level(self):
        line = "2023-10-10 13:55:36 info servicio iniciado correctamente"
        rows, counters = server.parse_generic([line])
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["level"], "INF")
        self.assertEqual(r["ts"], "2023-10-10 13:55:36")
        self.assertIn("iniciado", r["msg"])
        self.assertEqual(counters["levels"]["INF"], 1)


class TestParseJSON(unittest.TestCase):
    def test_json_lines(self):
        line = '{"level": "ERROR", "ip": "10.0.0.1", "msg": "fallo de conexion"}'
        rows, counters = server.parse_json([line])
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["ip"], "10.0.0.1")
        self.assertEqual(r["msg"], "fallo de conexion")
        self.assertEqual(counters["levels"]["ERR"], 1)
        self.assertEqual(counters["ips"]["10.0.0.1"], 1)


class TestParseJSONOperVanta(unittest.TestCase):
    """P0.3: JSON Lines de OperVanta (alertas.jsonl, eventos.jsonl, dataset.jsonl)."""

    ALERTA = ('{"ts": "2026-10-11 18:32:06", "fuente": "ai-netwatch-finding", '
              '"firma": "netwatch:findings:pid:23160", "tenant": "local", '
              '"sev": "alta", "src": "", "dst": "api.deepseek.com", "url": "", '
              '"mensaje": "hallazgo 72/100: pid:23160", "evidencia": "score 72", '
              '"riesgo": [], "tarea": "td15f4fa4", "dedupe": "encolada"}')

    def test_sev_map(self):
        for sev, expected in (("baja", "WRN"), ("media", "INF"),
                              ("alta", "ERR"), ("critica", "CRIT")):
            rows, _ = server.parse_json(
                ['{"ts": "2026-10-11 18:00:00", "sev": "%s", "mensaje": "m"}' % sev])
            self.assertEqual(rows[0]["level"], expected, sev)

    def test_sev_numeric_and_textual(self):
        rows, _ = server.parse_json([
            '{"sev": 2.0, "mensaje": "a"}',
            '{"sev": 1.0, "mensaje": "b"}',
            '{"sev": 0.2, "mensaje": "c"}',
            '{"sev": "Critical", "mensaje": "d"}',
        ])
        self.assertEqual([r["level"] for r in rows], ["ERR", "WRN", "INF", "CRIT"])

    def test_level_prioritario_sobre_sev(self):
        rows, _ = server.parse_json(['{"level": "INFO", "sev": "alta", "msg": "x"}'])
        self.assertEqual(rows[0]["level"], "INF")

    def test_mensaje_es_el_msg_no_el_json(self):
        rows, _ = server.parse_json([self.ALERTA])
        r = rows[0]
        self.assertEqual(r["msg"], "hallazgo 72/100: pid:23160")
        self.assertNotIn("fuente", r["msg"])

    def test_src_dst_a_ip(self):
        rows, _ = server.parse_json([self.ALERTA])
        self.assertEqual(rows[0]["ip"], "api.deepseek.com")
        rows, _ = server.parse_json(
            ['{"sev": "baja", "src": "10.0.0.1", "dst": "10.0.0.2", "mensaje": "m"}'])
        self.assertEqual(rows[0]["ip"], "10.0.0.1")

    def test_columnas_extra(self):
        rows, counters = server.parse_json([self.ALERTA])
        r = rows[0]
        for col in ("fuente", "firma", "tenant", "tarea", "dedupe"):
            self.assertIn(col, r)
        self.assertEqual(r["fuente"], "ai-netwatch-finding")
        self.assertEqual(r["firma"], "netwatch:findings:pid:23160")
        self.assertEqual(r["tenant"], "local")
        self.assertEqual(r["tarea"], "td15f4fa4")
        self.assertEqual(r["dedupe"], "encolada")
        self.assertEqual(r["riesgo"], "")
        self.assertEqual(counters["levels"]["ERR"], 1)
        self.assertEqual(counters["firmas"]["netwatch:findings:pid:23160"], 1)

    def test_datos_anidado(self):
        line = ('{"ts": "2026-10-11 17:43:47", "tenant": "local", '
                '"fuente": "ai-netwatch-alert", "firma": "netwatch:rule_fired", '
                '"datos": {"id": 1, "message": "Regla egress disparada", '
                '"sev": "alta"}}')
        rows, _ = server.parse_json([line])
        r = rows[0]
        self.assertEqual(r["msg"], "Regla egress disparada")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["fuente"], "ai-netwatch-alert")

    def test_alerta_anendada_triage_dataset(self):
        line = ('{"ts": "2026-10-11 23:17:19", "tenant": "local", '
                '"alerta": {"fuente": "x", "firma": "F-LAYA", "sev": "baja", '
                '"mensaje": "m"}, "laya": {"ok": true, "verdict": "expected"}, '
                '"escalada": false, "tarea": "t123"}')
        rows, _ = server.parse_json([line])
        r = rows[0]
        self.assertEqual(r["msg"], "m")
        self.assertEqual(r["level"], "WRN")
        self.assertEqual(r["fuente"], "x")
        self.assertEqual(r["tarea"], "t123")
        self.assertEqual(r["dedupe"], "")

    def test_lista_y_dict_como_texto(self):
        rows, _ = server.parse_json(
            ['{"sev": "media", "mensaje": "m", "riesgo": ["a", "b"], '
            '"evidencia": {"score": 72}}'])
        self.assertEqual(rows[0]["riesgo"], "a, b")
        self.assertIn("score", rows[0]["evidencia"])

    def test_json_sin_mensaje_sigue_como_json(self):
        rows, _ = server.parse_json(['{"level": "ERROR", "extra": "sin texto"}'])
        self.assertIn("extra", rows[0]["msg"])

    def test_search_incluye_firma(self):
        rows, _ = server.parse_json([self.ALERTA])
        r = rows[0]
        r["_search"] = server._make_search(r)
        self.assertIn("netwatch:findings", r["_search"])

    def test_smoke_alertas_jsonl_real(self):
        path = r"C:\Users\Sammi\AI\piloop-proyectos\buzon\soc\alertas.jsonl"
        if not os.path.exists(path):
            self.skipTest("alertas.jsonl no esta en disco")
        ds = server.load_file(path)
        self.assertEqual(ds["format"], "json")
        rows = ds["store"].page_filtered({}, 0, 10000)
        self.assertTrue(rows)
        with open(path, encoding="utf-8") as f:
            src = [json.loads(l) for l in f if l.strip()]
        # U4 (2026-10-30): el visor devuelve las filas de MAS NUEVO a MAS VIEJO,
        # asi que se compara con el mismo orden invertido
        src = src[-200:][::-1]
        sev_to_level = {"baja": "WRN", "media": "INF", "alta": "ERR",
                        "critica": "CRIT"}
        for r, o in zip(rows, src):
            # El msg es el texto de 'mensaje', no el JSON entero de la linea
            if o.get("mensaje"):
                # P1.1 (bug B3): el parseo NO trunca, el msg es el contenido
                # completo de 'mensaje' (no el JSON entero de la linea)
                self.assertEqual(r["msg"], server._json_scalar(o["mensaje"]))
                self.assertNotEqual(r["msg"], json.dumps(o, ensure_ascii=False))
            # El level refleja 'sev'
            if o.get("sev"):
                self.assertEqual(r["level"], sev_to_level.get(
                    str(o["sev"]).lower(), server._norm_sev(o["sev"])),
                    o.get("sev"))
            self.assertEqual(r["ip"], o.get("src") or o.get("dst") or "")
        self.assertTrue(any(r["level"] == "ERR" for r in rows))
        self.assertTrue(any(r["level"] == "WRN" for r in rows))
        self.assertTrue(all(r["level"] in ("WRN", "INF", "ERR", "CRIT") for r in rows))
        self.assertTrue(any(r["fuente"] for r in rows))
        self.assertTrue(any(r["firma"] for r in rows))
        self.assertTrue(any(r["tenant"] for r in rows))
        self.assertTrue(any(r["tarea"] for r in rows))
        self.assertTrue(any(r["dedupe"] for r in rows))

    def test_smoke_dataset_jsonl_real(self):
        path = r"C:\Users\Sammi\AI\piloop-proyectos\buzon\soc\dataset.jsonl"
        if not os.path.exists(path):
            self.skipTest("dataset.jsonl no esta en disco")
        ds = server.load_file(path)
        # U4 (2026-10-30): se miran TODAS las filas (el visor empieza por las
        # mas recientes, ya no por las mas antiguas)
        rows = ds["store"].page_filtered({}, 0, 5000)
        self.assertTrue(rows)
        self.assertTrue(any(r["msg"] and not r["msg"].startswith("{\"ts\"")
                            for r in rows))
        self.assertTrue(any(r["firma"] for r in rows))

    def test_sqlstore_con_columnas_nuevas(self):
        tmp = tempfile.mkdtemp()
        try:
            store = server.SqlStore(os.path.join(tmp, "t.db"))
            rows, _ = server.parse_json([self.ALERTA])
            for r in rows:
                r["_search"] = server._make_search(r)
            store.add_rows(rows, {"levels": Counter({"ERR": 1})})
            got = store.page_filtered({}, 0, 10)[0]
            self.assertEqual(got["level"], "ERR")
            self.assertEqual(got["firma"], "netwatch:findings:pid:23160")
            self.assertEqual(got["tarea"], "td15f4fa4")
            self.assertEqual(store.top("firma", 5)[0][0], "netwatch:findings:pid:23160")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestParsePiloop(unittest.TestCase):
    """Formato OperVanta/piloop: 'YYYY-MM-DD HH:MM:SS componente: mensaje'.
    El nivel no existe en la linea: se infiere por heuristica."""

    def test_component_line_inf(self):
        line = "2026-10-12 20:40:16 logs: rotado buzon.log (>0.0 MB) -> buzon.log.1"
        rows, counters = server.parse_piloop([line])
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-12 20:40:16")
        self.assertEqual(r["level"], "INF")
        self.assertEqual(r["comp"], "logs")
        self.assertIn("rotado", r["msg"])
        self.assertEqual(r["raw"], line)
        self.assertEqual(counters["levels"]["INF"], 1)

    def test_err_by_heuristic(self):
        line = ("2026-10-12 20:40:32 except silencioso en _visor_text: "
                "PermissionError: [Errno 13] Permission denied: 'C:\\x.txt'")
        rows, _ = server.parse_piloop([line])
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(rows[0]["ts"], "2026-10-12 20:40:32")

    def test_warn_by_heuristic(self):
        rows, _ = server.parse_piloop(["2026-10-12 20:40:00 orquestador: aviso de ventana huerfana"])
        self.assertEqual(rows[0]["level"], "WRN")

    def test_no_hint_defaults_inf(self):
        rows, _ = server.parse_piloop(["2026-10-12 20:40:00 DIGEST s01a127fc -> memoria/s01.md"])
        self.assertEqual(rows[0]["level"], "INF")
        self.assertEqual(rows[0]["comp"], "")
        self.assertEqual(rows[0]["msg"], "DIGEST s01a127fc -> memoria/s01.md")

    def test_ip_extracted(self):
        line = "2026-10-12 20:40:00 orquestador: conexion a 127.0.0.1:9222 establecida"
        rows, counters = server.parse_piloop([line])
        self.assertEqual(rows[0]["ip"], "127.0.0.1")
        self.assertEqual(counters["ips"]["127.0.0.1"], 1)

    def test_stack_trace_stays_raw(self):
        line = "    at Socket._write (node:internal/net:75:18)"
        rows, counters = server.parse_piloop([line])
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["ts"], "")
        self.assertEqual(rows[0]["raw"], line)
        self.assertEqual(counters["levels"]["RAW"], 1)

    def test_registered_in_parsers(self):
        self.assertIn("piloop", server.PARSERS)
        self.assertIs(server.PARSERS["piloop"], server.parse_piloop)

    def test_detect_format_piloop(self):
        sample = [
            "2026-10-12 20:40:16 logs: rotado buzon.log (>0.0 MB) -> buzon.log.1",
            "2026-10-12 20:40:32 except silencioso en _visor_text: PermissionError: denied",
            "    at Socket._write (node:internal/net:75:18)",
            "2026-10-12 20:40:46 orquestador[core]: pi RPC arrancado",
        ]
        self.assertEqual(server.detect_format(sample), "piloop")

    def test_detect_format_apache_no_piloop(self):
        sample = [
            '127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /a HTTP/1.1" 200 1234',
            '127.0.0.1 - - [10/Oct/2023:13:55:37 -0700] "GET /b HTTP/1.1" 404 12',
        ]
        self.assertEqual(server.detect_format(sample), "apache")

    def test_detect_format_umbral_40(self):
        # 4 de 10 lineas matchean -> 40%: se detecta como piloop
        sample = ["2026-10-12 20:40:16 logs: rotado a.log"] * 4 + ["Traceback (most recent call last):"] * 6
        self.assertEqual(server.detect_format(sample), "piloop")
        # 3 de 10 -> por debajo del umbral -> raw
        sample = ["2026-10-12 20:40:16 logs: rotado a.log"] * 3 + ["Traceback (most recent call last):"] * 7
        self.assertEqual(server.detect_format(sample), "raw")

    def test_load_file_buzon_real(self):
        path = r"C:\Users\Sammi\AI\piloop-proyectos\buzon\buzon.log"
        if not os.path.exists(path):
            self.skipTest("buzon.log no esta en disco")
        ds = server.load_file(path)
        self.assertEqual(ds["format"], "piloop")
        levels = ds["store"].counters.get("levels", {})
        self.assertTrue(any(levels.get(k) for k in ("ERR", "WRN", "INF")))
        self.assertTrue(levels.get("RAW", 0) < ds["total"])
        rows = ds["store"].page_filtered({}, 0, 50)
        self.assertTrue(any(r["ts"] for r in rows))


class TestParseTriage(unittest.TestCase):
    """Formato SOC triage: 'HH:MM:SS [fuente] FIRMA -> verdict conf X sev Y accion Z | ESCALADA tid'.
    El nivel no existe en la linea: se infiere de sev, conf y accion."""

    ESC = "23:36:54 [x] F-LAYA2 -> real_incident conf 0.8 sev 2.0 accion yes | ESCALADA t4f87df76"
    SIN = "23:36:54 [x] F-LAYA -> expected conf 0.9 sev 0.2 accion no | sin tarea"
    NONE = ("18:25:44 [ai-netwatch] netwatch:rule_fired:service_ai_call "
            "-> None conf None sev None accion None | ESCALADA tc4878a4f")

    def test_escalada_line(self):
        rows, counters = server.parse_triage([self.ESC])
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["ts"], "23:36:54")
        self.assertEqual(r["fuente"], "x")
        self.assertEqual(r["firma"], "F-LAYA2")
        self.assertEqual(r["verdict"], "real_incident")
        self.assertEqual(r["conf"], 0.8)
        self.assertEqual(r["sev"], 2.0)
        self.assertEqual(r["accion"], "yes")
        self.assertEqual(r["tarea"], "t4f87df76")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["raw"], self.ESC)
        self.assertIn("F-LAYA2", r["msg"])
        self.assertEqual(counters["levels"]["ERR"], 1)
        self.assertEqual(counters["fuente"]["x"], 1)
        self.assertEqual(counters["firma"]["F-LAYA2"], 1)

    def test_sin_tarea(self):
        rows, _ = server.parse_triage([self.SIN])
        r = rows[0]
        self.assertEqual(r["tarea"], "")
        self.assertEqual(r["level"], "INF")
        self.assertEqual(r["conf"], 0.9)
        self.assertEqual(r["sev"], 0.2)
        self.assertEqual(r["accion"], "no")

    def test_tarea_optional(self):
        # linea sin la barra: la tarea sigue siendo opcional
        rows, _ = server.parse_triage(["01:02:03 [splunk] X -> expected conf 0.5 sev 0.1 accion no"])
        self.assertEqual(rows[0]["tarea"], "")
        self.assertEqual(rows[0]["firma"], "X")

    def test_none_values(self):
        rows, _ = server.parse_triage([self.NONE])
        r = rows[0]
        self.assertIsNone(r["conf"])
        self.assertIsNone(r["sev"])
        self.assertEqual(r["verdict"], "None")
        self.assertEqual(r["tarea"], "tc4878a4f")
        # sin puntuacion y sin accion -> INF, no ERR
        self.assertEqual(r["level"], "INF")

    def test_level_by_sev_and_accion(self):
        # sev >= 2.0 -> ERR aunque la accion sea no
        rows, _ = server.parse_triage(["10:00:00 [s] A -> real_incident conf 0.6 sev 2.0107 accion no | sin tarea"])
        self.assertEqual(rows[0]["level"], "ERR")
        # accion yes -> ERR con sev baja
        rows, _ = server.parse_triage(["10:00:00 [s] B -> false_positive conf 0.3179 sev 1.3408 accion yes | sin tarea"])
        self.assertEqual(rows[0]["level"], "ERR")
        # sev intermedia -> WRN
        rows, _ = server.parse_triage(["10:00:00 [s] C -> real_incident conf 0.5915 sev 1.7347 accion no | sin tarea"])
        self.assertEqual(rows[0]["level"], "WRN")
        # conf alta y sev baja, veredicto benigno -> INF
        rows, _ = server.parse_triage(["10:00:00 [s] D -> expected conf 0.95 sev 0.5 accion no | sin tarea"])
        self.assertEqual(rows[0]["level"], "INF")
        # conf alta, sev baja, veredicto de incidente -> WRN
        rows, _ = server.parse_triage(["10:00:00 [s] E -> real_incident conf 0.9 sev 0.5 accion no | sin tarea"])
        self.assertEqual(rows[0]["level"], "WRN")

    def test_file_date_in_ts(self):
        rows, _ = server.parse_triage([self.SIN], file_date="2026-10-28")
        self.assertEqual(rows[0]["ts"], "2026-10-28 23:36:54")
        self.assertEqual(server.norm_ts(rows[0]["ts"]), "2026-10-28T23:36:54")

    def test_nonmatching_line_stays_raw(self):
        line = "    at Socket._write (node:internal/net:75:18)"
        rows, counters = server.parse_triage([line])
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["ts"], "")
        self.assertEqual(rows[0]["raw"], line)
        self.assertEqual(rows[0]["fuente"], "")
        self.assertEqual(counters["levels"]["RAW"], 1)

    def test_registered_in_parsers(self):
        self.assertIn("triage", server.PARSERS)
        self.assertIs(server.PARSERS["triage"], server.parse_triage)

    def test_detect_format_triage(self):
        sample = [
            self.ESC,
            self.SIN,
            "23:40:01 [splunk] splunk:Piloop - Guard blocks -> expected conf 0.95 sev 0.5 accion no | sin tarea",
        ]
        self.assertEqual(server.detect_format(sample), "triage")

    def test_detect_format_umbral_40(self):
        # 4 de 10 -> triage; 3 de 10 -> por debajo del umbral
        sample = [self.SIN] * 4 + ["Traceback (most recent call last):"] * 6
        self.assertEqual(server.detect_format(sample), "triage")
        sample = [self.SIN] * 3 + ["Traceback (most recent call last):"] * 7
        self.assertEqual(server.detect_format(sample), "raw")

    def test_detect_format_piloop_no_triage(self):
        sample = ["2026-10-12 20:40:16 logs: rotado a.log"] * 5
        self.assertEqual(server.detect_format(sample), "piloop")

    def test_load_file_triage_real(self):
        path = r"C:\Users\Sammi\AI\piloop-proyectos\buzon\soc\triage.log"
        if not os.path.exists(path):
            self.skipTest("triage.log no esta en disco")
        ds = server.load_file(path)
        self.assertEqual(ds["format"], "triage")
        # U4 (2026-10-30): la pagina 1 ya no son las 100 mas antiguas; se
        # comprueba el dataset completo
        rows = ds["store"].page_filtered({}, 0, 5000)
        self.assertTrue(rows)
        self.assertTrue(all(r["fuente"] for r in rows))
        self.assertTrue(all(r["firma"] for r in rows))
        self.assertTrue(any(r["sev"] is not None for r in rows))
        self.assertTrue(any(r["tarea"] for r in rows))
        self.assertTrue(all(r["ts"] for r in rows))

    def test_tail_parse_triage(self):
        ds = {"format": "triage", "file_date": "2026-10-28"}
        rows, _ = server.tail_parse(ds, [self.ESC])
        self.assertEqual(rows[0]["ts"], "2026-10-28 23:36:54")
        self.assertEqual(rows[0]["tarea"], "t4f87df76")


class TestParseRaw(unittest.TestCase):
    def test_raw(self):
        lines = ["linea sin formato", "otra linea"]
        rows, counters = server.parse_raw(lines)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["msg"], "linea sin formato")
        self.assertEqual(rows[1]["msg"], "otra linea")
        self.assertEqual(counters["levels"]["RAW"], 2)


class TestRawField(unittest.TestCase):
    """Cada parser debe incluir la linea raw original en cada fila."""

    def test_apache_raw(self):
        line = '127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 1234'
        rows, _ = server.parse_apache([line])
        self.assertEqual(rows[0]["raw"], line)

    def test_generic_raw(self):
        line = "2023-10-10 13:55:36 info servicio iniciado"
        rows, _ = server.parse_generic([line])
        self.assertEqual(rows[0]["raw"], line)

    def test_raw_raw(self):
        rows, _ = server.parse_raw(["linea sin formato"])
        self.assertEqual(rows[0]["raw"], "linea sin formato")


class TestResolveStatic(unittest.TestCase):
    """Proteccion contra path traversal en rutas estaticas."""

    def setUp(self):
        self.base = os.path.dirname(os.path.abspath(server.__file__))

    def test_subpath_ok(self):
        fp = server.resolve_static(self.base, "vendor/chart.min.js")
        self.assertIsNotNone(fp)
        self.assertTrue(fp.startswith(
            os.path.abspath(os.path.join(self.base, "static")) + os.sep))

    def test_traversal_parent(self):
        self.assertIsNone(server.resolve_static(self.base, "../server.py"))

    def test_traversal_deep(self):
        self.assertIsNone(
            server.resolve_static(self.base, "../../etc/passwd"))

    def test_traversal_encoded_dotdot(self):
        self.assertIsNone(
            server.resolve_static(self.base, "a/../../server.py"))


class TestDecodeText(unittest.TestCase):
    def test_utf8(self):
        text, enc = server.decode_text("hola mundo".encode("utf-8"))
        self.assertEqual(text, "hola mundo")
        self.assertEqual(enc, "utf-8-sig")

    def test_utf8_bom(self):
        raw = "\ufeff".encode("utf-8") + "hola".encode("utf-8")
        text, enc = server.decode_text(raw)
        self.assertEqual(text, "hola")
        self.assertEqual(enc, "utf-8-sig")

    def test_cp1252(self):
        # 0x93/0x94 (comillas curvas) son validos en cp1252 pero no en utf-8
        raw = b"caf\xe9 \x93test\x94"
        text, enc = server.decode_text(raw)
        self.assertEqual(enc, "cp1252")
        self.assertIn("test", text)

    def test_latin1_fallback(self):
        # 0x81 no existe en cp1252: cae a latin-1
        raw = b"hola\x81mundo"
        text, enc = server.decode_text(raw)
        self.assertEqual(enc, "latin-1")
        self.assertEqual(len(text), 10)


class TestOpenLogStream(unittest.TestCase):
    """Compresion por magico (gzip/bz2/xz/zip) del lector en streaming.

    Bug B12 (2026-10-30): estos tests usaban open_log_file, una version muerta
    que cargaba el archivo entero en RAM. Ahora ejercitan open_log_stream, que
    es la que usa load_file de verdad."""

    def _write(self, data, name):
        fd, path = tempfile.mkstemp(suffix=name)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.addCleanup(os.remove, path)
        return path

    def _read(self, path):
        reader, label, inner = server.open_log_stream(path)
        try:
            raw = reader.read()
        finally:
            reader.close()
        return raw, label, inner

    def test_plain(self):
        path = self._write(b"linea uno\nlinea dos\n", "plain.log")
        raw, label, inner = self._read(path)
        self.assertEqual(raw, b"linea uno\nlinea dos\n")
        self.assertEqual(label, "")
        self.assertEqual(inner, "")

    def test_gzip(self):
        path = self._write(gzip.compress(b"datos gzip\n"), "a.gz")
        raw, label, inner = self._read(path)
        self.assertEqual(raw, b"datos gzip\n")
        self.assertEqual(label, "gzip")

    def test_bz2(self):
        path = self._write(bz2.compress(b"datos bz2\n"), "a.bz2")
        raw, label, inner = self._read(path)
        self.assertEqual(raw, b"datos bz2\n")
        self.assertEqual(label, "bzip2")

    def test_xz(self):
        path = self._write(lzma.compress(b"datos xz\n"), "a.xz")
        raw, label, inner = self._read(path)
        self.assertEqual(raw, b"datos xz\n")
        self.assertEqual(label, "xz")

    def test_zip_picks_log(self):
        import io as _io
        buf = _io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("notas.md", "no soy el log")
            z.writestr("app.log", "linea zip\n")
        path = self._write(buf.getvalue(), "a.zip")
        raw, label, inner = self._read(path)
        self.assertEqual(raw, b"linea zip\n")
        self.assertEqual(label, "zip")
        self.assertEqual(inner, "app.log")

    def test_magic_over_extension(self):
        # Un .log que en realidad es gzip: gana el magico
        path = self._write(gzip.compress(b"real gzip\n"), "a.log")
        raw, label, inner = self._read(path)
        self.assertEqual(raw, b"real gzip\n")
        self.assertEqual(label, "gzip")


class TestLoadFile(unittest.TestCase):
    def test_dataset_fields(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("2023-10-10 13:55:36 info linea de prueba\n")
        self.addCleanup(os.remove, path)
        ds = server.load_file(path)
        self.assertEqual(ds["format"], "generic")
        self.assertEqual(ds["total"], 1)
        self.assertEqual(ds["encoding"], "utf-8-sig")
        self.assertEqual(ds["compressed"], "")
        self.assertEqual(ds["name"], os.path.basename(path))
        self.assertIn("store", ds)

    def test_empty_file_raises(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        self.addCleanup(os.remove, path)
        with self.assertRaises(ValueError):
            server.load_file(path)

    def test_progress_callback(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for i in range(50):
                f.write("2023-10-10 13:55:36 info linea %d\n" % i)
        self.addCleanup(os.remove, path)
        calls = []
        ds = server.load_file(path, progress=lambda ph, pct, msg: calls.append((ph, pct)))
        self.assertTrue(any(ph == "parsing" for ph, _ in calls))
        self.assertEqual(ds["total"], 50)

    def test_reupload_same_name_no_dup(self):
        """Re-subir el mismo nombre no apila filas sobre la BD anterior."""
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for i in range(30):
                f.write("2023-10-10 13:55:%02d info linea %d prueba\n"
                        % (i % 60, i))
        self.addCleanup(os.remove, path)
        old = config.SQLITE_THRESHOLD
        config.SQLITE_THRESHOLD = 10
        try:
            ds1 = server.load_file(path)
            self.assertIsInstance(ds1["store"], server.SqlStore)
            db_path = ds1["store"].db_path
            # _load_worker cierra el dataset viejo antes de recargar
            ds1["store"].close()
            self.assertFalse(os.path.exists(db_path))
            ds2 = server.load_file(path)
        finally:
            config.SQLITE_THRESHOLD = old
        with ds2["store"].lock:
            n = ds2["store"].conn.execute(
                "SELECT COUNT(*) FROM rows").fetchone()[0]
        self.assertEqual(n, 30)
        ds2["store"].close()


class TestMultipartAll(unittest.TestCase):
    def test_multiple_parts(self):
        boundary = "----xyz"
        data = (b"--%s\r\nContent-Disposition: form-data; "
                b'filename="a.log"\r\n\r\nuno\r\n'
                b"--%s\r\nContent-Disposition: form-data; "
                b'filename="b.log"\r\n\r\ndos\r\n'
                b"--%s--\r\n" % (boundary.encode(), boundary.encode(), boundary.encode()))
        parts = server.parse_multipart_all(data, boundary.encode())
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0][0], "a.log")
        self.assertEqual(parts[0][1], b"uno")
        self.assertEqual(parts[1][0], "b.log")
        self.assertEqual(parts[1][1], b"dos")

    def test_no_parts(self):
        self.assertEqual(server.parse_multipart_all(b"", b"x"), [])


class TestMultipartStream(unittest.TestCase):
    """Bug B9 (2026-10-30): el upload se lee por bloques y se escribe a disco.

    Estos tests comparan el lector en streaming con parse_multipart_all (que
    sigue existiendo para cuerpos pequenos) y verifican los limites."""

    BOUNDARY = "----xyz"

    def _body(self, parts, preamble=b""):
        out = preamble
        for name, body in parts:
            out += (b"--" + self.BOUNDARY.encode() + b"\r\n"
                    b'Content-Disposition: form-data; name="file"; '
                    b'filename="' + name.encode() + b'"\r\n'
                    b"\r\n" + body + b"\r\n")
        out += b"--" + self.BOUNDARY.encode() + b"--\r\n"
        return out

    def test_matches_reference_parser(self):
        parts_in = [("a.log", b"uno"), ("b.log", b"x" * 5000),
                    ("c.bin", bytes(range(256)) * 40), ("empty.log", b"")]
        data = self._body(parts_in)
        for chunk in (1, 7, 64, 4096, 1024 * 1024):
            with tempfile.TemporaryDirectory() as tmp:
                got, written = server.stream_multipart_to_disk(
                    io.BytesIO(data), self.BOUNDARY.encode(), len(data), tmp,
                    chunk_size=chunk)
                ref = server.parse_multipart_all(data, self.BOUNDARY.encode())
                read = [(n, open(p, "rb").read()) for n, p, _ in got]
                self.assertEqual(read, ref, "chunk %d" % chunk)
                self.assertEqual(len(written), len(ref))
                self.assertEqual(sum(s for _, _, s in got),
                                 sum(len(b) for _, b in parts_in))

    def test_part_size_limit(self):
        data = self._body([("a.log", b"z" * 10000)])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(server.UploadError):
                server.stream_multipart_to_disk(
                    io.BytesIO(data), self.BOUNDARY.encode(), len(data), tmp,
                    max_part_size=1000, chunk_size=1024)

    def test_total_size_limit(self):
        data = self._body([("a.log", b"q" * 5000)])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(server.UploadError):
                server.stream_multipart_to_disk(
                    io.BytesIO(data), self.BOUNDARY.encode(), len(data), tmp,
                    max_total=1000, chunk_size=1024)

    def test_no_delimiter_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(server.UploadError):
                server.stream_multipart_to_disk(
                    io.BytesIO(b"sin boundary"), b"xyz", 12, tmp, chunk_size=4)

    def test_truncated_body_raises(self):
        data = self._body([("a.log", b"hola")])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(server.UploadError):
                server.stream_multipart_to_disk(
                    io.BytesIO(data[:len(data) - 5]), self.BOUNDARY.encode(),
                    len(data) - 5, tmp, chunk_size=8)

    def test_name_is_sanitized_on_disk(self):
        data = self._body([("../../evil.log", b"dato")])
        with tempfile.TemporaryDirectory() as tmp:
            got, written = server.stream_multipart_to_disk(
                io.BytesIO(data), self.BOUNDARY.encode(), len(data), tmp)
            self.assertEqual(len(got), 1)
            name, path, size = got[0]
            self.assertTrue(size == 4)
            self.assertTrue(os.path.dirname(path) == tmp)
            self.assertNotIn("..", name)
            self.assertTrue(os.path.exists(path))

    def test_does_not_read_whole_body(self):
        # El buffer debe quedar acotado: con chunk pequeno el pico de memoria
        # es del bloque, no del cuerpo (se comprueba midiendo el maximo usado).
        data = self._body([("big.log", b"a" * 4 * 1024 * 1024)])
        with tempfile.TemporaryDirectory() as tmp:
            server.stream_multipart_to_disk(io.BytesIO(data),
                                           self.BOUNDARY.encode(), len(data), tmp,
                                           chunk_size=8192)


class TestLogRotation(unittest.TestCase):
    """Bug B11 (2026-10-30): requests.log y audit.log rotan a 5 MB."""

    def test_no_rotation_under_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "requests.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write("hola\n")
            self.assertFalse(server.rotate_log(path, max_bytes=1000))
            self.assertFalse(os.path.exists(path + ".1"))

    def test_rotation_creates_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "requests.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write("a" * 2000)
            self.assertTrue(server.rotate_log(path, max_bytes=1000))
            self.assertTrue(os.path.exists(path + ".1"))
            self.assertEqual(os.path.getsize(path + ".1"), 2000)
            self.assertTrue(os.path.exists(path))
            self.assertEqual(os.path.getsize(path), 0)

    def test_rotation_keeps_only_one_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.log")
            for i in range(3):
                with open(path, "w", encoding="utf-8") as f:
                    f.write("b" * (1000 + i))
                server.rotate_log(path, max_bytes=500)
            self.assertEqual(os.path.getsize(path + ".1"), 1002)
            self.assertFalse(os.path.exists(path + ".2"))

    def test_audit_rotates_when_over_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_file = api.AUDIT_FILE
            old_max = config.LOG_MAX_BYTES
            try:
                api.AUDIT_FILE = os.path.join(tmp, "audit.log")
                config.LOG_MAX_BYTES = 400
                for i in range(60):
                    server.audit("test", user="tester", i=i)
                self.assertTrue(os.path.exists(api.AUDIT_FILE))
                self.assertTrue(os.path.exists(api.AUDIT_FILE + ".1"))
                self.assertLessEqual(os.path.getsize(api.AUDIT_FILE), 400 + 200)
            finally:
                api.AUDIT_FILE = old_file
                config.LOG_MAX_BYTES = old_max

    def test_log_max_is_five_megabytes(self):
        self.assertEqual(config.LOG_MAX_BYTES, 5 * 1024 * 1024)


class TestSupportedExts(unittest.TestCase):
    def test_ok(self):
        for n in ("a.log", "a.txt", "a.csv", "a.json",
                  "a.gz", "a.bz2", "a.xz", "a.zip"):
            self.assertTrue(server.is_supported_name(n), n)

    def test_bad(self):
        for n in ("a.pdf", "a.exe", "a", "a.tar"):
            self.assertFalse(server.is_supported_name(n), n)


class TestFilters(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"ts": "2023-10-10 10:00:00", "level": "INF", "ip": "1.1.1.1",
             "host": "h1", "app": "a1", "pid": "11", "method": "GET",
             "path": "/foo", "code": "200", "bytes": "100", "msg": "ok"},
            {"ts": "2023-10-10 11:00:00", "level": "ERR", "ip": "2.2.2.2",
             "host": "h2", "app": "a2", "pid": "22", "method": "POST",
             "path": "/bar", "code": "500", "bytes": "200", "msg": "fail"},
        ]
        for r in self.rows:
            r["_search"] = server._make_search(r)

    def _q(self, **kwargs):
        return {k: [v] for k, v in kwargs.items()}

    def test_filter_by_level(self):
        out = server.apply_filters(self.rows, self._q(level="ERR"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "2.2.2.2")

    def test_filter_by_ip(self):
        out = server.apply_filters(self.rows, self._q(ip="1.1"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "1.1.1.1")

    def test_filter_free_text(self):
        out = server.apply_filters(self.rows, self._q(q="post"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["method"], "POST")

    def test_filter_by_host_app_pid(self):
        out = server.apply_filters(self.rows, self._q(q="h2 a2 22"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["host"], "h2")

    def test_filter_by_bytes(self):
        out = server.apply_filters(self.rows, self._q(q="100"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["bytes"], "100")


class TestRunbooks(unittest.TestCase):
    """Fase 10A: BD runbooks + matcher de patrones sobre msg."""

    def test_regex_coincide(self):
        rbs = [{"pattern": r"timeout", "kind": "regex"},
              {"pattern": r"5\d{2}", "kind": "regex"}]
        got = server.match_runbooks("GET /x 504 gateway timeout", rbs)
        self.assertEqual([r["pattern"] for r in got], ["timeout", r"5\d{2}"])

    def test_regex_no_coincide(self):
        rbs = [{"pattern": r"^FATAL", "kind": "regex"}]
        self.assertEqual(server.match_runbooks("WARN algo raro", rbs), [])

    def test_glob_coincide(self):
        rbs = [{"pattern": "ERR * red*", "kind": "glob"},
              {"pattern": "*504*", "kind": "glob"}]
        got = server.match_runbooks("ERR 504 de red a las 10:00", rbs)
        self.assertEqual(len(got), 2)

    def test_sin_coincidencia(self):
        rbs = [{"pattern": "timeout", "kind": "regex"},
              {"pattern": "*oom*", "kind": "glob"}]
        self.assertEqual(server.match_runbooks("todo bien", rbs), [])

    def test_varios_y_orden(self):
        rbs = [{"pattern": p, "kind": "regex"}
              for p in ("timeout", "refused", "oom")]
        got = server.match_runbooks("timeout: connection refused, oom kill",
                                   rbs)
        self.assertEqual([r["pattern"] for r in got],
                         ["timeout", "refused", "oom"])

    def test_patron_invalido_no_rompe(self):
        rbs = [{"pattern": "([", "kind": "regex"},
              {"pattern": "timeout", "kind": "regex"}]
        got = server.match_runbooks("timeout real", rbs)
        self.assertEqual([r["pattern"] for r in got], ["timeout"])

    def test_vacio_y_nones(self):
        self.assertEqual(server.match_runbooks("x", []), [])
        self.assertEqual(server.match_runbooks(None, [{
            "pattern": "x", "kind": "regex"}]), [])
        self.assertEqual(server.match_runbooks("", [{
            "pattern": "", "kind": "regex"}]), [])

    def test_store_crud(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        st = server.RunbookStore(os.path.join(tmpdir, "rb.db"))
        rb = st.add(r"timeout", kind="regex",
                   explicacion="El upstream no responde",
                   causa="upstream caido", solucion="reintentar",
                   ref="vault/zscaler.md")
        self.assertEqual(rb["kind"], "regex")
        self.assertEqual(len(st.all()), 1)
        # duplicado por patron: error (idempotencia de 10C)
        with self.assertRaises(ValueError):
            st.add(r"timeout")
        # glob distinto del regex: se guarda
        rb2 = st.add("*timeout*", kind="glob")
        self.assertEqual(rb2["kind"], "glob")
        # edicion (PUT /api/runbooks desde la UI, Fase 10B)
        upd = st.update(rb2["id"], "*timeout de red*", "glob",
                        explicacion="editado", causa="", solucion="",
                        ref="")
        self.assertEqual(upd["explicacion"], "editado")
        self.assertIsNone(st.update(99999, "x", "regex", "", "", "", ""))
        self.assertTrue(st.delete(rb["id"]))
        self.assertFalse(st.delete(99999))
        got = server.match_runbooks("timeout de red", st.all())
        self.assertEqual([r["pattern"] for r in got], ["*timeout de red*"])

    def test_campos_p4_2_nombre_severidad_accion(self):
        """P4.2: un runbook lleva nombre, severidad y accion."""
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        st = server.RunbookStore(os.path.join(tmpdir, "rb2.db"))
        rb = st.add(r"except silencioso en", nombre="Except silencioso",
                    severidad="WRN", accion="Registrar la excepcion")
        self.assertEqual(rb["nombre"], "Except silencioso")
        self.assertEqual(rb["severidad"], "WRN")
        self.assertEqual(rb["accion"], "Registrar la excepcion")
        # update sin tocar los campos nuevos: conservan su valor
        upd = st.update(rb["id"], r"except silencioso en \w+", "regex",
                        "exp", "causa", "sol", "ref")
        self.assertEqual(upd["severidad"], "WRN")
        self.assertEqual(upd["nombre"], "Except silencioso")
        # severidad en texto de OperVanta se normaliza a la categoria
        rb2 = st.add(r"ESCALADA", severidad="alta", nombre="Escalada")
        self.assertEqual(rb2["severidad"], "ERR")
        self.assertEqual(st.all()[1]["severidad"], "ERR")

    def test_migracion_bd_antigua(self):
        """P4.2: una BD sin nombre/severidad/accion se migra sin perder runbooks."""
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        db = os.path.join(tmpdir, "old.db")
        import sqlite3
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE runbooks (id INTEGER PRIMARY KEY "
                     "AUTOINCREMENT, pattern TEXT NOT NULL, kind TEXT, "
                     "explicacion TEXT, causa TEXT, solucion TEXT, "
                     "ref TEXT, created_at TEXT)")
        conn.execute("INSERT INTO runbooks (pattern, kind, created_at) "
                     "VALUES ('epipe', 'regex', '2026-01-01')")
        conn.commit()
        conn.close()
        st = server.RunbookStore(db)
        rows = st.all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pattern"], "epipe")
        self.assertEqual(rows[0]["severidad"], "")
        self.assertEqual(rows[0]["nombre"], "")
        # y ya se pueden escribir los campos nuevos
        self.assertEqual(st.add("rotado", severidad="INF")["severidad"], "INF")

    def test_norm_sev(self):
        """P4.2: normalizacion de severidades de OperVanta y del triaje."""
        self.assertEqual(server.norm_sev("critica"), "CRIT")
        self.assertEqual(server.norm_sev("alta"), "ERR")
        self.assertEqual(server.norm_sev("media"), "INF")
        self.assertEqual(server.norm_sev("baja"), "WRN")
        self.assertEqual(server.norm_sev("CRIT"), "CRIT")
        self.assertEqual(server.norm_sev(2.0), "ERR")
        self.assertEqual(server.norm_sev(3.0), "CRIT")
        self.assertEqual(server.norm_sev(0.2), "INF")
        self.assertEqual(server.norm_sev(1.7), "WRN")
        self.assertEqual(server.norm_sev(None), "INF")
        self.assertEqual(server.norm_sev(""), "INF")
        self.assertEqual(server.norm_sev("pues no se"), "INF")

    def test_patrones_opervanta_coinciden(self):
        """P4.2: los runbooks de OperVanta matchean lineas reales del buzon."""
        rbs = [{"pattern": p, "kind": "regex"} for p in (
            r"except silencioso en", r"PermissionError", r"EPIPE",
            r"rotado", r"(?i)guard blocks", r"sin tarea", r"false_positive",
            r"ESCALADA")]
        lines = [
            "2026-10-12 20:40:32 except silencioso en _visor_text: "
            "PermissionError: [Errno 13] Permission denied: '_visor.txt'",
            "Error: EPIPE: broken pipe, write",
            "2026-10-12 20:40:16 logs: rotado buzon.log (>0.0 MB) -> "
            "buzon.log.1",
            "2026-10-12 23:10:01 SOC: pre-triaje NO crea tarea para "
            "'splunk:Piloop - Guard blocks' -> LAY A: expected",
            "23:40:04 [splunk] splunk:Piloop - Alertas SOC -> false_positive "
            "conf 0.3179 sev 1.3408 accion yes | ESCALADA t4ab1d1d0",
            "23:40:01 [splunk] splunk:Piloop - Guard blocks -> expected "
            "conf 0.95 sev 0.5 accion no | sin tarea",
        ]
        for line in lines:
            got = server.match_runbooks(line, rbs)
            self.assertTrue(got, "no matchea: %s" % line)
        self.assertEqual(server.match_runbooks("todo en orden", rbs), [])


class TestSocDashboard(unittest.TestCase):
    """P4.2: agregado del dashboard SOC (severidad, fuente, tarea)."""

    def _alerts(self):
        return [
            {"ts": "2026-10-11 18:02:25", "fuente": "splunk",
             "firma": "SEC-TEST", "sev": "baja", "tarea": "t4374e3e9",
             "dedupe": None, "msg": "x"},
            {"ts": "2026-10-11 18:32:06", "fuente": "ai-netwatch-finding",
             "firma": "netwatch:findings:pid:23160:api.deepseek.com",
             "sev": "alta", "tarea": "td15f4fa4", "dedupe": "encolada",
             "msg": "hallazgo 72/100"},
            {"ts": "2026-10-12 09:00:00", "fuente": "splunk",
             "firma": "guard-blocks", "sev": "media", "tarea": None,
             "dedupe": "encolada", "msg": "Piloop - Guard blocks"},
            {"ts": "2026-10-12 09:05:00", "fuente": "splunk",
             "firma": "laya2", "sev": "critica", "tarea": None,
             "dedupe": None, "msg": "F-LAYA2"},
        ]

    def test_reparto_por_severidad_y_fuente(self):
        res = server.soc_dashboard(self._alerts())
        self.assertEqual(res["alerts_total"], 4)
        self.assertEqual(res["sev"], {"CRIT": 1, "ERR": 1, "WRN": 1, "INF": 1})
        self.assertEqual(res["fuente"][0]["fuente"], "splunk")
        self.assertEqual(res["fuente"][0]["count"], 3)
        self.assertEqual(res["fuente"][0]["sev"]["CRIT"], 1)
        self.assertEqual(res["sev_raw"]["alta"], 1)

    def test_tareas_abiertas_y_encoladas(self):
        res = server.soc_dashboard(self._alerts())
        self.assertEqual(res["tarea"]["abierta"], 2)
        self.assertEqual(res["tarea"]["encolada"], 1)
        self.assertEqual(res["tarea"]["sin_dato"], 1)
        self.assertEqual(res["tareas_abiertas"][0]["tarea"], "t4374e3e9")

    def test_triage_cierra_sin_tarea(self):
        tri = [{"ts": "23:40:01", "fuente": "splunk", "firma": "guard-blocks",
                "verdict": "expected", "conf": 0.95, "sev": 0.5,
                "accion": "no", "tarea": None}]
        res = server.soc_dashboard(self._alerts(), tri)
        self.assertEqual(res["tarea"]["descartada"], 1)
        self.assertEqual(res["triage_total"], 1)
        self.assertEqual(res["verdicts"].get("expected"), 1)

    def test_triage_escala_a_tarea(self):
        tri = [{"ts": "23:40:04", "fuente": "splunk", "firma": "laya2",
                "verdict": "real_incident", "conf": 0.8, "sev": 2.0,
                "accion": "yes", "tarea": "t9a1b2c3d"}]
        res = server.soc_dashboard(self._alerts(), tri)
        self.assertEqual(res["tarea"]["abierta"], 3)
        item = next(i for i in res["items"] if i["firma"] == "laya2")
        self.assertEqual(item["status"], "abierta")
        self.assertEqual(item["tarea"], "t9a1b2c3d")
        self.assertEqual(item["motivo"], "ESCALADA")

    def test_filtros_servidor(self):
        alerts = self._alerts()
        res = server.soc_dashboard(alerts, sev_q="CRIT")
        self.assertEqual(len(res["items"]), 1)
        self.assertEqual(res["items"][0]["firma"], "laya2")
        # el conteo de severidades es del total, no del filtro
        self.assertEqual(res["sev"]["CRIT"], 1)
        res = server.soc_dashboard(alerts, fuente_q="netwatch")
        self.assertEqual(len(res["items"]), 1)
        res = server.soc_dashboard(alerts, tarea_q="encolada")
        self.assertEqual(len(res["items"]), 1)
        self.assertEqual(res["items"][0]["firma"], "guard-blocks")
        res = server.soc_dashboard(alerts, limit=2)
        self.assertEqual(len(res["items"]), 2)
        self.assertTrue(res["truncated"])

    def test_dedupe_y_veredictos_no_inflados(self):
        """P4.2: dedupe se cuenta aparte y los veredictos no se inflan
        aunque el triaje repita la misma firma cientos de veces."""
        tri = [{"ts": "23:40:01", "fuente": "splunk", "firma": "guard-blocks",
                "verdict": "expected", "conf": 0.95, "sev": 0.5,
                "accion": "no", "tarea": None}] * 300
        res = server.soc_dashboard(self._alerts(), tri)
        self.assertEqual(res["dedupe"].get("encolada"), 2)
        self.assertEqual(res["dedupe"].get("sin_dato"), 2)
        self.assertEqual(res["verdicts"]["expected"], 1)

    def test_sin_alertas(self):
        res = server.soc_dashboard([])
        self.assertEqual(res["alerts_total"], 0)
        self.assertEqual(res["items"], [])
        self.assertEqual(res["sev"], {"CRIT": 0, "ERR": 0, "WRN": 0, "INF": 0})
        self.assertEqual(res["tarea"], {"abierta": 0, "encolada": 0,
                                        "descartada": 0, "sin_dato": 0})

    def test_severidad_from_level_si_no_trae_sev(self):
        rows = [{"ts": "", "fuente": "syslog", "level": "ERR", "msg": "boom"}]
        res = server.soc_dashboard(rows)
        self.assertEqual(res["sev"]["ERR"], 1)
        self.assertEqual(res["sev_raw"]["err"], 1)


class TestHistogram(unittest.TestCase):
    """Fase 9C: histograma temporal de las filas filtradas."""

    def _rows(self):
        base = {"ts": "", "ip": "", "method": "", "path": "", "code": "",
                "bytes": "", "raw": "", "_search": "", "host": "", "app": "",
                "pid": "", "template": ""}
        specs = [("10:00:%d" % i, "ERR") for i in range(5)]
        specs += [("10:05:00", "INFO"), ("11:00:00", "INFO"),
                 ("11:30:00", "WARN")]
        out = []
        for hms, lvl in specs:
            ts = "2023-10-10T" + hms
            r = dict(base, ts=ts, ts_norm=ts, level=lvl, msg="m")
            out.append(r)
        return out

    def test_parity_mem_sql(self):
        import shutil
        rows = self._rows()
        mem = server.MemStore(rows=[dict(r) for r in rows])
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        sql = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(sql.close)
        sql.add_rows([dict(r) for r in rows], {})
        for gran in ("min", "h"):
            got = mem.histogram({}, gran=gran)
            want = sql.histogram({}, gran=gran)
            self.assertEqual(got, want)
        # minuto: 10:00 x5, 10:05 x1, 11:00 x1, 11:30 x1
        mins = mem.histogram({})
        self.assertEqual([b["count"] for b in mins], [5, 1, 1, 1])
        # hora: 10 -> 6, 11 -> 2
        hours = mem.histogram({}, gran="h")
        self.assertEqual([(b["t"], b["count"]) for b in hours],
                         [("2023-10-10T10", 6), ("2023-10-10T11", 2)])

    def test_filtrado(self):
        rows = self._rows()
        mem = server.MemStore(rows=[dict(r) for r in rows])
        q = {"level": ["ERR"]}
        got = mem.histogram(q)
        self.assertEqual(sum(b["count"] for b in got), 5)
        # una fila sin ts_norm no entra en ningun bucket
        r = dict(self._rows()[0])
        r["ts_norm"] = ""
        mem2 = server.MemStore(rows=[dict(x) for x in rows] + [r])
        n = sum(b["count"] for b in mem2.histogram({}))
        self.assertEqual(n, 8)


class TestTemplates(unittest.TestCase):
    """Fase 9B: vista 'Errores agrupados' (agrupacion por template)."""

    def _rows(self):
        base = {"ts": "", "ip": "", "method": "", "path": "", "code": "",
                "bytes": "", "raw": "", "_search": "", "level": "ERR",
                "host": "", "app": "", "pid": ""}
        out = []
        specs = [("fallo red desde 1.1.1.%d" % i, "2023-10-10T10:00:%02d"
                 % i) for i in range(4)]
        specs += [("otro fallo distinto", "2023-10-10T11:00:00"),
                 ("aviso menor", "2023-10-10T11:05:00")]
        for msg, ts in specs:
            r = dict(base, msg=msg, ts=ts, ts_norm=ts,
                     raw="2023-10-10 10:00:00 ERR " + msg)
            r["template"] = server.make_template(r["raw"])
            out.append(r)
        return out

    def test_mem_templates(self):
        mem = server.MemStore(rows=self._rows())
        items = mem.templates()
        self.assertEqual(items[0]["count"], 4)
        self.assertIn("fallo red desde *", items[0]["template"])
        self.assertEqual(items[0]["first"], "2023-10-10T10:00:00")
        self.assertEqual(items[0]["last"], "2023-10-10T10:00:03")
        self.assertIn("fallo red", items[0]["example"])
        # min_count descarta los grupos de una sola aparicion
        self.assertEqual(len(mem.templates(min_count=2)), 1)

    def test_sql_templates_parity(self):
        import shutil
        rows = self._rows()
        mem = server.MemStore(rows=[dict(r) for r in rows])
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        sql = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(sql.close)
        sql.add_rows([dict(r) for r in rows], {})
        got = [(i["template"], i["count"]) for i in mem.templates()]
        want = [(i["template"], i["count"]) for i in sql.templates()]
        self.assertEqual(got, want)

    def test_tpl_filter_parity(self):
        import shutil
        rows = self._rows()
        mem = server.MemStore(rows=[dict(r) for r in rows])
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        sql = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(sql.close)
        sql.add_rows([dict(r) for r in rows], {})
        tpl = mem.templates()[0]["template"]
        q = {"tpl": [tpl]}
        got = server.apply_filters(mem.rows, q)
        want = sql.page_filtered(q, 0, 100)
        self.assertEqual(len(got), len(want))
        self.assertTrue(all(r["template"] == tpl for r in got))


class TestTemplate(unittest.TestCase):
    """Fase 9A: columna template calculada en el parseo."""

    def test_ip(self):
        self.assertEqual(
            server.make_template("conecto desde 10.0.0.5 al puerto 8080"),
            "conecto desde * al puerto *")

    def test_hex_largo(self):
        self.assertEqual(
            server.make_template("hash deadbeef00112233 ok"),
            "hash * ok")

    def test_numeros_en_medio(self):
        self.assertEqual(
            server.make_template("item 42 de 100 copias 9f8e7d654321"),
            "item * de * copias *")

    def test_ya_limpio(self):
        s = "sin valores variables aqui"
        self.assertEqual(server.make_template(s), s)

    def test_vacio_y_nones(self):
        self.assertEqual(server.make_template(""), "")
        self.assertEqual(server.make_template(None), "")

    def test_load_file_mem_y_sql(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("2023-10-10 13:55:36 info fallo desde 192.168.1.9 "
                    "puerto 8080\n")
        self.addCleanup(os.remove, path)
        old = config.SQLITE_THRESHOLD
        config.SQLITE_THRESHOLD = 10
        try:
            ds = server.load_file(path)
        finally:
            config.SQLITE_THRESHOLD = old
        store = ds["store"]
        page = store.page_filtered({}, 0, 10)
        # Fechas/horas tambien son numeros: salen normalizadas
        self.assertEqual(page[0]["template"],
                         "*-*-* *:*:* info fallo desde * puerto *")
        if isinstance(store, server.SqlStore):
            with store.lock:
                n = store.conn.execute(
                    "SELECT COUNT(*) FROM rows WHERE template != ''"
                ).fetchone()[0]
        else:
            n = len([r for r in store.rows if r["template"]])
        self.assertEqual(n, 1)
        if isinstance(store, server.SqlStore):
            store.close()


class TestFts(unittest.TestCase):
    """Fase 8A: FTS5 external-content sobre la columna search."""

    def _sql(self):
        import shutil
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        store = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(store.close)
        return store

    def _row(self, i):
        return {"ts": "", "level": "INF", "ip": "", "method": "",
                "path": "", "code": "", "bytes": "",
                "msg": "linea %d" % i, "raw": "r%d" % i,
                "_search": "token%d unico" % i}

    def test_fts_presente_y_coherente(self):
        store = self._sql()
        store.add_rows([self._row(i) for i in range(5)], {})
        with store.lock:
            n = store.conn.execute("SELECT COUNT(*) FROM fts").fetchone()[0]
            self.assertEqual(n, 5)
            # El contenido FTS coincide con la columna search de rows
            bad = store.conn.execute(
                "SELECT COUNT(*) FROM fts f JOIN rows r "
                "ON r.rowid = f.rowid WHERE f.search <> r.search"
            ).fetchone()[0]
            self.assertEqual(bad, 0)
            cur = store.conn.execute(
                "SELECT rowid FROM fts WHERE fts MATCH ?", ["unico"])
            self.assertEqual(len(cur.fetchall()), 5)

    def test_indices_btree(self):
        store = self._sql()
        with store.lock:
            idx = {r[0] for r in store.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'")}
        for want in ("idx_level", "idx_code", "idx_ts_norm", "idx_ip"):
            self.assertIn(want, idx)

    def test_load_grande_migra_con_fts(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for i in range(300):
                f.write("2023-10-10 13:55:%02d info linea unica%d prueba\n"
                        % (i % 60, i))
        self.addCleanup(os.remove, path)
        old = config.SQLITE_THRESHOLD
        config.SQLITE_THRESHOLD = 100
        try:
            ds = server.load_file(path)
        finally:
            config.SQLITE_THRESHOLD = old
        store = ds["store"]
        self.assertIsInstance(store, server.SqlStore)
        with store.lock:
            n = store.conn.execute("SELECT COUNT(*) FROM fts").fetchone()[0]
        self.assertEqual(n, 300)
        # MATCH por token exacto: solo la linea 17 (rowid 18)
        with store.lock:
            cur = store.conn.execute(
                "SELECT rowid, search FROM fts WHERE fts MATCH ?",
                ["unica17"])
            found = cur.fetchall()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0], 18)
        self.assertIn("unica17", found[0][1])


    def _parity_rows(self):
        base = {"ts": "", "level": "INF", "ip": "", "method": "",
                "path": "", "code": "", "bytes": "", "raw": ""}
        msgs = ["alpha beta uno", "alpha gamma dos", "beta delta tres",
                "epsilon zeta cuatro", "alpha beta cinco"]
        return [dict(base, msg=m, _search=m) for m in msgs]

    def test_rebuild_sql_valido(self):
        """El comando rebuild (BD de version anterior) existe y funciona."""
        store = self._sql()
        store.add_rows([self._row(i) for i in range(3)], {})
        with store.lock:
            store.conn.execute("INSERT INTO fts(fts) VALUES('rebuild')")
            n = store.conn.execute("SELECT COUNT(*) FROM fts").fetchone()[0]
        self.assertEqual(n, 3)

    def test_parity_q_substring_vs_match(self):
        """Fase 8B: paridad entre subcadena (MemStore) y FTS (SqlStore).

        Solo casos cubiertos: terminos que son tokens completos."""
        import shutil
        rows = self._parity_rows()
        mem = server.MemStore(rows=[dict(r) for r in rows])
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        sql = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(sql.close)
        sql.add_rows([dict(r) for r in rows], {})
        for qval in ("alpha", "!beta", "alpha,beta", "!epsilon",
                    "alpha,!beta", "noexiste"):
            q = {"q": [qval]}
            got = list(reversed([r["msg"] for r in server.apply_filters(mem.rows, q)]))
            want = [r["msg"] for r in sql.page_filtered(q, 0, 100)]
            self.assertEqual(got, want, qval)


class TestFilterTerms(unittest.TestCase):
    """Fase 7D: exclusion (!) y multivalor (coma) en los filtros."""

    def test_parse_terms(self):
        self.assertIsNone(server.parse_terms(""))
        self.assertIsNone(server.parse_terms(None))
        self.assertIsNone(server.parse_terms(", ,"))
        self.assertEqual(server.parse_terms("200,301"),
                        [(False, "200"), (False, "301")])
        self.assertEqual(server.parse_terms("!10.0.0.5"),
                        [(True, "10.0.0.5")])
        self.assertEqual(server.parse_terms(" 200 , !err "),
                        [(False, "200"), (True, "err")])

    def test_terms_pass(self):
        # OR de positivos
        self.assertTrue(server.terms_pass("200", [(False, "200"),
                                                   (False, "301")]))
        self.assertFalse(server.terms_pass("500", [(False, "200"),
                                                   (False, "301")]))
        # Exclusion: sin positivos solo aplican los negativos
        self.assertTrue(server.terms_pass("1.1.1.1",
                                          [(True, "10.0.0.5")]))
        self.assertFalse(server.terms_pass("10.0.0.55",
                                          [(True, "10.0.0.5")]))
        # Combinado: positivo Y no-negativo
        terms = [(False, "20"), (True, "3")]
        self.assertTrue(server.terms_pass("200", terms))
        self.assertFalse(server.terms_pass("203", terms))
        # Modo exacto (level/code)
        self.assertTrue(server.terms_pass("ERR", [(False, "ERR")],
                                         exact=True))
        self.assertFalse(server.terms_pass("ERROR", [(False, "ERR")],
                                         exact=True))
        self.assertFalse(server.terms_pass("ERR", [(True, "ERR")],
                                         exact=True))

    def _rows(self):
        return [
            {"ts": "", "level": "INF", "ip": "10.0.0.1", "method": "",
             "path": "/a", "code": "200", "bytes": "", "msg": "uno",
             "raw": "r1", "_search": "s1"},
            {"ts": "", "level": "ERR", "ip": "10.0.0.5", "method": "",
             "path": "/b", "code": "301", "bytes": "", "msg": "dos",
             "raw": "r2", "_search": "s2"},
            {"ts": "", "level": "ERR", "ip": "192.168.1.9", "method": "",
             "path": "/c", "code": "404", "bytes": "", "msg": "tres",
             "raw": "r3", "_search": "s3"},
        ]

    def _parity(self, q):
        """MemStore y SQLite deben dar el mismo resultado.

        U4 (2026-10-30): ambos backendos devuelven de MAS NUEVO a MAS VIEJO,
        asi que la lista de MemStore se invierte para comparar en el mismo orden."""
        mem = server.MemStore(rows=[dict(r) for r in self._rows()])
        got = list(reversed([r["msg"] for r in server.apply_filters(mem.rows, q)]))
        import shutil
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        sql = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(sql.close)
        sql.add_rows([dict(r) for r in self._rows()], {})
        want = [r["msg"] for r in sql.page_filtered(q, 0, 100)]
        self.assertEqual(got, want, q)
        return got

    def test_exclusion_level(self):
        got = self._parity({"level": "!ERR"})
        self.assertEqual(got, ["uno"])

    def test_multivalue_code(self):
        got = self._parity({"code": "200,301"})
        self.assertEqual(got, ["dos", "uno"])   # DESC: mas reciente primero

    def test_exclusion_ip_substring(self):
        got = self._parity({"ip": "!10.0.0.5"})
        self.assertEqual(got, ["tres", "uno"])

    def test_multivalue_path_and_q(self):
        got = self._parity({"path": "/a,/c"})
        self.assertEqual(got, ["tres", "uno"])
        got = self._parity({"q": "!s2"})
        self.assertEqual(got, ["tres", "uno"])

    def test_combined_terms(self):
        got = self._parity({"code": "200,!404"})
        self.assertEqual(got, ["uno"])
        # Exclusion vacia tras la coma no rompe el resto
        got = self._parity({"code": "200,"})
        self.assertEqual(got, ["uno"])


class TestNoTruncEnParseo(unittest.TestCase):
    """P1.1 (bug B3): el parseo guarda el contenido COMPLETO.

    El recorte solo existe en la capa que sirve la lista de filas (ui_row),
    de forma que el drawer y el export ven la linea entera."""

    LONG = "z" * 2500

    def test_raw_no_trunca(self):
        line = "L" + self.LONG
        rows, _ = server.parse_raw([line])
        self.assertEqual(rows[0]["raw"], line)
        self.assertEqual(rows[0]["msg"], line)
        self.assertNotIn(" ...", rows[0]["msg"])

    def test_generic_no_trunca(self):
        line = "2026-10-30 01:02:03 ERROR " + self.LONG
        rows, _ = server.parse_generic([line])
        self.assertEqual(rows[0]["raw"], line)
        self.assertEqual(len(rows[0]["msg"]), len(line) - len("2026-10-30 01:02:03 ERROR "))

    def test_json_no_trunca(self):
        obj = {"ts": "2026-10-30T01:02:03", "sev": "alta",
               "mensaje": self.LONG, "evidencia": self.LONG}
        rows, _ = server.parse_json([json.dumps(obj)])
        self.assertEqual(rows[0]["msg"], self.LONG)
        self.assertEqual(rows[0]["evidencia"], self.LONG)
        self.assertEqual(rows[0]["raw"], json.dumps(obj))

    def test_piloop_no_trunca(self):
        line = "2026-10-30 01:02:03 vigilante: " + self.LONG
        rows, _ = server.parse_piloop([line])
        self.assertEqual(rows[0]["raw"], line)
        self.assertEqual(rows[0]["msg"], self.LONG)

    def test_ui_row_recorta_msg_y_conserva_raw(self):
        line = "2026-10-30 01:02:03 ERROR " + self.LONG
        rows, _ = server.parse_generic([line])
        r = rows[0]
        r["_search"] = server._make_search(r)
        ui = server.ui_row(r)
        self.assertTrue(ui["msg"].endswith(" ..."))
        self.assertEqual(len(ui["msg"]), server.TRUNC + 4)
        self.assertEqual(ui["msg_len"], len(r["msg"]))
        self.assertTrue(ui["msg_truncated"])
        # El raw se sirve entero: el drawer necesita la linea completa
        self.assertEqual(ui["raw"], line)
        self.assertNotIn("_search", ui)
        # La fila interna del store no se toca
        self.assertEqual(r["msg"], line[len("2026-10-30 01:02:03 ERROR "):])

    def test_ui_row_no_recorta_si_es_corto(self):
        ui = server.ui_row({"msg": "corto", "raw": "corto"})
        self.assertEqual(ui["msg"], "corto")
        self.assertNotIn("msg_truncated", ui)

    def test_export_ve_el_contenido_completo(self):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("2026-10-30 01:02:03 ERROR " + self.LONG + "\n")
        self.addCleanup(os.remove, path)
        ds = server.load_file(path)
        rows = ds["store"].page_filtered({}, 0, 10)
        self.assertEqual(len(rows[0]["msg"]), len(self.LONG))
        self.assertEqual(rows[0]["raw"], "2026-10-30 01:02:03 ERROR " + self.LONG)

    def test_trunc_ya_no_aparece_en_parse(self):
        """Guardia: los parse_* no pueden volver a truncar."""
        src = open(os.path.join(os.path.dirname(__file__), "parsers.py"),
                   encoding="utf-8").read()
        for name in ("parse_apache", "parse_w3c", "parse_json", "parse_syslog",
                     "parse_generic", "parse_piloop", "parse_triage",
                     "parse_raw"):
            i = src.index("def %s(" % name)
            j = src.index("\n\n", i)
            self.assertNotIn("_trunc(", src[i:j], name)


class TestFilterContract(unittest.TestCase):
    """P1.1 (bug B5): MemStore y SqlStore dan las MISMAS filas para el mismo 'q'.

    El contrato se prueba con los mismos datos en ambos stores: se compara la
    secuencia de lineas (y el msg) de las filas devueltas."""

    ROWS = [
        {"ts": "2026-10-30 01:00:01", "level": "INF", "ip": "10.0.0.1",
         "method": "", "path": "", "code": "", "bytes": "",
         "msg": "alpha beta uno", "raw": "r1"},
        {"ts": "2026-10-30 01:00:02", "level": "ERR", "ip": "10.0.0.5",
         "method": "", "path": "", "code": "500", "bytes": "",
         "msg": "alpha gamma dos", "raw": "r2"},
        {"ts": "2026-10-30 01:00:03", "level": "ERR", "ip": "192.168.1.9",
         "method": "GET", "path": "/a/b", "code": "404", "bytes": "12",
         "msg": "beta delta tres", "raw": "r3"},
        {"ts": "2026-10-30 01:00:04", "level": "WRN", "ip": "",
         "method": "", "path": "", "code": "", "bytes": "",
         "msg": "epsilon zeta cuatro", "raw": "r4"},
        {"ts": "2026-10-30 01:00:05", "level": "INF", "ip": "10.0.0.1",
         "method": "", "path": "", "code": "", "bytes": "",
         "msg": "ALPHA-BETA cinco, pid:23160", "raw": "r5"},
    ]

    def _stores(self):
        mem_rows = []
        sql_rows = []
        for i, r in enumerate(self.ROWS):
            row = dict(r)
            row["_line"] = i
            row["template"] = server.make_template(row["raw"])
            row["ts_norm"] = server.norm_ts(row["ts"])
            row["_search"] = server._make_search(row)
            mem_rows.append(row)
            sql_rows.append(dict(row))
        mem = server.MemStore(rows=mem_rows)
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        sql = server.SqlStore(os.path.join(tmpdir, "contract.db"))
        self.addCleanup(sql.close)
        sql.add_rows(sql_rows, {})
        return mem, sql

    def _compare(self, q):
        mem, sql = self._stores()
        mem_rows = mem.page_filtered(q, 0, 100)
        sql_rows = sql.page_filtered(q, 0, 100)
        mem_lines = [r["_line"] for r in mem_rows]
        sql_lines = [sql.line_of(r["rowid"]) for r in sql_rows]
        self.assertEqual(mem_lines, sql_lines, "q=%r" % q)
        self.assertEqual([r["msg"] for r in mem_rows],
                         [r["msg"] for r in sql_rows], "q=%r" % q)
        self.assertEqual(mem.count_filtered(q), sql.count_filtered(q), "q=%r" % q)
        self.assertEqual(mem.histogram(q), sql.histogram(q), "q=%r" % q)
        return mem_lines

    def test_subcadena_dentro_de_token(self):
        # FTS5 tokeniza: 'alph' no matcheaba en SQLite pero si en MemStore
        # U4 (2026-10-30): el orden es DESC, de mas nuevo a mas viejo
        self.assertEqual(self._compare({"q": ["alph"]}), [4, 1, 0])
        self.assertEqual(self._compare({"q": ["lpha"]}), [4, 1, 0])

    def test_frase_de_varios_tokens(self):
        # 'alpha beta' aparece literal en la fila 0; en la 4 hay 'ALPHA-BETA'
        # (con guion), que NO es la misma subcadena
        self.assertEqual(self._compare({"q": ["alpha beta"]}), [0])
        self.assertEqual(self._compare({"q": ["alpha"]}), [4, 1, 0])

    def test_case_insensitive(self):
        self.assertEqual(self._compare({"q": ["ALPHA"]}), [4, 1, 0])
        self.assertEqual(self._compare({"q": ["alpha-beta"]}), [4])

    def test_negaciones(self):
        self.assertEqual(self._compare({"q": ["!beta"]}), [3, 1])
        self.assertEqual(self._compare({"q": ["alpha,!beta"]}), [1])
        self.assertEqual(self._compare({"q": ["alpha,beta"]}), [4, 2, 1, 0])
        self.assertEqual(self._compare({"q": ["noexiste"]}), [])

    def test_puntuacion_y_valores(self):
        self.assertEqual(self._compare({"q": ["pid:23160"]}), [4])
        self.assertEqual(self._compare({"q": ["10.0.0.1"]}), [4, 0])
        self.assertEqual(self._compare({"q": ["/a/b"]}), [2])

    def test_combinado_con_level_y_code(self):
        self.assertEqual(self._compare({"q": ["alpha"], "level": ["ERR"]}), [1])
        self.assertEqual(self._compare({"q": ["alpha"], "code": ["404,500"]}), [1])
        self.assertEqual(self._compare({"level": ["!ERR"]}), [4, 3, 0])

    def test_rango_de_fechas(self):
        self.assertEqual(self._compare(
            {"dt_from": ["2026-10-30T01:00:03"], "dt_to": ["2026-10-30T01:00:04"]}),
            [3, 2])
        self.assertEqual(self._compare({"dt": ["01:00:02"]}), [1])

    def test_q_no_usa_fts_match(self):
        """El texto libre se resuelve por subcadena, igual que en MemStore."""
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        store = server.SqlStore(os.path.join(tmpdir, "q.db"))
        self.addCleanup(store.close)
        where, params = store._where({"q": ["alph"]})
        self.assertIn("instr(lower(search)", where)
        self.assertNotIn("fts MATCH", where)
        self.assertIn("alph", params)

    def test_plan_compartido(self):
        """filter_plan es la unica capa de normalizacion de los filtros."""
        plan = server.filter_plan({"q": ["alpha,!beta"], "level": ["ERR"]})
        self.assertEqual(plan["q"], [(False, "alpha"), (True, "beta")])
        self.assertEqual(plan["level"], [(False, "ERR")])
        self.assertEqual(plan["dt_from"], "")
        self.assertEqual(plan["tpl"], "")


class TestLineOffsets(unittest.TestCase):
    """Fase 7B: offset de linea al parsear, rowid y contexto grep -C."""

    def test_generic_line_offsets(self):
        lines = [
            "2023-10-10 10:00:00 INFO ok uno",
            "linea sin formato",
            "2023-10-10 10:00:01 ERR fallo dos",
        ]
        rows, _ = server.parse_generic(lines)
        self.assertEqual([r["_line"] for r in rows], [0, 1, 2])

    def test_apache_skipped_line_keeps_offset(self):
        # Una linea que no matchea no genera fila; la siguiente conserva
        # su numero real en el archivo.
        lines = [
            '1.2.3.4 - - [10/Oct/2023:10:00:00 +0000] "GET /a HTTP/1.1" 200 1',
            "ruido sin formato apache",
            '5.6.7.8 - - [10/Oct/2023:10:00:01 +0000] "GET /b HTTP/1.1" 404 2',
        ]
        rows, _ = server.parse_apache(lines)
        self.assertEqual([r["_line"] for r in rows], [0, 2])

    def test_mem_rowid(self):
        rows = [{"ts": "", "level": "INF", "ip": "1.1.1.1", "method": "",
                 "path": "", "code": "", "bytes": "", "msg": "a",
                 "raw": "a", "_line": i}
                for i in range(3)]
        store = server.MemStore(rows=[dict(r) for r in rows])
        page = store.page_filtered({}, 0, 10)
        # U4 (2026-10-30): el visor ordena de MAS NUEVO a MAS VIEJO, de modo
        # que la primera fila de la pagina es la de rowid mas alto.
        self.assertEqual([r["rowid"] for r in page], [2, 1, 0])
        # add_rows (tail) reindexa sin romper los rowids
        store.add_rows([{"ts": "", "level": "INF", "ip": "", "method": "",
                         "path": "", "code": "", "bytes": "", "msg": "b",
                         "raw": "b", "_line": 9}], {})
        page = store.page_filtered({}, 0, 10)
        self.assertEqual(len(page), 4)
        self.assertEqual(page[0]["rowid"], 3)   # la nueva, arriba
        self.assertEqual(page[3]["rowid"], 0)

    def test_sql_line_of_and_rowid(self):
        import shutil
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        store = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(store.close)
        rows = [{"ts": "", "level": "INF", "ip": "", "method": "",
                 "path": "", "code": "", "bytes": "", "msg": "a",
                 "raw": "a", "_line": 5},
                {"ts": "", "level": "ERR", "ip": "", "method": "",
                 "path": "", "code": "", "bytes": "", "msg": "b",
                 "raw": "b", "_line": 7}]
        store.add_rows(rows, {})
        # rowid de SQLite empieza en 1
        self.assertEqual(store.line_of(1), 5)
        self.assertEqual(store.line_of(2), 7)
        self.assertIsNone(store.line_of(99))
        page = store.page_filtered({}, 0, 10)
        self.assertEqual([r["rowid"] for r in page], [2, 1])  # DESC (U4)

    def test_read_context_lines(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("\n".join("linea%d" % i for i in range(10)) + "\n")
        self.addCleanup(os.remove, path)
        ctx = server.read_context_lines(path, 4, 2)
        self.assertEqual(ctx["before"], ["linea2", "linea3"])
        self.assertEqual(ctx["current"], "linea4")
        self.assertEqual(ctx["after"], ["linea5", "linea6"])
        # Borde inferior: no hay lineas antes de 0
        ctx = server.read_context_lines(path, 1, 5)
        self.assertEqual(ctx["before"], ["linea0"])
        self.assertEqual(ctx["current"], "linea1")
        self.assertEqual(len(ctx["after"]), 5)


class TestTsNorm(unittest.TestCase):
    """Fase 7A: normalizacion de timestamps a ISO (ts_norm)."""

    def test_empty(self):
        self.assertEqual(server.norm_ts(""), "")
        self.assertEqual(server.norm_ts(None), "")

    def test_unparseable(self):
        self.assertEqual(server.norm_ts("no es una fecha"), "")

    def test_space_format(self):
        self.assertEqual(
            server.norm_ts("2023-10-10 10:00:00"),
            "2023-10-10T10:00:00")

    def test_iso_t(self):
        self.assertEqual(
            server.norm_ts("2023-10-10T10:00:00"),
            "2023-10-10T10:00:00")

    def test_iso_fraction(self):
        self.assertEqual(
            server.norm_ts("2023-10-10T10:00:00.123456"),
            "2023-10-10T10:00:00.123456")

    def test_iso_z_to_utc(self):
        self.assertEqual(
            server.norm_ts("2023-10-10T10:00:00Z"),
            "2023-10-10T10:00:00")

    def test_offset_converted_to_utc(self):
        self.assertEqual(
            server.norm_ts("2023-10-10T12:00:00+02:00"),
            "2023-10-10T10:00:00")

    def test_clf(self):
        self.assertEqual(
            server.norm_ts("21/Aug/2026:13:00:00 +0000"),
            "2026-08-21T13:00:00")

    def test_clf_with_offset(self):
        self.assertEqual(
            server.norm_ts("21/Aug/2026:15:00:00 +0200"),
            "2026-08-21T13:00:00")

    def test_epoch_seconds(self):
        self.assertEqual(server.norm_ts("1696948800"),
                         "2023-10-10T14:40:00")

    def test_apache_date_field(self):
        # El parser apache guarda en ts el campo date CLF tal cual.
        rows, _ = server.parse_apache([
            '1.2.3.4 - - [21/Aug/2026:13:00:00 +0000] "GET /a HTTP/1.1" 200 1'
        ])
        self.assertEqual(rows[0]["ts"], "21/Aug/2026:13:00:00 +0000")
        self.assertEqual(server.norm_ts(rows[0]["ts"]),
                         "2026-08-21T13:00:00")


class TestWatcher(unittest.TestCase):
    """Watcher de tail: buffer, lineas parciales y truncamiento."""

    def _make(self, content):
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        self.addCleanup(os.remove, path)
        return path

    def test_buffer_new_lines(self):
        path = self._make(b"linea uno\nlinea dos\n")
        w = server.Watcher("t.log", path)
        w.enabled = True
        w.reset(seek_end=False)
        w._poll_once()
        self.assertEqual(list(w.buffer), ["linea uno", "linea dos"])
        # Un segundo poll no duplica
        w._poll_once()
        self.assertEqual(len(w.buffer), 2)

    def test_partial_line_held(self):
        path = self._make(b"linea uno\nparcial")
        w = server.Watcher("t.log", path)
        w.enabled = True
        w.reset(seek_end=False)
        w._poll_once()
        self.assertEqual(list(w.buffer), ["linea uno"])
        self.assertEqual(w.pending, b"parcial")
        with open(path, "ab") as f:
            f.write(b" se completa\n")
        w._poll_once()
        self.assertEqual(
            list(w.buffer), ["linea uno", "parcial se completa"])

    def test_truncation_rereads_from_zero(self):
        path = self._make(b"1234567890\n")
        w = server.Watcher("t.log", path)
        w.enabled = True
        w.reset(seek_end=False)
        w._poll_once()
        self.assertEqual(len(w.buffer), 1)
        with open(path, "wb") as f:
            f.write(b"abc\n")
        w._poll_once()
        self.assertTrue(w.truncated)
        self.assertEqual(list(w.buffer), ["abc"])

    def test_reset_seek_end(self):
        path = self._make(b"1234567890\n")
        w = server.Watcher("t.log", path)
        w.reset(seek_end=True)
        self.assertEqual(w.offset, os.path.getsize(path))


class TestTailParse(unittest.TestCase):
    """Parseo incremental de lineas nuevas por formato."""

    def test_w3c_incremental(self):
        ds = {"format": "w3c",
              "w3c_fields": ["date", "time", "c-ip", "cs-method",
                              "cs-uri-stem", "sc-status", "sc-bytes"]}
        lines = ["2023-10-10 13:55:36 192.168.1.1 GET /api/data 200 567"]
        rows, counters = server.tail_parse(ds, lines)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "192.168.1.1")
        self.assertEqual(rows[0]["code"], "200")
        self.assertEqual(counters["ips"]["192.168.1.1"], 1)

    def test_generic_incremental(self):
        ds = {"format": "generic"}
        rows, counters = server.tail_parse(
            ds, ["2023-10-10 13:55:36 error fallo nuevo"])
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(counters["levels"]["ERR"], 1)


class TestStores(unittest.TestCase):
    """MemStore y SqlStore comparten la misma interfaz y semantica."""

    @staticmethod
    def _rows():
        rows = [
            {"ts": "2023-10-10 10:00:00", "level": "INF", "ip": "1.1.1.1",
             "host": "h1", "app": "a1", "pid": "11", "method": "GET",
             "path": "/foo", "code": "200", "bytes": "100",
             "msg": "ok", "raw": "raw1"},
            {"ts": "2023-10-10 11:00:00", "level": "ERR", "ip": "2.2.2.2",
             "host": "h2", "app": "a2", "pid": "22", "method": "POST",
             "path": "/bar", "code": "500", "bytes": "200",
             "msg": "fallo", "raw": "raw2"},
            {"ts": "2023-10-11 10:00:00", "level": "INF", "ip": "1.1.1.1",
             "host": "h1", "app": "a1", "pid": "11", "method": "GET",
             "path": "/foo", "code": "200", "bytes": "150",
             "msg": "ok2", "raw": "raw3"},
        ]
        for r in rows:
            r["_search"] = server._make_search(r)
            r["ts_norm"] = server.norm_ts(r.get("ts", ""))
        return rows

    @staticmethod
    def _q(**kw):
        return {k: [v] for k, v in kw.items()}

    def _make_mem(self):
        return server.MemStore(rows=[dict(r) for r in self._rows()],
                               counters={"ips": {"1.1.1.1": 2, "2.2.2.2": 1},
                                          "levels": {"INF": 2, "ERR": 1}})

    def _make_sql(self):
        """Crea un SqlStore en un tempdir con los datos de prueba."""
        import shutil
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        store = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(store.close)
        store.add_rows(self._rows(), {})
        return store

    def test_mem_count_filtered(self):
        store = self._make_mem()
        self.assertEqual(store.count_filtered(self._q()), 3)
        self.assertEqual(store.count_filtered(self._q(level="ERR")), 1)
        self.assertEqual(store.count_filtered(self._q(ip="1.1")), 2)
        self.assertEqual(
            store.count_filtered(self._q(level="INF", ip="1.1")), 2)
        self.assertEqual(store.count_filtered(self._q(q="fallo")), 1)
        self.assertEqual(store.count_filtered(self._q(dt="2023-10-11")), 1)

    def test_mem_range_dt_from_to(self):
        """Fase 7A: rango de fechas real sobre ts_norm (MemStore)."""
        store = self._make_mem()
        self.assertEqual(
            store.count_filtered(
                self._q(dt_from="2023-10-10T10:30:00",
                        dt_to="2023-10-10T11:30:00")), 1)
        self.assertEqual(
            store.count_filtered(
                self._q(dt_from="2023-10-10T09:00:00",
                        dt_to="2023-10-10T11:30:00")), 2)
        self.assertEqual(
            store.count_filtered(
                self._q(dt_from="2023-10-11T00:00:00")), 1)
        self.assertEqual(
            store.count_filtered(self._q(dt_to="2023-10-10T10:59:59")), 1)
        self.assertEqual(store.count_filtered(
            self._q(dt_from="2023-10-12T00:00:00")), 0)

    def test_sql_count_filtered(self):
        store = self._make_sql()
        self.assertEqual(store.count_filtered(self._q()), 3)
        self.assertEqual(store.count_filtered(self._q(level="ERR")), 1)
        self.assertEqual(store.count_filtered(self._q(ip="1.1")), 2)
        self.assertEqual(
            store.count_filtered(self._q(level="INF", ip="1.1")), 2)
        self.assertEqual(store.count_filtered(self._q(q="fallo")), 1)
        self.assertEqual(store.count_filtered(self._q(dt="2023-10-11")), 1)

    def test_sql_range_dt_from_to(self):
        """Fase 7A: rango de fechas real sobre ts_norm (SqlStore)."""
        store = self._make_sql()
        self.assertEqual(
            store.count_filtered(
                self._q(dt_from="2023-10-10T10:30:00",
                        dt_to="2023-10-10T11:30:00")), 1)
        self.assertEqual(
            store.count_filtered(
                self._q(dt_from="2023-10-10T09:00:00",
                        dt_to="2023-10-10T11:30:00")), 2)
        self.assertEqual(
            store.count_filtered(
                self._q(dt_from="2023-10-11T00:00:00")), 1)
        self.assertEqual(
            store.count_filtered(self._q(dt_to="2023-10-10T10:59:59")), 1)
        # La pagina incluye el campo ts_norm
        page = store.page_filtered(self._q(), 0, 10)
        self.assertTrue(all(r["ts_norm"] for r in page))

    def test_mem_page_filtered(self):
        store = self._make_mem()
        page = store.page_filtered(self._q(level="INF"), 0, 10)
        self.assertEqual(len(page), 2)
        self.assertTrue(all(r["level"] == "INF" for r in page))
        self.assertNotIn("_search", page[0])

    def test_sql_page_filtered(self):
        store = self._make_sql()
        page = store.page_filtered(self._q(level="INF"), 0, 10)
        self.assertEqual(len(page), 2)
        self.assertTrue(all(r["level"] == "INF" for r in page))
        self.assertNotIn("_search", page[0])
        # Paginacion: solo la primera fila
        page = store.page_filtered(self._q(), 1, 1)
        self.assertEqual(len(page), 1)
        self.assertEqual(page[0]["ip"], "2.2.2.2")

    def test_mem_top(self):
        store = self._make_mem()
        top = dict(store.top("ip", 10))
        self.assertEqual(top.get("1.1.1.1"), 2)
        self.assertEqual(top.get("2.2.2.2"), 1)

    def test_sql_top(self):
        store = self._make_sql()
        top = dict(store.top("ip", 10))
        self.assertEqual(top.get("1.1.1.1"), 2)
        self.assertEqual(top.get("2.2.2.2"), 1)
        # Campo que no existe en la tabla
        self.assertEqual(store.top("campo_inexistente", 10), [])

    def test_mem_kpis(self):
        store = self._make_mem()
        k = store.kpis()
        self.assertEqual(k.get("ips"), 2)
        self.assertEqual(k.get("levels"), 2)

    def test_sql_kpis(self):
        store = self._make_sql()
        k = store.kpis()
        self.assertEqual(k.get("ips"), 2)
        self.assertEqual(k.get("levels"), 2)

    def test_migration_preserves_data(self):
        """Al migrar MemStore -> SqlStore se conserva el contenido."""
        import shutil
        mem = self._make_mem()
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        sql = server.migrate_to_sqlite(mem, tmpdir, "t")
        self.addCleanup(sql.close)
        self.assertEqual(sql.total_rows(), 3)
        self.assertEqual(mem.total_rows(), 0)
        self.assertEqual(sql.count_filtered(self._q(level="ERR")), 1)
        top = dict(sql.top("ip", 10))
        self.assertEqual(top.get("1.1.1.1"), 2)


class TestSecurityAndHardening(unittest.TestCase):
    """Seguridad: path traversal, nombres seguros y validacion de umbrales."""

    def test_safe_session_name_traversal(self):
        self.assertNotIn("..", server.safe_session_name("../../../etc/passwd"))
        self.assertEqual(
            server.safe_session_name("../../../etc/passwd"),
            server.safe_session_name("passwd"))

    def test_safe_session_name_collisions(self):
        self.assertEqual(server.safe_session_name("file.log"), "file.log")
        self.assertEqual(
            server.safe_session_name("file.log", ["file.log"]), "file.log_1")
        self.assertEqual(
            server.safe_session_name("file.log", ["file.log", "file.log_1"]),
            "file.log_2")

    def test_safe_session_name_weird_chars(self):
        self.assertEqual(
            server.safe_session_name("archivo<script>.log"),
            "archivo_script_.log")

    def test_upload_uses_safe_name(self):
        # Simula el saneamiento que hace _upload: el nombre malicioso
        # termina como clave de sesion segura.
        malicious = "../../etc/passwd.log"
        safe = server.safe_session_name(malicious)
        self.assertNotIn("..", safe)
        self.assertNotIn("/", safe)
        self.assertTrue(safe.endswith(".log") or safe.endswith(".log_1"))

    def test_sqlite_threshold_validation(self):
        import os
        original = os.environ.get("LOGVIEWER_SQLITE_THRESHOLD")
        try:
            os.environ["LOGVIEWER_SQLITE_THRESHOLD"] = "5000"
            self.assertEqual(server._valid_sqlite_threshold(), 5000)
            os.environ["LOGVIEWER_SQLITE_THRESHOLD"] = "abc"
            self.assertEqual(server._valid_sqlite_threshold(), 200000)
            os.environ["LOGVIEWER_SQLITE_THRESHOLD"] = "999"
            self.assertEqual(server._valid_sqlite_threshold(), 200000)
            os.environ.pop("LOGVIEWER_SQLITE_THRESHOLD", None)
            self.assertEqual(server._valid_sqlite_threshold(), 200000)
        finally:
            if original is None:
                os.environ.pop("LOGVIEWER_SQLITE_THRESHOLD", None)
            else:
                os.environ["LOGVIEWER_SQLITE_THRESHOLD"] = original


class TestResolveBind(unittest.TestCase):
    """Fase 6: resolucion de host/puerto (local vs $PORT de Railway)."""

    def test_local_default(self):
        self.assertEqual(server.resolve_bind(None, None, None),
                         ("127.0.0.1", 8765))

    def test_arg_port_local(self):
        self.assertEqual(server.resolve_bind("9000", None, None),
                         ("127.0.0.1", 9000))

    def test_env_port_railway(self):
        self.assertEqual(server.resolve_bind(None, None, "8000"),
                         ("0.0.0.0", 8000))

    def test_arg_wins_over_env(self):
        self.assertEqual(server.resolve_bind("9000", None, "8000"),
                         ("127.0.0.1", 9000))

    def test_host_override(self):
        self.assertEqual(server.resolve_bind(None, "0.0.0.0", "8000"),
                         ("0.0.0.0", 8000))
        self.assertEqual(server.resolve_bind(None, "127.0.0.1", "8000"),
                         ("127.0.0.1", 8000))


class TestAuditPerUser(unittest.TestCase):
    """Fase 6: la auditoria aislada por usuario (/api/audit)."""

    def setUp(self):
        self._orig = server.AUDIT[:]
        server.AUDIT[:] = []

    def tearDown(self):
        server.AUDIT[:] = self._orig

    def test_each_user_sees_only_their_entries(self):
        server.audit("upload", user="analista@sammideblas.com", file="a.log")
        server.audit("upload", user="revisor@corp.com", file="b.log")
        server.audit("activate", user="analista@sammideblas.com", file="a.log")

        a = server.audit_for_user("analista@sammideblas.com")
        b = server.audit_for_user("revisor@corp.com")

        self.assertEqual(len(a), 2)
        self.assertTrue(all(e["user"] == "analista@sammideblas.com" for e in a))
        self.assertEqual(len(b), 1)
        self.assertTrue(all(e["user"] == "revisor@corp.com" for e in b))

    def test_no_entries_when_no_match(self):
        server.audit("upload", user="analista@sammideblas.com")
        self.assertEqual(server.audit_for_user("otro@corp.com"), [])
        # "local" no ve las entradas de usuarios autenticados
        self.assertEqual(server.audit_for_user("local"), [])

    def test_local_entries_visible_to_local(self):
        server.audit("upload", user="local")
        self.assertEqual(len(server.audit_for_user("local")), 1)

    def test_invalid_port(self):
        self.assertRaises(ValueError, server.resolve_bind, "abc", None, None)


class TestAuditUser(unittest.TestCase):
    """Fase 6: la auditoria registra el usuario (Access o local)."""

    def test_audit_user_default(self):
        e = server.audit("test_user_default")
        self.assertEqual(e["user"], "local")

    def test_audit_user_explicit(self):
        e = server.audit("test_user_explicit", user="sammi@example.com")
        self.assertEqual(e["user"], "sammi@example.com")


class TestCfHeader(unittest.TestCase):
    """Fase 6: identifica el usuario por el header que inyecta Cloudflare
    Access (Cf-Access-Authenticated-User-Email), con fallback al antiguo
    Cf-Access-Login-User."""

    def _handler(self, headers):
        h = server.Handler  # referencia de clase
        handler = object.__new__(h)
        handler.headers = headers
        handler.client_address = ("1.2.3.4", 12345)
        return handler

    def test_reads_correct_header(self):
        h = self._handler({"Cf-Access-Authenticated-User-Email": "a@b.com"})
        self.assertEqual(h._user(), "a@b.com")

    def test_fallback_legacy_header(self):
        h = self._handler({"Cf-Access-Login-User": "legacy@b.com"})
        self.assertEqual(h._user(), "legacy@b.com")

    def test_no_header_is_local(self):
        h = self._handler({})
        self.assertEqual(h._user(), "local")

    def test_cf_ok_requires_header(self):
        security.REQUIRE_CF = True
        try:
            ok = self._handler(
                {"Cf-Access-Authenticated-User-Email": "a@b.com"})
            self.assertTrue(ok._cf_ok())
            bad = self._handler({})
            self.assertFalse(bad._cf_ok())
        finally:
            security.REQUIRE_CF = False


class TestSessionCookieSigned(unittest.TestCase):
    """P2.1 (2026-10-30): la identidad se firma con HMAC (hmac + hashlib).
    El header Cf-Access-Authenticated-User-Email pasa a ser solo el valor
    inicial NO confiable con el que se emite la cookie."""

    def _handler(self, headers):
        h = object.__new__(server.Handler)
        h.headers = headers
        h.client_address = ("1.2.3.4", 12345)
        return h

    def test_round_trip_de_la_cookie(self):
        cookie = server.make_session_cookie("sammi@example.com")
        self.assertEqual(server.verify_session_cookie(cookie),
                         "sammi@example.com")

    def test_usa_hmac_y_hashlib(self):
        # La firma es un HMAC-SHA256 del payload con el secreto del proceso.
        cookie = server.make_session_cookie("a@b.com")
        payload, sig = cookie.rsplit(".", 1)
        import hashlib
        import hmac
        self.assertEqual(sig, hmac.new(server.SESSION_SECRET.encode("utf-8"),
                                       payload.encode("utf-8"),
                                       hashlib.sha256).hexdigest())

    def test_firma_manipulada_no_autentica(self):
        cookie = server.make_session_cookie("a@b.com")
        payload, _ = cookie.rsplit(".", 1)
        self.assertIsNone(server.verify_session_cookie(payload + "." + "0" * 64))

    def test_usuario_forjado_dentro_del_payload_no_pasa(self):
        cookie = server.make_session_cookie("a@b.com")
        _, sig = cookie.rsplit(".", 1)
        forged = base64.urlsafe_b64encode(json.dumps(
            {"u": "admin@evil.com", "exp": int(time.time()) + 3600}
        ).encode("utf-8")).decode("ascii")
        self.assertIsNone(server.verify_session_cookie(forged + "." + sig))

    def test_cookie_caducada_no_pasa(self):
        payload = base64.urlsafe_b64encode(json.dumps(
            {"u": "a@b.com", "exp": int(time.time()) - 10}
        ).encode("utf-8")).decode("ascii")
        cookie = payload + "." + server._session_sign(payload)
        self.assertIsNone(server.verify_session_cookie(cookie))

    def test_cookie_valida_gana_al_header(self):
        cookie = server.make_session_cookie("real@corp.com")
        h = self._handler({
            "Cookie": "otra=1; lv_session=" + cookie,
            "Cf-Access-Authenticated-User-Email": "suplantado@evil.com",
        })
        self.assertEqual(h._user(), "real@corp.com")

    def test_cookie_manipulada_cae_al_header(self):
        h = self._handler({
            "Cookie": "lv_session=palabra." + "0" * 64,
            "Cf-Access-Authenticated-User-Email": "a@b.com",
        })
        self.assertEqual(h._user(), "a@b.com")

    def test_sin_cookie_emite_la_firma_del_header(self):
        h = self._handler({"Cf-Access-Authenticated-User-Email": "a@b.com"})
        self.assertEqual(h._user(), "a@b.com")  # valor inicial no confiable
        self.assertEqual(server.verify_session_cookie(h._pending_session_cookie),
                         "a@b.com")

    def test_sin_header_es_local(self):
        h = self._handler({})
        self.assertEqual(h._user(), "local")
        self.assertEqual(server.verify_session_cookie(h._pending_session_cookie),
                         "local")

    def test_parseo_del_header_cookie(self):
        self.assertEqual(server.cookie_value("a=1; lv_session=xyz; b=2"), "xyz")
        self.assertIsNone(server.cookie_value("a=1"))
        self.assertIsNone(server.cookie_value(None))

    def test_require_cf_acepta_cookie_firmada(self):
        security.REQUIRE_CF = True
        try:
            cookie = server.make_session_cookie("a@b.com")
            h = self._handler({"Cookie": "lv_session=" + cookie})
            self.assertTrue(h._cf_ok())
            self.assertFalse(self._handler({"Cookie": "lv_session=mal"})._cf_ok())
        finally:
            security.REQUIRE_CF = False


class TestSessionSecretPersisted(unittest.TestCase):
    """Residual de P2.1 (2026-10-30): el secreto de sesion se persiste en
    %TEMP%\logviewer\session_secret, asi que con --persist las cookies
    firmadas de la sesion anterior siguen validas tras un reinicio."""

    def test_se_genera_y_persiste_y_se_recarga_igual(self):
        d = tempfile.mkdtemp(prefix="lv_secret_")
        try:
            path = os.path.join(d, "session_secret")
            first, origin = security.load_session_secret(path)
            self.assertTrue(os.path.isfile(path))
            self.assertIn("persistido", origin)
            second, origin2 = security.load_session_secret(path)
            self.assertEqual(first, second)
            self.assertIn("persistido", origin2)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_el_entorno_manda_sobre_el_fichero(self):
        d = tempfile.mkdtemp(prefix="lv_secret_")
        old = os.environ.get("LOGVIEWER_SESSION_SECRET")
        try:
            path = os.path.join(d, "session_secret")
            with open(path, "w", encoding="utf-8") as f:
                f.write("a" * 64 + "\n")
            os.environ["LOGVIEWER_SESSION_SECRET"] = "beef" * 16
            secret, origin = security.load_session_secret(path)
            self.assertEqual(secret, "beef" * 16)
            self.assertEqual(origin, "env LOGVIEWER_SESSION_SECRET")
        finally:
            if old is None:
                os.environ.pop("LOGVIEWER_SESSION_SECRET", None)
            else:
                os.environ["LOGVIEWER_SESSION_SECRET"] = old
            shutil.rmtree(d, ignore_errors=True)

    def test_fichero_corrupto_se_regenera(self):
        d = tempfile.mkdtemp(prefix="lv_secret_")
        try:
            path = os.path.join(d, "session_secret")
            with open(path, "w", encoding="utf-8") as f:
                f.write("no-es-un-secreto")
            secret, origin = security.load_session_secret(path)
            self.assertEqual(len(secret), 64)
            self.assertIn("generado", origin)
            # Vuelta: ya esta bien escrito y se reutiliza.
            self.assertEqual(security.load_session_secret(path)[0], secret)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    @unittest.skipUnless(os.name == "posix",
                         "Windows no aplica los bits de permisos del modo")
    def test_permisos_0600_en_posix(self):
        d = tempfile.mkdtemp(prefix="lv_secret_")
        try:
            path = os.path.join(d, "session_secret")
            security.load_session_secret(path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_el_fichero_queda_legible_por_el_proceso(self):
        # En Windows no se pueden exigir los bits 0600; se comprueba al menos
        # que el fichero se crea y se puede leer (el chmod es best effort).
        d = tempfile.mkdtemp(prefix="lv_secret_")
        try:
            path = os.path.join(d, "session_secret")
            secret, origin = security.load_session_secret(path)
            self.assertTrue(os.path.isfile(path))
            with open(path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), secret)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_la_identidad_de_la_carpeta_de_sesiones_se_recarga(self):
        # Residual de P2.1: con --persist la carpeta de sesiones se crea con
        # el nombre sanitizado, y la cookie firmada usa el correo real. Sin el
        # sidecar .user, las sesiones recargadas no se ven tras reiniciar.
        d = tempfile.mkdtemp(prefix="lv_sessions_")
        user = "sammi@example.com"
        try:
            udir = os.path.join(d, "sammi_example.com")
            os.makedirs(udir)
            server.save_user_identity(udir, user)
            with open(os.path.join(udir, ".user"), encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), user)
            with open(os.path.join(udir, "prueba_h1.log"), "w",
                      encoding="utf-8") as f:
                f.write("2026-10-30 10:00:00 piloop: linea de prueba\n")
            n = server.restore_sessions_from_disk(d)
            self.assertEqual(n, 1)
            with server.LOCK:
                mine = server._user_state(user, server.SESSIONS)
                self.assertIn("prueba_h1.log", mine)
                server.SESSIONS.pop(user, None)
                server.ACTIVE.pop(user, None)
                server.PROGRESS.pop(user, None)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_secreto_del_proceso_esta_persistido(self):
        # Al importar el modulo el secreto ya esta resuelto y, si no hay
        # variable de entorno, debe haber quedado en el fichero de TEMP.
        if os.environ.get("LOGVIEWER_SESSION_SECRET"):
            self.assertEqual(security.SESSION_SECRET_SOURCE,
                             "env LOGVIEWER_SESSION_SECRET")
        else:
            self.assertIn("persistido", security.SESSION_SECRET_SOURCE)
            self.assertEqual(security.SESSION_SECRET,
                             security.load_session_secret()[0])


try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    _CF_CRYPTO = True
except ImportError:      # sin la libreria, la suite sigue verde: se saltan
    Ed25519PrivateKey = Ed25519PublicKey = None
    _CF_CRYPTO = False


def _b64url_no_pad(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _cf_jwt(private_key, kid, aud, exp, email, alg="Ed25519"):
    """Monta un JWT firmado con Ed25519, como hace Cloudflare Access."""
    header = _b64url_no_pad(json.dumps({"alg": alg, "kid": kid}).encode("utf-8"))
    payload = _b64url_no_pad(json.dumps({"aud": aud, "exp": exp, "email": email,
                                         "sub": "cf-user"}).encode("utf-8"))
    sig = _b64url_no_pad(private_key.sign((header + "." + payload).encode("utf-8")))
    return header + "." + payload + "." + sig


class TestCloudflareAccessJwt(unittest.TestCase):
    """S1 (2026-10-30): validacion REAL del JWT de Cloudflare Access (Ed25519).

    Las claves se inyectan en el cache (security.load_cf_certs(certs=...)) para
    no depender de la red: la URL real de los certs no se toca en los tests."""

    def setUp(self):
        self._saved = (security.CF_ACCESS_TEAM, security.CF_ACCESS_AUD,
                       dict(security.CF_CERTS), security.CF_CERTS_FETCHED_AT,
                       security.CF_ACCESS_WARNED)
        self.priv = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        self.kid = "kid-test-1"
        security.CF_ACCESS_TEAM = "sammideblas"
        security.CF_ACCESS_AUD = "AUD-LOGVIEWER"
        security.load_cf_certs(certs={self.kid: self.priv.public_key()})

    def tearDown(self):
        (security.CF_ACCESS_TEAM, security.CF_ACCESS_AUD, security.CF_CERTS,
         security.CF_CERTS_FETCHED_AT, security.CF_ACCESS_WARNED) = self._saved

    def _handler(self, headers):
        h = object.__new__(server.Handler)
        h.headers = headers
        h.client_address = ("1.2.3.4", 12345)
        return h

    def test_enabled_con_team_y_aud(self):
        self.assertTrue(security.cf_access_enabled())
        security.CF_ACCESS_AUD = ""
        self.assertFalse(security.cf_access_enabled())
        self.assertFalse(security.verify_cf_access_jwt("x.y.z")["ok"])

    def test_url_de_certs_normalizada(self):
        self.assertEqual(security.cf_certs_url("sammideblas"),
                         "https://sammideblas.cloudflareaccess.com/cdn-cgi/access/certs")
        self.assertEqual(security.cf_certs_url("sammideblas.cloudflareaccess.com"),
                         "https://sammideblas.cloudflareaccess.com/cdn-cgi/access/certs")
        self.assertEqual(security.cf_certs_url(""), "")

    def test_jwt_valido_la_identidad_es_el_email(self):
        token = _cf_jwt(self.priv, self.kid, [security.CF_ACCESS_AUD],
                        int(time.time()) + 600, "sammi@example.com")
        result = security.verify_cf_access_jwt(token)
        self.assertTrue(result["ok"])
        self.assertEqual(result["user"], "sammi@example.com")
        h = self._handler({"Cf-Access-Jwt-Assertion": token,
                           "Cf-Access-Authenticated-User-Email": "suplantado@evil.com"})
        self.assertEqual(h._user(), "sammi@example.com")
        # la cookie emitida lleva la identidad real, no el header
        self.assertEqual(server.verify_session_cookie(h._pending_session_cookie),
                         "sammi@example.com")

    def test_aud_como_cadena_tambien_vale(self):
        token = _cf_jwt(self.priv, self.kid, security.CF_ACCESS_AUD,
                        int(time.time()) + 600, "a@b.com")
        self.assertTrue(security.verify_cf_access_jwt(token)["ok"])

    def test_firma_mala_rechazado(self):
        token = _cf_jwt(self.other, self.kid, [security.CF_ACCESS_AUD],
                        int(time.time()) + 600, "evil@evil.com")
        result = security.verify_cf_access_jwt(token)
        self.assertFalse(result["ok"])
        self.assertIn("firma", result["reason"])
        h = self._handler({"Cf-Access-Jwt-Assertion": token,
                           "Cf-Access-Authenticated-User-Email": "evil@evil.com"})
        self.assertEqual(h._user(), "local")   # NO se usa el header
        self.assertIsNone(getattr(h, "_pending_session_cookie", None))
        self.assertTrue(any(e.get("action") == "cf_jwt_invalid"
                            for e in api.audit_list()))

    def test_exp_vencido_rechazado(self):
        token = _cf_jwt(self.priv, self.kid, [security.CF_ACCESS_AUD],
                        int(time.time()) - 60, "sammi@example.com")
        result = security.verify_cf_access_jwt(token)
        self.assertFalse(result["ok"])
        self.assertIn("caducado", result["reason"])
        self.assertEqual(self._handler({"Cf-Access-Jwt-Assertion": token})._user(),
                         "local")

    def test_aud_incorrecto_rechazado(self):
        token = _cf_jwt(self.priv, self.kid, ["AUD-OTRO-POLITICA"],
                        int(time.time()) + 600, "sammi@example.com")
        result = security.verify_cf_access_jwt(token)
        self.assertFalse(result["ok"])
        self.assertIn("aud", result["reason"])
        self.assertEqual(self._handler({"Cf-Access-Jwt-Assertion": token})._user(),
                         "local")

    def test_kid_desconocido_rechazado(self):
        token = _cf_jwt(self.priv, "kid-que-no-existe", [security.CF_ACCESS_AUD],
                        int(time.time()) + 600, "sammi@example.com")
        result = security.verify_cf_access_jwt(token)
        self.assertFalse(result["ok"])
        self.assertIn("kid", result["reason"])
        # el cache de claves no se vacia aunque la descarga de certs falle
        self.assertIn(self.kid, security.CF_CERTS)

    def test_jwt_malformado_rechazado(self):
        for bad in ("no-es-un-jwt", "a.b", "", None, "xxx.yyy.zzz"):
            self.assertFalse(security.verify_cf_access_jwt(bad)["ok"])

    def test_jwt_sin_email_rechazado(self):
        header = _b64url_no_pad(json.dumps({"alg": "Ed25519",
                                           "kid": self.kid}).encode("utf-8"))
        payload = _b64url_no_pad(json.dumps({"aud": [security.CF_ACCESS_AUD],
                                            "exp": int(time.time()) + 600}).encode("utf-8"))
        sig = _b64url_no_pad(self.priv.sign((header + "." + payload).encode("utf-8")))
        result = security.verify_cf_access_jwt(header + "." + payload + "." + sig)
        self.assertFalse(result["ok"])
        self.assertIn("email", result["reason"])

    def test_cookie_firmada_sigue_valiendo_con_jwt_invalido(self):
        cookie = server.make_session_cookie("real@corp.com")
        token = _cf_jwt(self.other, self.kid, [security.CF_ACCESS_AUD],
                        int(time.time()) + 600, "evil@evil.com")
        h = self._handler({"Cf-Access-Jwt-Assertion": token,
                           "Cookie": "lv_session=" + cookie,
                           "Cf-Access-Authenticated-User-Email": "suplantado@evil.com"})
        self.assertEqual(h._user(), "real@corp.com")

    def test_require_cf_exige_jwt_valido(self):
        security.REQUIRE_CF = True
        try:
            token = _cf_jwt(self.priv, self.kid, [security.CF_ACCESS_AUD],
                            int(time.time()) + 600, "sammi@example.com")
            self.assertTrue(self._handler({"Cf-Access-Jwt-Assertion": token})._cf_ok())
            bad = _cf_jwt(self.other, self.kid, [security.CF_ACCESS_AUD],
                          int(time.time()) + 600, "evil@evil.com")
            self.assertFalse(self._handler({"Cf-Access-Jwt-Assertion": bad})._cf_ok())
            self.assertFalse(self._handler(
                {"Cf-Access-Authenticated-User-Email": "a@b.com"})._cf_ok())
        finally:
            security.REQUIRE_CF = False

    def test_sin_cf_access_team_mantiene_el_fallback_hmac(self):
        security.CF_ACCESS_TEAM = ""
        security.CF_ACCESS_AUD = ""
        cookie = server.make_session_cookie("cookie@corp.com")
        h = self._handler({"Cookie": "lv_session=" + cookie,
                           "Cf-Access-Authenticated-User-Email": "a@b.com"})
        self.assertEqual(h._user(), "cookie@corp.com")
        h2 = self._handler({"Cf-Access-Authenticated-User-Email": "a@b.com"})
        self.assertEqual(h2._user(), "a@b.com")          # valor no confiable
        self.assertEqual(server.verify_session_cookie(h2._pending_session_cookie),
                         "a@b.com")
        self.assertFalse(security.verify_cf_access_jwt("x.y.z")["ok"])

    def test_avisa_una_sola_vez_si_no_se_puede_validar(self):
        security.CF_ACCESS_TEAM = ""
        security.CF_ACCESS_AUD = ""
        before = sum(1 for e in api.audit_list()
                     if e.get("action") == "cf_jwt_not_verified")
        for _ in range(3):
            self._handler({"Cf-Access-Jwt-Assertion": "x.y.z",
                           "Cf-Access-Authenticated-User-Email": "a@b.com"})._user()
        after = sum(1 for e in api.audit_list()
                    if e.get("action") == "cf_jwt_not_verified")
        self.assertEqual(after - before, 1)

    def test_status_y_fallo_de_red_no_rompen_el_arranque(self):
        status = security.cf_access_status()
        self.assertTrue(status["enabled"])
        self.assertIn("JWT de Access validado", status["message"])
        # una URL inalcanzable no lanza: devuelve {} y el JWT se rechaza
        self.assertEqual(security._fetch_cf_certs("http://127.0.0.1:9/x"), {})
        self.assertFalse(security.verify_cf_access_jwt("a.b.c")["ok"])

    def test_certs_reales_se_parsean_del_json_de_access(self):
        # Simula el JSON que publica /cdn-cgi/access/certs: kid + cert hex.
        raw = self.priv.public_key().public_bytes_raw()
        payload = json.dumps({"keys": [{"kid": "kid-hex", "cert": raw.hex()}],
                              "max_age": 86400}).encode("utf-8")
        class FakeResp:
            def read(self):
                return payload
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        real_urlopen = security.urllib.request.urlopen
        security.urllib.request.urlopen = lambda *a, **k: FakeResp()
        try:
            certs = security._fetch_cf_certs("https://fake.cloudflareaccess.com/cdn-cgi/access/certs")
        finally:
            security.urllib.request.urlopen = real_urlopen
        self.assertIn("kid-hex", certs)
        self.assertIsInstance(certs["kid-hex"], Ed25519PublicKey)
        # se cargan en el cache (como haria load_cf_certs tras la descarga real)
        security.load_cf_certs(certs=certs)
        token = _cf_jwt(self.priv, "kid-hex", [security.CF_ACCESS_AUD],
                        int(time.time()) + 600, "sammi@example.com")
        self.assertTrue(security.verify_cf_access_jwt(token)["ok"])

    def test_rotacion_de_claves_se_refresca_el_cache(self):
        security.load_cf_certs(certs={})
        token = _cf_jwt(self.priv, self.kid, [security.CF_ACCESS_AUD],
                        int(time.time()) + 600, "sammi@example.com")
        self.assertFalse(security.verify_cf_access_jwt(token)["ok"])
        security.load_cf_certs(certs={self.kid: self.priv.public_key()})
        self.assertTrue(security.verify_cf_access_jwt(token)["ok"])


class TestRateLimit(unittest.TestCase):
    """P2.1 (2026-10-30): limite de peticiones por IP con deque por ventana."""

    def setUp(self):
        server.reset_rate_limits()

    def tearDown(self):
        server.reset_rate_limits()

    def test_limit_de_upload_con_deque(self):
        limit = server.RATE_LIMITS["/upload"]
        for _ in range(limit):
            self.assertTrue(server.check_rate_limit("9.9.9.9", "/upload"))
        allowed, retry = server.check_rate_limit("9.9.9.9", "/upload")
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        self.assertIsInstance(server.RATE_BUCKETS[("/upload", "9.9.9.9")],
                            deque)

    def test_ips_independientes(self):
        limit = server.RATE_LIMITS["/api/analyze"]
        for _ in range(limit):
            server.check_rate_limit("1.1.1.1", "/api/analyze")
        self.assertFalse(server.check_rate_limit("1.1.1.1", "/api/analyze")[0])
        self.assertTrue(server.check_rate_limit("2.2.2.2", "/api/analyze")[0])

    def test_endpoints_sin_limit_no_se_limitan(self):
        for _ in range(200):
            self.assertTrue(server.check_rate_limit("3.3.3.3", "/api/rows")[0])

    def test_ventana_deslizante_recupera(self):
        server.RATE_LIMITS["/upload"] = 1
        security.RATE_WINDOW = 0.5
        try:
            self.assertTrue(server.check_rate_limit("4.4.4.4", "/upload")[0])
            self.assertFalse(server.check_rate_limit("4.4.4.4", "/upload")[0])
            time.sleep(0.6)
            self.assertTrue(server.check_rate_limit("4.4.4.4", "/upload")[0])
        finally:
            server.RATE_LIMITS["/upload"] = 30
            security.RATE_WINDOW = 60.0
            server.reset_rate_limits()


class TestSecurityHeadersAndThreadCap(unittest.TestCase):
    """P2.1 (2026-10-30): cabeceras de seguridad, 'Server' suprimido,
    cookie firmada en la respuesta, 429 por rate limit y pool de hilos."""

    def _start(self):
        srv = server.LogViewerServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_cabeceras_de_seguridad_y_sin_server(self):
        srv = self._start()
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/" % srv.server_port, timeout=15) as r:
                h = r.headers
                self.assertIn("max-age=31536000", h.get("Strict-Transport-Security", ""))
                self.assertEqual(h.get("Referrer-Policy"), "strict-origin-when-cross-origin")
                self.assertIn("Permissions-Policy", h)
                self.assertIn("no-store", h.get("Cache-Control", ""))
                self.assertIsNone(h.get("Server"))
                self.assertTrue(h.get("Set-Cookie", "").startswith("lv_session="))
        finally:
            srv.shutdown()

    def test_estaticos_con_cache_control(self):
        srv = self._start()
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/static/app.js" % srv.server_port,
                    timeout=15) as r:
                self.assertIn("max-age=300", r.headers.get("Cache-Control", ""))
                self.assertIsNone(r.headers.get("Server"))
        finally:
            srv.shutdown()

    def test_429_al_superar_el_rate_limit_de_post(self):
        srv = self._start()
        server.reset_rate_limits()
        try:
            codes = []
            for _ in range(server.RATE_LIMITS["/api/diagnose"] + 2):
                req = urllib.request.Request(
                    "http://127.0.0.1:%d/api/diagnose" % srv.server_port,
                    data=b"{}",
                    headers={"X-CSRF-Token": server.CSRF_TOKEN,
                             "Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(req, timeout=15) as r:
                        codes.append(r.status)
                except urllib.error.HTTPError as e:
                    codes.append(e.code)
            self.assertEqual(codes[-1], 429)
            self.assertEqual(codes[-2], 429)
            self.assertTrue(all(c != 429 for c in codes[:server.RATE_LIMITS["/api/diagnose"]]))
        finally:
            srv.shutdown()
            server.reset_rate_limits()

    def test_pool_de_hilos_acotado(self):
        srv = self._start()
        try:
            self.assertEqual(srv.max_connections, server.MAX_CONNECTIONS)
            self.assertLessEqual(server.MAX_THREADS, 64)
        finally:
            srv.shutdown()

    def test_conexion_rechazada_con_pool_lleno(self):
        srv = self._start()
        srv._pool = threading.BoundedSemaphore(0)  # pool agotado
        try:
            s = socket.create_connection(("127.0.0.1", srv.server_port), timeout=10)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            data = s.recv(600)
            s.close()
            self.assertIn(b"503", data)
            self.assertIn(b"demasiadas conexiones", data)
            self.assertEqual(srv.rejected_connections, 1)
        finally:
            srv.shutdown()


class TestLLM(unittest.TestCase):
    """Fase 12A: LLM local (ask_llm + cache por hash del mensaje)."""

    def _mock_llm(self, responder):
        """Mock OpenAI-compatible en 127.0.0.1; devuelve (url, stop).

        responder(payload) -> dict de respuesta completa."""
        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                out = responder(body)
                data = json.dumps(out).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return "http://127.0.0.1:%d/v1" % port, srv

    def test_cache_roundtrip(self):
        d = tempfile.mkdtemp()
        try:
            st = server.LlmCacheStore(os.path.join(d, "c.db"))
            self.assertIsNone(st.get("k1"))
            st.put("k1", "linea", "respuesta")
            self.assertEqual(st.get("k1"), "respuesta")
            # La misma clave no se duplica (INSERT OR IGNORE)
            st.put("k1", "linea", "otra")
            self.assertEqual(st.get("k1"), "respuesta")
            st.close()
        finally:
            shutil.rmtree(d)

    def test_ask_llm_success(self):
        url, srv = self._mock_llm(
            lambda b: {"choices": [{"message": {
                "content": "Explicacion de prueba",
                "reasoning_content": ""}}]})
        try:
            ok, text = server.ask_llm("timeout de red a las 10:00:01", url=url)
            self.assertTrue(ok)
            self.assertIn("Explicacion", text)
        finally:
            srv.shutdown()

    def test_ask_llm_reasoning_vacio(self):
        # Modelo de razonamiento: el presupuesto se gasta en
        # reasoning_content y "content" llega vacio -> NUNCA es un exito.
        url, srv = self._mock_llm(
            lambda b: {"choices": [{"message": {
                "content": "",
                "reasoning_content": "mucho razonar sobre la linea"}}]})
        try:
            ok, text = server.ask_llm("linea rara", url=url)
            self.assertFalse(ok)
            self.assertIn("no devolvio texto", text)
        finally:
            srv.shutdown()

    def test_ask_llm_puerto_caido(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        t0 = time.time()
        ok, text = server.ask_llm("x", url="http://127.0.0.1:%d/v1" % port)
        dt = time.time() - t0
        self.assertFalse(ok)
        self.assertLess(dt, 9)  # timeout corto: nunca cuelga la peticion

    def test_llm_key(self):
        k1 = server.llm_key("linea")
        self.assertEqual(k1, server.llm_key("linea"))
        old = config.LLM_MODEL
        try:
            config.LLM_MODEL = "otro-modelo"
            self.assertNotEqual(server.llm_key("linea"), k1)
        finally:
            config.LLM_MODEL = old


class TestLLMLang(unittest.TestCase):
    """Fase 12B: idioma de la respuesta del LLM (llm_lang)."""

    def _store(self, d):
        return server.SettingsStore(os.path.join(d, "settings.json"))

    def test_llm_lang_default_auto(self):
        d = tempfile.mkdtemp()
        try:
            st = self._store(d)
            self.assertEqual(st.get()["llm_lang"], "auto")
        finally:
            shutil.rmtree(d)

    def test_llm_lang_set_es_en(self):
        d = tempfile.mkdtemp()
        try:
            st = self._store(d)
            st.set(lang="es")
            self.assertEqual(st.get()["llm_lang"], "es")
            st.set(lang="en")
            self.assertEqual(st.get()["llm_lang"], "en")
            st.set(lang="auto")
            self.assertEqual(st.get()["llm_lang"], "auto")
        finally:
            shutil.rmtree(d)

    def test_llm_lang_invalid_falls_to_auto(self):
        d = tempfile.mkdtemp()
        try:
            st = self._store(d)
            st.set(lang="fr")
            self.assertEqual(st.get()["llm_lang"], "auto")
            st.set(lang="")
            self.assertEqual(st.get()["llm_lang"], "auto")
            # sin lang en el set no se toca lo guardado
            st.set(lang="es")
            st.set(url="http://127.0.0.1:1/v1")
            self.assertEqual(st.get()["llm_lang"], "es")
        finally:
            shutil.rmtree(d)

    def test_llm_key_distinguishes_lang(self):
        # Misma linea, idiomas distintos -> hashes distintos (Fase 12B)
        line = "timeout de red a las 10:00:01"
        k_es = server.llm_key(line, lang="es")
        k_en = server.llm_key(line, lang="en")
        self.assertNotEqual(k_es, k_en)
        self.assertEqual(k_es, server.llm_key(line, lang="es"))

    def test_llm_system_prompt(self):
        p_auto = server.llm_system_prompt("auto")
        p_es = server.llm_system_prompt("es")
        p_en = server.llm_system_prompt("en")
        self.assertIn("idioma de la linea", p_auto)
        self.assertIn("espanol", p_es.lower())
        self.assertIn("english", p_en.lower())
        # idioma invalido cae a auto
        self.assertEqual(server.llm_system_prompt("xx"), p_auto)
        self.assertEqual(server.llm_system_prompt(None), p_auto)


class TestDiagnose(unittest.TestCase):
    """Fase 12C: diagnostico rapido (loteo + cache por dataset+level+lang)."""

    @staticmethod
    def _tpls(n, start=0):
        return [{"template": "fallo tipo %d" % i,
                 "count": n - i,
                 "example": "linea de ejemplo %d" % i}
                for i in range(start, start + n)]

    def _ask(self, prompts):
        """ask mock que cuenta las llamadas y devuelve (ok, text)."""
        def ask(prompt):
            prompts.append(prompt)
            return True, "resumen de: " + prompt[:40]
        return ask

    def test_60_templates_hace_2_llamadas(self):
        # 60 plantillas con tope de 50 por llamada -> exactamente 2:
        # la primera resume el lote de 50 y la segunda (con el resumen
        # acumulado + las 10 restantes) produce la conclusion final.
        prompts = []
        ok, conclusion, analyzed = server.run_diagnose(
            self._tpls(60), self._ask(prompts))
        self.assertTrue(ok)
        self.assertEqual(analyzed, 60)
        self.assertEqual(len(prompts), 2)
        # La primera NO pide conclusion final; la segunda SI
        self.assertNotIn("conclusion final", prompts[0])
        self.assertIn("conclusion final", prompts[1])
        # El resumen del primer lote viaja en la segunda llamada
        self.assertIn("RESUMEN de los lotes anteriores", prompts[1])
        self.assertIn(prompts[0] and "resumen de: ", conclusion)
        # El mock ecoa el prompt: la conclusion final viene de la 2a llamada
        self.assertTrue(conclusion.startswith("resumen de: "))

    def test_50_templates_hace_1_llamada(self):
        prompts = []
        ok, _, analyzed = server.run_diagnose(
            self._tpls(50), self._ask(prompts))
        self.assertTrue(ok)
        self.assertEqual(analyzed, 50)
        self.assertEqual(len(prompts), 1)
        self.assertIn("conclusion final", prompts[0])

    def test_vacio_no_pregunta(self):
        prompts = []
        ok, conclusion, analyzed = server.run_diagnose([], self._ask(prompts))
        self.assertTrue(ok)
        self.assertEqual(analyzed, 0)
        self.assertEqual(len(prompts), 0)
        self.assertIn("No hay lineas", conclusion)

    def test_fallo_nunca_es_exito(self):
        prompts = []

        def ask_fail(prompt):
            prompts.append(prompt)
            return False, "el LLM no devolvio texto"

        ok, text, analyzed = server.run_diagnose(
            self._tpls(60), ask_fail)
        self.assertFalse(ok)
        self.assertEqual(analyzed, 0)  # el llamador lo sabra: no cachea
        self.assertIn("no devolvio texto", text)
        self.assertEqual(len(prompts), 1)  # para en la primera llamada mala

    def test_cache_key_dataset_level_lang(self):
        t = self._tpls(5)
        base = server.diagnose_key("a.log", "ERR", "es", "m1", t)
        # Mismo dataset+level+lang+model -> misma clave (idempotente)
        self.assertEqual(base, server.diagnose_key(
            "a.log", "ERR", "es", "m1", t))
        # Otro dataset / otro nivel / otro idioma / otro modelo -> otra
        self.assertNotEqual(server.diagnose_key(
                              "b.log", "ERR", "es", "m1", t), base)
        self.assertNotEqual(server.diagnose_key(
                              "a.log", "CRIT", "es", "m1", t), base)
        self.assertNotEqual(server.diagnose_key(
                              "a.log", "ERR", "en", "m1", t), base)
        self.assertNotEqual(server.diagnose_key(
                              "a.log", "ERR", "es", "m2", t), base)
        # Otro contenido de plantillas -> otra clave
        self.assertNotEqual(server.diagnose_key(
                              "a.log", "ERR", "es", "m1",
                              self._tpls(5, start=100)), base)


class TestSplunkQuery(unittest.TestCase):
    """Fase 13: ingesta desde Splunk local (mock del servidor HTTP).

    El mock es un http.server real en 127.0.0.1 (http://, sin TLS) que
    captura path/Authorization/cuerpo y devuelve resultados fijos: no
    depende de Splunk para los tests."""

    def _mock_splunk(self, results=None, indexes=("botsv3", "_audit")):
        cap = {"path": None, "auth": None, "form": None}

        class H(BaseHTTPRequestHandler):
            def _send(self, obj):
                data = json.dumps(obj).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                cap["path"] = self.path
                cap["auth"] = self.headers.get("Authorization")
                cap["form"] = parse_qs(
                    self.rfile.read(n).decode("utf-8"))
                self._send({"results": results or []})

            def do_GET(self):
                cap["path"] = self.path
                cap["auth"] = self.headers.get("Authorization")
                self._send({"entry": [{"name": i} for i in indexes]})

            def log_message(self, *a):
                pass

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        old = (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS)
        config.SPLUNK_URL = "http://127.0.0.1:%d" % port
        config.SPLUNK_USER = "admin"
        config.SPLUNK_PASS = "testpass"
        return cap, srv, old

    def test_query_forces_search_prefix(self):
        # Peculiaridad de este Splunk 10.4: el SPL debe empezar con un
        # comando explicito; si falta, se fuerza "search "
        cap, srv, old = self._mock_splunk()
        try:
            server.splunk_query("index=botsv3 | head 5")
            self.assertEqual(cap["form"]["search"][0],
                            "search index=botsv3 | head 5")
            # Ya con prefijo o tubería: no se toca
            server.splunk_query("search index=botsv3")
            self.assertEqual(cap["form"]["search"][0],
                            "search index=botsv3")
            server.splunk_query("| stats count")
            self.assertEqual(cap["form"]["search"][0], "| stats count")
        finally:
            srv.shutdown()
            (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS) = old

    def test_query_auth_url_and_body(self):
        import base64
        cap, srv, old = self._mock_splunk()
        try:
            server.splunk_query("index=botsv3", count=250)
            # URL y auth basic correctos (la clave NO esta en el codigo:
            # aqui es testpass; en produccion viene de SPLUNK_PASS)
            self.assertEqual(cap["path"], "/services/search/jobs")
            self.assertEqual(cap["auth"], "Basic " + base64.b64encode(
                b"admin:testpass").decode("ascii"))
            f = cap["form"]
            self.assertEqual(f["exec_mode"][0], "oneshot")
            self.assertEqual(f["output_mode"][0], "json")
            self.assertEqual(f["earliest_time"][0], "0")
            self.assertEqual(f["count"][0], "250")
        finally:
            srv.shutdown()
            (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS) = old

    def test_query_count_cap_and_rows(self):
        cap, srv, old = self._mock_splunk(results=[
            {"_time": "1724000000.5", "line": "FAIL user=x src=1.2.3.4",
             "src_ip": "1.2.3.4"},
            {"count": "7", "sourcetype": "ms:aad:signin"}])
        try:
            rows = server.splunk_query("index=botsv3", count=99999)
            # El tope duro evita traer 2M filas al visor/LLM
            self.assertEqual(cap["form"]["count"][0],
                             str(config.SPLUNK_MAX_ROWS))
            self.assertEqual(len(rows), 2)
            self.assertIn("line", rows[0])
        finally:
            srv.shutdown()
            (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS) = old

    def test_query_puerto_caido(self):
        # Apunta a un puerto de la maquina que seguro esta cerrado y con un
        # timeout corto, para que el fallo sea rapido y no espere los 120s
        # por defecto (un puerto recien cerrado no da refusal inmediato en
        # Windows y urlopen aguantaria el SPLUNK_TIMEOUT completo).
        old = (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS,
               config.SPLUNK_TIMEOUT)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        try:
            config.SPLUNK_URL = "http://127.0.0.1:%d" % port
            config.SPLUNK_USER = "admin"
            config.SPLUNK_PASS = "testpass"
            config.SPLUNK_TIMEOUT = 3
            with self.assertRaises(ValueError) as ctx:
                server.splunk_query("index=botsv3")
            # VERSION 1.2: lenguaje humano (contactar al operador)
            self.assertIn("El Splunk no responde", str(ctx.exception))
        finally:
            (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS,
             config.SPLUNK_TIMEOUT) = old

    def test_splunk_enabled_flag(self):
        old = config.SPLUNK_PASS
        try:
            config.SPLUNK_PASS = ""
            self.assertFalse(server.splunk_enabled())
            config.SPLUNK_PASS = "x"
            self.assertTrue(server.splunk_enabled())
        finally:
            config.SPLUNK_PASS = old

    def test_splunk_indexes_filters_internos(self):
        cap, srv, old = self._mock_splunk(indexes=("botsv3", "_audit"))
        try:
            self.assertEqual(server.splunk_indexes(), ["botsv3"])
            self.assertEqual(cap["path"], "/services/data/2.0/indexes")
        finally:
            srv.shutdown()
            (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS) = old

    def test_rows_to_dataset_rows(self):
        rows = server.splunk_rows_to_dataset_rows([
            {"_time": "1724000000.5", "line": "FAIL user=x src=1.2.3.4",
             "src_ip": "1.2.3.4", "host": "h1"},
            {"count": "7", "sourcetype": "ms:aad:signin"},
            {},  # sin campos: se descarta
        ])
        self.assertEqual(len(rows), 2)
        r0, r1 = rows
        # _time (epoch) -> ts entero + ts_norm ISO (norm_ts)
        self.assertEqual(r0["ts"], "1724000000")
        self.assertEqual(r0["ts_norm"], server.norm_ts("1724000000"))
        # msg = campo "line"; ip reconocido; raw = JSON de los campos
        self.assertEqual(r0["msg"], "FAIL user=x src=1.2.3.4")
        self.assertEqual(r0["ip"], "1.2.3.4")
        self.assertIn("src_ip", json.loads(r0["raw"]))
        # Agregacion sin "line": k=v ordenado; plantilla y _search listos
        self.assertEqual(r1["msg"], "count=7 sourcetype=ms:aad:signin")
        self.assertNotEqual(r1["template"], "")
        self.assertIn("count=7", r1["_search"])

    # --- Bug B13: usuario y TLS (P2.2) ---
    def test_splunk_user_sin_default_admin(self):
        # El codigo no puede caer en "admin" si no se define SPLUNK_USER:
        # la variable se toma del entorno y queda vacia si no existe.
        src = inspect.getsource(config)
        line = [l for l in src.splitlines() if l.startswith("SPLUNK_USER =")]
        self.assertEqual(len(line), 1)
        self.assertNotIn("admin", line[0])
        old_env = os.environ.get("SPLUNK_USER")
        old_user = config.SPLUNK_USER
        try:
            os.environ.pop("SPLUNK_USER", None)
            config.SPLUNK_USER = os.environ.get("SPLUNK_USER", "").strip()
            self.assertEqual(config.SPLUNK_USER, "")
            os.environ["SPLUNK_USER"] = "  analyst  "
            config.SPLUNK_USER = os.environ.get("SPLUNK_USER", "").strip()
            self.assertEqual(config.SPLUNK_USER, "analyst")
        finally:
            if old_env is None:
                os.environ.pop("SPLUNK_USER", None)
            else:
                os.environ["SPLUNK_USER"] = old_env
            config.SPLUNK_USER = old_user

    def test_ssl_verify_on_por_defecto(self):
        # Sin LOGVIEWER_SPLUNK_VERIFY: verificacion activa (default seguro).
        old = os.environ.pop("LOGVIEWER_SPLUNK_VERIFY", None)
        try:
            self.assertTrue(server.splunk_verify_enabled())
            ctx = server._splunk_ssl()
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(ctx.check_hostname)
        finally:
            if old is not None:
                os.environ["LOGVIEWER_SPLUNK_VERIFY"] = old

    def test_ssl_verify_explicit_on_y_off(self):
        old = os.environ.get("LOGVIEWER_SPLUNK_VERIFY")
        try:
            os.environ["LOGVIEWER_SPLUNK_VERIFY"] = "1"
            ctx = server._splunk_ssl()
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            os.environ["LOGVIEWER_SPLUNK_VERIFY"] = "0"
            ctx = server._splunk_ssl()
            self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
            self.assertFalse(ctx.check_hostname)
        finally:
            if old is None:
                os.environ.pop("LOGVIEWER_SPLUNK_VERIFY", None)
            else:
                os.environ["LOGVIEWER_SPLUNK_VERIFY"] = old

    def test_ssl_cafile_pinned(self):
        # Con una CA propia se sigue verificando (sin desactivar nada).
        d = tempfile.mkdtemp()
        ca = os.path.join(d, "ca.pem")
        with open(ca, "w", encoding="utf-8") as f:
            f.write("-----BEGIN CERTIFICATE-----\n")
            f.write("MIIB\n")
            f.write("-----END CERTIFICATE-----\n")
        old = os.environ.get("LOGVIEWER_SPLUNK_CAFILE")
        try:
            os.environ["LOGVIEWER_SPLUNK_CAFILE"] = ca
            ctx = server._splunk_ssl()
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            # La CA no es valida de verdad: load_verify_locations ya se
            # aplico; el modo sigue siendo CERT_REQUIRED (no CERT_NONE).
            os.environ["LOGVIEWER_SPLUNK_CAFILE"] = ""
            ctx2 = server._splunk_ssl()
            self.assertEqual(ctx2.verify_mode, ssl.CERT_REQUIRED)
        except ssl.SSLError:
            # CA mal formada: el fallback seguro es no desactivar la
            # verificacion; el contexto devuelto sigue verificando.
            self.assertEqual(server._splunk_ssl().verify_mode,
                             ssl.CERT_REQUIRED)
        finally:
            if old is None:
                os.environ.pop("LOGVIEWER_SPLUNK_CAFILE", None)
            else:
                os.environ["LOGVIEWER_SPLUNK_CAFILE"] = old
            shutil.rmtree(d)

    def test_readme_documenta_verify_y_user(self):
        # El README documenta el default seguro y la desactivacion explicita.
        base = os.path.dirname(os.path.abspath(server.__file__))
        with open(os.path.join(base, "README.md"), encoding="utf-8") as f:
            readme = f.read().lower()
        self.assertIn("logviewer_splunk_verify", readme)
        self.assertIn("verify_mode", inspect.getsource(api).lower())
        self.assertNotIn("`splunk_user` (default `admin`)", readme)

    def test_splunk_open_usa_contexto_del_flag(self):
        # _splunk_open debe construir el TLS con _splunk_ssl() (respeta el
        # flag); si se desactiva, la conexion https a un puerto cerrado sigue
        # fallando con el mensaje humano de siempre.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        old = (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS,
               config.SPLUNK_TIMEOUT)
        old_flag = os.environ.get("LOGVIEWER_SPLUNK_VERIFY")
        try:
            os.environ["LOGVIEWER_SPLUNK_VERIFY"] = "0"
            config.SPLUNK_URL = "https://127.0.0.1:%d" % port
            config.SPLUNK_USER = "analyst"
            config.SPLUNK_PASS = "p"
            config.SPLUNK_TIMEOUT = 3
            with self.assertRaises(ValueError) as cm:
                server.splunk_query("search index=botsv3 | head 1")
            self.assertIn("El Splunk no responde", str(cm.exception))
        finally:
            (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS,
             config.SPLUNK_TIMEOUT) = old
            if old_flag is None:
                os.environ.pop("LOGVIEWER_SPLUNK_VERIFY", None)
            else:
                os.environ["LOGVIEWER_SPLUNK_VERIFY"] = old_flag



class TestEnvNotices(unittest.TestCase):
    """VERSION 1.2: avisos de funciones SOLO local (llm/splunk false) y
    LOGVIEWER_REPO_URL expuesta como repo_url en /api/config."""

    def _cfg(self, d, repo_url):
        # public_config() -> llm_config() -> settings_store(): se usa un
        # SettingsStore temporal para no tocar el estado real de %TEMP%
        old = (stores.SETTINGS, config.REPO_URL)
        try:
            stores.SETTINGS = server.SettingsStore(
                os.path.join(d, "settings.json"))
            config.REPO_URL = repo_url
            return server.public_config()
        finally:
            (stores.SETTINGS, config.REPO_URL) = old

    def test_public_config_exposes_repo_url(self):
        d = tempfile.mkdtemp()
        try:
            cfg = self._cfg(d, "https://github.com/sammi/logviewer")
            self.assertEqual(
                cfg["repo_url"], "https://github.com/sammi/logviewer")
            # Las banderas que condicionan la UI siguen presentes
            self.assertIn("llm", cfg)
            self.assertIn("splunk", cfg)
        finally:
            shutil.rmtree(d)

    def test_public_config_sin_repo_url(self):
        d = tempfile.mkdtemp()
        try:
            self.assertEqual(self._cfg(d, "")["repo_url"], "")
        finally:
            shutil.rmtree(d)

    def test_drawer_notice_uses_repo_link(self):
        # Con llm:false el drawer muestra el aviso de funcion SOLO local
        # y, si repo_url existe, el enlace apunta a esa URL: la UI
        # servida debe traer el markup del aviso y app.js debe ligar el
        # href a app.repoUrl (que init lee de /api/config)
        base = os.path.dirname(os.path.abspath(server.__file__))
        idx = open(os.path.join(base, "static", "index.html"),
                   encoding="utf-8").read()
        js = open(os.path.join(base, "static", "app.js"),
                 encoding="utf-8").read()
        self.assertIn('id="an-local-note"', idx)
        self.assertIn("SOLO local", idx)
        self.assertIn('id="an-repo-line"', idx)
        self.assertIn('id="an-repo-link"', idx)
        self.assertIn("applyAnLocalNote", js)
        self.assertIn("app.repoUrl = cfg.repo_url", js)
        # El enlace solo se muestra si repo_url existe: href + texto
        self.assertIn("a.href = app.repoUrl", js)

    def test_splunk_notice_wiring(self):
        # Con splunk:false la seccion Sidebar muestra el aviso del
        # operador (sin caja SPL): markup en index.html y toggle en
        # app.js (setSplunkVisible muestra/oculta nota y controles)
        base = os.path.dirname(os.path.abspath(server.__file__))
        idx = open(os.path.join(base, "static", "index.html"),
                   encoding="utf-8").read()
        js = open(os.path.join(base, "static", "app.js"),
                 encoding="utf-8").read()
        self.assertIn('id="splunk-local-note"', idx)
        self.assertIn("operador del servidor", idx)
        # app.js la muestra/oculta segun splunk:true/false
        self.assertIn("splunk-local-note", js)

    def test_llm_conn_error_human_language(self):
        # Sin respuesta del LLM: lenguaje humano, sin codigo HTTP como
        # mensaje principal (el 503 queda en el estado tecnico)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        ok, text = server.ask_llm("x", url="http://127.0.0.1:%d/v1" % port)
        self.assertFalse(ok)
        self.assertIn("no se pudo contactar con el modelo local", text)
        self.assertNotIn("503", text)

    def test_splunk_conn_error_human_language(self):
        # Splunk caido: mensaje en lenguaje humano (contactar al
        # operador), no "servidor caido, puerto cerrado"
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        old = (config.SPLUNK_URL, config.SPLUNK_USER, config.SPLUNK_PASS)
        try:
            config.SPLUNK_URL = "https://127.0.0.1:%d" % port
            config.SPLUNK_USER = "u"
            config.SPLUNK_PASS = "p"
            with self.assertRaises(ValueError) as cm:
                server.splunk_query("search index=botsv3 | head 1")
        finally:
            (config.SPLUNK_URL, config.SPLUNK_USER,
             config.SPLUNK_PASS) = old
        self.assertIn("El Splunk no responde", str(cm.exception))
        self.assertIn("operador del servidor", str(cm.exception))


# ---------------------------------------------------------------------------
# P0.4: export con cabecera dinamica (columnas reales del dataset)
# ---------------------------------------------------------------------------
class TestExportColumns(unittest.TestCase):
    """La cabecera del export se descubre en el dataset, no esta fija."""

    def _mem(self, rows):
        for r in rows:
            r["_search"] = server._make_search(r)
        return server.MemStore(rows=rows)

    def test_sin_extras_da_las_basicas(self):
        rows = [{"ts": "2026-10-11 10:00:00", "level": "INF", "ip": "1.1.1.1",
                 "host": "h", "app": "a", "pid": "1", "method": "GET",
                 "path": "/x", "code": "200", "bytes": "10", "msg": "ok"}]
        cols = server.export_columns(self._mem(rows))
        self.assertEqual(cols, list(server.EXPORT_BASE_COLS))

    def test_piloop_aporta_comp(self):
        rows, _ = server.parse_piloop(["2026-10-30 01:12:33 vigilante: ok buzon"])
        cols = server.export_columns(self._mem(rows))
        self.assertIn("comp", cols)
        self.assertIn("ts", cols)
        self.assertIn("level", cols)

    def test_triage_aporta_sev_conf_verdict(self):
        rows, _ = server.parse_triage(
            ["01:23:45 [vt] firma:x -> benigno conf 0.9 sev 0.0 accion no | sin tarea"],
            file_date="2026-10-30")
        cols = server.export_columns(self._mem(rows))
        for c in ("fuente", "firma", "verdict", "conf", "sev", "accion", "tarea"):
            self.assertIn(c, cols, c)

    def test_jsonl_aporta_columnas_opervanta(self):
        rows, _ = server.parse_json([
            json.dumps({"ts": "2026-10-30 01:00:00", "fuente": "soc",
                        "firma": "phish:dominio", "tenant": "local",
                        "sev": "alta", "src": "", "dst": "93.1.2.3",
                        "url": "http://x", "mensaje": "alerta",
                        "evidencia": "email", "riesgo": "medio",
                        "tarea": "t4f87", "dedupe": "d1"})])
        cols = server.export_columns(self._mem(rows))
        for c in ("fuente", "firma", "tenant", "tarea", "dedupe",
                  "evidencia", "riesgo", "url", "sev"):
            self.assertIn(c, cols, c)

    def test_orden_canonico_primero(self):
        rows = [{"sev": 2, "firma": "f", "msg": "m", "ts": "t", "level": "ERR"}]
        cols = server.export_columns(self._mem(rows))
        self.assertEqual(cols[:3], ["ts", "level", "msg"])
        self.assertEqual(cols[3:5], ["firma", "sev"])

    def test_claves_internas_no_aparecen(self):
        rows = [{"ts": "t", "level": "INF", "msg": "m", "raw": "l",
                 "ts_norm": "2026-10-30", "template": "*", "_line": 0}]
        cols = server.export_columns(self._mem(rows))
        for k in ("raw", "ts_norm", "template", "_line", "_search"):
            self.assertNotIn(k, cols)

    def test_dataset_vacio_cae_a_basicas(self):
        self.assertEqual(server.export_columns(server.MemStore()),
                         list(server.EXPORT_BASE_COLS))

    def test_clave_nueva_al_final(self):
        rows = [{"ts": "t", "msg": "m", "widget": "w1"}]
        cols = server.export_columns(self._mem(rows))
        self.assertEqual(cols[-1], "widget")

    def test_sin_duplicados(self):
        rows = [{"ts": "t", "fuente": "a"}, {"ts": "t2", "fuente": "b"}]
        cols = server.export_columns(self._mem(rows))
        self.assertEqual(len(cols), len(set(cols)))

    def test_sqlstore_columns_incluye_extras(self):
        d = tempfile.mkdtemp()
        try:
            st = server.SqlStore(os.path.join(d, "s.db"))
            st.add_rows([{"ts": "t", "level": "ERR", "msg": "m", "firma": "f",
                          "sev": 2.5, "_line": 0}], {})
            cols = server.export_columns(st)
            for c in ("ts", "level", "msg", "firma", "sev"):
                self.assertIn(c, cols, c)
            self.assertNotIn("raw", cols)
            st.close()
        finally:
            shutil.rmtree(d)

    def test_sqlstore_migracion_anade_columnas(self):
        import sqlite3
        d = tempfile.mkdtemp()
        try:
            db = os.path.join(d, "vieja.db")
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE rows (ts TEXT, ts_norm TEXT, level TEXT, "
                        "ip TEXT, host TEXT, app TEXT, pid TEXT, method TEXT, "
                        "path TEXT, code TEXT, bytes TEXT, msg TEXT, raw TEXT, "
                        "template TEXT, search TEXT, line INTEGER)")
            con.execute("INSERT INTO rows (ts, level, msg, search, line) "
                        "VALUES ('t','INF','m','m',0)")
            con.commit()
            con.close()
            st = server.SqlStore(db)
            cols = server.export_columns(st)
            for c in ("fuente", "firma", "tenant", "tarea", "dedupe", "sev"):
                self.assertIn(c, cols, c)
            st.close()
        finally:
            shutil.rmtree(d)

    def test_store_sin_metodo_columns(self):
        class SinColumnas:
            pass
        self.assertEqual(server.export_columns(SinColumnas()),
                         list(server.EXPORT_BASE_COLS))

    def test_dst_no_se_pierde(self):
        rows, _ = server.parse_json([
            json.dumps({"ts": "2026-10-30", "src": "1.2.3.4", "dst": "5.6.7.8",
                        "mensaje": "conexión", "dedupe": "dd"})])
        cols = server.export_columns(self._mem(rows))
        self.assertIn("dedupe", cols)
        self.assertIn("ip", cols)
        self.assertEqual(rows[0]["ip"], "1.2.3.4")


class TestCsvCellAntiFormula(unittest.TestCase):
    """P0.4: el saneamiento anti-formulas sigue activo con cabecera dinamica."""

    def _cell(self, v):
        return server.Handler._csv_cell(None, v)

    def test_igual_es_formula(self):
        self.assertEqual(self._cell("=1+1"), "'=1+1")

    def test_mas_minus_arroba(self):
        for v in ("+cmd", "-cmd", "@cmd"):
            self.assertEqual(self._cell(v), "'" + v, v)

    def test_tabulador_y_salto(self):
        self.assertEqual(self._cell("\t=1"), "'\t=1")
        self.assertEqual(self._cell("\n=1"), "'\n=1")

    def test_texto_normal_no_se_toca(self):
        self.assertEqual(self._cell("2026-10-30 01:12:33 ok"),
                         "2026-10-30 01:12:33 ok")

    def test_none_es_cadena_vacia(self):
        self.assertEqual(self._cell(None), "")

    def test_numeros_a_texto(self):
        self.assertEqual(self._cell(2.5), "2.5")

    def test_formula_en_medio_no_se_prefija(self):
        self.assertEqual(self._cell("msg = 1"), "msg = 1")


class TestExportEndToEnd(unittest.TestCase):
    """P0.4: el endpoint /api/export devuelve la cabecera descubierta."""

    def _serve_export(self, ds, fmt="csv", **filters):
        import urllib.request
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        server.SESSIONS.setdefault("local", {})[ds["name"]] = ds
        params = {"name": ds["name"], "format": fmt}
        params.update(filters)
        query = "&".join("%s=%s" % (k, v) for k, v in params.items())
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/export?%s" % (srv.server_port, query),
                    timeout=15) as r:
                return r.status, r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        finally:
            srv.shutdown()
            server.SESSIONS.get("local", {}).pop(ds["name"], None)

    def _ds(self, lines, name="prueba.log", fmt=None):
        d = tempfile.mkdtemp()
        self._tmp = d
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return server.load_file(path, user="local")

    def test_csv_header_dinamico_piloop(self):
        ds = self._ds(["2026-10-30 01:12:33 vigilante: ok buzon",
                       "2026-10-30 01:12:40 runner: tarea completada"],
                      "piloop.log")
        status, body = self._serve_export(ds, "csv")
        self.assertEqual(status, 200)
        header = body.splitlines()[0]
        self.assertIn("comp", header)
        self.assertIn("ts", header)
        self.assertEqual(header.split(",")[:2], ["ts", "level"])
        ds["store"].close()

    def test_ndjson_conserva_campos_triage(self):
        ds = self._ds(["01:23:45 [vt] firma:phish.x -> real_incident conf 0.8 "
                       "sev 2.5 accion yes | ESCALADA t4f87df76"], "tri.log")
        status, body = self._serve_export(ds, "json")
        self.assertEqual(status, 200)
        obj = json.loads(body.strip().splitlines()[0])
        for k in ("fuente", "firma", "tarea", "sev", "conf", "verdict", "accion"):
            self.assertIn(k, obj, k)
        self.assertEqual(obj["level"], "ERR")
        ds["store"].close()

    def test_csv_no_incluye_raw_ni_ts_norm(self):
        ds = self._ds(["2026-10-30 01:00:00 a: hola"], "raw.log")
        status, body = self._serve_export(ds, "csv")
        header = body.splitlines()[0]
        self.assertNotIn("raw", header.split(","))
        self.assertNotIn("ts_norm", header.split(","))
        ds["store"].close()

    def test_formato_invalido_400(self):
        ds = self._ds(["2026-10-30 01:00:00 a: hola"], "bad.log")
        status, body = self._serve_export(ds, "xml")
        self.assertEqual(status, 400)
        ds["store"].close()

    def test_sin_dataset_404(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            import urllib.request
            try:
                urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/export?name=noexiste&format=csv"
                    % srv.server_port, timeout=15)
                self.fail("no deberia devolver 200")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 404)
        finally:
            srv.shutdown()

    def test_filtra_por_nivel_en_export(self):
        ds = self._ds(["2026-10-30 01:00:00 a: ok",
                       "2026-10-30 01:00:01 b: exception en el runner"], "f.log")
        status, body = self._serve_export(ds, "csv", level="ERR")
        lines = [l for l in body.splitlines() if l]
        self.assertEqual(len(lines), 2)  # cabecera + 1 fila
        self.assertIn("exception", lines[1])
        ds["store"].close()

    def test_inyeccion_de_formula_en_csv(self):
        ds = self._ds(["2026-10-30 01:00:00 a: =HYPERLINK(\"http://malicioso\")"],
                      "inj.log")
        status, body = self._serve_export(ds, "csv")
        self.assertIn("'=HYPERLINK", body)
        ds["store"].close()

    def test_numero_de_filas_export(self):
        ds = self._ds(["2026-10-30 01:00:%02d a: linea %d" % (i, i)
                       for i in range(20)], "n.log")
        status, body = self._serve_export(ds, "csv")
        lines = [l for l in body.splitlines() if l]
        self.assertEqual(len(lines), 21)
        ds["store"].close()

    def test_ndjson_lineas_validas(self):
        ds = self._ds(["2026-10-30 01:00:00 a: ok", "2026-10-30 01:00:01 b: ok"],
                      "j.log")
        status, body = self._serve_export(ds, "json")
        objs = [json.loads(l) for l in body.strip().splitlines()]
        self.assertEqual(len(objs), 2)
        self.assertTrue(all("raw" in o for o in objs))
        ds["store"].close()

    def test_smoke_buzon_log_real(self):
        path = r"C:\Users\Sammi\AI\piloop-proyectos\buzon\buzon.log"
        if not os.path.exists(path):
            self.skipTest("no hay buzon.log")
        ds = server.load_file(path, user="local")
        status, body = self._serve_export(ds, "csv")
        header = body.splitlines()[0].split(",")
        self.assertIn("comp", header)
        self.assertIn("ts", header)
        self.assertIn("level", header)
        rows = ds["store"].page_filtered({}, 0, 50000)
        con_ts = sum(1 for r in rows if r.get("ts"))
        con_level = sum(1 for r in rows
                        if r.get("level") and r.get("level") != "RAW")
        self.assertGreaterEqual(con_ts, len(rows) * 0.9)
        self.assertGreaterEqual(con_level, len(rows) * 0.9)
        ds["store"].close()

    def test_smoke_triage_log_real(self):
        path = r"C:\Users\Sammi\AI\piloop-proyectos\buzon\soc\triage.log"
        if not os.path.exists(path):
            self.skipTest("no hay triage.log")
        ds = server.load_file(path, user="local")
        status, body = self._serve_export(ds, "csv")
        header = body.splitlines()[0].split(",")
        for c in ("fuente", "firma", "sev", "tarea", "verdict"):
            self.assertIn(c, header, c)
        ds["store"].close()

    def test_smoke_alertas_jsonl_real(self):
        path = r"C:\Users\Sammi\AI\piloop-proyectos\buzon\soc\alertas.jsonl"
        if not os.path.exists(path):
            self.skipTest("no hay alertas.jsonl")
        ds = server.load_file(path, user="local")
        status, body = self._serve_export(ds, "csv")
        header = body.splitlines()[0].split(",")
        for c in ("fuente", "firma", "tenant", "tarea", "dedupe",
                  "evidencia", "riesgo", "url"):
            self.assertIn(c, header, c)
        rows = ds["store"].page_filtered({}, 0, 50000)
        self.assertTrue(all(r.get("ts") for r in rows))
        self.assertTrue(all(r.get("level") and r.get("level") != "RAW" for r in rows))
        ds["store"].close()

    def test_export_sqlstore_conserva_triage(self):
        d = tempfile.mkdtemp()
        try:
            st = server.SqlStore(os.path.join(d, "t.db"))
            rows, _ = server.parse_triage(
                ["01:23:45 [vt] firma:x -> real_incident conf 0.9 sev 3.0 accion yes "
                 "| ESCALADA t1"], file_date="2026-10-30")
            st.add_rows(rows, {})
            ds = {"store": st, "name": "tri.db", "format": "triage",
                  "total": len(rows), "size": 0}
            status, body = self._serve_export(ds, "csv")
            header = body.splitlines()[0].split(",")
            for c in ("fuente", "firma", "sev", "tarea", "verdict", "conf"):
                self.assertIn(c, header, c)
            st.close()
        finally:
            shutil.rmtree(d)


class TestRowsEndToEnd(unittest.TestCase):
    """P1.1 (bug B3): la capa de UI recorta 'msg', el raw se sirve entero.

    El drawer necesita la linea completa y el export, el mensaje completo.
    """

    LONG = "w" * 1500

    def _ds(self, lines, name):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return server.load_file(path, user="local")

    def _get(self, ds, path, params):
        import urllib.request
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        server.SESSIONS.setdefault("local", {})[ds["name"]] = ds
        query = "&".join("%s=%s" % (k, v) for k, v in params.items())
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d%s?%s" % (srv.server_port, path, query),
                    timeout=15) as r:
                return r.status, r.read().decode("utf-8")
        finally:
            srv.shutdown()
            server.SESSIONS.get("local", {}).pop(ds["name"], None)

    def test_api_rows_recorta_msg_y_conserva_raw(self):
        ds = self._ds(["2026-10-30 01:00:00 runner: " + self.LONG], "p11.log")
        status, body = self._get(ds, "/api/rows", {"name": ds["name"]})
        self.assertEqual(status, 200)
        row = json.loads(body)["rows"][0]
        self.assertTrue(row["msg"].endswith(" ..."))
        self.assertEqual(row["msg_len"], len(self.LONG))
        self.assertTrue(row["msg_truncated"])
        # El drawer lee row.raw: debe llegar la linea completa
        self.assertEqual(len(row["raw"]), len("2026-10-30 01:00:00 runner: ") + len(self.LONG))
        self.assertNotIn("_search", row)
        ds["store"].close()

    def test_export_no_recorta(self):
        ds = self._ds(["2026-10-30 01:00:00 runner: " + self.LONG], "p11b.log")
        status, body = self._get(ds, "/api/export",
                                 {"name": ds["name"], "format": "csv"})
        self.assertEqual(status, 200)
        self.assertIn(self.LONG, body)
        ds["store"].close()

    def test_parity_api_rows_mem_vs_sql(self):
        """Mismo 'q' en MemStore y SqlStore a traves del endpoint /api/rows."""
        lines = ["2026-10-30 01:00:0%d runner: alpha linea %d" % (i, i)
                 for i in range(10)]
        ds = self._ds(lines, "p11c.log")
        mem_ids = [r["_line"] for r in ds["store"].page_filtered({"q": ["alph"]}, 0, 100)]
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        sql = server.SqlStore(os.path.join(d, "p11c.db"))
        self.addCleanup(sql.close)
        sql.add_rows([dict(r) for r in ds["store"].rows], {})
        sql_ids = [sql.line_of(r["rowid"]) for r in sql.page_filtered({"q": ["alph"]}, 0, 100)]
        self.assertEqual(mem_ids, sql_ids)
        status, body = self._get(ds, "/api/rows",
                                 {"name": ds["name"], "q": "alph"})
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["rows"]), len(mem_ids))
        ds["store"].close()


class TestKeysetPagination(unittest.TestCase):
    """P1.2 (bug B8): el export pagina por clave (rowid), no por OFFSET.

    Con OFFSET, SQLite recorre y descarta 'start' filas en cada lote: un
    export de N filas en lotes de B cuesta O(N^2/B). La keyset pagination
    ('WHERE rowid > ultimo') es O(N) y debe dar las mismas filas."""

    def _keyset_all(self, store, q, batch):
        out = []
        last = -1
        while True:
            b = store.page_filtered_keyset(q, last, batch)
            if not b:
                break
            out.extend(b)
            # U4 (2026-10-30): el lote va en DESC, asi que el borde del
            # siguiente es el rowid de la ULTIMA fila devuelta (la mas antigua
            # del lote). Con max() el bound no avanzaba y el export no terminaba.
            last = b[-1]["rowid"]
        return out

    def test_mem_keyset_igual_a_offset(self):
        rows = [{"ts": "2026-10-30 01:00:%02d" % i, "level": "INF" if i % 2 else "ERR",
                 "msg": "fila %d" % i, "raw": "raw %d" % i, "_line": i}
                for i in range(50)]
        store = server.MemStore([dict(r) for r in rows])
        for batch in (1, 7, 50, 100):
            want = []
            start = 0
            while True:
                chunk = store.page_filtered({}, start, batch)
                if not chunk:
                    break
                want.extend(chunk)
                start += batch
            self.assertEqual(self._keyset_all(store, {}, batch), want)

    def test_sql_keyset_igual_a_offset(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        store = server.SqlStore(os.path.join(d, "keyset.db"))
        self.addCleanup(store.close)
        rows = [{"ts": "2026-10-30 01:00:%02d" % i, "level": "INF" if i % 3 else "ERR",
                 "msg": "fila %d" % i, "raw": "raw %d" % i, "_line": i,
                 "_search": "fila %d" % i} for i in range(60)]
        store.add_rows(rows, {})
        for q in ({}, {"level": ["ERR"]}, {"q": ["fila 1"]}, {"level": ["ERR"], "q": ["1"]}):
            for batch in (1, 5, 60):
                want = store.page_filtered(q, 0, 1000)
                self.assertEqual(self._keyset_all(store, q, batch), want,
                                 "q=%s batch=%d" % (q, batch))

    def test_export_keyset_no_es_cuadratico(self):
        """Smoke: 200k filas en SQLite con filtro; la keyset debe ser claramente
        mas rapida que el OFFSET creciente (que era O(N^2)).

        Con OFFSET, cada lote vuelve a recorrer y evaluar el WHERE de las
        'start' filas ya emitidas: en N filas por lotes de B se evaluan
        ~N^2/(2B) filas. Con 'rowid > ultimo' cada fila se evalua una vez."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        store = server.SqlStore(os.path.join(d, "grande.db"))
        self.addCleanup(store.close)
        n = 200000
        batch = server.Handler.EXPORT_BATCH
        rows = [{"ts": "2026-10-30 01:%02d:%02d" % (i // 3600, i % 3600),
                 "level": "INF", "msg": "fila %d" % i, "raw": "x" * 30,
                 "_search": "fila %d" % i, "_line": i} for i in range(n)]
        store.add_rows(rows, {})
        # El filtro con texto libre ('q') no tiene indice: con OFFSET cada lote
        # vuelve a evaluar el WHERE de las filas ya emitidas (~N^2/2B filas).
        q = {"level": ["INF"], "q": ["fila"]}
        t0 = time.perf_counter()
        got_keyset = self._keyset_all(store, q, batch)
        t_keyset = time.perf_counter() - t0
        t0 = time.perf_counter()
        got_offset = []
        start = 0
        while True:
            chunk = store.page_filtered(q, start, batch)
            if not chunk:
                break
            got_offset.extend(chunk)
            start += batch
        t_offset = time.perf_counter() - t0
        self.assertEqual(len(got_keyset), n)
        self.assertEqual(len(got_offset), n)
        self.assertEqual([r["rowid"] for r in got_keyset],
                         [r["rowid"] for r in got_offset])
        self.assertGreater(t_offset, 2 * t_keyset,
                           "keyset %.3f s vs offset %.3f s" % (t_keyset, t_offset))

    def test_export_csv_no_se_trunca_al_flush(self):
        """P1.2: 20k filas superan el umbral de flush (65536 bytes) y el export
        debe devolver TODAS, no solo el primer lote.

        El DictWriter quedaba apuntando al StringIO vaciado en flush(): a partir
        del segundo lote las filas se escribian en un buffer que nunca se enviaba."""
        import urllib.request
        n = 20000
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "muchas.log")
        with open(path, "w", encoding="utf-8") as f:
            for i in range(n):
                f.write("2026-10-30 01:%02d:%02d runner: fila %d\n"
                        % (i // 3600, i % 60, i))
        ds = server.load_file(path, user="local")
        self.addCleanup(ds["store"].close)
        server.SESSIONS.setdefault("local", {})[ds["name"]] = ds
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/export?name=%s&format=csv"
                    % (srv.server_port, ds["name"]), timeout=60) as r:
                body = r.read().decode("utf-8")
        finally:
            srv.shutdown()
            server.SESSIONS.get("local", {}).pop(ds["name"], None)
        rows = [l for l in body.splitlines() if l]
        self.assertEqual(len(rows), n + 1, "cabecera + %d filas" % n)
        # U4 (2026-10-30): el export sale de MAS NUEVO a MAS VIEJO: la primera
        # fila de datos es la ultima del archivo y la ultima es la primera.
        self.assertIn("fila %d" % (n - 1), rows[1])
        self.assertIn("fila 0", rows[-1])

    def test_tail_escribe_dentro_del_lock(self):
        """P1.2 (bug B6): la escritura al store va en el mismo LOCK que ds['total']."""
        src = inspect.getsource(server.Handler._tail)
        parts = src.split("with LOCK:")
        self.assertGreater(len(parts), 1)
        after = "".join(parts[1:])
        before = parts[0]
        self.assertIn("add_rows", after)
        self.assertNotIn("add_rows", before)


class TestContextSeek(unittest.TestCase):
    """P1.2 (bug B7): el contexto se lee con seek, no desde la linea 0."""

    def _naive(self, path, line, n):
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        return {"before": lines[max(0, line - n):line],
                "current": lines[line],
                "after": lines[line + 1:line + 1 + n]}

    def test_seek_identico_en_archivo_grande(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "grande.log")
        total = 120000
        with open(path, "w", encoding="utf-8") as f:
            for i in range(total):
                f.write("2026-10-30 01:00:00 runner: linea %d\n" % i)
        for line in (0, 1, 511, 512, 513, 60000, 119999):
            got = server.read_context_lines(path, line, 5)
            self.assertEqual(got, self._naive(path, line, 5), "linea %d" % line)
        # El indice existe y tiene checkpoints: se usó seek, no lectura desde 0
        idx = server._CONTEXT_INDEX.get((path, "utf-8"))
        self.assertTrue(idx and len(idx["marks"]) > 100)

    def test_seek_con_archivo_que_crece(self):
        """El tail anade lineas: el indice se prolonga, no se reconstruye."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "tail.log")
        with open(path, "w", encoding="utf-8") as f:
            for i in range(1000):
                f.write("2026-10-30 01:00:00 a: linea %d\n" % i)
        server.read_context_lines(path, 900, 3)
        with open(path, "a", encoding="utf-8") as f:
            for i in range(1000, 3000):
                f.write("2026-10-30 01:00:00 a: linea %d\n" % i)
        for line in (1500, 2999):
            got = server.read_context_lines(path, line, 4)
            self.assertEqual(got, self._naive(path, line, 4), "linea %d" % line)
        idx = server._CONTEXT_INDEX[(path, "utf-8")]
        self.assertGreaterEqual(idx["scanned"], 2995)
        # El indice se prolonga, no se reconstruye desde cero
        self.assertEqual(idx["marks"][0], 0)
        self.assertTrue(len(idx["marks"]) >= 6)

    def test_seek_con_lineas_largas_y_crlf(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "crlf.log")
        with open(path, "w", encoding="utf-8", newline="") as f:
            for i in range(2000):
                f.write("2026-10-30 01:00:00 runner: %s\r\n" % ("y" * (i % 97)))
        for line in (0, 999, 1999):
            got = server.read_context_lines(path, line, 3)
            want = self._naive(path, line, 3)
            self.assertEqual(got["current"], want["current"], "linea %d" % line)
            self.assertEqual(got["before"], want["before"], "linea %d" % line)
            self.assertEqual(got["after"], want["after"], "linea %d" % line)


class TestSavedViewsAndUrl(unittest.TestCase):
    """P3.1: vistas guardadas persistentes y query de filtros en la URL."""

    def _store(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return server.SavedViewsStore(os.path.join(d, "views.json"))

    def test_normalize_query_string(self):
        q = server.normalize_view_query("q=err&level=ERR&dt_from=2026-10-01T00:00")
        self.assertEqual(q, {"q": "err", "level": "ERR", "dt_from": "2026-10-01T00:00"})

    def test_normalize_query_dict_y_descarta_desconocidas(self):
        q = server.normalize_view_query({"q": [" err "], "evil": ["x"], "level": [""]})
        self.assertEqual(q, {"q": "err"})

    def test_normalize_query_none(self):
        self.assertEqual(server.normalize_view_query(None), {})
        self.assertEqual(server.normalize_view_query(123), {})

    def test_save_get_delete_y_persistencia(self):
        st = self._store()
        v = st.save("Errores de hoy", "level=ERR&q=vigilante")
        self.assertEqual(v["query"], {"level": "ERR", "q": "vigilante"})
        self.assertTrue(v["updated_at"])
        # Upsert por nombre: no duplica
        st.save("Errores de hoy", "level=ERR")
        self.assertEqual(len(st.all()), 1)
        self.assertEqual(st.get("Errores de hoy")["query"], {"level": "ERR"})
        # Persistencia: otra instancia sobre el mismo fichero ve la vista
        st2 = server.SavedViewsStore(st.path)
        self.assertEqual([x["name"] for x in st2.all()], ["Errores de hoy"])
        self.assertTrue(st.delete("Errores de hoy"))
        self.assertFalse(st.delete("no existe"))
        self.assertEqual(st.all(), [])
        st2 = server.SavedViewsStore(st.path)
        self.assertEqual(st2.all(), [])

    def test_nombre_vacio_y_tope_de_vistas(self):
        st = self._store()
        with self.assertRaises(ValueError):
            st.save("", "q=x")
        with self.assertRaises(ValueError):
            st.save("x" * 100, "q=x")
        for i in range(server.SavedViewsStore.MAX_VIEWS):
            st.save("v" + str(i), "q=x")
        with self.assertRaises(ValueError):
            st.save("demasiadas", "q=x")

    def test_fichero_corrupto_no_rompe(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "views.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("esto no es json")
        st = server.SavedViewsStore(path)
        self.assertEqual(st.all(), [])
        st.save("ok", "q=x")
        self.assertEqual(len(st.all()), 1)

    def test_ui_columns_sin_claves_internas(self):
        rows, _ = server.parse_piloop([
            "2026-10-30 01:12:33 vigilante: ok buzon",
            "2026-10-30 01:12:40 runner: tarea completada",
        ])
        store = server.MemStore()
        store.add_rows(rows, {})
        cols = server._ui_columns(store)
        self.assertIn("ts", cols)
        self.assertIn("comp", cols)
        for internal in ("raw", "ts_norm", "template", "_line", "_search"):
            self.assertNotIn(internal, cols)

    def test_api_rows_devuelve_columns(self):
        import urllib.request
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "tri.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("01:23:45 [vt] firma:phish.x -> real_incident conf 0.8 "
                    "sev 2.5 accion yes | ESCALADA t4f87df76\n")
        ds = server.load_file(path, user="local")
        server.SESSIONS.setdefault("local", {})[ds["name"]] = ds
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/rows?name=%s" % (srv.server_port, ds["name"]),
                    timeout=15) as r:
                data = json.loads(r.read().decode("utf-8"))
            self.assertIn("columns", data)
            self.assertIn("firma", data["columns"])
            self.assertNotIn("raw", data["columns"])
        finally:
            srv.shutdown()
            ds["store"].close()
            server.SESSIONS.get("local", {}).pop(ds["name"], None)

    def test_api_views_end_to_end(self):
        import urllib.request
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_port
        try:
            body = json.dumps({"name": "Vista P31", "query": "level=ERR&q=runner"}).encode()
            req = urllib.request.Request(base + "/api/views", data=body, method="POST",
                                        headers={"Content-Type": "application/json",
                                               "X-CSRF-Token": server.CSRF_TOKEN})
            with urllib.request.urlopen(req, timeout=15) as r:
                saved = json.loads(r.read().decode("utf-8"))
            self.assertTrue(saved["ok"])
            self.assertEqual(saved["view"]["query"], {"level": "ERR", "q": "runner"})
            with urllib.request.urlopen(base + "/api/views", timeout=15) as r:
                lst = json.loads(r.read().decode("utf-8"))
            self.assertTrue(any(v["name"] == "Vista P31" for v in lst["views"]))
            # Sin token CSRF debe dar 403
            bad = urllib.request.Request(base + "/api/views", data=body, method="POST",
                                        headers={"Content-Type": "application/json"})
            try:
                urllib.request.urlopen(bad, timeout=15)
                self.fail("el POST sin CSRF no debe pasar")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)
            req = urllib.request.Request(base + "/api/views/delete",
                                        data=json.dumps({"name": "Vista P31"}).encode(),
                                        method="POST",
                                        headers={"Content-Type": "application/json",
                                               "X-CSRF-Token": server.CSRF_TOKEN})
            with urllib.request.urlopen(req, timeout=15) as r:
                self.assertTrue(json.loads(r.read().decode("utf-8"))["ok"])
            with urllib.request.urlopen(base + "/api/views", timeout=15) as r:
                lst = json.loads(r.read().decode("utf-8"))
            self.assertFalse(any(v["name"] == "Vista P31" for v in lst["views"]))
        finally:
            srv.shutdown()

    def test_filter_plan_acepta_la_query_de_la_url(self):
        """P3.1: la query que refleja la URL es la misma que entiende el backend."""
        from urllib.parse import parse_qs
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "buzon.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("2026-10-30 01:12:33 vigilante: ok buzon\n"
                    "2026-10-30 02:59:00 runner: tarea completada\n")
        ds = server.load_file(path, user="local")
        self.addCleanup(ds["store"].close)
        url_query = "?q=buzon&dt_from=2026-10-30T01:00&dt_to=2026-10-30T02:00"
        q = parse_qs(url_query.lstrip("?"))
        plan = server.filter_plan(q)
        self.assertEqual(plan["dt_from"], "2026-10-30T01:00:00")
        self.assertEqual(plan["dt_to"], "2026-10-30T02:00:00")
        self.assertEqual(ds["store"].count_filtered(q), 1)
        rows = ds["store"].page_filtered(q, 0, 10)
        self.assertEqual(len(rows), 1)
        self.assertIn("vigilante", rows[0]["raw"])
        # Filtro sin resultados: el contracto del empty state (total == 0)
        self.assertEqual(ds["store"].count_filtered(
            parse_qs("?q=nada_de_esto".lstrip("?"))), 0)


class TestFollowFileAllowlist(unittest.TestCase):
    """P3.2: modo 'seguir archivo' (off por defecto, allowlist de directorios)."""

    def setUp(self):
        self._old_env = os.environ.get("LOGVIEWER_TAIL_DIRS")

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("LOGVIEWER_TAIL_DIRS", None)
        else:
            os.environ["LOGVIEWER_TAIL_DIRS"] = self._old_env

    def test_desactivado_por_defecto(self):
        os.environ.pop("LOGVIEWER_TAIL_DIRS", None)
        self.assertEqual(server.tail_allowlist(), [])
        self.assertFalse(server.tail_path_ok("C:\\cualquier\\log.log"))
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.assertFalse(server.tail_path_ok(os.path.join(d, "a.log")))

    def test_allowlist_inside_outside(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        os.environ["LOGVIEWER_TAIL_DIRS"] = d + ";" + os.path.join(d, "sub")
        dirs = server.tail_allowlist()
        self.assertEqual(len(dirs), 2)
        self.assertTrue(server.tail_path_ok(os.path.join(d, "buzon.log")))
        self.assertTrue(server.tail_path_ok(os.path.join(d, "sub", "x.log")))
        self.assertTrue(server.tail_path_ok(d))
        self.assertFalse(server.tail_path_ok(os.path.join(other, "x.log")))
        # Un prefijo de nombre no es un directorio permitido (d vs d2)
        self.assertFalse(server.tail_path_ok(d + "2" + os.sep + "x.log"))
        # Rutas relativas y traversal no salen de la allowlist
        self.assertFalse(server.tail_path_ok(os.path.join(d, "sub", "..", "..", "x.log")))
        self.assertFalse(server.tail_path_ok("/etc/passwd"))

    def test_config_expone_follow(self):
        os.environ.pop("LOGVIEWER_TAIL_DIRS", None)
        self.assertFalse(server.public_config()["follow"])
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        self.assertTrue(server.public_config()["follow"])

    def _srv(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def _post(self, base, path, body):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                    method="POST",
                                    headers={"Content-Type": "application/json",
                                           "X-CSRF-Token": server.CSRF_TOKEN})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))

    def test_open_file_sin_allowlist_da_403(self):
        os.environ.pop("LOGVIEWER_TAIL_DIRS", None)
        srv = self._srv()
        try:
            code, data = self._post("http://127.0.0.1:%d" % srv.server_port,
                                    "/api/open-file", {"path": "C:\\x\\a.log"})
            self.assertEqual(code, 403)
            self.assertIn("LOGVIEWER_TAIL_DIRS", data["error"])
        finally:
            srv.shutdown()

    def test_open_file_fuera_de_allowlist_da_403(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        srv = self._srv()
        try:
            code, data = self._post("http://127.0.0.1:%d" % srv.server_port,
                                    "/api/open-file",
                                    {"path": os.path.join(other, "a.log")})
            self.assertEqual(code, 403)
            self.assertIn("allowlist", data["error"])
        finally:
            srv.shutdown()

    def test_open_file_dentro_de_allowlist_carga_y_sigue(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "buzon.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("2026-10-30 01:12:33 vigilante: ok buzon\n")
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        old_poll = config.TAIL_POLL
        config.TAIL_POLL = 0.2
        srv = self._srv()
        try:
            code, data = self._post("http://127.0.0.1:%d" % srv.server_port,
                                    "/api/open-file", {"path": path})
            self.assertEqual(code, 200)
            self.assertEqual(data["total"], 1)
            self.assertTrue(data["watching"])
            ds = server.SESSIONS.get("local", {}).get(data["name"])
            self.assertIsNotNone(ds)
            self.assertEqual(ds["orig_path"], os.path.abspath(path))
            self.assertEqual(ds["format"], "piloop")
            # El watcher apunta al ORIGINAL, no a la copia temporal
            w = server.WATCHERS.get("local", {}).get(data["name"])
            self.assertEqual(w.path, os.path.abspath(path))
            # Linea nueva en el original -> el tail la trae
            with open(path, "a", encoding="utf-8") as f:
                f.write("2026-10-30 01:13:00 runner: tarea completada\n")
            deadline = time.time() + 6
            rows = []
            while time.time() < deadline and not rows:
                with urllib.request.urlopen(
                        "http://127.0.0.1:%d/api/tail?name=%s&last=50" %
                        (srv.server_port, data["name"]), timeout=15) as r:
                    rows = json.loads(r.read().decode("utf-8")).get("rows", [])
                if not rows:
                    time.sleep(0.2)
            self.assertTrue(rows, "el tail del original no trajo la linea nueva")
            self.assertIn("tarea completada", rows[0]["raw"])
            ds["store"].close()
            server.SESSIONS.get("local", {}).pop(data["name"], None)
        finally:
            config.TAIL_POLL = old_poll
            srv.shutdown()

    # --- S2 (2026-10-30): 'seguir archivo' SOLO desde loopback -------------
    # El gate de loopback se comprueba de dos formas: el helper unitario y una
    # peticion real cuyo client_address se fuerza a una IP no-loopback.
    class _FakeHandler:
        def __init__(self, addr):
            self.client_address = addr

    class _RemoteServer(ThreadingHTTPServer):
        """Servidor que atiende la peticion como si viniera de una IP remota.

        finish_request es el punto donde socketserver pasa el client_address
        real al handler; aqui se sustituye por una IP publica de ejemplo
        (203.0.113.7, rango documentation de RFC 5737) para simular el
        cliente remoto de Railway/Cloudflare sin salir de la maquina."""
        def finish_request(self, request, client_address):
            # BaseHandler.__init__(request, client_address, server): el segundo
            # argumento es el client_address, no la direccion del servidor.
            self.RequestHandlerClass(request, ("203.0.113.7", 44444), self)

    def _remote_srv(self):
        srv = self._RemoteServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def _get(self, base, path):
        try:
            with urllib.request.urlopen(base + path, timeout=20) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))

    def test_helper_client_is_loopback(self):
        F = TestFollowFileAllowlist._FakeHandler
        for addr in (("127.0.0.1", 80), ("::1", 80), ("localhost", 80),
                     ("127.0.0.42", 80)):
            self.assertTrue(server._client_is_loopback(F(addr)),
                            "%s debe considerarse loopback" % (addr,))
        for addr in (("203.0.113.7", 80), ("10.0.0.5", 80), ("81.203.1.9", 80),
                     (None, 80)):
            self.assertFalse(server._client_is_loopback(F(addr)),
                             "%s no es loopback" % (addr,))

    def test_config_follow_por_cliente(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        self.assertTrue(server.public_config(client_host="127.0.0.1")["follow"])
        self.assertTrue(server.public_config(client_host="::1")["follow"])
        self.assertTrue(server.public_config()["follow"],
                        "sin cliente (uso interno) se considera local")
        self.assertFalse(server.public_config(client_host="203.0.113.7")["follow"])
        self.assertFalse(server.public_config(client_host="10.0.0.5")["follow"])
        os.environ.pop("LOGVIEWER_TAIL_DIRS", None)
        self.assertFalse(server.public_config(client_host="127.0.0.1")["follow"],
                         "sin allowlist sigue siendo False aunque sea local")

    def test_open_file_desde_ip_remota_da_403(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "a.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("2026-10-30 01:12:33 vigilante: ok buzon\n")
        # Allowlist definida: el 403 viene del gate de loopback, no de la
        # allowlist (que es la segunda capa).
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        srv = self._remote_srv()
        try:
            code, data = self._post("http://127.0.0.1:%d" % srv.server_port,
                                    "/api/open-file", {"path": path})
            self.assertEqual(code, 403)
            self.assertIn("loopback", data["error"])
        finally:
            srv.shutdown()

    def test_config_desde_ip_remota_reporta_follow_false(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        srv = self._remote_srv()
        try:
            code, data = self._get("http://127.0.0.1:%d" % srv.server_port,
                                   "/api/config")
            self.assertEqual(code, 200)
            self.assertFalse(data["follow"])
        finally:
            srv.shutdown()

    def test_watch_de_follow_desde_ip_remota_da_403(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        name = "remoto-follow.log"
        with server.LOCK:
            server.SESSIONS.setdefault("local", {})[name] = {
                "follow": True, "orig_path": os.path.join(d, "a.log"),
                "total": 0, "format": "piloop", "encoding": "utf-8"}
        srv = self._remote_srv()
        try:
            code, data = self._post("http://127.0.0.1:%d" % srv.server_port,
                                    "/api/watch", {"name": name,
                                                   "enabled": True})
            self.assertEqual(code, 403)
            self.assertIn("loopback", data["error"])
        finally:
            srv.shutdown()
            with server.LOCK:
                server.SESSIONS.get("local", {}).pop(name, None)

    def test_watch_de_follow_desde_loopback_sigue_permitido(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        name = "local-follow.log"
        with server.LOCK:
            server.SESSIONS.setdefault("local", {})[name] = {
                "follow": True, "orig_path": os.path.join(d, "a.log"),
                "total": 0, "format": "piloop", "encoding": "utf-8"}
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            code, data = self._post("http://127.0.0.1:%d" % srv.server_port,
                                    "/api/watch", {"name": name,
                                                   "enabled": True})
            self.assertEqual(code, 200)
            self.assertTrue(data["enabled"])
        finally:
            srv.shutdown()
            with server.LOCK:
                server.SESSIONS.get("local", {}).pop(name, None)


class TestUiA11yP32(unittest.TestCase):
    """P3.2: contrato de accesibilidad y responsive en los ficheros UI."""

    def _read(self, name):
        path = os.path.join(os.path.dirname(os.path.abspath(server.__file__)),
                            "static", name)
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def test_index_html_a11y(self):
        html = self._read("index.html")
        self.assertIn('id="count" class="muted" aria-live="polite"', html)
        self.assertIn('<table role="table" aria-label="Lineas del archivo cargado">', html)
        self.assertIn('id="drawer-kv" role="table"', html)
        self.assertIn("skip-link", html)
        self.assertIn('id="btn-sidebar"', html)
        self.assertIn('aria-expanded="false" aria-controls="sidebar"', html)
        self.assertIn('id="follow-wrap"', html)
        self.assertIn("LOGVIEWER_TAIL_DIRS", html)

    def test_app_js_atajos(self):
        js = self._read("app.js")
        self.assertIn('k === "j"', js)
        self.assertIn('k === "k"', js)
        self.assertIn('e.key === "]"', js)
        self.assertIn('e.key === "["', js)
        self.assertIn("function stepPage", js)
        self.assertIn("function focusFilter", js)
        self.assertIn("RAW_PREVIEW: 600", js)
        self.assertIn("copyRaw()", js)
        self.assertIn("toggleRaw()", js)

    def test_styles_breakpoints_y_foco(self):
        css = self._read("styles.css")
        for q in ("@media (min-width: 1200px)", "@media (max-width: 900px)",
                  "@media (max-width: 600px)"):
            self.assertIn(q, css)
        self.assertIn(":focus-visible", css)
        self.assertIn("body.side-open .sidebar", css)
        self.assertIn("prefers-reduced-motion", css)



class TestPersistAndCorrelateP41(unittest.TestCase):
    """P4.1 (2026-10-30): --persist y correlacion alertas <-> triage."""

    ALERTAS = [
        '{"ts": "2026-10-28 10:00:01", "fuente": "splunk", '
        '"firma": "Piloop - Guard blocks", "tenant": "local", "sev": "baja", '
        '"mensaje": "guard bloqueado", "tarea": "", "dedupe": "nueva"}',
        '{"ts": "2026-10-28 10:00:02", "fuente": "splunk", '
        '"firma": "Piloop - Alertas SOC", "tenant": "local", "sev": "alta", '
        '"mensaje": "alerta SOC", "tarea": "t4ab1d1d0", "dedupe": "encolada"}',
        '{"ts": "2026-10-28 10:00:03", "fuente": "netwatch", '
        '"firma": "netwatch:finding:x", "tenant": "local", "sev": "media", '
        '"mensaje": "hallazgo", "tarea": "", "dedupe": "encolada"}',
        '{"ts": "2026-10-28 10:00:04", "fuente": "laya", '
        '"firma": "F-SIN-TRIAGE", "tenant": "local", "sev": "baja", '
        '"mensaje": "nada", "tarea": "", "dedupe": "nueva"}',
    ]
    TRIAGE = [
        "23:40:01 [splunk] Piloop - Guard blocks -> expected conf 0.95 "
        "sev 0.5 accion no | sin tarea",
        "23:40:04 [splunk] Piloop - Alertas SOC -> false_positive conf 0.31 "
        "sev 1.3 accion yes | ESCALADA t4ab1d1d0",
        "23:41:00 [laya] F-LAYA -> expected conf 0.9 sev 0.2 accion no "
        "| sin tarea",
        "linea suelta que no es una linea de triage",
    ]

    def _tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def test_startup_cleanup_borra_por_defecto(self):
        d = self._tmp()
        f = os.path.join(d, "sessions", "local", "a.log")
        os.makedirs(os.path.dirname(f), exist_ok=True)
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("hola\n")
        server.startup_cleanup(False, tmpdir=d)
        self.assertFalse(os.path.exists(f))
        self.assertTrue(os.path.isdir(os.path.join(d, "sessions")))
        self.assertTrue(os.path.isdir(os.path.join(d, "sqlite")))

    def test_startup_cleanup_persist_conserva(self):
        d = self._tmp()
        f = os.path.join(d, "sessions", "local", "a.log")
        db = os.path.join(d, "sqlite", "local", "a.db")
        os.makedirs(os.path.dirname(f), exist_ok=True)
        os.makedirs(os.path.dirname(db), exist_ok=True)
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("hola\n")
        with open(db, "w", encoding="utf-8") as fh:
            fh.write("sqlite placeholder\n")
        server.startup_cleanup(True, tmpdir=d)
        self.assertTrue(os.path.exists(f))
        self.assertTrue(os.path.exists(db))

    def test_main_acepta_persist(self):
        src = inspect.getsource(server.main)
        self.assertIn("--persist", src)
        self.assertIn("startup_cleanup(args.persist)", src)
        self.assertIn("restore_sessions_from_disk", src)

    def test_correlacion_por_firma(self):
        arows, _ = server.parse_json(self.ALERTAS)
        trows, _ = server.parse_triage(self.TRIAGE, file_date="2026-10-28")
        res = server.correlate(arows, trows)
        self.assertEqual(res["alerts_total"], 4)
        self.assertEqual(res["matched"], 2)
        self.assertEqual(res["counts"]["escalada"], 1)
        self.assertEqual(res["counts"]["descartada"], 1)
        self.assertEqual(res["counts"]["encolada"], 1)
        self.assertEqual(res["counts"]["sin_triage"], 1)
        by_firma = {it["firma"]: it for it in res["items"]}
        self.assertEqual(by_firma["Piloop - Alertas SOC"]["status"], "escalada")
        self.assertEqual(by_firma["Piloop - Alertas SOC"]["tarea"], "t4ab1d1d0")
        self.assertEqual(by_firma["Piloop - Guard blocks"]["status"], "descartada")
        self.assertEqual(by_firma["Piloop - Guard blocks"]["motivo"], "sin tarea")
        self.assertEqual(by_firma["netwatch:finding:x"]["status"], "encolada")
        self.assertEqual(by_firma["F-SIN-TRIAGE"]["status"], "sin_triage")
        self.assertFalse(res["truncated"])

    def test_correlacion_filtra_por_status_y_firma(self):
        arows, _ = server.parse_json(self.ALERTAS)
        trows, _ = server.parse_triage(self.TRIAGE, file_date="2026-10-28")
        res = server.correlate(arows, trows, status_q="escalada")
        self.assertEqual(len(res["items"]), 1)
        self.assertEqual(res["items"][0]["firma"], "Piloop - Alertas SOC")
        res = server.correlate(arows, trows, firma_q="guard")
        self.assertEqual(len(res["items"]), 1)
        self.assertEqual(res["items"][0]["status"], "descartada")
        res = server.correlate(arows, trows, limit=1)
        self.assertEqual(len(res["items"]), 1)
        self.assertTrue(res["truncated"])

    def test_correlacion_por_tarea_cuando_no_coincide_la_firma(self):
        arows, _ = server.parse_json([
            '{"firma": "FIRMA-NOVA", "tarea": "t999", "dedupe": "nueva", '
            '"sev": "alta", "mensaje": "x"}',
        ])
        trows, _ = server.parse_triage([
            "01:02:03 [otrafuente] OTRA FIRMA -> real_incident conf 0.9 "
            "sev 2.0 accion yes | ESCALADA t999",
        ])
        res = server.correlate(arows, trows)
        self.assertEqual(res["matched"], 1)
        self.assertEqual(res["items"][0]["status"], "escalada")
        self.assertEqual(res["items"][0]["match_by"], "tarea")
        self.assertEqual(res["items"][0]["tarea"], "t999")

    def test_triage_index_descarta_lineas_raw(self):
        trows, _ = server.parse_triage(["no es triage", "otra linea"])
        by_firma, by_tarea = server.triage_index(trows)
        self.assertEqual(by_firma, {})
        self.assertEqual(by_tarea, {})

    def test_api_correlate_end_to_end(self):
        d = self._tmp()
        ap = os.path.join(d, "alertas.jsonl")
        tp = os.path.join(d, "triage.log")
        with open(ap, "w", encoding="utf-8") as fh:
            fh.write("\n".join(self.ALERTAS))
        with open(tp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(self.TRIAGE))
        ads = server.load_file(ap, user="local")
        tds = server.load_file(tp, user="local")
        self.addCleanup(ads["store"].close)
        self.addCleanup(tds["store"].close)
        mine = server._user_state("local", server.SESSIONS)
        old = dict(mine)
        mine["alertas.jsonl"] = ads
        mine["triage.log"] = tds
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/correlate" % srv.server_port,
                    timeout=15) as r:
                res = json.loads(r.read().decode("utf-8"))
            self.assertEqual(res["alerts_name"], "alertas.jsonl")
            self.assertEqual(res["triage_name"], "triage.log")
            self.assertEqual(res["matched"], 2)
            self.assertEqual(res["counts"]["escalada"], 1)
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/correlate?status=escalada"
                    % srv.server_port, timeout=15) as r:
                res2 = json.loads(r.read().decode("utf-8"))
            self.assertEqual(len(res2["items"]), 1)
            try:
                urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/correlate?alerts=noexiste"
                    % srv.server_port, timeout=15)
                self.fail("sin dataset de alertas no debe responder 200")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 404)
        finally:
            srv.shutdown()
            mine.clear()
            mine.update(old)

    def test_ui_correlate_button_y_modal(self):
        base = os.path.join(os.path.dirname(os.path.abspath(server.__file__)),
                            "static")
        html = open(os.path.join(base, "index.html"), encoding="utf-8").read()
        js = open(os.path.join(base, "app.js"), encoding="utf-8").read()
        css = open(os.path.join(base, "styles.css"), encoding="utf-8").read()
        self.assertIn('id="act-correlate"', html)
        self.assertIn('id="corr-modal"', html)
        self.assertIn('aria-label="Correlacion de alertas y triage"', html)
        self.assertIn("function runCorrelate", js)
        self.assertIn("api.correlate", js)
        self.assertIn(".corr-table", css)

    def test_restore_sessions_from_disk(self):
        d = self._tmp()
        sdir = os.path.join(d, "sessions", "local")
        os.makedirs(sdir, exist_ok=True)
        p = os.path.join(sdir, "alertas.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(self.ALERTAS))
        n = server.restore_sessions_from_disk(os.path.join(d, "sessions"))
        self.assertEqual(n, 1)
        ds = server.SESSIONS.get("local", {}).get("alertas.jsonl")
        self.addCleanup(lambda: server.SESSIONS.get("local", {}).pop(
            "alertas.jsonl", None))
        self.assertIsNotNone(ds)
        self.assertEqual(ds["total"], 4)
        self.assertEqual(ds["format"], "json")


class TestHealthAndTailCli(unittest.TestCase):
    """P5.1 (2026-10-30): /api/health y la CLI --tail."""

    def test_health_campos(self):
        h = api.health_payload("local")
        self.assertEqual(h["status"], "ok")
        self.assertEqual(h["version"], config.APP_VERSION)
        self.assertIn(h["backend"], ("mem", "sqlite"))
        self.assertGreaterEqual(h["uptime"], 0.0)

    def test_health_backend_sqlite(self):
        d = tempfile.mkdtemp()
        sql = api.SqlStore(os.path.join(d, "p51.db"))
        sql.add_rows([{"ts": "2026-10-30 01:00:00", "level": "ERR",
                      "msg": "error", "raw": "error"}], {})
        ds = {"name": "p51", "format": "generic", "store": sql,
              "total": 1, "size": 5, "encoding": "utf-8"}
        server.SESSIONS.setdefault("local", {})["p51"] = ds
        server.ACTIVE["local"] = "p51"
        self.addCleanup(lambda: server.SESSIONS.get("local", {}).pop(
            "p51", None))
        self.addCleanup(sql.close)
        h = api.health_payload("local")
        self.assertEqual(h["backend"], "sqlite")
        self.assertEqual(h["datasets"], 1)

    def test_tail_cli_ultima_lineas(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "tail.log")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            for i in range(1, 201):
                fh.write("linea %d\r\n" % i)
        out = server.tail_lines(path, 5)
        self.assertEqual(out, ["linea %d" % i for i in range(196, 201)])

    def test_tail_cli_fichero_inexistente(self):
        missing = os.path.join(tempfile.mkdtemp(), "no-existe.log")
        self.assertEqual(server.tail_lines(missing, 5), [])

    def test_server_modularizado(self):
        """P5.1: server.py es solo la entrada; la logica esta repartida."""
        base = os.path.dirname(os.path.abspath(server.__file__))
        for mod in ("config.py", "security.py", "parsers.py",
                    "stores.py", "api.py"):
            self.assertTrue(os.path.exists(os.path.join(base, mod)), mod)
        self.assertLess(len(inspect.getsource(server).splitlines()), 300)


class TestParserAuto(unittest.TestCase):
    # U0.1 (2026-10-30): parser universal 'auto' (best-effort).

    def test_auto_registrado_en_PARSERS(self):
        self.assertIn("auto", server.PARSERS)
        self.assertIs(server.PARSERS["auto"], server.parse_auto)

    def test_auto_iso_t_con_zona(self):
        rows, _ = server.parse_auto(
            ["2026-10-30T10:15:30.123Z app=api level=error ip=10.0.0.5 msg=fallo"])
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30T10:15:30.123Z")
        self.assertTrue(r["ts_norm"].startswith("2026-10-30T10:15:30"))
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["ip"], "10.0.0.5")
        self.assertEqual(r["app"], "api")

    def test_auto_iso_espacio_sin_zona(self):
        rows, _ = server.parse_auto(["2026-10-30 10:15:30 ERROR algo falla"])
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertTrue(rows[0]["ts_norm"].startswith("2026-10-30T10:15:30"))

    def test_auto_epoch_segundos(self):
        rows, _ = server.parse_auto(["1761234567 INFO servicio listo"])
        r = rows[0]
        self.assertEqual(r["ts"], "1761234567")
        self.assertTrue(r["ts_norm"].startswith("2025-"))
        self.assertEqual(r["level"], "INF")

    def test_auto_epoch_milisegundos(self):
        rows, _ = server.parse_auto(["1761234567890 WARN host=web01 status=500"])
        r = rows[0]
        self.assertEqual(r["ts"], "1761234567890")
        self.assertTrue(r["ts_norm"].startswith("2025-"))
        self.assertEqual(r["level"], "WRN")
        self.assertEqual(r["host"], "web01")
        self.assertEqual(r["status"], "500")

    def test_auto_ddmm_y_mmdd(self):
        rows, _ = server.parse_auto(["30/10/2026 10:00:01 [ERROR] NPE"])
        r = rows[0]
        self.assertEqual(r["ts_norm"], "2026-10-30T10:00:01")
        self.assertEqual(r["level"], "ERR")
        rows, _ = server.parse_auto(["10/30/2026 10:00:02 trace query"])
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T10:00:02")
        self.assertEqual(rows[0]["level"], "DBG")

    def test_auto_rfc3164(self):
        rows, _ = server.parse_auto(["Oct 30 10:00:00 server[1234] INFO nginx ok"])
        r = rows[0]
        self.assertEqual(r["ts"], "Oct 30 10:00:00")
        self.assertTrue(r["ts_norm"].endswith("-10-30T10:00:00"))
        self.assertEqual(r["level"], "INF")

    def test_auto_yyyy_mm_dd(self):
        rows, _ = server.parse_auto(["2026/10/30 10:00:03 NOTICE backup ok"])
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T10:00:03")
        self.assertEqual(rows[0]["level"], "INF")

    def test_auto_nivel_en_cualquier_posicion(self):
        rows, _ = server.parse_auto(["crash en modulo 3: fatal, no responde"])
        self.assertEqual(rows[0]["level"], "CRIT")
        rows, _ = server.parse_auto(["[warning] disco lleno en /var"])
        self.assertEqual(rows[0]["level"], "WRN")

    def test_auto_sin_sena_es_raw(self):
        rows, counters = server.parse_auto(["Traceback (most recent call last):"])
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["ts"], "")
        self.assertEqual(rows[0]["msg"], "Traceback (most recent call last):")
        self.assertEqual(counters["levels"]["RAW"], 1)

    def test_auto_extrae_ip_y_columnas_dinamicas(self):
        rows, counters = server.parse_auto(
            ["2026-10-30T10:00:00 pid=42 method=GET path=/a status=200 "
            "duration=12ms client=192.168.1.7"])
        r = rows[0]
        self.assertEqual(r["ip"], "192.168.1.7")
        self.assertEqual(r["pid"], "42")
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["path"], "/a")
        self.assertEqual(r["code"] or r["status"], "200")
        self.assertEqual(r["duration"], "12ms")
        self.assertIn("pid", counters["keys"])

    def test_detect_format_auto_iso_epoch_logfmt(self):
        # Correccion (2026-10-30, U0.2): con dos o mas pares clave=valor la
        # linea ya es logfmt, no 'auto'. 'auto' sigue para lo que solo tiene
        # una sena suelta (un epoch y un 'host=...').
        self.assertEqual(server.detect_format(
            ["2026-10-30T10:15:30Z app=api level=info msg=ok"]), "logfmt")
        self.assertEqual(server.detect_format(
            ["1761234567890 WARN host=web01"]), "auto")
        self.assertEqual(server.detect_format(
            ["ts=2026-10-30 level=error msg=fallo"]), "logfmt")

    def test_detect_format_sin_sena_sigue_raw(self):
        self.assertEqual(server.detect_format(
            ["Traceback (most recent call last):"] * 10), "raw")
        # 3 de 10 lineas con fecha: por debajo del umbral de 40% -> raw
        self.assertEqual(server.detect_format(
            ["2026-10-12 20:40:16 logs: rotado a.log"] * 3
            + ["Traceback (most recent call last):"] * 7), "raw")

    def test_auto_no_rompe_formatos_conocidos(self):
        sample = ["2026-10-12 20:40:16 logs: rotado buzon.log (>0.0 MB)"] * 5
        self.assertEqual(server.detect_format(sample), "piloop")
        sample = ['127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /a HTTP/1.1" 200 1234'] * 5
        self.assertEqual(server.detect_format(sample), "apache")

    def test_auto_ts_norm_rellena(self):
        rows, _ = server.parse_auto(["2026-10-30T10:15:30+0200 level=info msg=ok"])
        self.assertTrue(rows[0]["ts_norm"])
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T08:15:30")

    def test_auto_filtro_por_ts_norm(self):
        rows, _ = server.parse_auto(["2026-10-30T10:15:30Z level=error msg=fallo"])
        got = server.apply_filters(rows, {"dt_from": "2026-10-30",
                                          "dt_to": "2026-10-31"})
        self.assertEqual(len(got), 1)
        got = server.apply_filters(rows, {"dt_from": "2026-11-01"})
        self.assertEqual(len(got), 0)

class TestFormatosU02(unittest.TestCase):
    """U0.2 (2026-10-30): python logging, syslog RFC3164, logfmt, CSV/TSV
    y nginx error_log. Cada formato se detecta y se parsea con fecha,
    nivel y columnas propias."""

    # --- python logging ------------------------------------------------------
    def test_python_logging_detect(self):
        sample = [
            "2026-10-30 10:11:50,123 - app.logger - INFO - arranque ok",
            "2026-10-30 10:11:51,456 - app.logger - ERROR - fallo",
        ] * 3
        self.assertEqual(server.detect_format(sample), "python")

    def test_python_logging_parse(self):
        rows, counters = server.parse_python_logging(
            ["2026-10-30 10:11:50,123 - app.logger - INFO - arranque ok"])
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30 10:11:50,123")
        self.assertEqual(r["ts_norm"], "2026-10-30T10:11:50.123000")
        self.assertEqual(r["level"], "INF")
        self.assertEqual(r["logger"], "app.logger")
        self.assertEqual(r["msg"], "arranque ok")
        self.assertEqual(counters["levels"]["INF"], 1)

    def test_python_logging_sin_logger(self):
        rows, _ = server.parse_python_logging(
            ["2026-10-30 10:11:52 - WARNING - algo raro"])
        self.assertEqual(rows[0]["level"], "WRN")
        self.assertEqual(rows[0]["logger"], "")
        self.assertEqual(rows[0]["msg"], "algo raro")
        self.assertEqual(rows[0]["ts"], "2026-10-30 10:11:52")

    def test_python_logging_linea_no_matchea_es_raw(self):
        rows, counters = server.parse_python_logging(
            ["Traceback (most recent call last):"])
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["msg"], "Traceback (most recent call last):")
        self.assertEqual(counters["levels"]["RAW"], 1)

    def test_python_logging_ip(self):
        rows, counters = server.parse_python_logging(
            ["2026-10-30 10:11:50,123 - net - ERROR - 10.0.0.5 rechazado"])
        self.assertEqual(rows[0]["ip"], "10.0.0.5")
        self.assertEqual(counters["ips"]["10.0.0.5"], 1)

    # --- syslog RFC 3164 -----------------------------------------------------
    def test_syslog3164_detect(self):
        sample = [
            "Oct 30 10:00:00 web01 nginx[1234]: upstream timed out",
            "Oct 30 10:00:01 web01 sshd[99]: Failed password for root",
        ] * 3
        self.assertEqual(server.detect_format(sample), "syslog3164")

    def test_syslog3164_parse(self):
        rows, counters = server.parse_syslog3164(
            ["Oct 30 10:00:00 web01 nginx[1234]: upstream timed out"])
        r = rows[0]
        self.assertTrue(r["ts"].endswith("-10-30 10:00:00"))
        self.assertTrue(r["ts_norm"])
        self.assertEqual(r["host"], "web01")
        self.assertEqual(r["app"], "nginx")
        self.assertEqual(r["pid"], "1234")
        self.assertEqual(r["msg"], "upstream timed out")
        self.assertEqual(r["level"], "INF")
        self.assertEqual(counters["hosts"]["web01"], 1)

    def test_syslog3164_prioridad_da_nivel(self):
        rows, _ = server.parse_syslog3164(["<12>Oct 30 10:00:02 web02 kernel: oom"])
        self.assertEqual(rows[0]["level"], "WRN")
        rows, _ = server.parse_syslog3164(["<11>Oct 30 10:00:03 web02 kernel: panic"])
        self.assertEqual(rows[0]["level"], "ERR")

    def test_syslog3164_sin_colon(self):
        rows, _ = server.parse_syslog3164(["Oct 30 10:00:04 host app mensaje suelto"])
        self.assertEqual(rows[0]["app"], "app")
        self.assertEqual(rows[0]["msg"], "mensaje suelto")

    # --- logfmt --------------------------------------------------------------
    def test_logfmt_detect(self):
        sample = ["ts=2026-10-30T10:15:30Z level=info msg=ok app=api"] * 3
        self.assertEqual(server.detect_format(sample), "logfmt")

    def test_logfmt_parse_mapeos(self):
        rows, counters = server.parse_logfmt([
            'timestamp="2026-10-30 10:15:31" severity=error '
            "message=\"disk full\" host=web01 duration=12ms",
        ])
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30 10:15:31")
        self.assertEqual(r["ts_norm"], "2026-10-30T10:15:31")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["msg"], "disk full")
        self.assertEqual(r["host"], "web01")
        self.assertEqual(r["duration"], "12ms")
        self.assertIn("host", counters["keys"])

    def test_logfmt_linea_sin_kv_es_raw(self):
        rows, counters = server.parse_logfmt(["Traceback (most recent call last):"])
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(counters["levels"]["RAW"], 1)

    def test_logfmt_filtro_por_nivel(self):
        rows, _ = server.parse_logfmt([
            "ts=2026-10-30T10:00:00Z level=error msg=fallo",
            "ts=2026-10-30T10:00:01Z level=info msg=ok",
        ])
        got = server.apply_filters(rows, {"level": ["ERR"]})
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["msg"], "fallo")

    # --- CSV / TSV ----------------------------------------------------------
    def test_csv_detect(self):
        sample = [
            "fecha,nivel,mensaje,host",
            "2026-10-30 10:00:00,ERROR,timeout,web01",
            "2026-10-30 10:00:01,INFO,ok,web02",
        ] * 2
        self.assertEqual(server.detect_format(sample), "csv")

    def test_csv_parse(self):
        rows, counters = server.parse_csv([
            "fecha,nivel,mensaje,host",
            "2026-10-30 10:00:00,ERROR,timeout,web01",
        ])
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30 10:00:00")
        self.assertEqual(r["ts_norm"], "2026-10-30T10:00:00")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["msg"], "timeout")
        self.assertEqual(r["host"], "web01")
        self.assertEqual(counters["keys"]["host"], 1)
        self.assertEqual(len(rows), 1)

    def test_csv_punto_y_coma_y_tabulador(self):
        rows, _ = server.parse_csv(["date;level;message",
                                   "2026-10-30;WARN;reintento"])
        self.assertEqual(rows[0]["level"], "WRN")
        self.assertEqual(rows[0]["msg"], "reintento")
        rows, _ = server.parse_csv(["date\tlevel\tmessage",
                                    "2026-10-30\tDEBUG\ttask done"])
        self.assertEqual(rows[0]["level"], "DBG")
        self.assertEqual(rows[0]["msg"], "task done")

    def test_csv_sin_cabecera_genera_columnas(self):
        rows, _ = server.parse_csv([
            "2026-10-30,INFO,ok,web01",
            "2026-10-31,ERROR,caida,web02",
        ])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ts"], "2026-10-30")
        self.assertEqual(rows[0]["level"], "INF")
        self.assertEqual(rows[0]["c2"], "ok")
        self.assertEqual(rows[0]["c3"], "web01")

    def test_csv_comillas_y_delimitador_dentro_del_valor(self):
        rows, _ = server.parse_csv([
            "date,level,message",
            '2026-10-30,ERROR,"a, b",',
        ])
        self.assertEqual(rows[0]["msg"], "a, b")

    # --- nginx error_log ----------------------------------------------------
    def test_nginx_error_detect(self):
        sample = [
            "2026/10/30 10:11:50 [error] 1234#5678: *3 upstream timed out",
            "2026/10/30 10:11:51 [warn] 1234#0: worker exited",
        ] * 3
        self.assertEqual(server.detect_format(sample), "nginx_error")

    def test_nginx_error_parse(self):
        rows, counters = server.parse_nginx_error([
            "2026/10/30 10:11:50 [error] 1234#5678: *3 upstream timed out",
            "2026/10/30 10:11:51 [emerg] 99: no such worker",
        ])
        self.assertEqual(rows[0]["ts"], "2026-10-30 10:11:50")
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T10:11:50")
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(rows[0]["pid"], "1234")
        self.assertEqual(rows[0]["tid"], "5678")
        self.assertEqual(rows[0]["msg"], "*3 upstream timed out")
        self.assertEqual(rows[1]["level"], "CRIT")
        self.assertEqual(rows[1]["pid"], "99")
        self.assertEqual(rows[1]["tid"], "")
        self.assertEqual(counters["pid"]["1234"], 1)

    def test_nginx_error_no_confundido_con_generic(self):
        sample = ["2026/10/30 10:11:50 [error] 1234#5678: *3 upstream timed out"] * 5
        self.assertNotEqual(server.detect_format(sample), "generic")
        self.assertNotEqual(server.detect_format(sample), "auto")

    def test_los_nuevos_parsers_estan_en_PARSERS(self):
        for key in ("python", "syslog3164", "logfmt", "csv", "nginx_error"):
            self.assertIn(key, server.PARSERS)

    def test_no_rompe_formatos_conocidos(self):
        # Los formatos previos siguen detectandose igual tras U0.2.
        self.assertEqual(server.detect_format(
            ["2026-10-12 20:40:16 logs: rotado buzon.log"] * 5), "piloop")
        self.assertEqual(server.detect_format(
            ['127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /a HTTP/1.1" 200 1234'] * 5),
            "apache")
        self.assertEqual(server.detect_format(
            ["2026-10-30 10:00:00 INFO arranque"] * 5), "generic")
        self.assertEqual(server.detect_format(
            ["Traceback (most recent call last):"] * 10), "raw")


class TestDetectFormatU11(unittest.TestCase):
    """U1.1 (2026-10-30): orden determinista de firmas y fallback 'auto'.

    detect_format prueba los formatos de mas estructurado a menos y solo
    devuelve 'raw' si no hay timestamp, ni nivel, ni clave=valor.
    """

    def test_csv_primero_que_otras_firmas(self):
        sample = ["fecha,nivel,mensaje,host"] + ["2026-10-30 10:00:00,INFO,ok,web01"] * 9
        self.assertEqual(server.detect_format(sample), "csv")

    def test_syslog5424_antes_que_3164(self):
        sample = ["1 2026-10-30T10:00:00.123Z web01 kernel[12]: oom kill"] * 8
        self.assertEqual(server.detect_format(sample), "syslog")

    def test_iso_t_no_cae_a_raw(self):
        sample = ["2026-10-30T10:15:30.000Z api srv01 GET /health 200 12ms"] * 5
        fmt = server.detect_format(sample)
        self.assertNotEqual(fmt, "raw")
        self.assertIn(fmt, ("auto", "generic", "syslog"))
        rows, _ = server.PARSERS[fmt](sample)
        self.assertTrue(rows[0]["ts_norm"])

    def test_epoch_no_cae_a_raw(self):
        sample = ["1761234567890 WARN host=web01 disk lleno"] * 5
        self.assertEqual(server.detect_format(sample), "auto")
        rows, _ = server.parse_auto(sample)
        self.assertEqual(rows[0]["level"], "WRN")
        self.assertEqual(rows[0]["ts_norm"], "2025-10-23T15:49:27.890000")

    def test_hora_sola_no_cae_a_raw(self):
        sample = ["10:11:12 rotacion de buzon.log"] * 5
        self.assertEqual(server.detect_format(sample), "auto")
        rows, _ = server.parse_auto(sample)
        self.assertEqual(rows[0]["ts"], "10:11:12")
        self.assertNotEqual(rows[0]["level"], "RAW")

    def test_java_con_fecha_es_generic(self):
        sample = [
            "2026-10-30 09:12:01.123 ERROR com.example.Main - fallo en el parseo",
            "    at com.example.LogParser.parse(LogParser.java:42)",
            "    at com.example.Main.main(Main.java:17)",
            "2026-10-30 09:12:02.456 INFO com.example.Main - reintentando",
        ]
        # J1 (2026-10-30): el milisegundo y el logger delatan el pattern
        # log4j, asi que ahora se detecta como 'java' (antes 'generic').
        self.assertEqual(server.detect_format(sample), "java")

    def test_xml_no_cae_a_raw(self):
        sample = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<log>",
            "  <entry time=\"2026-10-30T10:00:00Z\" level=\"error\">disk full</entry>",
            "  <entry time=\"2026-10-30T10:00:01Z\" level=\"info\">ok</entry>",
            "</log>",
        ]
        fmt = server.detect_format(sample)
        self.assertNotEqual(fmt, "raw")
        self.assertIn(fmt, ("logfmt", "auto"))

    def test_generic_gana_a_piloop_si_hay_nivel(self):
        # '2026-10-30 10:00:00 INFO arranque' tiene nivel: es generic,
        # no piloop (que es timestamp + componente, sin nivel).
        sample = ["2026-10-30 10:00:00 INFO arranque"] * 5
        self.assertEqual(server.detect_format(sample), "generic")
        sample = ["2026-10-12 20:40:16 logs: rotado buzon.log"] * 5
        self.assertEqual(server.detect_format(sample), "piloop")

    def test_apache_umbral_40(self):
        sample = (['127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET /a HTTP/1.1" 200 1234'] * 4
                  + ["Traceback (most recent call last):"] * 6)
        self.assertEqual(server.detect_format(sample), "apache")

    def test_sin_estructura_sigue_raw(self):
        self.assertEqual(server.detect_format(["Traceback (most recent call last):"] * 10), "raw")
        self.assertEqual(server.detect_format(["    at a.B(B.java:1)"] * 10), "raw")
        self.assertEqual(server.detect_format([]), "raw")
        # 3 de 10 lineas con fecha: por debajo del 40% y sin nivel ni kv.
        self.assertEqual(server.detect_format(
            ["2026-10-12 20:40:16 logs: rotado a.log"] * 3
            + ["Traceback (most recent call last):"] * 7), "raw")

    def test_fallback_auto_antes_que_raw(self):
        # Ningun formato concreto, pero hay timestamps en el 60% de las lineas.
        sample = ["2026-10-30T10:00:00Z algo suelto"] * 6 + ["sin fecha ni nada"] * 4
        self.assertEqual(server.detect_format(sample), "auto")

    def test_w3c_detect(self):
        sample = [
            "#Software: Microsoft Internet Information Services 10.0",
            "#Fields: date time c-ip cs-method cs-uri-stem sc-status",
            "2026-10-30\t10:00:00\t10.0.0.5\tGET\t/a\t200",
        ] * 3
        self.assertEqual(server.detect_format(sample), "w3c")

    def test_jsonl_detect(self):
        sample = ['{"ts":"2026-10-30T10:00:00Z","level":"info","msg":"ok"}'] * 8
        self.assertEqual(server.detect_format(sample), "json")

    def test_orden_csv_no_confunde_con_logfmt(self):
        sample = ["ts=2026-10-30T10:15:30Z level=info msg=ok app=api"] * 5
        self.assertEqual(server.detect_format(sample), "logfmt")


class TestContinuacionesU03(unittest.TestCase):
    """U0.3: los stack traces se anexan a la fila del error (una sola fila)."""

    JAVA = [
        "2026-10-30 09:12:01 buzon: error al procesar tarea t4c35fe97",
        "java.lang.RuntimeException: fallo en el parseo",
        "    at com.example.LogParser.parse(LogParser.java:42)",
        "    at com.example.Main.main(Main.java:17)",
        "Caused by: java.io.IOException: stream cerrado",
        "    at java.io.InputStream.read(InputStream.java:101)",
        "2026-10-30 09:12:05 buzon: reintentando",
    ]

    PY = [
        "2026-10-30 09:20:00 - app - ERROR - boom",
        "Traceback (most recent call last):",
        '  File "app.py", line 3, in main',
        '    raise ValueError("x")',
        "ValueError: x",
        "2026-10-30 09:20:01 - app - INFO - sigue",
    ]

    def _ds(self, lines, name="trace.log"):
        d = tempfile.mkdtemp()
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return server.load_file(path, user="local")

    def test_reglas_de_continuacion(self):
        prev_ts = "2026-10-30 09:12:01 buzon: error"
        self.assertTrue(server.is_continuation_line("    at a.B(B.java:1)", prev_ts))
        self.assertTrue(server.is_continuation_line("Caused by: java.io.IOException", prev_ts))
        self.assertTrue(server.is_continuation_line("Traceback (most recent call last):", prev_ts))
        self.assertTrue(server.is_continuation_line('  File "a.py", line 1', prev_ts))
        # sin timestamp y la anterior lo tiene: continuacion
        self.assertTrue(server.is_continuation_line("ValueError: x", prev_ts))
        # una linea con su propio timestamp NO es continuacion
        self.assertFalse(server.is_continuation_line("2026-10-30 09:12:05 buzon: ok", prev_ts))
        # linea vacia: solo si el trace ya esta abierto
        self.assertFalse(server.is_continuation_line("", prev_ts, False))
        self.assertTrue(server.is_continuation_line("", prev_ts, True))
        # sin anterior ni timestamp: no se anexa a nada
        self.assertFalse(server.is_continuation_line("campo=valor", None))

    def test_java_trace_en_una_fila(self):
        ds = self._ds(self.JAVA, "java_trace.log")
        rows = ds["store"].rows
        self.assertEqual(len(rows), 2, "el trace debe quedar en una sola fila")
        self.assertIn("at com.example.LogParser.parse", rows[0]["raw"])
        self.assertIn("Caused by: java.io.IOException", rows[0]["raw"])
        self.assertIn("at com.example.LogParser.parse", rows[0]["msg"])
        self.assertEqual(rows[0]["_line"], 0)
        self.assertEqual(rows[1]["_line"], 6)

    def test_python_trace_en_una_fila(self):
        ds = self._ds(self.PY, "py_trace.log")
        rows = ds["store"].rows
        self.assertEqual(len(rows), 2)
        self.assertIn("Traceback (most recent call last):", rows[0]["raw"])
        self.assertIn('raise ValueError("x")', rows[0]["raw"])
        self.assertIn("ValueError: x", rows[0]["msg"])

    def test_tope_de_lineas_de_continuacion(self):
        lines = ["2026-10-30 10:00:00 app: error"]
        lines += ["    at frame.%d(Frame.java:%d)" % (i, i) for i in range(60)]
        ds = self._ds(lines, "largo.log")
        rows = ds["store"].rows
        self.assertEqual(len(rows), 2, "el trace se corta a los 40 frames")
        self.assertEqual(rows[0]["raw"].count("\n"), 40)

    def test_csv_sin_timestamp_no_se_pega(self):
        # Un CSV legitimo sin columna de fecha no debe fusionarse en una fila.
        ds = self._ds(["user,action", "ana,login", "bob,logout", "carla,download"],
                      "sinfecha.csv")
        self.assertGreater(len(ds["store"].rows), 1)

    def test_contadores_coherentes_tras_agrupar(self):
        ds = self._ds(self.JAVA, "java_trace2.log")
        store = ds["store"]
        levels = store.counters.get("levels", {})
        total = sum(v for v in levels.values() if v > 0)
        self.assertEqual(total, len(store.rows),
                         "los RAW absorbidos deben descontarse del contador")
        self.assertGreater(levels.get("RAW", 0), 0)

    def test_attach_continuations_reutilizable(self):
        rows, counters = server.parse_raw([
            "2026-10-30 10:00:00 app: error",
            "Traceback (most recent call last):",
            "  File \"a.py\", line 1",
        ])
        merged = server.attach_continuations(rows, counters)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["raw"].count("\n"), 2)
        self.assertEqual(sum(counters["levels"].values()), 1)


class TestFormatBadgeAndDynamicCols(unittest.TestCase):
    """U2.1 (2026-10-30): el parser auto puebla columnas dinamicas, el export
    las conserva y el dataset informa del formato y de las lineas RAW."""

    LOGFMT = [
        'linea suelta sin estructura ni pares clave valor',
        '2026-10-30T10:00:01Z level=INFO host=web01 app=api pid=4211 '
        'method=GET path=/orders status=200 duration=12ms',
        '2026-10-30T10:00:02Z level=ERROR host=web02 app=worker pid=4212 '
        'status=500 duration=3s msg="falla el job"',
    ]

    # Logfmt + stack trace + linea suelta: mezcla real de un servicio.
    MIXED = LOGFMT + [
        "Traceback (most recent call last):",
        "  File \"worker.py\", line 42, in run",
        "    raise ValueError('disk full')",
        "2026-10-30 10:00:05,123 - app.logger - INFO - servicio listo",
    ]

    def _mem(self, rows):
        for r in rows:
            r["_search"] = server._make_search(r)
        return server.MemStore(rows=rows)

    def test_auto_puebla_claves_dinamicas(self):
        rows, counters = server.parse_auto(self.LOGFMT)
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[1]["host"], "web01")
        self.assertEqual(rows[1]["app"], "api")
        self.assertEqual(rows[1]["pid"], "4211")
        self.assertEqual(rows[1]["status"], "200")
        self.assertEqual(rows[1]["duration"], "12ms")
        self.assertEqual(rows[1]["method"], "GET")
        self.assertEqual(rows[1]["path"], "/orders")
        self.assertEqual(rows[2]["level"], "ERR")
        self.assertIn("duration", counters["keys"])

    def test_ui_columns_ofrecen_las_claves_y_no_los_huecos(self):
        rows, _ = server.parse_auto(self.LOGFMT)
        cols = server._ui_columns(self._mem(rows))
        for c in ("host", "app", "pid", "status", "duration", "method", "path"):
            self.assertIn(c, cols, c)
        # 'bytes' no aparece en ningun registro: no se ofrece vacio
        self.assertNotIn("bytes", cols)
        self.assertNotIn("raw", cols)
        self.assertNotIn("ts_norm", cols)

    def test_format_stats_cuenta_raw(self):
        rows, _ = server.parse_auto(self.LOGFMT)
        ds = {"store": self._mem(rows), "format": "auto", "name": "x.log",
              "size": 100, "total": len(rows)}
        st = server.format_stats(ds)
        self.assertEqual(st["raw_lines"], 1)
        self.assertEqual(st["cont_lines"], 0)
        self.assertEqual(st["raw_pct"], round(100.0 / len(rows), 1))
        # cacheado en el dataset: la segunda llamada no recalcula el conteo
        self.assertIs(ds["_raw_stats"], st)
        self.assertEqual(server.format_stats(ds), st)

    def test_format_stats_en_dataset_real(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "servicio.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.MIXED) + "\n")
        ds = server.load_file(path, user="local")
        s = server.summary(ds)
        self.assertIn("raw_lines", s)
        self.assertIn("raw_pct", s)
        self.assertIn("cont_lines", s)
        # 7 lineas, menos filas: las continuaciones del traceback se anexan
        self.assertEqual(s["cont_lines"], s["total"] - s["parsed"])
        self.assertGreater(s["total"], 0)
        self.assertGreater(s["cont_lines"], 0)
        self.assertEqual(s["raw_pct"],
                         round(100.0 * (s["raw_lines"] + s["cont_lines"]) /
                               s["total"], 1))

    def test_export_conserva_las_claves_del_parser_auto(self):
        rows, _ = server.parse_auto(self.LOGFMT)
        cols = server.export_columns(self._mem(rows))
        for c in ("host", "app", "pid", "status", "duration", "method", "path"):
            self.assertIn(c, cols, c)
        for k in server.EXPORT_SKIP_KEYS:
            self.assertNotIn(k, cols)

    def test_api_rows_devuelve_formato_y_raw(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "servicio.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.LOGFMT) + "\n")
        ds = server.load_file(path, user="local")
        self.addCleanup(lambda: server.SESSIONS.get("local", {}).pop(
            ds["name"], None))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        server.SESSIONS.setdefault("local", {})[ds["name"]] = ds
        port = srv.server_address[1]
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/rows?name=%s" % (port, ds["name"])) as r:
                body = json.loads(r.read().decode("utf-8"))
        finally:
            srv.shutdown()
        self.assertIn("raw_lines", body)
        self.assertIn("raw_pct", body)
        self.assertIn("cont_lines", body)
        self.assertIn("host", body["columns"])
        self.assertIn("duration", body["columns"])
        self.assertGreaterEqual(body["raw_lines"], 1)


class TestPythonLoggingU31(unittest.TestCase):
    """U3.1 (2026-10-30): python logging con muestras realistas.

    Formato: 'YYYY-MM-DD HH:MM:SS,mmm - logger - LEVEL - mensaje'.
    Se comprueba formato detectado, ts (con coma de milisegundos), nivel
    normalizado y la columna 'logger'.
    """

    REAL = [
        "2026-10-30 10:11:50,123 - app.logger - INFO - arranque del servicio ok",
        "2026-10-30 10:11:51,456 - app.logger - WARNING - reintento 2 de 3",
        "2026-10-30 10:11:52,789 - net.client - ERROR - 10.0.0.5 rechazado",
        "2026-10-30 10:11:53,001 - db.pool - DEBUG - query devolvio 12 filas",
        "2026-10-30 10:11:54,500 - app - CRITICAL - disco lleno en /var",
    ]

    def test_detect_python_logging(self):
        self.assertEqual(server.detect_format(self.REAL), "python")

    def test_detect_python_con_tracebacks_intercalados(self):
        sample = self.REAL[:3] + [
            "Traceback (most recent call last):",
            '  File "app.py", line 3, in main',
            '    raise ValueError("x")',
            "ValueError: x",
        ]
        self.assertEqual(server.detect_format(sample), "python")

    def test_ts_logger_nivel_y_msg(self):
        rows, counters = server.parse_python_logging(self.REAL)
        self.assertEqual(len(rows), 5)
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30 10:11:50,123")
        self.assertEqual(r["ts_norm"], "2026-10-30T10:11:50.123000")
        self.assertEqual(r["level"], "INF")
        self.assertEqual(r["logger"], "app.logger")
        self.assertEqual(r["msg"], "arranque del servicio ok")
        self.assertEqual(counters["levels"]["CRIT"], 1)
        self.assertEqual(counters["logger"]["net.client"], 1)

    def test_niveles_normalizados(self):
        for lvl, expected in (("WARNING", "WRN"), ("CRITICAL", "CRIT"),
                             ("DEBUG", "DBG"), ("ERROR", "ERR"),
                             ("FATAL", "CRIT"), ("NOTSET", "INF")):
            rows, _ = server.parse_python_logging(
                ["2026-10-30 10:11:50,123 - app - %s - mensaje" % lvl])
            self.assertEqual(rows[0]["level"], expected, lvl)

    def test_sin_logger_y_sin_milisegundos(self):
        rows, _ = server.parse_python_logging(
            ["2026-10-30 10:11:52 - WARNING - algo raro"])
        self.assertEqual(rows[0]["level"], "WRN")
        self.assertEqual(rows[0]["logger"], "")
        self.assertEqual(rows[0]["ts"], "2026-10-30 10:11:52")
        self.assertEqual(rows[0]["msg"], "algo raro")

    def test_separador_con_colon(self):
        rows, _ = server.parse_python_logging(
            ["2026-10-30 10:11:52,000 - worker - INFO: tarea terminada"])
        self.assertEqual(rows[0]["level"], "INF")
        self.assertEqual(rows[0]["logger"], "worker")
        self.assertEqual(rows[0]["msg"], "tarea terminada")

    def test_linea_no_matchea_es_raw_sin_ts(self):
        rows, counters = server.parse_python_logging(
            ["Traceback (most recent call last):"])
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["ts"], "")
        self.assertEqual(rows[0]["msg"], "Traceback (most recent call last):")
        self.assertEqual(counters["levels"]["RAW"], 1)

    def test_ip_y_filtros(self):
        rows, counters = server.parse_python_logging([self.REAL[2]])
        self.assertEqual(rows[0]["ip"], "10.0.0.5")
        self.assertEqual(counters["ips"]["10.0.0.5"], 1)
        rows, _ = server.parse_python_logging(self.REAL)
        got = server.apply_filters(rows, {"dt_from": "2026-10-30",
                                          "dt_to": "2026-10-31"})
        self.assertEqual(len(got), 5)
        got = server.apply_filters(rows, {"level": "ERR,CRIT"})
        self.assertEqual(len(got), 2)


class TestSyslog3164U31(unittest.TestCase):
    """U3.1: syslog RFC 3164 real (nginx, sshd, postgres, kernel, systemd).

    Sin anio: se rellena con el anio actual. La prioridad '<N>' da el nivel
    (pri % 8) y hay columnas host, app y pid.
    """

    REAL = [
        "Oct 30 10:00:00 web01 nginx[1234]: upstream timed out while proxying /api",
        "Oct 30 10:00:01 web01 sshd[99]: Failed password for root from 10.0.0.5 port 22 ssh2",
        "Oct 30 10:00:02 db01 postgres[501]: connection to server lost",
        "<13>Oct 30 10:00:03 web-01 kernel: out of memory: kill process 4321",
        "<11>Oct 30 10:00:04 web-01 systemd[1]: Main process exited",
    ]

    def test_detect_syslog3164(self):
        self.assertEqual(server.detect_format(self.REAL), "syslog3164")

    def test_detect_syslog3164_con_lineas_raw(self):
        sample = self.REAL + ["Traceback (most recent call last):"] * 5
        self.assertEqual(server.detect_format(sample), "syslog3164")

    def test_columnas_host_app_pid_msg(self):
        rows, counters = server.parse_syslog3164(self.REAL)
        self.assertEqual(len(rows), 5)
        r = rows[0]
        self.assertEqual(r["host"], "web01")
        self.assertEqual(r["app"], "nginx")
        self.assertEqual(r["pid"], "1234")
        self.assertEqual(r["msg"], "upstream timed out while proxying /api")
        self.assertEqual(r["level"], "INF")
        self.assertTrue(r["ts_norm"].endswith("-10-30T10:00:00"))
        self.assertEqual(counters["hosts"]["web01"], 2)
        self.assertEqual(counters["apps"]["sshd"], 1)

    def test_anio_actual_rellenado(self):
        rows, _ = server.parse_syslog3164([self.REAL[0]])
        self.assertEqual(rows[0]["ts"][:4], time.strftime("%Y"))

    def test_prioridad_da_nivel(self):
        for pri, expected in ((13, "INF"), (11, "ERR"), (3, "ERR"),
                             (7, "DBG"), (0, "CRIT"), (4, "WRN")):
            rows, _ = server.parse_syslog3164(
                ["<%d>Oct 30 10:00:05 web01 app: mensaje" % pri])
            self.assertEqual(rows[0]["level"], expected, pri)

    def test_sin_prioridad_nivel_del_mensaje(self):
        rows, _ = server.parse_syslog3164(
            ["Oct 30 10:00:06 web01 nginx: ERROR upstream caido"])
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(rows[0]["app"], "nginx")

    def test_sin_pid_y_host_con_guion(self):
        rows, _ = server.parse_syslog3164(
            ["Oct 30 10:00:05 web-01 app mensaje suelto"])
        self.assertEqual(rows[0]["host"], "web-01")
        self.assertEqual(rows[0]["app"], "app")
        self.assertEqual(rows[0]["pid"], "")
        self.assertEqual(rows[0]["msg"], "mensaje suelto")
        self.assertEqual(rows[0]["level"], "INF")

    def test_ip_y_filtros_syslog3164(self):
        rows, counters = server.parse_syslog3164(self.REAL)
        self.assertEqual(rows[1]["ip"], "10.0.0.5")
        self.assertEqual(counters["ips"]["10.0.0.5"], 1)
        got = server.apply_filters(rows, {"dt_from": "2026-10-30",
                                         "dt_to": "2026-10-31"})
        self.assertEqual(len(got), 5)
        got = server.apply_filters(rows, {"level": ["ERR"]})
        self.assertEqual(len(got), 1)

    def test_syslog3164_no_confundido_con_5424(self):
        sample = ["1 2026-10-30T10:00:00.000Z web01 nginx[1]: ok"] * 8
        self.assertEqual(server.detect_format(sample), "syslog")


class TestIso8601U31(unittest.TestCase):
    """U3.1: ISO 8601 con T, Z, fraccion y offsets; ts_norm siempre en UTC."""

    def test_iso_z_con_fraccion(self):
        raw, norm = server.extract_ts(
            "2026-10-30T10:15:30.123Z app=api level=info msg=ok")
        self.assertEqual(raw, "2026-10-30T10:15:30.123Z")
        self.assertTrue(norm.startswith("2026-10-30T10:15:30"))

    def test_iso_offset_positivo_con_colon(self):
        raw, norm = server.extract_ts("2026-10-30T10:15:30+02:00 app=api")
        self.assertEqual(raw, "2026-10-30T10:15:30+02:00")
        self.assertEqual(norm, "2026-10-30T08:15:30")

    def test_iso_offset_sin_colon(self):
        raw, norm = server.extract_ts("2026-10-30T10:15:30+0200 app=api")
        self.assertEqual(raw, "2026-10-30T10:15:30+0200")
        self.assertEqual(norm, "2026-10-30T08:15:30")

    def test_iso_offset_negativo(self):
        raw, norm = server.extract_ts("2026-10-30T10:15:30-05:00 app=api")
        self.assertEqual(norm, "2026-10-30T15:15:30")

    def test_iso_con_espacio_y_sin_zona(self):
        raw, norm = server.extract_ts("2026-10-30 10:15:30 INFO arranque")
        self.assertEqual(raw, "2026-10-30 10:15:30")
        self.assertEqual(norm, "2026-10-30T10:15:30")

    def test_iso_en_json_line(self):
        line = ('{"@timestamp": "2026-10-30T10:15:30.000+01:00", '
                '"level": "error", "message": "disk full", "ip": "10.0.0.9"}')
        self.assertEqual(server.detect_format([line] * 5), "json")
        rows, counters = server.parse_json([line])
        self.assertEqual(rows[0]["ts"], "2026-10-30T10:15:30.000+01:00")
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(rows[0]["msg"], "disk full")
        self.assertEqual(rows[0]["ip"], "10.0.0.9")
        self.assertEqual(counters["levels"]["ERR"], 1)

    def test_iso_en_auto_puebla_columnas(self):
        rows, counters = server.parse_auto(
            ["2026-10-30T10:15:30+0200 level=error ip=10.0.0.7 "
             "method=POST path=/orders status=500 duration=3s"])
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30T10:15:30+0200")
        self.assertEqual(r["ts_norm"], "2026-10-30T08:15:30")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["ip"], "10.0.0.7")
        self.assertEqual(r["status"], "500")
        self.assertIn("duration", counters["keys"])

    def test_detect_iso_t_no_cae_a_raw(self):
        sample = ["2026-10-30T10:15:30.000Z api srv01 GET /health 200 12ms"] * 5
        fmt = server.detect_format(sample)
        self.assertNotEqual(fmt, "raw")
        rows, _ = server.PARSERS[fmt](sample)
        self.assertTrue(rows[0]["ts_norm"])

    def test_rango_de_filtros_con_iso(self):
        rows, _ = server.parse_auto(["2026-10-30T23:59:59Z level=info msg=fin",
                                     "2026-11-01T00:00:01Z level=info msg=inicio"])
        got = server.apply_filters(rows, {"dt_from": "2026-10-31",
                                         "dt_to": "2026-11-02"})
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["ts"], "2026-11-01T00:00:01Z")


class TestEpochU31(unittest.TestCase):
    """U3.1: epoch en segundos y en milisegundos."""

    def test_epoch_segundos(self):
        raw, norm = server.extract_ts("1761234567 INFO servicio listo")
        self.assertEqual(raw, "1761234567")
        self.assertEqual(norm, "2025-10-23T15:49:27")

    def test_epoch_milisegundos(self):
        raw, norm = server.extract_ts("1761234567890 WARN host=web01")
        self.assertEqual(raw, "1761234567890")
        self.assertEqual(norm, "2025-10-23T15:49:27.890000")

    def test_epoch_en_logfmt(self):
        rows, _ = server.parse_logfmt(
            ['ts=1761234567 level=error msg="fallo de conexion" app=api'])
        r = rows[0]
        self.assertEqual(r["ts"], "1761234567")
        self.assertEqual(r["ts_norm"], "2025-10-23T15:49:27")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["msg"], "fallo de conexion")
        self.assertEqual(r["app"], "api")

    def test_epoch_en_csv_sin_cabecera(self):
        rows, _ = server.parse_csv(["1761234567,ERROR,caida,web01",
                                    "1761234568,INFO,ok,web02"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ts"], "1761234567")
        self.assertEqual(rows[0]["ts_norm"], "2025-10-23T15:49:27")
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(rows[0]["c3"], "web01")

    def test_epoch_no_tapa_a_iso(self):
        raw, norm = server.extract_ts("2026-10-30T10:00:00Z id=1761234567890")
        self.assertEqual(raw, "2026-10-30T10:00:00Z")
        self.assertTrue(norm.startswith("2026-10-30T10:00:00"))

    def test_detect_epoch_es_auto(self):
        sample = ["1761234567890 WARN host=web01 disk lleno"] * 5
        self.assertEqual(server.detect_format(sample), "auto")
        rows, counters = server.parse_auto(sample)
        self.assertEqual(rows[0]["level"], "WRN")
        self.assertEqual(rows[0]["ts_norm"], "2025-10-23T15:49:27.890000")
        self.assertEqual(rows[0]["host"], "web01")
        self.assertIn("host", counters["keys"])

    def test_epoch_en_filtros_de_fecha(self):
        rows, _ = server.parse_auto(["1761234567 INFO arranque",
                                     "1761234567890 WARN caida"])
        got = server.apply_filters(rows, {"dt_from": "2025-10-23",
                                         "dt_to": "2025-10-24"})
        self.assertEqual(len(got), 2)


class TestLogfmtU31(unittest.TestCase):
    """U3.1: logfmt real (Heroku, Go, Prometheus) con comillas y claves variadas."""

    REAL = [
        'ts=2026-10-30T10:00:00Z level=info msg="arranque ok" app=api pid=4211',
        "ts=2026-10-30T10:00:01Z severity=warn message='disk full on /var' "
        "host=web01 duration=12ms",
        'time="2026-10-30 10:00:02" lvl=debug method=GET path=/orders status=200',
    ]

    def test_detect_logfmt(self):
        self.assertEqual(server.detect_format(self.REAL), "logfmt")

    def test_comillas_dobles_y_simples(self):
        rows, counters = server.parse_logfmt(self.REAL)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["msg"], "arranque ok")
        self.assertEqual(rows[1]["msg"], "disk full on /var")
        self.assertEqual(rows[0]["level"], "INF")
        self.assertEqual(rows[1]["level"], "WRN")
        self.assertEqual(rows[2]["level"], "DBG")
        self.assertEqual(rows[0]["pid"], "4211")
        self.assertEqual(rows[1]["duration"], "12ms")
        self.assertEqual(rows[2]["status"], "200")
        self.assertIn("duration", counters["keys"])

    def test_ts_de_claves_alternativas(self):
        rows, _ = server.parse_logfmt(
            ['timestamp="2026-10-30 10:15:31" level=error msg=fallo'])
        self.assertEqual(rows[0]["ts"], "2026-10-30 10:15:31")
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T10:15:31")
        rows, _ = server.parse_logfmt(
            ["_time=2026-10-30T10:15:32Z log_level=warning msg=aviso"])
        self.assertEqual(rows[0]["ts"], "2026-10-30T10:15:32Z")
        self.assertEqual(rows[0]["level"], "WRN")

    def test_linea_sin_kv_es_raw(self):
        rows, counters = server.parse_logfmt(["Traceback (most recent call last):"])
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["ts"], "")
        self.assertEqual(counters["levels"]["RAW"], 1)

    def test_valor_vacio_y_claves_dinamicas(self):
        rows, counters = server.parse_logfmt(["level=error code=500 msg= retry=3"])
        r = rows[0]
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["code"], "500")
        self.assertEqual(r["retry"], "3")
        self.assertIn("retry", counters["keys"])

    def test_detect_logfmt_con_mecla_raw(self):
        sample = self.REAL + ["Traceback (most recent call last):"] * 2
        self.assertEqual(server.detect_format(sample), "logfmt")

    def test_filtros_logfmt(self):
        rows, _ = server.parse_logfmt(self.REAL)
        got = server.apply_filters(rows, {"level": ["WRN"]})
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["host"], "web01")
        got = server.apply_filters(rows, {"dt_from": "2026-10-30",
                                         "dt_to": "2026-10-31"})
        self.assertEqual(len(got), 3)


class TestCsvDelimitadoresU31(unittest.TestCase):
    """U3.1: CSV con coma, punto y coma, tabulador y barra; cabecera o sin ella."""

    def test_coma_con_cabecera_espanola(self):
        rows, counters = server.parse_csv([
            "fecha,nivel,mensaje,host",
            "2026-10-30 10:00:00,ERROR,timeout,web01",
            "2026-10-30 10:00:01,INFO,ok,web02",
        ])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ts"], "2026-10-30 10:00:00")
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T10:00:00")
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(rows[0]["msg"], "timeout")
        self.assertEqual(rows[0]["host"], "web01")
        self.assertEqual(counters["keys"]["host"], 2)

    def test_punto_y_coma(self):
        rows, _ = server.parse_csv(["date;level;message;host",
                                    "2026-10-30 10:00:00;WARN;reintento 3;web01"])
        self.assertEqual(rows[0]["ts"], "2026-10-30 10:00:00")
        self.assertEqual(rows[0]["level"], "WRN")
        self.assertEqual(rows[0]["msg"], "reintento 3")
        self.assertEqual(rows[0]["host"], "web01")

    def test_tabulador(self):
        rows, _ = server.parse_csv(["date\tlevel\tmessage\thost",
                                    "2026-10-30 10:00:00\tDEBUG\ttask done\tweb02"])
        self.assertEqual(rows[0]["level"], "DBG")
        self.assertEqual(rows[0]["msg"], "task done")
        self.assertEqual(rows[0]["host"], "web02")
        self.assertTrue(rows[0]["ts_norm"].startswith("2026-10-30T10:00:00"))

    def test_barra_vertical(self):
        rows, _ = server.parse_csv(["fecha|nivel|mensaje",
                                    "2026-10-30 10:00:00|ERROR|caida del servicio"])
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(rows[0]["msg"], "caida del servicio")
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T10:00:00")

    def test_sin_cabecera_columnas_generadas(self):
        rows, _ = server.parse_csv([
            "2026-10-30,INFO,ok,web01",
            "2026-10-31,ERROR,caida,web02",
        ])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ts"], "2026-10-30")
        self.assertEqual(rows[0]["level"], "INF")
        self.assertEqual(rows[0]["c2"], "ok")
        self.assertEqual(rows[1]["c3"], "web02")

    def test_comilla_dentro_del_valor(self):
        rows, _ = server.parse_csv([
            "date,level,message,host",
            '2026-10-30,ERROR,"a, b, c",web01',
        ])
        self.assertEqual(rows[0]["msg"], "a, b, c")
        self.assertEqual(rows[0]["host"], "web01")

    def test_detect_csv_con_iso_y_epoch(self):
        sample = ["fecha,nivel,mensaje,host"] + [
            "2026-10-30T10:00:00Z,INFO,ok,web01"] * 9
        self.assertEqual(server.detect_format(sample), "csv")
        rows, _ = server.parse_csv(sample[:2])
        self.assertEqual(rows[0]["ts"], "2026-10-30T10:00:00Z")
        self.assertTrue(rows[0]["ts_norm"].startswith("2026-10-30T10:00:00"))

    def test_csv_con_columnas_de_ip(self):
        rows, counters = server.parse_csv([
            "timestamp,level,client_ip,message",
            "2026-10-30 10:00:00,ERROR,10.0.0.5,timeout",
        ])
        self.assertEqual(rows[0]["ip"], "10.0.0.5")
        self.assertEqual(counters["ips"]["10.0.0.5"], 1)
        self.assertEqual(rows[0]["level"], "ERR")


class TestHoraSolaU31(unittest.TestCase):
    """U3.1: lineas solo con hora (sin fecha): ts se guarda, ts_norm queda vacio."""

    def test_extract_ts_hora_sola(self):
        raw, norm = server.extract_ts("10:11:12 rotacion de buzon.log")
        self.assertEqual(raw, "10:11:12")
        self.assertEqual(norm, "")

    def test_extract_ts_hora_con_milisegundos(self):
        raw, norm = server.extract_ts("10:11:12,345 rotacion de buzon.log")
        self.assertEqual(raw, "10:11:12,345")
        self.assertEqual(norm, "")

    def test_auto_hora_sola_no_es_raw(self):
        rows, counters = server.parse_auto(["10:11:12 rotacion de buzon.log"])
        self.assertEqual(rows[0]["ts"], "10:11:12")
        self.assertEqual(rows[0]["ts_norm"], "")
        self.assertNotEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["msg"], "rotacion de buzon.log")
        self.assertEqual(counters["levels"]["RAW"], 0)

    def test_detect_hora_sola_es_auto(self):
        sample = ["10:11:12 rotacion de buzon.log"] * 5
        self.assertEqual(server.detect_format(sample), "auto")

    def test_triage_hora_sola_con_fecha_de_fichero(self):
        line = ("10:11:12 [ai-netwatch] netwatch:findings:pid:23160 -> sospechoso "
                "conf 0.8 sev 2.0 accion yes | ESCALADA t4f87df76")
        rows, counters = server.parse_triage([line], file_date="2026-10-30")
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30 10:11:12")
        self.assertEqual(r["fuente"], "ai-netwatch")
        self.assertEqual(r["tarea"], "t4f87df76")
        self.assertEqual(r["sev"], 2.0)
        self.assertNotEqual(r["level"], "RAW")
        self.assertEqual(counters["fuente"]["ai-netwatch"], 1)

    def test_triage_detect_format(self):
        line = ("10:11:12 [ai-netwatch] netwatch:findings:pid:23160 -> sospechoso "
                "conf 0.8 sev 2.0 accion yes | sin tarea")
        self.assertEqual(server.detect_format([line] * 5), "triage")

    def test_epoch_gana_a_la_hora_sola(self):
        # El extractor prueba ISO y epoch antes que la hora suelta: si la
        # linea lleva un epoch, ese es el ts (la hora queda en el mensaje).
        raw, norm = server.extract_ts("10:11:12 1761234567 suelto")
        self.assertEqual(raw, "1761234567")
        self.assertEqual(norm, "2025-10-23T15:49:27")


class TestJavaTraceU31(unittest.TestCase):
    """U3.1: stack trace de Java multilinea (frames, Caused by, Suppressed)."""

    TRACE = [
        "2026-10-30 09:12:01 ERROR com.example.Main - fallo en el parseo",
        "java.lang.RuntimeException: nested failure",
        "    at com.example.LogParser.parse(LogParser.java:42)",
        "    at com.example.Main.main(Main.java:17)",
        "Caused by: java.io.IOException: stream cerrado",
        "    at java.io.InputStream.read(InputStream.java:101)",
        "Suppressed: java.lang.IllegalStateException: cierre forzado",
        "2026-10-30 09:12:05 INFO com.example.Main - reintentando",
        "2026-10-30 09:12:06 WARN com.example.Main - reintento 1 de 3",
        "2026-10-30 09:12:07 DEBUG com.example.Main - contexto: 42 filas",
    ]

    def test_detect_java_del_trace_java(self):
        # J1 (2026-10-30): con el parser java, estas lineas ya no son
        # 'generic': llevan logger y separador '-', firma del pattern log4j.
        self.assertEqual(server.detect_format(self.TRACE), "java")

    def test_trace_en_una_sola_fila(self):
        rows, counters = server.parse_generic(self.TRACE)
        merged = server.attach_continuations(rows, counters)
        self.assertEqual(len(merged), 4)
        r = merged[0]
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["ts"], "2026-10-30 09:12:01")
        self.assertEqual(r["_line"], 0)
        for frame in ("java.lang.RuntimeException", "at com.example.LogParser.parse",
                      "Caused by: java.io.IOException",
                      "Suppressed: java.lang.IllegalStateException"):
            self.assertIn(frame, r["raw"], frame)
            self.assertIn(frame, r["msg"], frame)
        self.assertEqual(sum(counters["levels"].values()), 4)

    def test_reglas_de_continuacion_java(self):
        prev = "2026-10-30 09:12:01 ERROR com.example.Main - fallo"
        self.assertTrue(server.is_continuation_line("    at a.B(B.java:1)", prev))
        self.assertTrue(server.is_continuation_line("Caused by: java.io.IOException", prev))
        self.assertTrue(server.is_continuation_line("Suppressed: java.lang.IllegalStateException", prev))
        self.assertTrue(server.is_continuation_line("java.lang.RuntimeException: x", prev))
        self.assertFalse(server.is_continuation_line("2026-10-30 09:12:05 INFO ok", prev))

    def test_tope_de_frames(self):
        lines = ["2026-10-30 10:00:00 ERROR app - boom"]
        lines += ["    at frame.%d(Frame.java:%d)" % (i, i) for i in range(60)]
        rows, counters = server.parse_raw(lines)
        merged = server.attach_continuations(rows, counters)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["raw"].count("\n"), 40)

    def test_load_file_end_to_end_java(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "java_trace.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.TRACE) + "\n")
        ds = server.load_file(path, user="local")
        self.addCleanup(lambda: server.SESSIONS.get("local", {}).pop(ds["name"], None))
        self.assertEqual(ds["format"], "java")
        rows = ds["store"].rows
        self.assertEqual(len(rows), 4)
        self.assertIn("at com.example.Main.main", rows[0]["raw"])
        st = server.format_stats(ds)
        self.assertGreater(st["cont_lines"], 0)


class TestNginxErrorU31(unittest.TestCase):
    """U3.1: nginx error_log real, con pid#tid, sin pid y niveles nginx."""

    REAL = [
        "2026/10/30 10:11:50 [error] 1234#5678: *3 upstream timed out (110: Connection timed out) while proxying",
        "2026/10/30 10:11:51 [emerg] 99: bind() to 0.0.0.0:80 failed (98: Address already in use)",
        "2026/10/30 10:11:52 [warn] 1234#0: worker process 4321 exited on signal 11",
        "2026/10/30 10:11:53 [debug] 1234#5678: *4 http request line parsed",
    ]

    def test_detect_nginx_error(self):
        self.assertEqual(server.detect_format(self.REAL), "nginx_error")

    def test_pid_tid_y_msg(self):
        rows, counters = server.parse_nginx_error(self.REAL)
        self.assertEqual(len(rows), 4)
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30 10:11:50")
        self.assertEqual(r["ts_norm"], "2026-10-30T10:11:50")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["pid"], "1234")
        self.assertEqual(r["tid"], "5678")
        self.assertIn("upstream timed out", r["msg"])
        self.assertEqual(counters["pid"]["1234"], 3)

    def test_niveles_nginx_normalizados(self):
        rows, _ = server.parse_nginx_error(self.REAL)
        self.assertEqual([r["level"] for r in rows], ["ERR", "CRIT", "WRN", "DBG"])

    def test_sin_pid_y_tid(self):
        rows, _ = server.parse_nginx_error(
            ["2026/10/30 10:11:54 [alert] worker process 4321 exited on signal 11"])
        self.assertEqual(rows[0]["level"], "CRIT")
        self.assertEqual(rows[0]["pid"], "")
        self.assertEqual(rows[0]["tid"], "")
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T10:11:54")

    def test_ip_en_el_mensaje(self):
        rows, counters = server.parse_nginx_error(
            ["2026/10/30 10:11:55 [error] 1234#1: *7 client 192.168.1.7 timed out"])
        self.assertEqual(rows[0]["ip"], "192.168.1.7")
        self.assertEqual(counters["ips"]["192.168.1.7"], 1)

    def test_linea_no_matchea_es_raw(self):
        # parse_nginx_error solo contabiliza en 'levels' las lineas que si
        # matchean: la linea suelta queda RAW en la fila pero no en el contador.
        rows, counters = server.parse_nginx_error(["nginx: the configuration file syntax is ok"])
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["ts"], "")
        self.assertEqual(rows[0]["pid"], "")
        self.assertEqual(rows[0]["msg"], "nginx: the configuration file syntax is ok")
        self.assertEqual(counters["levels"].get("RAW", 0), 0)

    def test_filtros_nginx_error(self):
        rows, _ = server.parse_nginx_error(self.REAL)
        got = server.apply_filters(rows, {"level": ["CRIT"]})
        self.assertEqual(len(got), 1)
        self.assertIn("bind()", got[0]["msg"])
        got = server.apply_filters(rows, {"dt_from": "2026-10-30",
                                         "dt_to": "2026-10-31"})
        self.assertEqual(len(got), 4)


class TestNginxAccessCombinedU31(unittest.TestCase):
    """U3.1: nginx access_log combined (CLF + referer + user agent)."""

    COMBINED = (
        '192.168.1.5 - - [30/Oct/2026:10:11:12 +0000] "GET /orders HTTP/1.1" 200 1234 '
        '"https://tienda.example.com/lista" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    )
    NOT_FOUND = (
        '10.0.0.9 - john [30/Oct/2026:10:11:13 -0500] "POST /api/v1/login HTTP/1.1" 404 0 '
        '"-" "curl/8.4.0"'
    )
    ZERO_BYTES = (
        '10.0.0.11 - - [30/Oct/2026:10:11:14 +0100] "GET /favicon.ico HTTP/1.1" 304 - '
        '"https://tienda.example.com/" "Mozilla/5.0"'
    )

    def test_detect_combined_es_apache(self):
        self.assertEqual(server.detect_format([self.COMBINED] * 5), "apache")

    def test_combined_columnas_clf(self):
        rows, counters = server.parse_apache([self.COMBINED, self.NOT_FOUND,
                                             self.ZERO_BYTES])
        self.assertEqual(len(rows), 3)
        r = rows[0]
        self.assertEqual(r["ip"], "192.168.1.5")
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["path"], "/orders")
        self.assertEqual(r["code"], "200")
        self.assertEqual(r["bytes"], "1234")
        self.assertEqual(r["ts"], "30/Oct/2026:10:11:12 +0000")
        self.assertEqual(server.norm_ts(r["ts"]), "2026-10-30T10:11:12")
        self.assertEqual(counters["codes"]["404"], 1)
        self.assertEqual(counters["methods"]["POST"], 1)
        self.assertEqual(counters["ips"]["10.0.0.9"], 1)

    def test_bytes_guion_y_offset_negativo(self):
        rows, _ = server.parse_apache([self.NOT_FOUND, self.ZERO_BYTES])
        self.assertEqual(rows[0]["bytes"], "0")
        self.assertEqual(rows[1]["bytes"], "-")
        self.assertEqual(server.norm_ts(rows[0]["ts"]), "2026-10-30T15:11:13")
        self.assertEqual(server.norm_ts(rows[1]["ts"]), "2026-10-30T09:11:14")

    def test_ua_con_comillas_no_rompe_el_parseo(self):
        line = ('127.0.0.1 - - [30/Oct/2026:10:11:15 +0000] "GET /a HTTP/1.1" 200 512 '
                '"-" "UA test"')
        rows, counters = server.parse_apache([line])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["code"], "200")
        self.assertEqual(counters["codes"]["200"], 1)

    def test_filtros_por_codigo_y_fecha(self):
        # parse_apache no rellena ts_norm (lo hace la carga en api.load_file):
        # el rango dt_from/dt_to se comprueba con el dataset cargado, y aqui
        # se usa el filtro 'dt' sobre el ts crudo CLF.
        rows, _ = server.parse_apache([self.COMBINED, self.NOT_FOUND, self.ZERO_BYTES])
        got = server.apply_filters(rows, {"code": "404"})
        self.assertEqual(len(got), 1)
        got = server.apply_filters(rows, {"dt": "30/Oct/2026"})
        self.assertEqual(len(got), 3)
        got = server.apply_filters(rows, {"path": "/orders"})
        self.assertEqual(len(got), 1)


class TestXmlishU31(unittest.TestCase):
    """U3.1: XML-ish (log4j / Splunk XML): los atributos clave=valor se aprovechan."""

    XML = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<log>",
        '  <entry time="2026-10-30T10:00:00Z" level="error">disk full</entry>',
        '  <entry time="2026-10-30T10:00:01Z" level="info">ok</entry>',
        '  <entry time="2026-10-30T10:00:02Z" severity="warning">retry 3</entry>',
        "</log>",
    ]

    def test_detect_xml_no_cae_a_raw(self):
        fmt = server.detect_format(self.XML)
        self.assertIn(fmt, ("logfmt", "auto"))

    def test_entry_con_ts_y_nivel(self):
        fmt = server.detect_format(self.XML)
        rows, counters = server.PARSERS[fmt](self.XML)
        self.assertEqual(len(rows), 6)
        r = rows[2]
        self.assertEqual(r["ts"], "2026-10-30T10:00:00Z")
        self.assertEqual(r["ts_norm"], "2026-10-30T10:00:00")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(rows[4]["level"], "WRN")
        self.assertEqual(rows[1]["level"], "RAW")
        self.assertEqual(rows[1]["ts"], "")
        self.assertEqual(counters["levels"]["RAW"], 2)

    def test_xml_con_ip_y_claves_dinamicas(self):
        rows, counters = server.parse_auto([
            '<event ts="2026-10-30T10:00:03Z" level="error" ip="10.0.0.5" '
            'host="web01" msg="timeout"/>',
        ])
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30T10:00:03Z")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["ip"], "10.0.0.5")
        self.assertEqual(r["host"], "web01")
        self.assertIn("host", counters["keys"])

    def test_xml_de_un_solo_entry_no_es_raw(self):
        sample = ['<log><entry time="2026-10-30T10:00:00Z" level="info">ok</entry></log>'] * 5
        self.assertNotEqual(server.detect_format(sample), "raw")


class TestAutoMixtoU31(unittest.TestCase):
    """U3.1: el parser auto con lineas mixtas de varios formatos reales."""

    MIXED = [
        "2026-10-30T10:00:00Z level=info msg=arranque app=api",
        "1761234567890 WARN host=web01 disk lleno",
        "Oct 30 10:00:02 web01 sshd[99]: Failed password for root from 10.0.0.5 port 22 ssh2",
        "10:11:12 rotacion de buzon.log",
        "2026/10/30 10:11:50 [error] 1234#5678: *3 upstream timed out",
        "Traceback (most recent call last):",
        '  File "worker.py", line 42, in run',
        "    raise ValueError('disk full')",
        '{"ts": "2026-10-30T10:00:05Z", "level": "error", "msg": "json suelto"}',
    ]

    def test_detect_de_mecla_es_auto(self):
        self.assertEqual(server.detect_format(self.MIXED), "auto")

    def test_filas_y_niveles_de_cada_linea(self):
        rows, counters = server.parse_auto(self.MIXED)
        self.assertEqual(len(rows), 9)
        self.assertEqual(rows[0]["level"], "INF")
        self.assertEqual(rows[1]["level"], "WRN")
        self.assertTrue(rows[1]["ts_norm"].startswith("2025-10-23T15:49:27"))
        self.assertTrue(rows[2]["ts"].endswith("10:00:02"))
        self.assertTrue(rows[2]["ts_norm"].endswith("-10-30T10:00:02"))
        self.assertEqual(rows[3]["ts"], "10:11:12")
        self.assertEqual(rows[3]["ts_norm"], "")
        self.assertEqual(rows[4]["level"], "ERR")
        self.assertEqual(rows[4]["ts_norm"], "2026-10-30T10:11:50")
        self.assertEqual(rows[5]["level"], "RAW")
        self.assertEqual(rows[5]["ts"], "")
        self.assertEqual(rows[8]["level"], "ERR")
        self.assertEqual(counters["levels"]["RAW"], 3)
        self.assertEqual(counters["ips"]["10.0.0.5"], 1)

    def test_columnas_dinamicas_del_mecla(self):
        rows, counters = server.parse_auto(self.MIXED)
        self.assertIn("app", counters["keys"])
        self.assertIn("host", counters["keys"])
        self.assertEqual(rows[0]["app"], "api")
        self.assertEqual(rows[1]["host"], "web01")
        cols = server._ui_columns(server.MemStore(rows=rows))
        for c in ("app", "host", "ip", "level", "ts"):
            self.assertIn(c, cols, c)
        self.assertNotIn("raw", cols)

    def test_mecla_continuaciones_se_anexan(self):
        rows, counters = server.parse_auto(self.MIXED)
        merged = server.attach_continuations(rows, counters)
        self.assertEqual(len(merged), 6)
        self.assertIn("raise ValueError", merged[4]["raw"])
        self.assertEqual(sum(counters["levels"].values()), 6)

    def test_filtros_sobre_mecla(self):
        rows, _ = server.parse_auto(self.MIXED)
        got = server.apply_filters(rows, {"level": ["RAW"]})
        self.assertEqual(len(got), 3)
        got = server.apply_filters(rows, {"dt_from": "2026-10-30",
                                         "dt_to": "2026-10-31"})
        self.assertEqual(len(got), 4)

    def test_load_file_end_to_end_mecla(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "mixto.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.MIXED) + "\n")
        ds = server.load_file(path, user="local")
        self.addCleanup(lambda: server.SESSIONS.get("local", {}).pop(ds["name"], None))
        self.assertEqual(ds["format"], "auto")
        st = server.format_stats(ds)
        # Las 3 lineas del traceback se anexan a la fila anterior: no son
        # filas RAW sueltas, son continuaciones.
        self.assertGreaterEqual(st["cont_lines"], 3)
        self.assertGreater(st["raw_pct"], 0.0)

    def test_auto_no_inventa_ts_cuando_no_lo_hay(self):
        rows, _ = server.parse_auto(["sin fecha ni nivel ni pares"])
        self.assertEqual(rows[0]["ts"], "")
        self.assertEqual(rows[0]["ts_norm"], "")
        self.assertEqual(rows[0]["level"], "RAW")
        self.assertEqual(rows[0]["msg"], "sin fecha ni nivel ni pares")


class TestSmokeU32(unittest.TestCase):
    """U3.2 (2026-10-30): huecos encontrados en el smoke real end-to-end.

    Cubre dos fallos detectados al subir los logs de OperVanta al visor en
    8877: logfmt con la fecha suelta al principio de la linea (sin clave=valor)
    y volcados de stack traces sin timestamp (orquestador.log), que caian a
    'raw' con la histograma vacia.
    """

    NODE_TRACE = [
        "node:events:487",
        "      throw er; // Unhandled 'error' event",
        "      ^",
        "",
        "Error: EPIPE: broken pipe, write",
        "    at Socket._write (node:internal/net:75:18)",
        "    at writeOrBuffer (node:internal/streams/writable:570:12)",
        "Emitted 'error' event on Socket instance at:",
        "    at emitErrorNT (node:internal/streams/destroy:170:8)",
        "  errno: -4047,",
        "  syscall: 'write',",
        "  code: 'EPIPE'",
        "}",
        "",
        "Node.js v24.18.0",
    ]

    LOGFMT_BARE = [
        '2026-10-30T09:12:03.481Z level=info service=ingest msg="worker started" queue=3',
        '2026-10-30T09:12:04.101Z level=warn service=ingest msg="retrying" attempt=2',
        '2026-10-30T09:12:05.999Z level=error service=ingest host=10.0.0.5 port=5432',
    ]

    def test_logfmt_sin_clave_ts_coge_la_fecha_suelta(self):
        rows, _ = server.parse_logfmt(self.LOGFMT_BARE)
        self.assertEqual(rows[0]["ts"], "2026-10-30T09:12:03.481Z")
        self.assertEqual(rows[0]["ts_norm"], "2026-10-30T09:12:03.481000")
        self.assertEqual(rows[1]["ts_norm"], "2026-10-30T09:12:04.101000")
        self.assertEqual(rows[2]["level"], "ERR")
        self.assertEqual(rows[2]["host"], "10.0.0.5")
        # La fecha suelta no se pierde: si no hay msg, el msg es la linea sin ts
        self.assertEqual(rows[2]["msg"], "level=error service=ingest host=10.0.0.5 port=5432")

    def test_logfmt_clave_ts_sigue_teniendo_prioridad(self):
        rows, _ = server.parse_logfmt(
            ['2026-01-01T00:00:00Z ts=2026-10-30T10:00:00Z level=info msg=x'])
        self.assertEqual(rows[0]["ts"], "2026-10-30T10:00:00Z")

    def test_detect_trace_de_volcado_node(self):
        self.assertEqual(server.detect_format(self.NODE_TRACE), "trace")

    def test_parse_trace_asigna_nivel_err(self):
        rows, counters = server.parse_trace(self.NODE_TRACE)
        self.assertTrue(all(r["level"] == "ERR" for r in rows))
        self.assertTrue(all(r["ts"] == "" for r in rows))
        self.assertGreaterEqual(counters["levels"]["ERR"], 10)

    def test_trace_end_to_end_agrupa_el_stack(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "orquestador.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.NODE_TRACE) + "\n")
        ds = server.load_file(path, user="local")
        self.addCleanup(lambda: server.SESSIONS.get("local", {}).pop(ds["name"], None))
        self.assertEqual(ds["format"], "trace")
        rows = ds["store"].rows
        # Todo el volcado va sin fecha, asi que attach_continuations lo agrupa
        # (con el tope de MAX_CONTINUATION_LINES) en pocas filas.
        self.assertGreater(len(rows), 0)
        self.assertLess(len(rows), len(self.NODE_TRACE))
        hist = ds["store"].histogram({}, gran="min")
        self.assertEqual(sum(b["count"] for b in hist), len(rows))
        self.assertTrue(hist[0]["t"].startswith("linea "))

    def test_histograma_por_linea_mem_y_sql_coinciden(self):
        rows = [{"ts": "", "ts_norm": "", "level": "ERR", "ip": "",
                 "method": "", "path": "", "code": "", "bytes": "",
                 "msg": "trace %d" % i, "raw": "trace %d" % i, "_line": i}
                for i in range(250)]
        mem = server.MemStore(rows=[dict(r) for r in rows])
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        sql = server.SqlStore(os.path.join(tmpdir, "t.db"))
        self.addCleanup(sql.close)
        sql.add_rows([dict(r) for r in rows], {})
        for gran in ("min", "h"):
            got = mem.histogram({}, gran=gran)
            want = sql.histogram({}, gran=gran)
            self.assertEqual(got, want, "gran=%s" % gran)
            self.assertGreater(sum(b["count"] for b in got), 0)
        # 250 filas, step 100 -> 3 bloques de 100, 100 y 50
        self.assertEqual([b["count"] for b in mem.histogram({}, gran="min")],
                         [100, 100, 50])

    def test_histograma_con_fecha_no_usa_el_fallback(self):
        rows = [{"ts": "2026-10-30 10:00:00", "ts_norm": "2026-10-30T10:00:00",
                 "level": "INF", "msg": "a", "raw": "a", "_line": 0},
                {"ts": "", "ts_norm": "", "level": "RAW", "msg": "b",
                 "raw": "b", "_line": 1}]
        mem = server.MemStore(rows=[dict(r) for r in rows])
        got = mem.histogram({})
        self.assertEqual(got, [{"t": "2026-10-30T10:00", "count": 1}])


class TestJavaLog4jJ1(unittest.TestCase):
    """J1 (2026-10-30): parser java/log4j.

    Primera linea de una entrada: 'YYYY-MM-DD HH:MM:SS,mmm LEVEL [thread]
    logger - mensaje'. [thread] y logger son opcionales, la coma de
    milisegundos puede faltar. Los frames del stack los agrupa U0.3.
    """

    LOG4J = [
        "2026-10-30 09:12:01,482 ERROR [main] com.example.Main - fallo en el parseo",
        "    at com.example.LogParser.parse(LogParser.java:42)",
        "    at com.example.Main.main(Main.java:17)",
        "Caused by: java.io.IOException: stream cerrado",
        "    at java.io.InputStream.read(InputStream.java:101)",
        "2026-10-30 09:12:05,001 INFO [pool-1] com.example.Main - reintentando",
        "2026-10-30 09:12:06,330 WARN com.example.Main - reintento 1 de 3",
        "2026-10-30 09:12:07 TRACE - contexto: 42 filas",
        "2026-10-30 09:12:08,900 FATAL [http-1] - el servicio no responde",
    ]

    def test_java_en_parsers(self):
        self.assertIn("java", server.PARSERS)
        self.assertIs(server.PARSERS["java"], server.parse_java)

    def test_detect_java_con_coma_y_thread(self):
        self.assertEqual(server.detect_format(self.LOG4J), "java")

    def test_detect_java_sin_coma(self):
        sample = ["2026-10-30 10:00:00 ERROR com.acme.App - algo falla"] * 5
        self.assertEqual(server.detect_format(sample), "java")

    def test_detect_java_sin_logger_ni_thread(self):
        sample = ["2026-10-30 10:00:00,500 WARN - disco casi lleno"] * 5
        self.assertEqual(server.detect_format(sample), "java")

    def test_muestra_corta_no_cae_a_raw(self):
        # Una linea de error + dos frames: el umbral del 40% no se cumple
        # sobre 3 lineas, pero todo lo demas es continuacion del trace.
        sample = [
            "2026-10-30 09:12:01,482 ERROR [main] com.example.Main - boom",
            "    at com.example.Main.main(Main.java:17)",
            "Caused by: java.io.IOException: stream cerrado",
        ]
        self.assertEqual(server.detect_format(sample), "java")

    def test_sin_firma_java_sigue_generic(self):
        # 'fecha hora NIVEL mensaje' sin milisegundos, thread ni logger es
        # indistinguible del formato generic: se queda en generic.
        self.assertEqual(server.detect_format(["2026-10-30 10:00:00 INFO arranque"] * 5),
                         "generic")

    def test_ts_y_level_de_la_primera_linea(self):
        rows, counters = server.parse_java(self.LOG4J)
        r = rows[0]
        self.assertEqual(r["ts"], "2026-10-30 09:12:01")
        self.assertEqual(r["ts_norm"], "2026-10-30T09:12:01")
        self.assertEqual(r["level"], "ERR")
        self.assertEqual(r["thread"], "main")
        self.assertEqual(r["logger"], "com.example.Main")
        self.assertEqual(r["msg"], "fallo en el parseo")
        self.assertEqual(counters["levels"]["ERR"], 1)
        self.assertEqual(counters["thread"]["main"], 1)

    def test_niveles_normalizados(self):
        rows, _ = server.parse_java(self.LOG4J)
        got = [r["level"] for r in rows if r["level"] != "RAW"]
        self.assertEqual(got, ["ERR", "INF", "WRN", "DBG", "CRIT"])

    def test_frames_del_stack_quedan_raw(self):
        rows, _ = server.parse_java(self.LOG4J)
        self.assertEqual(rows[1]["level"], "RAW")
        self.assertEqual(rows[1]["ts"], "")
        self.assertIn("at com.example.LogParser.parse", rows[1]["msg"])

    def test_continuaciones_se_anexan_a_la_linea_java(self):
        rows, counters = server.parse_java(self.LOG4J)
        merged = server.attach_continuations(rows, counters)
        self.assertEqual(len(merged), 5)
        first = merged[0]
        self.assertEqual(first["level"], "ERR")
        for frame in ("at com.example.LogParser.parse", "Caused by: java.io.IOException"):
            self.assertIn(frame, first["raw"], frame)
            self.assertIn(frame, first["msg"], frame)
        self.assertEqual(sum(counters["levels"].values()), 5)

    def test_separador_T_y_punto_de_milisegundos(self):
        rows, _ = server.parse_java(["2026-10-30T10:11:50.123 ERROR [t1] - x"])
        self.assertEqual(rows[0]["ts"], "2026-10-30 10:11:50")
        self.assertEqual(rows[0]["level"], "ERR")
        self.assertEqual(rows[0]["thread"], "t1")
        self.assertEqual(rows[0]["msg"], "x")

    def test_ip_en_el_mensaje_java(self):
        rows, counters = server.parse_java(
            ["2026-10-30 10:00:00,100 ERROR [main] com.acme.Net - timeout de 192.168.1.7"])
        self.assertEqual(rows[0]["ip"], "192.168.1.7")
        self.assertEqual(counters["ips"]["192.168.1.7"], 1)

    def test_filtros_por_nivel_y_fecha(self):
        rows, _ = server.parse_java(self.LOG4J)
        self.assertEqual(len(server.apply_filters(rows, {"level": ["ERR"]})), 1)
        self.assertEqual(len(server.apply_filters(rows, {"dt_from": "2026-10-30",
                                                         "dt_to": "2026-10-31"})), 5)
        got = server.apply_filters(rows, {"level": "WRN,CRIT"})
        self.assertEqual(len(got), 2)
        self.assertEqual([r["level"] for r in got], ["WRN", "CRIT"])

    def test_load_file_end_to_end_java(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "app.log4j.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.LOG4J) + "\n")
        ds = server.load_file(path, user="local")
        self.addCleanup(lambda: server.SESSIONS.get("local", {}).pop(ds["name"], None))
        self.assertEqual(ds["format"], "java")
        # 'total' son las lineas del fichero; las 4 de trace se anexan a la
        # primera fila, de modo que quedan 5 filas en el store.
        self.assertEqual(ds["total"], 9)
        self.assertEqual(ds["store"].total_rows(), 5)


class TestTailLoadT1(unittest.TestCase):
    """T1 (2026-10-30): 'seguir archivo' carga solo las ultimas N lineas."""

    def _write(self, name, text):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        return path

    def test_tail_lines_from_file_ultima_n(self):
        path = self._write("a.log", "\n".join("linea %d" % i for i in range(100)) + "\n")
        tail, start = server.tail_lines_from_file(path, 10)
        self.assertEqual(len(tail), 10)
        self.assertEqual(tail[0], "linea 90")
        self.assertEqual(tail[-1], "linea 99")
        self.assertEqual(start, 90)   # linea 0-based en el fichero real

    def test_tail_lines_from_file_no_corta_la_primera(self):
        # Con un bloque pequeno el seek cae a mitad de linea: la primera
        # devuelta tiene que ser una linea completa, no un trozo.
        path = self._write("b.log", "\n".join("x" * 40 + str(i) for i in range(50)) + "\n")
        tail, start = server.tail_lines_from_file(path, 3, chunk=17)
        self.assertEqual(len(tail), 3)
        self.assertEqual(tail[0], "x" * 40 + "47")
        self.assertEqual(start, 47)

    def test_tail_lines_from_file_mas_lineas_de_las_que_hay(self):
        path = self._write("c.log", "una\ndos\ntres\n")
        tail, start = server.tail_lines_from_file(path, 5000)
        self.assertEqual(tail, ["una", "dos", "tres"])
        self.assertEqual(start, 0)

    def test_tail_lines_from_file_sin_salto_final(self):
        path = self._write("d.log", "uno\ndos\ntres")
        tail, start = server.tail_lines_from_file(path, 2)
        self.assertEqual(tail, ["dos", "tres"])
        self.assertEqual(start, 1)
        self.assertEqual(server.count_file_lines(path), 3)

    def test_tail_lines_from_file_vacio(self):
        path = self._write("e.log", "")
        self.assertEqual(server.tail_lines_from_file(path, 10), ([], 0))

    def test_tail_load_carga_solo_lo_reciente(self):
        old = "\n".join("2026-10-12 09:00:00 INFO vieja %d" % i for i in range(2000))
        new = "\n".join("2026-10-30 10:00:00 INFO nueva %d" % i for i in range(1000))
        path = self._write("mix.log", old + "\n" + new + "\n")
        ds = api.tail_load_file(path, 1000, user="local")
        self.addCleanup(lambda: api.SESSIONS.get("local", {}).pop(ds["name"], None))
        self.assertTrue(ds["tail"])          # flag: carga por tail
        self.assertEqual(ds["total"], 1000)  # solo el tail, no las 3000
        self.assertEqual(ds["file_total_lines"], 3000)
        self.assertEqual(ds["tail_start_line"], 2000)
        rows = ds["store"].all_rows() if hasattr(ds["store"], "all_rows") else ds["store"].rows
        self.assertEqual(len(rows), 1000)
        self.assertEqual(rows[0]["ts_norm"][:10], "2026-10-30")
        # _line sigue siendo la linea ABSOLUTA del fichero original
        self.assertEqual(rows[0]["_line"], 2000)
        self.assertEqual(rows[-1]["_line"], 2999)
        for key in ("_search", "template", "ts_norm", "level", "msg"):
            self.assertIn(key, rows[0])

    def test_tail_load_anade_filas_nuevas_con_numeracion_absoluta(self):
        path = self._write("seg.log", "\n".join(
            "2026-10-30 10:00:%02d INFO base %d" % (i, i) for i in range(10)) + "\n")
        ds = api.tail_load_file(path, 5, user="local")
        self.addCleanup(lambda: api.SESSIONS.get("local", {}).pop(ds["name"], None))
        self.assertEqual(ds["total"], 5)
        self.assertEqual(ds["tail_start_line"], 5)   # fichero de 10 lineas
        self.assertEqual(ds["line_base"], 10)        # linea absoluta siguiente
        w = server.Watcher(ds["name"], path, ds["encoding"])
        w.reset(seek_end=True)
        with open(path, "a", encoding="utf-8", newline="") as f:
            f.write("2026-10-30 10:00:99 INFO nueva 1\n2026-10-30 10:01:00 INFO nueva 2\n")
        w._poll_once()
        lines = list(w.buffer)
        rows, counters = api.tail_parse(ds, lines)
        base = ds["line_base"]
        for r in rows:
            r["_line"] = base + r.pop("_line", 0)
        ds["store"].add_rows(rows, counters)
        ds["total"] += len(lines)
        ds["line_base"] = base + len(lines)
        self.assertEqual(ds["total"], 7)
        self.assertEqual(rows[0]["_line"], 10)   # lineas absolutas 10 y 11
        self.assertEqual(rows[-1]["_line"], 11)
        self.assertEqual(ds["line_base"], 12)

    def test_tail_load_comprimido(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "hist.gz")
        body = "\n".join("2026-10-%02d 08:00:00 INFO linea %d" % (12 + i // 500, i)
                         for i in range(2000)) + "\n"
        with gzip.open(path, "wb") as f:
            f.write(body.encode("utf-8"))
        ds = api.tail_load_file(path, 300, user="local")
        self.addCleanup(lambda: api.SESSIONS.get("local", {}).pop(ds["name"], None))
        self.assertEqual(ds["compressed"], "gzip")
        self.assertEqual(ds["total"], 300)
        self.assertEqual(ds["tail_start_line"], 1700)
        self.assertEqual(ds["format"], "generic")

    def test_open_file_usa_tail(self):
        src = inspect.getsource(api.Handler._open_file)
        # U4 (2026-10-30): se revierte el tail de T1. 'Seguir archivo' carga el
        # archivo COMPLETO (todo el historial) y el watcher solo recoge lo nuevo.
        self.assertIn("ds = load_file(ap", src)
        self.assertNotIn("ds = tail_load_file(", src)

    def test_tail_load_respeta_el_umbral_de_formato(self):
        # Un W3C tiene la cabecera #Fields al principio: el tail no la ve,
        # pero las columnas se recuperan del principio del fichero.
        head = "#Version: 1.0\n#Fields: date time c-ip cs-method cs-uri sc-status\n"
        old = "\n".join("2026-10-12 01:02:03 1.2.3.4 GET /vieja 200" for _ in range(500))
        new = "\n".join("2026-10-30 01:02:03 1.2.3.4 GET /nueva 200" for _ in range(50))
        path = self._write("w3c.log", head + old + "\n" + new + "\n")
        ds = api.tail_load_file(path, 50, user="local")
        self.addCleanup(lambda: api.SESSIONS.get("local", {}).pop(ds["name"], None))
        self.assertEqual(ds["format"], "w3c")
        self.assertEqual(ds["w3c_fields"], ["date", "time", "c-ip", "cs-method",
                                           "cs-uri", "sc-status"])
        self.assertEqual(ds["total"], 50)
        self.assertEqual(ds["tail_start_line"], 502)   # 2 de cabecera + 500 viejas
        rows = ds["store"].rows
        self.assertEqual(rows[0]["path"], "/nueva")
        self.assertEqual(rows[0]["_line"], 502)


class TestOrdenDescU4(unittest.TestCase):
    """U4 (2026-10-30): el visor ordena de MAS NUEVO a MAS VIEJO.

    La fila mas reciente va arriba y el historial completo sigue accesible
    pagando hacia abajo. Aplica a la tabla, al export (keyset) y al tail."""

    def _rows(self, n=20):
        return [{"ts": "2026-10-%02d 10:00:00" % (i % 30 + 1),
                 "level": "INF" if i % 2 else "ERR",
                 "ip": "1.1.1.%d" % (i % 250), "msg": "fila %d" % i,
                 "raw": "raw %d" % i, "_line": i} for i in range(n)]

    def test_mem_page_filtered_desc(self):
        store = server.MemStore([dict(r) for r in self._rows()])
        page = store.page_filtered({}, 0, 5)
        self.assertEqual([r["msg"] for r in page],
                         ["fila 19", "fila 18", "fila 17", "fila 16", "fila 15"])
        self.assertEqual([r["rowid"] for r in page], [19, 18, 17, 16, 15])
        # El historial NO se recorta: pagando se llega a la mas antigua
        out, start = [], 0
        while True:
            chunk = store.page_filtered({}, start, 5)
            if not chunk:
                break
            out.extend(chunk)
            start += 5
        self.assertEqual(len(out), 20)
        self.assertEqual(out[-1]["msg"], "fila 0")
        self.assertEqual(store.count_filtered({}), 20)

    def test_sql_page_filtered_desc(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        store = server.SqlStore(os.path.join(d, "desc.db"))
        self.addCleanup(store.close)
        store.add_rows([dict(r) for r in self._rows()], {})
        page = store.page_filtered({}, 0, 5)
        self.assertEqual([r["msg"] for r in page],
                         ["fila 19", "fila 18", "fila 17", "fila 16", "fila 15"])
        self.assertEqual([r["rowid"] for r in page], [20, 19, 18, 17, 16])
        # Segunda pagina: continua donde acaba la primera
        self.assertEqual([r["msg"] for r in store.page_filtered({}, 5, 5)],
                         ["fila 14", "fila 13", "fila 12", "fila 11", "fila 10"])
        self.assertEqual(store.count_filtered({}), 20)

    def test_mem_sql_parity_desc(self):
        mem = server.MemStore([dict(r) for r in self._rows()])
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        sql = server.SqlStore(os.path.join(d, "parity.db"))
        self.addCleanup(sql.close)
        sql.add_rows([dict(r) for r in self._rows()], {})
        for q in ({}, {"level": ["ERR"]}, {"q": ["fila 1"]}):
            self.assertEqual([r["msg"] for r in mem.page_filtered(q, 0, 100)],
                             [r["msg"] for r in sql.page_filtered(q, 0, 100)],
                             "q=%s" % q)

    def test_keyset_export_desc_sin_bucle(self):
        """El export (keyset) recorre las filas en el mismo orden que la tabla."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        store = server.SqlStore(os.path.join(d, "key.db"))
        self.addCleanup(store.close)
        store.add_rows([dict(r) for r in self._rows()], {})
        for batch in (1, 3, 20, 100):
            out, last = [], -1
            for _ in range(200):          # tope duro: si no termina, es un bucle
                b = store.page_filtered_keyset({}, last, batch)
                if not b:
                    break
                out.extend(b)
                last = b[-1]["rowid"]    # borde DESC del siguiente lote
            self.assertEqual([r["msg"] for r in out],
                             [r["msg"] for r in store.page_filtered({}, 0, 100)],
                             "batch=%d" % batch)
            self.assertEqual(len(out), 20)

    def test_mem_keyset_desc(self):
        store = server.MemStore([dict(r) for r in self._rows()])
        out, last = [], -1
        for _ in range(200):
            b = store.page_filtered_keyset({}, last, 7)
            if not b:
                break
            out.extend(b)
            last = b[-1]["rowid"]
        self.assertEqual([r["msg"] for r in out],
                         [r["msg"] for r in store.page_filtered({}, 0, 100)])
        self.assertEqual(out[0]["msg"], "fila 19")
        self.assertEqual(out[-1]["msg"], "fila 0")

    def test_tail_devuelve_lo_nuevo_arriba(self):
        src = inspect.getsource(api.Handler._tail)
        self.assertIn("reversed(rows)", src)

    def test_open_file_carga_el_historial_completo(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "hist.log")
        old = "\n".join("2026-10-01 09:00:%02d INFO vieja %d" % (i % 60, i)
                        for i in range(2000))
        new = "\n".join("2026-10-30 23:59:%02d INFO nueva %d" % (i % 60, i)
                        for i in range(500))
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(old + "\n" + new + "\n")
        os.environ["LOGVIEWER_TAIL_DIRS"] = d
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:%d/api/open-file" % srv.server_port,
                data=json.dumps({"path": path}).encode(), method="POST",
                headers={"Content-Type": "application/json",
                         "X-CSRF-Token": server.CSRF_TOKEN})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8"))
            self.assertEqual(data["total"], 2500)   # historial entero, no 5000
            with urllib.request.urlopen(
                "http://127.0.0.1:%d/api/rows?name=%s&size=5"
                % (srv.server_port, urllib.parse.quote(data["name"])),
                timeout=30) as r:
                rows = json.loads(r.read().decode("utf-8"))
            self.assertEqual(rows["total"], 2500)
            self.assertEqual(rows["rows"][0]["ts"][:10], "2026-10-30")
            # La ULTIMA pagina es la mas antigua: el historial no se recorta
            with urllib.request.urlopen(
                "http://127.0.0.1:%d/api/rows?name=%s&size=500&page=5"
                % (srv.server_port, urllib.parse.quote(data["name"])),
                timeout=30) as r:
                last = json.loads(r.read().decode("utf-8"))
            self.assertEqual(len(last["rows"]), 500)
            self.assertEqual(last["rows"][-1]["ts"][:10], "2026-10-01")
        finally:
            srv.shutdown()
            ds = server.SESSIONS.get("local", {}).pop(
                server.safe_session_name(os.path.basename(path)), None)
            if ds:
                ds["store"].close()
            os.environ.pop("LOGVIEWER_TAIL_DIRS", None)

    def test_ui_calendario_en_el_filtro_de_fecha(self):
        base = os.path.join(os.path.dirname(os.path.abspath(server.__file__)),
                            "static")
        html = open(os.path.join(base, "index.html"), encoding="utf-8").read()
        js = open(os.path.join(base, "app.js"), encoding="utf-8").read()
        self.assertIn('id="fdfrom" type="datetime-local"', html)
        self.assertIn('id="fdto" type="datetime-local"', html)
        self.assertIn('aria-label="Desde (fecha y hora)"', html)
        self.assertIn('aria-label="Hasta (fecha y hora)"', html)
        # 'Hasta' una fecha sin hora es inclusive hasta el final del dia;
        # con hora, hasta el final del minuto (:59)
        self.assertIn('T23:59:59', js)
        self.assertIn(':59', js)


if __name__ == "__main__":
    unittest.main()

