#!/usr/bin/env python3
"""Tests para los parsers, filtros, compresion y sesiones."""
import bz2
import gzip
import json
import lzma
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

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


class TestOpenLogFile(unittest.TestCase):
    def _write(self, data, name):
        fd, path = tempfile.mkstemp(suffix=name)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.addCleanup(os.remove, path)
        return path

    def test_plain(self):
        path = self._write(b"linea uno\nlinea dos\n", "plain.log")
        raw, label, inner = server.open_log_file(path)
        self.assertEqual(raw, b"linea uno\nlinea dos\n")
        self.assertEqual(label, "")
        self.assertEqual(inner, "")

    def test_gzip(self):
        path = self._write(gzip.compress(b"datos gzip\n"), "a.gz")
        raw, label, inner = server.open_log_file(path)
        self.assertEqual(raw, b"datos gzip\n")
        self.assertEqual(label, "gzip")

    def test_bz2(self):
        path = self._write(bz2.compress(b"datos bz2\n"), "a.bz2")
        raw, label, inner = server.open_log_file(path)
        self.assertEqual(raw, b"datos bz2\n")
        self.assertEqual(label, "bzip2")

    def test_xz(self):
        path = self._write(lzma.compress(b"datos xz\n"), "a.xz")
        raw, label, inner = server.open_log_file(path)
        self.assertEqual(raw, b"datos xz\n")
        self.assertEqual(label, "xz")

    def test_zip_picks_log(self):
        import io as _io
        buf = _io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("notas.md", "no soy el log")
            z.writestr("app.log", "linea zip\n")
        path = self._write(buf.getvalue(), "a.zip")
        raw, label, inner = server.open_log_file(path)
        self.assertEqual(raw, b"linea zip\n")
        self.assertEqual(label, "zip")
        self.assertEqual(inner, "app.log")

    def test_magic_over_extension(self):
        # Un .log que en realidad es gzip: gana el magico
        path = self._write(gzip.compress(b"real gzip\n"), "a.log")
        raw, label, inner = server.open_log_file(path)
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
        old = server.SQLITE_THRESHOLD
        server.SQLITE_THRESHOLD = 10
        try:
            ds1 = server.load_file(path)
            self.assertIsInstance(ds1["store"], server.SqlStore)
            db_path = ds1["store"].db_path
            # _load_worker cierra el dataset viejo antes de recargar
            ds1["store"].close()
            self.assertFalse(os.path.exists(db_path))
            ds2 = server.load_file(path)
        finally:
            server.SQLITE_THRESHOLD = old
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
        old = server.SQLITE_THRESHOLD
        server.SQLITE_THRESHOLD = 10
        try:
            ds = server.load_file(path)
        finally:
            server.SQLITE_THRESHOLD = old
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
        old = server.SQLITE_THRESHOLD
        server.SQLITE_THRESHOLD = 100
        try:
            ds = server.load_file(path)
        finally:
            server.SQLITE_THRESHOLD = old
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
            got = [r["msg"] for r in server.apply_filters(mem.rows, q)]
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
        """MemStore y SQLite deben dar el mismo resultado."""
        mem = server.MemStore(rows=[dict(r) for r in self._rows()])
        got = [r["msg"] for r in server.apply_filters(mem.rows, q)]
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
        self.assertEqual(got, ["uno", "dos"])

    def test_exclusion_ip_substring(self):
        got = self._parity({"ip": "!10.0.0.5"})
        self.assertEqual(got, ["uno", "tres"])

    def test_multivalue_path_and_q(self):
        got = self._parity({"path": "/a,/c"})
        self.assertEqual(got, ["uno", "tres"])
        got = self._parity({"q": "!s2"})
        self.assertEqual(got, ["uno", "tres"])

    def test_combined_terms(self):
        got = self._parity({"code": "200,!404"})
        self.assertEqual(got, ["uno"])
        # Exclusion vacia tras la coma no rompe el resto
        got = self._parity({"code": "200,"})
        self.assertEqual(got, ["uno"])


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
        self.assertEqual([r["rowid"] for r in page], [0, 1, 2])
        # add_rows (tail) reindexa sin romper los rowids
        store.add_rows([{"ts": "", "level": "INF", "ip": "", "method": "",
                         "path": "", "code": "", "bytes": "", "msg": "b",
                         "raw": "b", "_line": 9}], {})
        page = store.page_filtered({}, 0, 10)
        self.assertEqual(len(page), 4)
        self.assertEqual(page[3]["rowid"], 3)

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
        self.assertEqual([r["rowid"] for r in page], [1, 2])

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
        server.audit("upload", user="sammideblas@gmail.com", file="a.log")
        server.audit("upload", user="revisor@corp.com", file="b.log")
        server.audit("activate", user="sammideblas@gmail.com", file="a.log")

        a = server.audit_for_user("sammideblas@gmail.com")
        b = server.audit_for_user("revisor@corp.com")

        self.assertEqual(len(a), 2)
        self.assertTrue(all(e["user"] == "sammideblas@gmail.com" for e in a))
        self.assertEqual(len(b), 1)
        self.assertTrue(all(e["user"] == "revisor@corp.com" for e in b))

    def test_no_entries_when_no_match(self):
        server.audit("upload", user="sammideblas@gmail.com")
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
        server.REQUIRE_CF = True
        try:
            ok = self._handler(
                {"Cf-Access-Authenticated-User-Email": "a@b.com"})
            self.assertTrue(ok._cf_ok())
            bad = self._handler({})
            self.assertFalse(bad._cf_ok())
        finally:
            server.REQUIRE_CF = False


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
        old = server.LLM_MODEL
        try:
            server.LLM_MODEL = "otro-modelo"
            self.assertNotEqual(server.llm_key("linea"), k1)
        finally:
            server.LLM_MODEL = old


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
        old = (server.SPLUNK_URL, server.SPLUNK_USER, server.SPLUNK_PASS)
        server.SPLUNK_URL = "http://127.0.0.1:%d" % port
        server.SPLUNK_USER = "admin"
        server.SPLUNK_PASS = "testpass"
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
            (server.SPLUNK_URL, server.SPLUNK_USER, server.SPLUNK_PASS) = old

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
            (server.SPLUNK_URL, server.SPLUNK_USER, server.SPLUNK_PASS) = old

    def test_query_count_cap_and_rows(self):
        cap, srv, old = self._mock_splunk(results=[
            {"_time": "1724000000.5", "line": "FAIL user=x src=1.2.3.4",
             "src_ip": "1.2.3.4"},
            {"count": "7", "sourcetype": "ms:aad:signin"}])
        try:
            rows = server.splunk_query("index=botsv3", count=99999)
            # El tope duro evita traer 2M filas al visor/LLM
            self.assertEqual(cap["form"]["count"][0],
                             str(server.SPLUNK_MAX_ROWS))
            self.assertEqual(len(rows), 2)
            self.assertIn("line", rows[0])
        finally:
            srv.shutdown()
            (server.SPLUNK_URL, server.SPLUNK_USER, server.SPLUNK_PASS) = old

    def test_query_puerto_caido(self):
        # Apunta a un puerto de la maquina que seguro esta cerrado y con un
        # timeout corto, para que el fallo sea rapido y no espere los 120s
        # por defecto (un puerto recien cerrado no da refusal inmediato en
        # Windows y urlopen aguantaria el SPLUNK_TIMEOUT completo).
        old = (server.SPLUNK_URL, server.SPLUNK_USER, server.SPLUNK_PASS,
               server.SPLUNK_TIMEOUT)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        try:
            server.SPLUNK_URL = "http://127.0.0.1:%d" % port
            server.SPLUNK_USER = "admin"
            server.SPLUNK_PASS = "testpass"
            server.SPLUNK_TIMEOUT = 3
            with self.assertRaises(ValueError) as ctx:
                server.splunk_query("index=botsv3")
            # VERSION 1.2: lenguaje humano (contactar al operador)
            self.assertIn("El Splunk no responde", str(ctx.exception))
        finally:
            (server.SPLUNK_URL, server.SPLUNK_USER, server.SPLUNK_PASS,
             server.SPLUNK_TIMEOUT) = old

    def test_splunk_enabled_flag(self):
        old = server.SPLUNK_PASS
        try:
            server.SPLUNK_PASS = ""
            self.assertFalse(server.splunk_enabled())
            server.SPLUNK_PASS = "x"
            self.assertTrue(server.splunk_enabled())
        finally:
            server.SPLUNK_PASS = old

    def test_splunk_indexes_filters_internos(self):
        cap, srv, old = self._mock_splunk(indexes=("botsv3", "_audit"))
        try:
            self.assertEqual(server.splunk_indexes(), ["botsv3"])
            self.assertEqual(cap["path"], "/services/data/2.0/indexes")
        finally:
            srv.shutdown()
            (server.SPLUNK_URL, server.SPLUNK_USER, server.SPLUNK_PASS) = old

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


class TestEnvNotices(unittest.TestCase):
    """VERSION 1.2: avisos de funciones SOLO local (llm/splunk false) y
    LOGVIEWER_REPO_URL expuesta como repo_url en /api/config."""

    def _cfg(self, d, repo_url):
        # public_config() -> llm_config() -> settings_store(): se usa un
        # SettingsStore temporal para no tocar el estado real de %TEMP%
        old = (server.SETTINGS, server.REPO_URL)
        try:
            server.SETTINGS = server.SettingsStore(
                os.path.join(d, "settings.json"))
            server.REPO_URL = repo_url
            return server.public_config()
        finally:
            (server.SETTINGS, server.REPO_URL) = old

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
        old = (server.SPLUNK_URL, server.SPLUNK_USER, server.SPLUNK_PASS)
        try:
            server.SPLUNK_URL = "https://127.0.0.1:%d" % port
            server.SPLUNK_USER = "u"
            server.SPLUNK_PASS = "p"
            with self.assertRaises(ValueError) as cm:
                server.splunk_query("search index=botsv3 | head 1")
        finally:
            (server.SPLUNK_URL, server.SPLUNK_USER,
             server.SPLUNK_PASS) = old
        self.assertIn("El Splunk no responde", str(cm.exception))
        self.assertIn("operador del servidor", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
