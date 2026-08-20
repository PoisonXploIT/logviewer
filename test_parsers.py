#!/usr/bin/env python3
"""Tests para los parsers, filtros, compresion y sesiones."""
import bz2
import gzip
import json
import lzma
import os
import tempfile
import unittest
import zipfile

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

    def test_sql_count_filtered(self):
        store = self._make_sql()
        self.assertEqual(store.count_filtered(self._q()), 3)
        self.assertEqual(store.count_filtered(self._q(level="ERR")), 1)
        self.assertEqual(store.count_filtered(self._q(ip="1.1")), 2)
        self.assertEqual(
            store.count_filtered(self._q(level="INF", ip="1.1")), 2)
        self.assertEqual(store.count_filtered(self._q(q="fallo")), 1)
        self.assertEqual(store.count_filtered(self._q(dt="2023-10-11")), 1)

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


if __name__ == "__main__":
    unittest.main()
