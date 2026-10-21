"""Testes da integração com o ClamAV.

Não exigem ClamAV instalado: usam um clamd falso que fala o protocolo real
(PING / VERSION / INSTREAM / RELOAD) e um clamscan/freshclam falsos com o mesmo
formato de saída. Um arquivo que contenha MARKER é tratado como infectado.
"""
import os
import socketserver
import stat
import struct
import sys
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp(prefix="aegis-clam-test-")
os.environ.setdefault("AEGIS_HOME", os.path.join(_tmp, "home"))
sys.path.insert(0, str(ROOT / "desktop"))

import clam  # noqa: E402
import config  # noqa: E402
import engine  # noqa: E402
from controller import Controller  # noqa: E402

MARKER = b"FAKE-CLAM-VIRUS-MARKER"
VERSION = "ClamAV 1.0.0/27000/Mon Jan  1 00:00:00 2026"


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(path)


# --------------------------------------------------------------------------- clamd falso
class FakeClamdHandler(socketserver.BaseRequestHandler):
    def _recv_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                raise ConnectionError
            data += chunk
        return data

    def handle(self):
        try:
            self._handle()
        except ConnectionError:
            pass                                   # cliente desistiu no meio (como um clamd real tolera)

    def _handle(self):
        command = b""
        while not command.endswith(b"\0"):
            chunk = self.request.recv(1)
            if not chunk:
                return
            command += chunk
        command = command.rstrip(b"\0")
        server = self.server
        if command == b"zPING":
            self.request.sendall(b"PONG\0")
        elif command == b"zVERSION":
            self.request.sendall(VERSION.encode() + b"\0")
        elif command == b"zRELOAD":
            server.reloaded += 1
            self.request.sendall(b"RELOADING\0")
        elif command == b"zINSTREAM":
            content, exceeded = b"", False
            while True:
                size = struct.unpack("!I", self._recv_exact(4))[0]
                if size == 0:
                    break
                content += self._recv_exact(size)
                if len(content) > server.limit:
                    exceeded = True
            if exceeded:
                self.request.sendall(b"INSTREAM size limit exceeded. ERROR\0")
            elif MARKER in content:
                self.request.sendall(b"stream: Fake.Test.Virus FOUND\0")
            else:
                self.request.sendall(b"stream: OK\0")


class FakeClamd(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, limit=10 * 1024 * 1024):
        super().__init__(("127.0.0.1", 0), FakeClamdHandler)
        self.limit = limit
        self.reloaded = 0
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]


# --------------------------------------------------------------------------- clamscan / freshclam falsos
CLAMSCAN_SRC = f'''
import os, sys
MARKER = {MARKER!r}
args = sys.argv[1:]
if "--version" in args:
    print("ClamAV 1.0.0" if os.environ.get("FAKE_CLAM_NODB") else {VERSION!r})
    sys.exit(0)
if os.environ.get("FAKE_CLAM_FAIL"):
    print("ERROR: Can't open database", file=sys.stderr)
    sys.exit(2)
lst = args[args.index("-f") + 1]
found = False
for path in open(lst, encoding="utf-8").read().splitlines():
    if not os.path.exists(path):
        print(path + ": No such file or directory. ERROR")
    elif MARKER in open(path, "rb").read():
        print(path + ": Fake.Test.Virus FOUND"); found = True
    else:
        print(path + ": OK")
    sys.stdout.flush()
sys.exit(1 if found else 0)
'''
FRESHCLAM_SRC = '''
import os, sys
if os.environ.get("FAKE_FRESH_FAIL"):
    print("ERROR: Can't open /var/lib/clamav/freshclam.dat for writing", file=sys.stderr); sys.exit(1)
print("ClamAV update process started"); print("daily.cvd database is up-to-date"); sys.exit(0)
'''


def make_fake_binary(folder, name, source):
    script = Path(folder) / f"{name}_impl.py"
    script.write_text(source)
    if os.name == "nt":
        wrapper = Path(folder) / f"{name}.bat"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n')
    else:
        wrapper = Path(folder) / name
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return str(wrapper)


class ClamTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=_tmp))
        self.clamscan = make_fake_binary(self.dir, "clamscan", CLAMSCAN_SRC)
        make_fake_binary(self.dir, "freshclam", FRESHCLAM_SRC)
        for var in ("FAKE_CLAM_NODB", "FAKE_CLAM_FAIL", "FAKE_FRESH_FAIL"):
            os.environ.pop(var, None)
        self.addCleanup(lambda: [os.environ.pop(v, None) for v in ("FAKE_CLAM_NODB", "FAKE_CLAM_FAIL", "FAKE_FRESH_FAIL")])
        # as configurações ficam em disco: apaga para não vazar para outros testes
        self.addCleanup(lambda: config.SETTINGS_FILE.unlink(missing_ok=True))


class ParsingTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(clam.parse_version(VERSION), ("ClamAV 1.0.0", "27000"))
        self.assertEqual(clam.parse_version("ClamAV 1.0.0"), ("ClamAV 1.0.0", ""))

    def test_clamscan_lines(self):
        p = clam.parse_clamscan_line
        self.assertEqual(p("/a/b c.txt: OK\n"), ("/a/b c.txt", "ok", ""))
        self.assertEqual(p("/a/x.txt: Win.Test.EICAR_HDB-1 FOUND"), ("/a/x.txt", "found", "Win.Test.EICAR_HDB-1"))
        self.assertEqual(p(r"C:\Users\Ana\x.exe: Win.Trojan.Agent-1 FOUND"), (r"C:\Users\Ana\x.exe", "found", "Win.Trojan.Agent-1"))
        self.assertEqual(p("/a/y: Access denied. ERROR")[1], "error")
        self.assertIsNone(p("LibClamAV Warning: algo"))


class ClamdTests(ClamTestCase):
    def setUp(self):
        super().setUp()
        self.server = FakeClamd(limit=1024)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.av = clam.ClamAV(host="127.0.0.1", port=self.server.port)

    def test_detect_and_scan(self):
        status = self.av.detect()
        self.assertTrue(status.available)
        self.assertEqual((status.mode, status.db_version), ("clamd", "27000"))
        self.assertIn("clamd", status.summary)
        bad = write(self.dir / "bad.txt", b"abc " + MARKER)
        ok = write(self.dir / "ok.txt", "tudo certo")
        self.assertEqual(self.av.scan_file(bad), "Fake.Test.Virus")
        self.assertIsNone(self.av.scan_file(ok))

    def test_scan_files_progress_size_limit_and_missing(self):
        self.av.detect()
        files = [write(self.dir / f"f{i}.txt", "x") for i in range(5)]
        files.append(write(self.dir / "mal.txt", MARKER))
        files.append(write(self.dir / "grande.bin", b"0" * 5000))        # acima do limite do daemon
        files.append(str(self.dir / "sumiu.txt"))                        # não existe
        seen = []
        hits = self.av.scan_files(files, on_progress=lambda d, t, p: seen.append((d, t)))
        self.assertEqual(hits, {files[5]: "Fake.Test.Virus"})
        self.assertEqual(seen[-1], (len(files), len(files)))

    def test_cancel(self):
        self.av.detect()
        files = [write(self.dir / f"c{i}.txt", MARKER) for i in range(5)]
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(self.av.scan_files(files, cancel=cancel), {})

    def test_daemon_down_raises(self):
        self.av.detect()
        self.server.shutdown()
        self.server.server_close()
        with self.assertRaises(clam.ClamError):
            self.av.scan_file(write(self.dir / "a.txt", "x"))

    def test_update_reloads_daemon(self):
        self.av.clamscan_hint = self.clamscan          # freshclam fica ao lado do clamscan falso
        self.av.detect()
        ok, message = self.av.update_database()
        self.assertTrue(ok, message)
        self.assertEqual(self.server.reloaded, 1)

    def test_self_test(self):
        self.av.detect()
        ok, _ = self.av.self_test()
        self.assertFalse(ok)                                  # o clamd falso só conhece o MARKER


class ClamscanTests(ClamTestCase):
    def setUp(self):
        super().setUp()
        # porta 1 fechada → o clamd não existe e o modo clamscan é usado
        self.av = clam.ClamAV(clamscan=self.clamscan, port=1)

    def test_detect(self):
        status = self.av.detect()
        self.assertEqual((status.available, status.mode, status.db_version), (True, "clamscan", "27000"))

    def test_detect_without_database(self):
        os.environ["FAKE_CLAM_NODB"] = "1"
        status = self.av.detect()
        self.assertFalse(status.available)
        self.assertIn("freshclam", status.message)

    def test_not_installed(self):
        with unittest.mock.patch.object(clam, "find_binary", return_value=""):
            status = clam.ClamAV(port=1).detect()
        self.assertFalse(status.available)
        self.assertIn("não encontrado", status.message)

    def test_batch_scan_with_progress_and_odd_names(self):
        self.av.detect()
        files = [write(self.dir / "pasta com espaço" / "a b.txt", "ok"),
                 write(self.dir / "x: y.txt", "ok") if os.name != "nt" else write(self.dir / "xy.txt", "ok"),
                 write(self.dir / "mal.txt", b"..." + MARKER),
                 write(self.dir / "mal2.txt", MARKER)]
        seen = []
        hits = self.av.scan_files(files, on_progress=lambda d, t, p: seen.append((d, t)))
        self.assertEqual(hits, {files[2]: "Fake.Test.Virus", files[3]: "Fake.Test.Virus"})
        self.assertEqual(seen[-1], (4, 4))

    def test_clamscan_failure_raises(self):
        self.av.detect()
        os.environ["FAKE_CLAM_FAIL"] = "1"
        with self.assertRaises(clam.ClamError) as ctx:
            self.av.scan_files([write(self.dir / "a.txt", "x")])
        self.assertIn("database", str(ctx.exception))

    def test_update_database(self):
        self.av.detect()
        ok, message = self.av.update_database()
        self.assertTrue(ok)
        self.assertIn("up-to-date", message)
        os.environ["FAKE_FRESH_FAIL"] = "1"
        ok, message = self.av.update_database()
        self.assertFalse(ok)
        self.assertIn("administrador", message)

    def test_self_test_sees_eicar_only_if_clamav_knows_it(self):
        self.av.detect()
        ok, text = self.av.self_test()
        self.assertFalse(ok)                                  # clamscan falso não conhece o EICAR
        self.assertIn("não detectou", text)


class EngineIntegrationTests(ClamTestCase):
    def setUp(self):
        super().setUp()
        self.av = clam.ClamAV(clamscan=self.clamscan, port=1)
        self.av.detect()

    def test_clamav_adds_a_detection_layer(self):
        folder = self.dir / "alvo"
        write(folder / "ok.txt", "limpo")
        virus = write(folder / "desconhecido.txt", MARKER)       # o AEGIS sozinho não conhece
        write(folder / "eicar.txt", engine.EICAR_BYTES)          # o AEGIS conhece, o ClamAV falso não
        sigs = engine.Signatures.builtin()

        alone = engine.Scanner(sigs).scan_paths([str(folder)])
        self.assertEqual(alone.malicious, 1)                     # só o EICAR

        phases, found = [], []
        both = engine.Scanner(sigs, clam=self.av).scan_paths(
            [str(folder)], on_result=found.append, on_phase=phases.append)
        self.assertEqual(phases, ["ClamAV", "AEGIS"])
        self.assertTrue(both.clam_used)
        self.assertEqual(both.malicious, 2)
        by_path = {r.path: r for r in both.results}
        self.assertEqual(by_path[virus].threat, "Fake.Test.Virus")
        self.assertEqual(by_path[virus].source, "ClamAV")
        self.assertEqual(by_path[str(folder / "eicar.txt")].source, "AEGIS")

    def test_falls_back_when_clamav_breaks(self):
        folder = self.dir / "alvo2"
        write(folder / "eicar.txt", engine.EICAR_BYTES)
        os.environ["FAKE_CLAM_FAIL"] = "1"
        summary = engine.Scanner(engine.Signatures.builtin(), clam=self.av).scan_paths([str(folder)])
        self.assertFalse(summary.clam_used)
        self.assertIn("clamscan", summary.clam_error)
        self.assertEqual(summary.malicious, 1)                   # o motor do AEGIS continua protegendo

    def test_single_file_uses_clam_only_in_clamd_mode(self):
        path = write(self.dir / "solto.txt", MARKER)
        self.assertEqual(engine.Scanner(engine.Signatures.builtin(), clam=self.av).scan_file(path).verdict,
                         "clean")                                # clamscan: lento demais para arquivo avulso
        server = FakeClamd()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        daemon = clam.ClamAV(port=server.port)
        daemon.detect()
        res = engine.Scanner(engine.Signatures.builtin(), clam=daemon).scan_file(path)
        self.assertEqual((res.verdict, res.threat, res.source), ("malicious", "Fake.Test.Virus", "ClamAV"))


class ControllerClamTests(ClamTestCase):
    def test_controller_flow(self):
        events = []
        ctl = Controller(emit=lambda k, p=None: events.append((k, p)))
        ctl.settings.clamscan_path = self.clamscan
        ctl.settings.clamd_port = 1
        ctl.settings.clamav_enabled = True
        ctl.settings.auto_quarantine = False
        with unittest.mock.patch.dict(os.environ, {"AEGIS_DISABLE_CLAMAV": "0"}):
            status = ctl.detect_clam()
        self.assertTrue(status.available)
        self.assertTrue(ctl.clam_active)

        folder = self.dir / "scan"
        write(folder / "ok.txt", "limpo")
        write(folder / "virus.txt", MARKER)
        ctl.start_scan("personalizada", [str(folder)]).join(20)
        kinds = [k for k, _ in events]
        self.assertIn("scan_done", kinds)
        self.assertEqual([p for k, p in events if k == "phase"], ["ClamAV", "AEGIS"])
        results = [p for k, p in events if k == "result"]
        self.assertEqual([(r.threat, r.source) for r in results], [("Fake.Test.Virus", "ClamAV")])
        self.assertTrue(ctl.last_summary.clam_used)

        ctl.set_clamav_enabled(False)
        self.assertFalse(ctl.clam_active)
        self.assertIsNone(ctl.scanner().clam)

        ctl.set_clamav_enabled(True)
        with unittest.mock.patch.dict(os.environ, {"AEGIS_DISABLE_CLAMAV": "0"}):
            ok, _ = ctl.update_clam_database()
            self.assertTrue(ok)
        self.assertTrue(ctl.clam_status.available)

    def test_disabled_by_environment(self):
        ctl = Controller(emit=lambda *a: None)
        with unittest.mock.patch.dict(os.environ, {"AEGIS_DISABLE_CLAMAV": "1"}):
            status = ctl.detect_clam()
        self.assertFalse(status.available)
        self.assertFalse(ctl.clam_active)


if __name__ == "__main__":
    unittest.main()
