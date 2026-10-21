"""Testes do site e da API. Execute na raiz do projeto: python -m unittest discover tests -v"""
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp(prefix="aegis-test-")
os.environ.setdefault("AEGIS_DB", os.path.join(_tmp, "test.db"))
os.environ.setdefault("AEGIS_SECRET_KEY", "chave-de-teste")
sys.path.insert(0, str(ROOT / "server"))

import app as aegis  # noqa: E402

PASSWORD = "Senha1234"
_counter = [0]


def new_email():
    _counter[0] += 1
    return f"cliente{_counter[0]}@teste.com"


def csrf_from(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)


def register(client, email=None, password=PASSWORD, plano=""):
    email = email or new_email()
    token = csrf_from(client, "/cadastro")
    resp = client.post("/cadastro", data={
        "_csrf": token, "nome": "Maria Souza", "email": email,
        "senha": password, "aceite": "on", "plano": plano})
    return email, resp


def api_login(client, email, device="dev-12345678", senha=PASSWORD, **extra):
    payload = {"email": email, "senha": senha, "device_id": device,
               "device_name": "PC de teste", "os": "TestOS"}
    payload.update(extra)
    return client.post("/api/auth/login", json=payload)


def buy(client, plano, card="4242 4242 4242 4242"):
    token = csrf_from(client, "/sistema")
    return client.post(f"/comprar/{plano}", data={
        "_csrf": token, "nome": "Maria Souza", "numero": card,
        "validade": "12/40", "cvv": "123"})


class SiteTests(unittest.TestCase):
    def setUp(self):
        self.client = aegis.app.test_client()

    def test_landing_and_headers(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
        html = resp.get_data(as_text=True)
        for needle in ("Essencial", "Plus", "Pro", "Perguntas frequentes"):
            self.assertIn(needle, html)
        self.assertNotIn("onclick=", html)          # CSP: sem JavaScript inline

    def test_public_pages(self):
        for path in ("/login", "/cadastro", "/termos", "/privacidade"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertEqual(self.client.get("/nao-existe").status_code, 404)

    def test_post_without_csrf_is_rejected(self):
        resp = self.client.post("/login", data={"email": "a@b.co", "senha": "x"})
        self.assertEqual(resp.status_code, 400)

    def test_register_validation(self):
        _, resp = register(self.client, password="curta1")
        self.assertEqual(resp.status_code, 400)
        _, resp = register(self.client, password="somenteletras")
        self.assertEqual(resp.status_code, 400)
        _, resp = register(self.client, email="invalido")
        self.assertEqual(resp.status_code, 400)

    def test_register_login_and_dashboard(self):
        email, resp = register(self.client)
        self.assertEqual(resp.status_code, 302)
        page = self.client.get("/sistema")
        self.assertEqual(page.status_code, 200)
        self.assertIn("AEGIS-", page.get_data(as_text=True))       # chave de licença
        for aba in aegis.ABAS:
            self.assertEqual(self.client.get(f"/sistema?aba={aba}").status_code, 200, aba)
        # e-mail duplicado
        other = aegis.app.test_client()
        _, resp = register(other, email=email)
        self.assertEqual(resp.status_code, 400)
        # logout (POST com CSRF) e login de novo
        token = csrf_from(self.client, "/sistema")
        self.client.post("/logout", data={"_csrf": token})
        self.assertEqual(self.client.get("/sistema").status_code, 302)
        token = csrf_from(self.client)
        bad = self.client.post("/login", data={"_csrf": token, "email": email, "senha": "errada123"})
        self.assertEqual(bad.status_code, 401)
        ok = self.client.post("/login", data={"_csrf": token, "email": email, "senha": PASSWORD})
        self.assertEqual(ok.status_code, 302)

    def test_login_does_not_redirect_to_external_sites(self):
        email, _ = register(self.client)
        other = aegis.app.test_client()
        token = csrf_from(other)
        resp = other.post("/login", data={"_csrf": token, "email": email, "senha": PASSWORD,
                                          "next": "//evil.example.com"})
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn("evil.example.com", resp.headers["Location"])

    def test_protected_routes_redirect_to_login(self):
        for path in ("/sistema", "/download", "/comprar/plus"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 302, path)
            self.assertIn("/login", resp.headers["Location"])

    def test_checkout_flow(self):
        register(self.client)
        bad = buy(self.client, "plus", card="1234 5678 9012 3456")
        self.assertEqual(bad.status_code, 400)
        ok = buy(self.client, "plus")
        self.assertEqual(ok.status_code, 302)
        self.assertIn("/comprar/sucesso/", ok.headers["Location"])
        self.assertEqual(self.client.get(ok.headers["Location"]).status_code, 200)
        dash = self.client.get("/sistema?aba=compras").get_data(as_text=True)
        self.assertIn("4242", dash)
        self.assertNotIn("4242 4242 4242 4242", dash)              # número completo não é guardado
        # não é possível "comprar" plano inferior ao atual
        buy(self.client, "pro")
        down = buy(self.client, "plus")
        self.assertEqual(down.status_code, 302)
        self.assertIn("/sistema", down.headers["Location"])

    def test_cancel_subscription_and_csv_export(self):
        register(self.client)
        buy(self.client, "plus")
        token = csrf_from(self.client, "/sistema")
        self.assertEqual(self.client.get("/sistema/historico.csv").status_code, 302)   # só Pro
        buy(self.client, "pro")
        csv_resp = self.client.get("/sistema/historico.csv")
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("text/csv", csv_resp.headers["Content-Type"])
        token = csrf_from(self.client, "/sistema")
        self.client.post("/sistema/assinatura/cancelar", data={"_csrf": token})
        self.assertIn("Essencial", self.client.get("/sistema").get_data(as_text=True))

    def test_change_password(self):
        email, _ = register(self.client)
        token = csrf_from(self.client, "/sistema?aba=conta")
        self.client.post("/sistema/senha", data={"_csrf": token, "atual": PASSWORD,
                                                 "nova": "NovaSenha99", "confirma": "NovaSenha99"})
        resp = api_login(aegis.app.test_client(), email, senha="NovaSenha99")
        self.assertEqual(resp.status_code, 200)

    def test_download_zip_is_preconfigured(self):
        register(self.client)
        resp = self.client.get("/download/aegis-antivirus.zip")
        self.assertEqual(resp.status_code, 200)
        zf = zipfile.ZipFile(io.BytesIO(resp.data))
        names = zf.namelist()
        self.assertIn("aegis-antivirus/engine.py", names)
        self.assertIn("aegis-antivirus/aegis_app.py", names)
        self.assertFalse([n for n in names if "/tests/" in n or "__pycache__" in n])
        cfg = json.loads(zf.read("aegis-antivirus/config.json"))
        self.assertTrue(cfg["server_url"].startswith("http://localhost"))


class DeployTests(unittest.TestCase):
    def test_proxy_headers_are_trusted_only_when_enabled(self):
        client = aegis.app.test_client()
        register(client)
        headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "aegis.onrender.com"}
        before = json.loads(zipfile.ZipFile(io.BytesIO(
            client.get("/download/aegis-antivirus.zip", headers=headers).data)).read("aegis-antivirus/config.json"))
        self.assertTrue(before["server_url"].startswith("http://localhost"))      # sem proxy: ignora os cabeçalhos

        original = aegis.app.wsgi_app
        aegis.enable_proxy_fix(aegis.app)
        try:
            client = aegis.app.test_client()
            register(client)
            after = json.loads(zipfile.ZipFile(io.BytesIO(
                client.get("/download/aegis-antivirus.zip", headers=headers).data)).read("aegis-antivirus/config.json"))
            self.assertEqual(after["server_url"], "https://aegis.onrender.com")
        finally:
            aegis.app.wsgi_app = original

    def test_demo_user_is_seeded_once(self):
        from unittest import mock
        env = {"AEGIS_DEMO_EMAIL": "Demo@Aegis.Test", "AEGIS_DEMO_PASSWORD": "DemoSenha123", "AEGIS_DEMO_PLAN": "pro"}
        with mock.patch.dict(os.environ, env):
            aegis.seed_demo_user()
            aegis.seed_demo_user()                                  # idempotente
        with sqlite3.connect(os.environ["AEGIS_DB"]) as conn:
            rows = conn.execute("SELECT plano FROM users WHERE email='demo@aegis.test'").fetchall()
        self.assertEqual(rows, [("pro",)])
        resp = api_login(aegis.app.test_client(), "demo@aegis.test", senha="DemoSenha123")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["user"]["tempo_real"])

    def test_no_demo_user_without_env(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"AEGIS_DEMO_EMAIL": "", "AEGIS_DEMO_PASSWORD": ""}):
            aegis.seed_demo_user()                                  # não deve falhar nem criar nada


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.web = aegis.app.test_client()
        self.api = aegis.app.test_client()
        self.email, _ = register(self.web)

    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def login_token(self, device="dev-12345678"):
        return api_login(self.api, self.email, device).get_json()["token"]

    def test_health_and_bad_requests(self):
        self.assertTrue(self.api.get("/api/health").get_json()["ok"])
        self.assertEqual(self.api.get("/api/me").status_code, 401)
        self.assertEqual(self.api.get("/api/me", headers=self.auth("lixo")).status_code, 401)
        self.assertEqual(api_login(self.api, self.email, device="x").status_code, 400)
        self.assertEqual(api_login(self.api, self.email, senha="errada").status_code, 401)

    def test_login_me_and_license_login(self):
        resp = api_login(self.api, self.email)
        data = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data["user"]["plano"], "essencial")
        self.assertFalse(data["user"]["tempo_real"])
        me = self.api.get("/api/me", headers=self.auth(data["token"]))
        self.assertEqual(me.get_json()["user"]["email"], self.email)
        with sqlite3.connect(os.environ["AEGIS_DB"]) as conn:
            key = conn.execute("SELECT license_key FROM users WHERE email=?", (self.email,)).fetchone()[0]
        lic = self.api.post("/api/auth/login", json={"license_key": key.lower(), "device_id": "dev-12345678"})
        self.assertEqual(lic.status_code, 200)

    def test_device_limit_per_plan(self):
        self.assertEqual(api_login(self.api, self.email, "dev-aaaaaaaa").status_code, 200)
        self.assertEqual(api_login(self.api, self.email, "dev-aaaaaaaa").status_code, 200)   # mesmo
        blocked = api_login(self.api, self.email, "dev-bbbbbbbb")
        self.assertEqual(blocked.status_code, 403)
        self.assertIn("Essencial", blocked.get_json()["erro"])
        buy(self.web, "plus")
        self.assertEqual(api_login(self.api, self.email, "dev-bbbbbbbb").status_code, 200)
        data = api_login(self.api, self.email, "dev-aaaaaaaa").get_json()
        self.assertTrue(data["user"]["tempo_real"])

    def test_removed_device_loses_access(self):
        token = self.login_token()
        self.assertEqual(self.api.get("/api/me", headers=self.auth(token)).status_code, 200)
        with sqlite3.connect(os.environ["AEGIS_DB"]) as conn:
            conn.execute("DELETE FROM devices WHERE device_id='dev-12345678'")
        self.assertEqual(self.api.get("/api/me", headers=self.auth(token)).status_code, 401)

    def test_signatures_versioning(self):
        token = self.login_token()
        full = self.api.get("/api/signatures?versao=0", headers=self.auth(token)).get_json()
        self.assertTrue(full["atualizado"])
        self.assertTrue(full["padroes"] and full["hashes"])
        same = self.api.get(f"/api/signatures?versao={full['versao']}", headers=self.auth(token)).get_json()
        self.assertFalse(same["atualizado"])

    def test_scan_report_shows_up_in_dashboard(self):
        token = self.login_token()
        resp = self.api.post("/api/scans", headers=self.auth(token), json={
            "tipo": "rapida", "arquivos": 321, "ameacas": 1, "duracao": 4.2,
            "deteccoes": [{"arquivo": "eicar_test.txt", "ameaca": "EICAR-Test-File", "acao": "quarentena"}]})
        self.assertEqual(resp.status_code, 200)
        html = self.web.get("/sistema?aba=historico").get_data(as_text=True)
        self.assertIn("eicar_test.txt", html)
        self.assertIn("321", html)
        self.assertIn("PC de teste", html)

    def test_plan_expiry_downgrades(self):
        buy(self.web, "plus")
        token = self.login_token()
        self.assertEqual(self.api.get("/api/me", headers=self.auth(token)).get_json()["user"]["plano"], "plus")
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        with sqlite3.connect(os.environ["AEGIS_DB"]) as conn:
            conn.execute("UPDATE users SET plano_expira_em=? WHERE email=?", (past, self.email))
        user = self.api.get("/api/me", headers=self.auth(token)).get_json()["user"]
        self.assertEqual(user["plano"], "essencial")
        self.assertFalse(user["tempo_real"])

    def test_brute_force_is_rate_limited(self):
        email = new_email()
        codes = [api_login(self.api, email, senha="x").status_code for _ in range(7)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[5], 429)


if __name__ == "__main__":
    unittest.main()
