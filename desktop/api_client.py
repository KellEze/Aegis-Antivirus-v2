"""Cliente HTTP para a API do site AEGIS (somente biblioteca padrão)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import config


class ApiError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.message = message
        self.status = status          # 0 = sem conexão


class ApiClient:
    def __init__(self, base_url: str, token: str = ""):
        self.base = base_url.rstrip("/")
        self.token = token

    def _request(self, method: str, path: str, payload=None, auth: bool = True,
                 timeout: float = 10):
        headers = {
            "Accept": "application/json",
            "User-Agent": f"AEGIS-Desktop/{config.APP_VERSION}",
        }
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            message = f"Erro {exc.code} do servidor."
            try:
                message = json.loads(exc.read().decode("utf-8")).get("erro", message)
            except Exception:
                pass
            raise ApiError(message, exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise ApiError(f"Não foi possível conectar ao servidor ({self.base}).", 0) from exc
        try:
            return json.loads(body.decode("utf-8") or "{}")
        except ValueError as exc:
            raise ApiError("Resposta inválida do servidor.", 502) from exc

    def health(self):
        return self._request("GET", "/api/health", auth=False, timeout=75)

    def login(self, payload: dict):
        return self._request("POST", "/api/auth/login", payload, auth=False, timeout=75)

    def me(self):
        return self._request("GET", "/api/me", timeout=30)

    def signatures(self, version: int = 0):
        return self._request("GET", f"/api/signatures?versao={int(version)}", timeout=45)

    def report_scan(self, payload: dict):
        return self._request("POST", "/api/scans", payload, timeout=30)
