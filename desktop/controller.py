"""Controlador: toda a lógica do aplicativo, sem depender de interface gráfica.

A interface (Tkinter) e a linha de comando usam esta classe. Eventos são
enviados pelo callback `emit(tipo, dados)`, que pode ser chamado de qualquer
thread (a interface o redireciona para uma fila).

Eventos emitidos:
  progress (feitos, total, caminho) | result ScanResult | scan_done dict
  rt_event ScanResult | account dict | signatures dict | realtime bool
  phase str ("ClamAV"/"AEGIS") | clam ClamStatus
  info str | error str | logout None
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

import clam
import config
import engine
import realtime
from api_client import ApiClient, ApiError
from quarantine import Quarantine, QuarantineError


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Controller:
    def __init__(self, emit: Optional[Callable] = None):
        self.emit = emit or (lambda kind, payload=None: None)
        config.ensure_dirs()
        self.settings = config.Settings.load()
        self.session = config.load_json(config.SESSION_FILE, None)
        if not (isinstance(self.session, dict) and self.session.get("token")):
            self.session = None
        self.signatures = engine.Signatures.load_cached()
        self.quarantine = Quarantine()
        self.cancel_event = threading.Event()
        self.scanning = False
        self.watcher: Optional[realtime.Watcher] = None
        self.realtime_interval = 3.0
        self.last_summary: Optional[engine.ScanSummary] = None
        self.clam = clam.ClamAV.from_settings(self.settings)
        self.clam_status = clam.ClamStatus()

    # ------------------------------------------------------------------
    # Conta
    # ------------------------------------------------------------------
    @property
    def logged_in(self) -> bool:
        return self.session is not None

    @property
    def user(self) -> dict:
        return (self.session or {}).get("user", {})

    @property
    def can_realtime(self) -> bool:
        return self.logged_in and bool(self.user.get("tempo_real"))

    def client(self) -> ApiClient:
        token = (self.session or {}).get("token", "")
        return ApiClient(self.settings.server_url, token)

    def set_server_url(self, url: str) -> None:
        self.settings.server_url = url.strip().rstrip("/") or config.default_server_url()
        self.settings.save()

    def login(self, email: str = "", senha: str = "", license_key: str = "") -> dict:
        payload = {
            "device_id": config.device_id(),
            "device_name": config.device_name(),
            "os": config.os_name(),
        }
        if license_key.strip():
            payload["license_key"] = license_key.strip()
        else:
            payload["email"] = email.strip()
            payload["senha"] = senha
        data = ApiClient(self.settings.server_url).login(payload)
        self.session = {"token": data["token"], "user": data["user"]}
        config.save_json(config.SESSION_FILE, self.session)
        self.emit("account", self.user)
        return self.user

    def refresh_account(self) -> None:
        """Atualiza plano/limites a partir do servidor. Chamado em segundo plano."""
        if not self.logged_in:
            return
        try:
            data = self.client().me()
        except ApiError as exc:
            if exc.status == 401:
                self.logout()
                self.emit("error", exc.message)
            else:
                self.emit("info", "Servidor indisponível: usando os dados salvos da conta.")
            return
        self.session["user"] = data["user"]
        config.save_json(config.SESSION_FILE, self.session)
        if not self.can_realtime and self.watcher:
            self.stop_realtime()
        self.emit("account", self.user)

    def use_offline(self) -> None:
        self.session = None
        self.emit("account", {})

    def logout(self) -> None:
        self.stop_realtime()
        self.session = None
        try:
            os.remove(config.SESSION_FILE)
        except OSError:
            pass
        self.emit("logout", None)

    # ------------------------------------------------------------------
    # Assinaturas
    # ------------------------------------------------------------------
    def update_signatures(self) -> bool:
        """Baixa novas assinaturas. Retorna True se houve atualização."""
        if not self.logged_in:
            raise ApiError("Entre na sua conta para atualizar as assinaturas.", 401)
        data = self.client().signatures(self.signatures.version)
        changed = bool(data.get("atualizado", True))
        if changed:
            data.pop("atualizado", None)
            self.signatures = engine.Signatures.from_server(data)
            self.signatures.save_cache(data)
        self.emit("signatures", {"versao": self.signatures.version,
                                 "total": self.signatures.total, "changed": changed})
        return changed

    def scanner(self) -> engine.Scanner:
        return engine.Scanner(self.signatures, skip_dirs=[str(self.quarantine.dir)],
                              clam=self.clam if self.clam_active else None)

    # ------------------------------------------------------------------
    # ClamAV
    # ------------------------------------------------------------------
    @property
    def clam_active(self) -> bool:
        return self.settings.clamav_enabled and self.clam_status.available

    def detect_clam(self) -> clam.ClamStatus:
        """(Re)detecta o ClamAV com as configurações atuais."""
        if os.environ.get("AEGIS_DISABLE_CLAMAV") == "1":
            self.clam_status = clam.ClamStatus(checked=True, message="ClamAV desativado (AEGIS_DISABLE_CLAMAV=1).")
        else:
            self.clam = clam.ClamAV.from_settings(self.settings)
            self.clam_status = self.clam.detect()
        self.emit("clam", self.clam_status)
        return self.clam_status

    def set_clamav_enabled(self, enabled: bool) -> None:
        self.settings.clamav_enabled = bool(enabled)
        self.settings.save()
        self.emit("clam", self.clam_status)

    def set_clamscan_path(self, path: str) -> clam.ClamStatus:
        self.settings.clamscan_path = path.strip()
        self.settings.save()
        return self.detect_clam()

    def update_clam_database(self) -> tuple[bool, str]:
        if not self.clam_status.checked:
            self.detect_clam()
        ok, message = self.clam.update_database()
        self.detect_clam()
        return ok, message

    def clam_self_test(self) -> tuple[bool, str]:
        if not self.clam_status.checked:
            self.detect_clam()
        return self.clam.self_test()

    # ------------------------------------------------------------------
    # Verificação
    # ------------------------------------------------------------------
    def start_scan(self, kind: str, paths: Iterable[str]) -> threading.Thread:
        if self.scanning:
            raise RuntimeError("Já existe uma verificação em andamento.")
        paths = [p for p in paths if os.path.exists(p)]
        if not paths:
            raise ValueError("Nenhuma pasta válida para verificar.")
        if not self.clam_status.checked:
            self.detect_clam()
        self.cancel_event.clear()
        self.scanning = True
        thread = threading.Thread(target=self._scan_worker, args=(kind, paths),
                                  daemon=True, name="aegis-scan")
        thread.start()
        return thread

    def cancel_scan(self) -> None:
        self.cancel_event.set()

    def _scan_worker(self, kind: str, paths: list) -> None:
        started_iso = _now_iso()
        t0 = time.monotonic()
        summary = engine.ScanSummary()
        try:
            def on_result(res: engine.ScanResult) -> None:
                if res.verdict == "malicious" and self.settings.auto_quarantine:
                    self._quarantine_result(res)
                self.emit("result", res)

            summary = self.scanner().scan_paths(
                paths,
                on_progress=lambda d, t, p: self.emit("progress", (d, t, p)),
                on_result=on_result,
                cancel=self.cancel_event,
                on_phase=lambda name: self.emit("phase", name),
            )
            if summary.clam_error:
                self.emit("info", f"ClamAV indisponível nesta verificação: {summary.clam_error}")
        except Exception as exc:  # nunca deixar a thread morrer em silêncio
            self.emit("error", f"Falha durante a verificação: {exc}")
        finally:
            self.scanning = False

        duration = time.monotonic() - t0
        self.last_summary = summary
        self.settings.last_scan = _now_iso()
        self.settings.last_scan_info = f"{summary.scanned} arquivos, {summary.threats} ameaça(s)"
        self.settings.save()
        self.emit("scan_done", {"kind": kind, "summary": summary, "duration": duration})
        self._report(kind, summary, started_iso, duration)

    def _report(self, kind: str, summary: engine.ScanSummary, started: str, duration: float) -> None:
        if not self.logged_in:
            return
        payload = {
            "tipo": kind,
            "iniciado_em": started,
            "arquivos": summary.scanned,
            "ameacas": summary.threats,
            "duracao": round(duration, 2),
            "deteccoes": [
                {"arquivo": r.name, "ameaca": r.threat or r.verdict, "acao": r.action or "detectado"}
                for r in summary.results[:100]
            ],
        }
        try:
            self.client().report_scan(payload)
        except ApiError as exc:
            if exc.status == 401:
                self.logout()
            else:
                self.emit("info", "Não foi possível enviar o resultado ao painel online.")

    # ------------------------------------------------------------------
    # Quarentena
    # ------------------------------------------------------------------
    def _quarantine_result(self, res: engine.ScanResult) -> bool:
        try:
            entry = self.quarantine.add(res.path, res.threat, res.reasons, res.sha256)
        except QuarantineError as exc:
            res.action = f"falha: {exc}"
            return False
        res.action = "quarentena"
        res.quarantine_id = entry["id"]
        return True

    def quarantine_results(self, results: Iterable[engine.ScanResult]) -> tuple[int, list[str]]:
        ok, errors = 0, []
        for res in results:
            if self._quarantine_result(res):
                ok += 1
            else:
                errors.append(f"{res.name}: {res.action}")
        return ok, errors

    # ------------------------------------------------------------------
    # Tempo real
    # ------------------------------------------------------------------
    @property
    def realtime_running(self) -> bool:
        return bool(self.watcher and self.watcher.is_alive())

    def start_realtime(self) -> None:
        if not self.can_realtime:
            raise PermissionError("A proteção em tempo real está disponível nos planos Plus e Pro.")
        if self.realtime_running:
            return
        folders = [f for f in self.settings.watch_folders if os.path.isdir(f)]
        if not folders:
            raise ValueError("Adicione ao menos uma pasta válida para monitorar.")
        self.watcher = realtime.Watcher(folders, self._on_realtime_file,
                                        interval=self.realtime_interval)
        self.watcher.start()
        self.settings.realtime = True
        self.settings.save()
        self.emit("realtime", True)

    def stop_realtime(self) -> None:
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        if self.settings.realtime:
            self.settings.realtime = False
            self.settings.save()
        self.emit("realtime", False)

    def _on_realtime_file(self, path: str) -> None:
        res = self.scanner().scan_file(path)
        if res.verdict not in ("malicious", "suspicious"):
            return
        if res.verdict == "malicious" and self.settings.auto_quarantine:
            self._quarantine_result(res)
        self.emit("rt_event", res)
        if self.logged_in:
            payload = {
                "tipo": "tempo_real", "iniciado_em": _now_iso(), "arquivos": 1, "ameacas": 1,
                "duracao": 0,
                "deteccoes": [{"arquivo": res.name, "ameaca": res.threat, "acao": res.action or "detectado"}],
            }
            try:
                self.client().report_scan(payload)
            except ApiError:
                pass

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------
    def create_test_files(self, folder: Optional[str] = None) -> list[str]:
        target = folder or os.path.join(str(config.downloads_dir()), "AEGIS-testes")
        return engine.write_test_files(target)
