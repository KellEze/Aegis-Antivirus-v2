"""Integração opcional com o ClamAV.

Dois modos, escolhidos automaticamente:

  clamd     O daemon mantém a base de vírus na memória. O AEGIS envia cada arquivo
            pelo protocolo INSTREAM (socket Unix ou TCP). É rápido e serve para o
            tempo real.
  clamscan  Executável de linha de comando. A base é carregada a cada execução
            (lento para começar), então o AEGIS roda UMA vez para a verificação
            inteira, lendo o progresso da saída.

Nada aqui é obrigatório: sem ClamAV instalado, o AEGIS continua funcionando com o
próprio motor.
"""
from __future__ import annotations

import locale
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

UNIX_SOCKETS = [
    "/var/run/clamav/clamd.ctl", "/run/clamav/clamd.ctl",
    "/var/run/clamd.scan/clamd.sock", "/run/clamd.scan/clamd.sock",
    "/tmp/clamd.socket", "/opt/homebrew/var/run/clamav/clamd.sock",
    "/usr/local/var/run/clamav/clamd.sock",
]
WINDOWS_DIRS = [
    r"C:\Program Files\ClamAV", r"C:\Program Files (x86)\ClamAV", r"C:\ClamAV", r"C:\clamav",
]
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

ProgressFn = Callable[[int, int, str], None]


class ClamError(Exception):
    """Falha geral do ClamAV (indisponível, daemon fora do ar, saída inesperada)."""


class ClamFileError(ClamError):
    """Falha só com um arquivo (limite de tamanho, sem permissão...). Pode ser ignorada."""


@dataclass
class ClamStatus:
    checked: bool = False
    available: bool = False
    mode: str = ""            # "clamd" | "clamscan" | ""
    version: str = ""
    db_version: str = ""
    message: str = "Ainda não verificado."

    @property
    def summary(self) -> str:
        if not self.checked:
            return "Verificando…"
        if not self.available:
            return self.message
        mode = "daemon clamd" if self.mode == "clamd" else "clamscan"
        extra = f" · base {self.db_version}" if self.db_version else ""
        return f"Ativo ({mode}) · {self.version}{extra}"


def parse_version(text: str) -> tuple[str, str]:
    """'ClamAV 1.0.5/27000/Mon Jan 1 ...' -> ('ClamAV 1.0.5', '27000')."""
    parts = text.strip().split("/")
    version = parts[0].strip()
    db = parts[1].strip() if len(parts) > 2 and parts[1].strip().isdigit() else ""
    return version, db


def find_binary(name: str, near: str = "") -> str:
    """Procura um executável do ClamAV: pasta indicada, PATH e pastas comuns do Windows."""
    exe = name + (".exe" if os.name == "nt" else "")
    if near:
        base = near if os.path.isdir(near) else os.path.dirname(near)
        for candidate in (os.path.join(base, exe), os.path.join(base, name)):
            if base and os.path.isfile(candidate):
                return candidate
        if os.path.isfile(near) and os.path.basename(near).lower().startswith(name):
            return near
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        for folder in WINDOWS_DIRS:
            candidate = os.path.join(folder, exe)
            if os.path.isfile(candidate):
                return candidate
    return ""


def parse_clamscan_line(line: str):
    """Interpreta uma linha de saída do clamscan. Retorna (caminho, estado, detalhe) ou None."""
    line = line.rstrip("\r\n")
    if line.endswith(": OK"):
        return line[:-4], "ok", ""
    if line.endswith(" FOUND"):
        path, sep, signature = line[:-6].rpartition(": ")
        if sep:
            return path, "found", signature
    if line.endswith(" ERROR"):
        path, sep, message = line[:-6].rpartition(": ")
        if sep:
            return path, "error", message
    return None


class ClamAV:
    def __init__(self, clamscan: str = "", host: str = "127.0.0.1", port: int = 3310,
                 socket_path: str = "", timeout: float = 30.0):
        self.clamscan_hint = clamscan
        self.host = host or "127.0.0.1"
        self.port = int(port or 3310)
        self.socket_path = socket_path
        self.timeout = timeout
        self.mode = ""
        self._endpoint: Optional[tuple] = None
        self._clamscan_bin = ""

    @classmethod
    def from_settings(cls, settings) -> "ClamAV":
        return cls(settings.clamscan_path, settings.clamd_host, settings.clamd_port,
                   settings.clamd_socket)

    # ------------------------------------------------------------------
    # Detecção
    # ------------------------------------------------------------------
    def detect(self) -> ClamStatus:
        self.mode, self._endpoint, self._clamscan_bin = "", None, ""
        status = ClamStatus(checked=True, message="ClamAV não encontrado. Instale-o para ampliar a detecção.")

        endpoint = self._find_clamd()
        if endpoint:
            self._endpoint = endpoint
            try:
                raw = self._command(b"zVERSION\0", endpoint, 3)
            except (OSError, ClamError):
                raw = ""
            self.mode = "clamd"
            status.available, status.mode = True, "clamd"
            status.version, status.db_version = parse_version(raw)
            status.version = status.version or "ClamAV"
            return status

        binary = find_binary("clamscan", self.clamscan_hint)
        if binary:
            try:
                proc = subprocess.run([binary, "--version"], capture_output=True, text=True,
                                      timeout=20, creationflags=NO_WINDOW)
            except (OSError, subprocess.SubprocessError) as exc:
                status.message = f"Não foi possível executar o clamscan: {exc}"
                return status
            version, db = parse_version(proc.stdout)
            status.version = version
            if not db:
                status.message = ("ClamAV encontrado, mas sem base de vírus. "
                                  "Use “Atualizar base ClamAV” (freshclam).")
                return status
            self._clamscan_bin = binary
            self.mode = "clamscan"
            status.available, status.mode, status.db_version = True, "clamscan", db
        return status

    def _find_clamd(self) -> Optional[tuple]:
        candidates: list[tuple] = []
        if self.socket_path:
            candidates.append(("unix", self.socket_path))
        if os.name != "nt" and hasattr(socket, "AF_UNIX"):
            candidates += [("unix", p) for p in UNIX_SOCKETS if os.path.exists(p)]
        candidates.append(("tcp", (self.host, self.port)))
        for endpoint in candidates:
            if self._ping(endpoint):
                return endpoint
        return None

    # ------------------------------------------------------------------
    # Protocolo do clamd
    # ------------------------------------------------------------------
    @staticmethod
    def _connect(endpoint: tuple, timeout: float) -> socket.socket:
        kind, target = endpoint
        if kind == "unix":
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(target)
            return sock
        return socket.create_connection(target, timeout=timeout)

    @staticmethod
    def _read_reply(sock: socket.socket) -> str:
        data = b""
        while b"\0" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", "replace").strip("\0\r\n ")

    def _command(self, command: bytes, endpoint: Optional[tuple] = None, timeout: float = 5) -> str:
        sock = self._connect(endpoint or self._endpoint, timeout)
        try:
            sock.sendall(command)
            return self._read_reply(sock)
        finally:
            sock.close()

    def _ping(self, endpoint: tuple) -> bool:
        try:
            return self._command(b"zPING\0", endpoint, 1.5) == "PONG"
        except (OSError, ClamError):
            return False

    def _instream(self, path: str) -> Optional[str]:
        """Envia um arquivo ao clamd. Retorna o nome da assinatura ou None se limpo."""
        try:                                   # abre o arquivo ANTES de falar com o daemon
            fh = open(path, "rb")
        except OSError as exc:
            raise ClamFileError(f"Não foi possível ler o arquivo: {exc}") from exc
        with fh:
            try:
                sock = self._connect(self._endpoint, self.timeout)
            except OSError as exc:
                raise ClamError(f"Não foi possível conectar ao clamd: {exc}") from exc
            try:
                try:
                    sock.sendall(b"zINSTREAM\0")
                    while True:
                        chunk = fh.read(1024 * 1024)
                        if not chunk:
                            break
                        sock.sendall(struct.pack("!I", len(chunk)) + chunk)
                    sock.sendall(struct.pack("!I", 0))
                except (BrokenPipeError, ConnectionResetError):
                    pass                       # o clamd encerrou antes (ex.: limite de tamanho)
                except OSError as exc:
                    if isinstance(exc, (socket.timeout, ConnectionError)):
                        raise ClamError(f"Falha de comunicação com o clamd: {exc}") from exc
                    raise ClamFileError(f"Não foi possível ler o arquivo: {exc}") from exc
                try:
                    reply = self._read_reply(sock)
                except OSError as exc:
                    raise ClamError(f"Falha de comunicação com o clamd: {exc}") from exc
            finally:
                sock.close()
        if reply.endswith(" FOUND"):
            return reply[:-6].rpartition(": ")[2]
        if reply.endswith("OK"):
            return None
        raise ClamFileError(reply or "Resposta vazia do clamd")

    # ------------------------------------------------------------------
    # Verificação
    # ------------------------------------------------------------------
    def scan_file(self, path: str) -> Optional[str]:
        if self.mode == "clamd":
            return self._instream(path)
        if self.mode == "clamscan":
            return self._clamscan_batch([path]).get(path)
        raise ClamError("ClamAV indisponível.")

    def scan_files(self, paths: Iterable[str], on_progress: Optional[ProgressFn] = None,
                   cancel: Optional[threading.Event] = None) -> dict[str, str]:
        """Verifica vários arquivos. Retorna {caminho: assinatura} apenas dos infectados."""
        paths = list(paths)
        if not paths:
            return {}
        if self.mode == "clamd":
            return self._clamd_many(paths, on_progress, cancel)
        if self.mode == "clamscan":
            return self._clamscan_batch(paths, on_progress, cancel)
        raise ClamError("ClamAV indisponível.")

    def _clamd_many(self, paths, on_progress, cancel) -> dict[str, str]:
        hits: dict[str, str] = {}
        total, last = len(paths), 0.0
        for i, path in enumerate(paths, 1):
            if cancel is not None and cancel.is_set():
                break
            try:
                signature = self._instream(path)
                if signature:
                    hits[path] = signature
            except ClamFileError:
                pass
            now = time.monotonic()
            if on_progress and (now - last > 0.1 or i == total):
                on_progress(i, total, path)
                last = now
        return hits

    def _clamscan_batch(self, paths, on_progress=None, cancel=None) -> dict[str, str]:
        total = len(paths)
        by_norm = {os.path.normcase(os.path.abspath(p)): p for p in paths}
        by_name: dict[str, list] = {}
        for p in paths:
            by_name.setdefault(os.path.basename(p).lower(), []).append(p)

        handle, list_file = tempfile.mkstemp(suffix=".lst", prefix="aegis-clam-")
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            fh.write("\n".join(paths))
        hits: dict[str, str] = {}
        tail: list[str] = []
        done, last = 0, 0.0
        try:
            with subprocess.Popen(
                    [self._clamscan_bin, "--no-summary", "--stdout", "-f", list_file],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    encoding=locale.getpreferredencoding(False), errors="replace",
                    creationflags=NO_WINDOW) as proc:

                def watchdog():
                    while proc.poll() is None:
                        if cancel is not None and cancel.is_set():
                            proc.terminate()
                            return
                        time.sleep(0.2)
                threading.Thread(target=watchdog, daemon=True).start()

                for line in proc.stdout:
                    parsed = parse_clamscan_line(line)
                    if parsed is None:
                        tail = (tail + [line.strip()])[-15:]
                        continue
                    path, state, detail = parsed
                    done += 1
                    original = by_norm.get(os.path.normcase(os.path.abspath(path)))
                    if original is None:                  # codificação do console pode alterar o nome
                        options = by_name.get(os.path.basename(path).lower(), [])
                        original = options[0] if len(options) == 1 else None
                    if state == "found" and original is not None:
                        hits[original] = detail
                    now = time.monotonic()
                    if on_progress and (now - last > 0.1 or done >= total):
                        on_progress(min(done, total), total, original or path)
                        last = now
                code = proc.wait()
        except OSError as exc:
            raise ClamError(f"Não foi possível executar o clamscan: {exc}") from exc
        finally:
            try:
                os.remove(list_file)
            except OSError:
                pass
        cancelled = cancel is not None and cancel.is_set()
        if code not in (0, 1) and done == 0 and not cancelled:
            raise ClamError("O clamscan falhou: " + (" | ".join(tail[-3:]) or f"código {code}"))
        return hits

    # ------------------------------------------------------------------
    # Manutenção
    # ------------------------------------------------------------------
    def update_database(self, timeout: int = 900) -> tuple[bool, str]:
        fresh = find_binary("freshclam", self._clamscan_bin or self.clamscan_hint)
        if not fresh:
            return False, "freshclam não encontrado. Instale o ClamAV completo (inclui o freshclam)."
        try:
            proc = subprocess.run([fresh], capture_output=True, text=True, timeout=timeout,
                                  creationflags=NO_WINDOW)
        except subprocess.TimeoutExpired:
            return False, "A atualização demorou demais e foi interrompida."
        except OSError as exc:
            return False, f"Não foi possível executar o freshclam: {exc}"
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        message = "\n".join(output.splitlines()[-6:])
        if proc.returncode != 0:
            hint = "\n\nSe o erro for de permissão, execute como administrador (Windows) ou com sudo (Linux)."
            return False, (message or f"freshclam terminou com código {proc.returncode}.") + hint
        if self.mode == "clamd" and self._endpoint:
            try:
                self._command(b"zRELOAD\0", timeout=10)      # o daemon relê a base nova
            except (OSError, ClamError):
                pass
        return True, message or "Base de vírus atualizada."

    def self_test(self) -> tuple[bool, str]:
        """Passa o arquivo EICAR SOMENTE pelo ClamAV (prova que ele está funcionando)."""
        if not self.mode:
            return False, "ClamAV indisponível."
        from engine import EICAR_BYTES              # import tardio: evita ciclo entre módulos
        with tempfile.TemporaryDirectory(prefix="aegis-selftest-") as folder:
            path = os.path.join(folder, "clamav_selftest.txt")
            with open(path, "wb") as fh:
                fh.write(EICAR_BYTES)
            try:
                signature = self.scan_file(path)
            except ClamError as exc:
                return False, str(exc)
        if signature:
            return True, f"O ClamAV detectou o arquivo de teste como “{signature}”."
        return False, ("O ClamAV não detectou o arquivo de teste. Verifique a base de vírus "
                       "(freshclam) e se outro antivírus não apagou o arquivo antes.")
