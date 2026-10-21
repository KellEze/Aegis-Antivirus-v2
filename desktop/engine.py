"""Motor de detecção do AEGIS.

Combina três camadas:
  1. Assinaturas de hash (SHA-256 de arquivos conhecidos);
  2. Assinaturas de padrão (sequências de bytes dentro do arquivo);
  3. Heurística (sinais de comportamento suspeito, com pontuação).

Este módulo não depende de interface gráfica nem de rede.
"""
from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import stat
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

import config
from clam import ClamAV, ClamError

# --------------------------------------------------------------------------
# Arquivos de teste inofensivos
# --------------------------------------------------------------------------
# O EICAR é a sequência padrão da indústria para testar antivírus. É inofensiva.
# A string é montada em partes para que o próprio código-fonte não seja
# confundido com um arquivo de teste por outros antivírus.
EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    + b"$H+H*"
)
EICAR_SHA256 = hashlib.sha256(EICAR_BYTES).hexdigest()

# Assinatura extra, entregue apenas pelo servidor: serve para demonstrar que a
# atualização de assinaturas realmente muda o que o aplicativo detecta.
AEGIS_TEST_BYTES = b"AEGIS-STANDARD-TEST-SIGNATURE-" + b"4f9c1e7a-NOT-MALWARE"

HEAD_BYTES = 4 * 1024 * 1024        # trecho inicial lido para padrões/heurística
DEFAULT_MAX_SIZE = 200 * 1024 * 1024  # arquivos maiores são ignorados

EXCLUDED_DIRS = {
    "$recycle.bin", "system volume information", "windows", "program files",
    "program files (x86)", "node_modules", ".git", "proc", "sys", "dev",
}


# --------------------------------------------------------------------------
# Assinaturas
# --------------------------------------------------------------------------
class Signatures:
    def __init__(self, version: int = 0, hashes: Optional[dict] = None,
                 patterns: Optional[list] = None):
        self.version = version
        self.hashes: dict[str, str] = dict(hashes or {})
        self.patterns: list[tuple[str, bytes]] = list(patterns or [])

    @classmethod
    def builtin(cls) -> "Signatures":
        return cls(0, {EICAR_SHA256: "EICAR-Test-File"},
                   [("EICAR-Test-File", EICAR_BYTES)])

    @classmethod
    def from_server(cls, data: dict) -> "Signatures":
        sig = cls.builtin()
        sig.version = int(data.get("versao", 0))
        for h, name in (data.get("hashes") or {}).items():
            sig.hashes[str(h).lower()] = str(name)
        for item in data.get("padroes") or []:
            try:
                raw = base64.b64decode(item["b64"])
            except (KeyError, ValueError):
                continue
            if raw:
                sig.patterns.append((str(item.get("nome", "Padrao-Desconhecido")), raw))
        return sig

    @classmethod
    def load_cached(cls) -> "Signatures":
        data = config.load_json(config.SIGNATURES_FILE)
        if isinstance(data, dict):
            try:
                return cls.from_server(data)
            except Exception:
                pass
        return cls.builtin()

    def save_cache(self, raw: dict) -> None:
        config.save_json(config.SIGNATURES_FILE, raw)

    @property
    def total(self) -> int:
        return len(self.hashes) + len(self.patterns)


# --------------------------------------------------------------------------
# Resultados
# --------------------------------------------------------------------------
@dataclass
class ScanResult:
    path: str
    verdict: str = "clean"          # clean | suspicious | malicious | error | skipped
    threat: str = ""
    score: int = 0
    reasons: list = field(default_factory=list)
    sha256: str = ""
    size: int = 0
    action: str = ""                # "", "quarentena", "ignorado", "falha: ..."
    quarantine_id: str = ""
    source: str = "AEGIS"           # quem detectou: AEGIS ou ClamAV

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def reason_text(self) -> str:
        return "; ".join(self.reasons)


@dataclass
class ScanSummary:
    scanned: int = 0
    malicious: int = 0
    suspicious: int = 0
    errors: int = 0
    skipped: int = 0
    cancelled: bool = False
    clam_used: bool = False
    clam_error: str = ""
    results: list = field(default_factory=list)   # apenas suspeitos e maliciosos

    @property
    def threats(self) -> int:
        return self.malicious + self.suspicious


# --------------------------------------------------------------------------
# Heurística
# --------------------------------------------------------------------------
PE_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".drv", ".com", ".efi", ".pif"}
EXEC_EXTENSIONS = PE_EXTENSIONS | {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                                   ".wsf", ".hta", ".ps1", ".lnk", ".msi", ".jar"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"}
DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg",
                    ".jpeg", ".png", ".gif", ".txt", ".mp3", ".mp4", ".zip", ".rar"}

DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)\s*\.(exe|scr|bat|cmd|com|pif|js|vbs|ps1|hta|lnk)$",
    re.IGNORECASE,
)

# (expressão, peso, descrição)
SCRIPT_INDICATORS = [
    (rb"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", 40, "PowerShell com comando codificado em Base64"),
    (rb"frombase64string", 15, "Decodificação Base64 dentro de script"),
    (rb"invoke-expression|\biex\b", 20, "Execução dinâmica de código"),
    (rb"downloadstring|downloadfile|invoke-webrequest|start-bitstransfer", 20, "Download de conteúdo remoto pelo script"),
    (rb"certutil(\.exe)?\s+.*-urlcache", 35, "Download disfarçado via certutil"),
    (rb"bitsadmin\s+/transfer", 30, "Download via bitsadmin"),
    (rb"vssadmin\s+delete\s+shadows", 70, "Apaga cópias de sombra (comportamento típico de ransomware)"),
    (rb"set-mppreference\s+-disablerealtimemonitoring", 50, "Tenta desativar a proteção do Windows Defender"),
    (rb"netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off", 30, "Tenta desligar o firewall"),
    (rb"reg\s+add\s+.*\\currentversion\\run", 25, "Cria persistência no registro (Run)"),
    (rb"schtasks\s+/create", 15, "Cria tarefa agendada"),
    (rb"wscript\.shell", 10, "Usa WScript.Shell para executar comandos"),
    (rb"powershell.*-w(indowstyle)?\s+hidden", 20, "Executa PowerShell com janela oculta"),
]
_COMPILED_INDICATORS = [(re.compile(p, re.IGNORECASE), w, d) for p, w, d in SCRIPT_INDICATORS]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def heuristic_score(path: str, head: bytes) -> tuple[int, list[str]]:
    """Retorna (pontuação, motivos). Pontuação >= 35 suspeito; >= 70 malicioso."""
    score = 0
    reasons: list[str] = []
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    lower_path = path.lower().replace("\\", "/")

    if DOUBLE_EXT.search(name):
        score += 60
        reasons.append("Dupla extensão enganosa (documento que é na verdade executável)")

    is_pe = head[:2] == b"MZ"
    is_elf = head[:4] == b"\x7fELF"
    if (is_pe or is_elf) and ext in DECOY_EXTENSIONS:
        score += 50
        reasons.append("Executável disfarçado de documento, imagem ou arquivo comum")

    if is_pe and ext in PE_EXTENSIONS:
        if "/temp/" in lower_path or "/tmp/" in lower_path:
            score += 10
            reasons.append("Executável em pasta temporária")
        if shannon_entropy(head[:1024 * 1024]) > 7.4:
            score += 20
            reasons.append("Executável compactado ou ofuscado (entropia muito alta)")

    if name.lower() == "autorun.inf":
        score += 30
        reasons.append("autorun.inf pode propagar programas por mídia removível")

    if ext in SCRIPT_EXTENSIONS:
        text = head[:512 * 1024]
        for regex, weight, description in _COMPILED_INDICATORS:
            if regex.search(text):
                score += weight
                reasons.append(description)

    return score, reasons


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------
ProgressFn = Callable[[int, int, str], None]
ResultFn = Callable[[ScanResult], None]


class Scanner:
    def __init__(self, signatures: Signatures, max_size: int = DEFAULT_MAX_SIZE,
                 skip_dirs: Iterable[str] = (), clam: Optional[ClamAV] = None):
        self.signatures = signatures
        self.clam = clam
        self.max_size = max_size
        self.skip_dirs = [os.path.abspath(d) for d in skip_dirs]

    # -- arquivo único -----------------------------------------------------
    def scan_file(self, path: str, clam_hit: Optional[str] = None,
                  clam_checked: bool = False) -> ScanResult:
        """Verifica um arquivo. `clam_hit`/`clam_checked` vêm da fase em lote do ClamAV;
        em arquivos avulsos (tempo real) o ClamAV só é consultado se estiver em modo clamd."""
        path = str(path)
        try:
            st = os.stat(path)
        except OSError as exc:
            return ScanResult(path, "error", reasons=[f"Não foi possível acessar: {exc.strerror}"])
        if not stat.S_ISREG(st.st_mode):
            return ScanResult(path, "skipped", reasons=["Não é um arquivo comum"])
        if st.st_size > self.max_size:
            return ScanResult(path, "skipped", size=st.st_size,
                              reasons=["Arquivo maior que o limite de verificação"])

        digest = hashlib.sha256()
        head = bytearray()
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    if len(head) < HEAD_BYTES:
                        head += chunk[: HEAD_BYTES - len(head)]
        except OSError as exc:
            return ScanResult(path, "error", size=st.st_size,
                              reasons=[f"Não foi possível ler: {exc.strerror}"])

        sha = digest.hexdigest()
        head_b = bytes(head)
        result = ScanResult(path, "clean", sha256=sha, size=st.st_size)

        if (clam_hit is None and not clam_checked and self.clam is not None
                and self.clam.mode == "clamd"):
            try:
                clam_hit = self.clam.scan_file(path)
            except ClamError:
                clam_hit = None
        if clam_hit:
            result.verdict, result.threat, result.score = "malicious", clam_hit, 100
            result.reasons = ["Detectado pelo ClamAV"]
            result.source = "ClamAV"
            return result

        known = self.signatures.hashes.get(sha)
        if known:
            result.verdict, result.threat, result.score = "malicious", known, 100
            result.reasons = ["Assinatura SHA-256 conhecida"]
            return result

        for name, pattern in self.signatures.patterns:
            if pattern in head_b:
                result.verdict, result.threat, result.score = "malicious", name, 100
                result.reasons = ["Padrão de assinatura encontrado no conteúdo"]
                return result

        score, reasons = heuristic_score(path, head_b)
        result.score, result.reasons = score, reasons
        if score >= 70:
            result.verdict, result.threat = "malicious", "AEGIS.Heur.Alto"
        elif score >= 35:
            result.verdict, result.threat = "suspicious", "AEGIS.Heur.Medio"
        return result

    def _eligible(self, path: str) -> bool:
        try:
            st = os.stat(path)
        except OSError:
            return False
        return stat.S_ISREG(st.st_mode) and st.st_size <= self.max_size

    # -- varredura de pastas -----------------------------------------------
    def iter_files(self, paths: Iterable[str], cancel: Optional[threading.Event] = None):
        for root_path in paths:
            if cancel is not None and cancel.is_set():
                return
            if os.path.isfile(root_path):
                yield root_path
                continue
            for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
                if cancel is not None and cancel.is_set():
                    return
                dirnames[:] = [
                    d for d in dirnames
                    if d.lower() not in EXCLUDED_DIRS
                    and os.path.abspath(os.path.join(dirpath, d)) not in self.skip_dirs
                ]
                for fname in filenames:
                    yield os.path.join(dirpath, fname)

    def scan_paths(self, paths: Iterable[str],
                   on_progress: Optional[ProgressFn] = None,
                   on_result: Optional[ResultFn] = None,
                   cancel: Optional[threading.Event] = None,
                   on_phase: Optional[Callable[[str], None]] = None) -> ScanSummary:
        summary = ScanSummary()
        files: list[str] = []
        last_emit = 0.0

        for f in self.iter_files(paths, cancel):
            files.append(f)
            now = time.monotonic()
            if on_progress and now - last_emit > 0.15:
                on_progress(len(files), 0, "")      # total 0 = ainda listando
                last_emit = now

        if cancel is not None and cancel.is_set():
            summary.cancelled = True          # cancelado ainda na fase de listagem
            return summary

        hits: dict[str, str] = {}
        if self.clam is not None and self.clam.mode and files:
            if on_phase:
                on_phase("ClamAV")
            try:
                hits = self.clam.scan_files([f for f in files if self._eligible(f)],
                                            on_progress=on_progress, cancel=cancel)
                summary.clam_used = True
            except ClamError as exc:                   # segue só com o motor do AEGIS
                summary.clam_error = str(exc)
            if cancel is not None and cancel.is_set():
                summary.cancelled = True
                return summary
            if on_phase:
                on_phase("AEGIS")

        total = len(files)
        for i, f in enumerate(files, 1):
            if cancel is not None and cancel.is_set():
                summary.cancelled = True
                break
            res = self.scan_file(f, clam_hit=hits.get(f), clam_checked=True)
            if res.verdict == "error":
                summary.errors += 1
            elif res.verdict == "skipped":
                summary.skipped += 1
            else:
                summary.scanned += 1
                if res.verdict == "malicious":
                    summary.malicious += 1
                elif res.verdict == "suspicious":
                    summary.suspicious += 1
            if res.verdict in ("malicious", "suspicious"):
                if on_result:
                    on_result(res)
                summary.results.append(res)
            now = time.monotonic()
            if on_progress and (now - last_emit > 0.1 or i == total):
                on_progress(i, total, f)
                last_emit = now
        return summary


def write_test_files(folder: str) -> list[str]:
    """Cria os arquivos de teste (inofensivos) na pasta indicada."""
    os.makedirs(folder, exist_ok=True)
    eicar = os.path.join(folder, "eicar_test.txt")
    aegis = os.path.join(folder, "aegis_update_test.txt")
    with open(eicar, "wb") as fh:
        fh.write(EICAR_BYTES)
    with open(aegis, "wb") as fh:
        fh.write(AEGIS_TEST_BYTES)
    return [eicar, aegis]
