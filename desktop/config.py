"""Configuração, caminhos e persistência local do aplicativo AEGIS."""
from __future__ import annotations

import json
import os
import platform
import sys
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

APP_NAME = "AEGIS"
APP_VERSION = "1.0.0"

# Pasta onde estão os arquivos do aplicativo (funciona também empacotado com PyInstaller).
BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
ASSETS_DIR = BASE_DIR / "assets"

# Pasta de dados do usuário (assinaturas, quarentena, sessão, configurações).
DATA_DIR = Path(os.environ.get("AEGIS_HOME", Path.home() / ".aegis"))
SETTINGS_FILE = DATA_DIR / "settings.json"
SESSION_FILE = DATA_DIR / "session.json"
SIGNATURES_FILE = DATA_DIR / "signatures.json"
DEVICE_FILE = DATA_DIR / "device.json"
QUARANTINE_DIR = DATA_DIR / "quarantine"


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save_json(path: Path, data) -> None:
    """Grava de forma atômica para não corromper o arquivo se o app fechar no meio."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def default_server_url() -> str:
    bundled = load_json(BASE_DIR / "config.json", {}) or {}
    return str(bundled.get("server_url") or "http://127.0.0.1:5000").rstrip("/")


def downloads_dir() -> Path:
    return Path.home() / "Downloads"


def quick_scan_paths() -> list[str]:
    """Locais onde as ameaças mais costumam aparecer."""
    candidates = [downloads_dir(), Path.home() / "Desktop", Path(tempfile.gettempdir())]
    return [str(p) for p in candidates if p.is_dir()]


def device_id() -> str:
    data = load_json(DEVICE_FILE, {}) or {}
    if not data.get("id"):
        data = {"id": uuid.uuid4().hex}
        save_json(DEVICE_FILE, data)
    return data["id"]


def device_name() -> str:
    return platform.node() or "Meu computador"


def os_name() -> str:
    return f"{platform.system()} {platform.release()}".strip()


@dataclass
class Settings:
    server_url: str = ""
    auto_quarantine: bool = True
    realtime: bool = False
    watch_folders: list = field(default_factory=list)
    last_scan: str = ""
    last_scan_info: str = ""
    clamav_enabled: bool = True
    clamscan_path: str = ""
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_socket: str = ""

    @classmethod
    def load(cls) -> "Settings":
        raw = load_json(SETTINGS_FILE, {}) or {}
        known = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        s = cls(**known)
        if not s.server_url:
            s.server_url = default_server_url()
        if not s.watch_folders:
            s.watch_folders = [str(downloads_dir())]
        return s

    def save(self) -> None:
        save_json(SETTINGS_FILE, asdict(self))
