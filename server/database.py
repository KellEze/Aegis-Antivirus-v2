"""Banco de dados SQLite do site AEGIS."""
from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"

_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # sem caracteres ambíguos (0/O, 1/I)


def db_path() -> Path:
    return Path(os.environ.get("AEGIS_DB", INSTANCE_DIR / "aegis.db"))


def get_db_connection() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db():
    """Abre uma conexão, confirma ao sair com sucesso e desfaz em caso de erro."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_license_key() -> str:
    groups = ["".join(secrets.choice(_KEY_ALPHABET) for _ in range(4)) for _ in range(4)]
    return "AEGIS-" + "-".join(groups)


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL,
    plano TEXT NOT NULL DEFAULT 'essencial',
    plano_expira_em TEXT,
    license_key TEXT NOT NULL UNIQUE,
    criado_em TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    nome TEXT NOT NULL,
    sistema TEXT,
    ultimo_acesso TEXT NOT NULL,
    criado_em TEXT NOT NULL,
    UNIQUE (user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS compras (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plano TEXT NOT NULL,
    valor_centavos INTEGER NOT NULL,
    bandeira TEXT,
    cartao_final TEXT,
    status TEXT NOT NULL DEFAULT 'pago',
    criado_em TEXT NOT NULL,
    expira_em TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_row_id INTEGER,
    tipo TEXT NOT NULL,
    arquivos INTEGER NOT NULL DEFAULT 0,
    ameacas INTEGER NOT NULL DEFAULT 0,
    duracao REAL NOT NULL DEFAULT 0,
    criado_em TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    arquivo TEXT NOT NULL,
    ameaca TEXT NOT NULL,
    acao TEXT NOT NULL,
    criado_em TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_user ON scans (user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_detections_user ON detections (user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_compras_user ON compras (user_id, id DESC);
"""


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
