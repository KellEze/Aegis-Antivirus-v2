"""Quarentena: isola arquivos perigosos de forma reversível.

O conteúdo é codificado (XOR) e salvo com extensão .qr, de modo que não possa
ser executado nem aberto acidentalmente. Os metadados ficam em index.json.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import config

_KEY = 0xA7
_TABLE = bytes((b ^ _KEY) for b in range(256))
_CHUNK = 1024 * 1024


class QuarantineError(Exception):
    pass


class Quarantine:
    def __init__(self, base: Optional[Path] = None):
        self.dir = Path(base) if base else config.QUARANTINE_DIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.dir / "index.json"

    # -- índice ------------------------------------------------------------
    def _load(self) -> list[dict]:
        data = config.load_json(self.index_file, [])
        return data if isinstance(data, list) else []

    def _save(self, items: list[dict]) -> None:
        config.save_json(self.index_file, items)

    def list(self) -> list[dict]:
        return sorted(self._load(), key=lambda e: e.get("data", ""), reverse=True)

    def _find(self, qid: str) -> dict:
        for item in self._load():
            if item["id"] == qid:
                return item
        raise QuarantineError("Item não encontrado na quarentena.")

    # -- operações ---------------------------------------------------------
    def add(self, path: str, threat: str, reasons: Optional[list] = None,
            sha256: str = "") -> dict:
        src = Path(path)
        if not src.is_file():
            raise QuarantineError("O arquivo não existe mais.")
        qid = uuid.uuid4().hex
        dest = self.dir / f"{qid}.qr"
        try:
            with open(src, "rb") as fin, open(dest, "wb") as fout:
                while True:
                    chunk = fin.read(_CHUNK)
                    if not chunk:
                        break
                    fout.write(chunk.translate(_TABLE))
        except OSError as exc:
            dest.unlink(missing_ok=True)
            raise QuarantineError(f"Não foi possível copiar o arquivo: {exc.strerror}") from exc

        try:
            os.remove(src)
        except OSError as exc:
            # Se não der para remover o original (em uso/sem permissão), desfaz a cópia.
            dest.unlink(missing_ok=True)
            raise QuarantineError(
                f"Não foi possível remover o original ({exc.strerror}). Feche o programa que o usa."
            ) from exc

        entry = {
            "id": qid,
            "caminho": str(src),
            "nome": src.name,
            "ameaca": threat,
            "motivos": list(reasons or []),
            "sha256": sha256,
            "data": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        items = self._load()
        items.append(entry)
        self._save(items)
        return entry

    def restore(self, qid: str, dest: Optional[str] = None) -> str:
        entry = self._find(qid)
        src = self.dir / f"{qid}.qr"
        if not src.is_file():
            raise QuarantineError("O arquivo isolado não foi encontrado em disco.")
        target = Path(dest or entry["caminho"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target = target.with_name(f"{target.stem} (restaurado){target.suffix}")
        with open(src, "rb") as fin, open(target, "wb") as fout:
            while True:
                chunk = fin.read(_CHUNK)
                if not chunk:
                    break
                fout.write(chunk.translate(_TABLE))
        src.unlink(missing_ok=True)
        self._save([e for e in self._load() if e["id"] != qid])
        return str(target)

    def delete(self, qid: str) -> None:
        self._find(qid)
        (self.dir / f"{qid}.qr").unlink(missing_ok=True)
        self._save([e for e in self._load() if e["id"] != qid])
