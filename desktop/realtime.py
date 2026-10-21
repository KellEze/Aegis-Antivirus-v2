"""Proteção em tempo real por monitoramento de pastas.

Usa varredura periódica (sem dependências externas): a cada poucos segundos
compara um "retrato" das pastas e verifica arquivos novos ou alterados. Um
arquivo só é verificado depois de ficar estável por dois ciclos seguidos, para
não pegar downloads pela metade.
"""
from __future__ import annotations

import os
import threading
from typing import Callable, Iterable

PARTIAL_SUFFIXES = (".crdownload", ".part", ".tmp", ".partial", ".download", ".opdownload")
MAX_FILES = 20000


class Watcher(threading.Thread):
    def __init__(self, folders: Iterable[str], on_file: Callable[[str], None],
                 interval: float = 3.0, depth: int = 3):
        super().__init__(daemon=True, name="aegis-realtime")
        self.folders = [os.path.abspath(f) for f in folders]
        self.on_file = on_file
        self.interval = interval
        self.depth = depth
        self._stop_event = threading.Event()
        self._known: dict[str, tuple] = {}
        self._pending: dict[str, tuple] = {}

    def stop(self) -> None:
        self._stop_event.set()

    def _snapshot(self) -> dict[str, tuple]:
        snap: dict[str, tuple] = {}
        for folder in self.folders:
            base_depth = folder.rstrip(os.sep).count(os.sep)
            for dirpath, dirnames, filenames in os.walk(folder):
                if dirpath.count(os.sep) - base_depth >= self.depth:
                    dirnames[:] = []
                for fname in filenames:
                    full = os.path.join(dirpath, fname)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    snap[full] = (st.st_mtime_ns, st.st_size)
                    if len(snap) >= MAX_FILES:
                        return snap
        return snap

    def poll_once(self) -> list[str]:
        """Uma rodada de verificação. Retorna os arquivos enviados ao callback."""
        current = self._snapshot()
        fired: list[str] = []
        for path, sig in current.items():
            if self._known.get(path) == sig:
                continue
            if self._pending.get(path) == sig:        # estável por dois ciclos
                self._known[path] = sig
                self._pending.pop(path, None)
                if not path.lower().endswith(PARTIAL_SUFFIXES):
                    fired.append(path)
            else:
                self._pending[path] = sig
        for path in list(self._pending):
            if path not in current:
                del self._pending[path]
        for path in list(self._known):
            if path not in current:
                del self._known[path]
        for path in fired:
            try:
                self.on_file(path)
            except Exception:
                pass
        return fired

    def run(self) -> None:
        self._known = self._snapshot()       # o que já existia não é reverificado
        while not self._stop_event.wait(self.interval):
            self.poll_once()
