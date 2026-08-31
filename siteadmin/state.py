"""Атомарное локальное состояние и outbox агента."""

import json
import os
import secrets
import time
from pathlib import Path


class State:
    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory / "state.json"
        self.outbox = directory / "outbox"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.outbox.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)

    def read(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}

    def update(self, **values) -> dict:
        data = self.read()
        data.update(values)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)
        return data

    def enqueue(self, kind: str, payload: dict) -> Path:
        name = "%020d-%s.json" % (time.time_ns(), secrets.token_hex(4))
        path = self.outbox / name
        path.write_text(json.dumps({"kind": kind, "payload": payload}, ensure_ascii=False), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def pending(self) -> list[Path]:
        return sorted(self.outbox.glob("*.json"))
