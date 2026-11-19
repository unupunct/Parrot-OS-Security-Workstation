"""Append-only, hash-chained audit log (JSON lines) for every operation and policy decision."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._last = self._read_last_hash()
        if not path.exists():
            path.touch()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    last = json.loads(line)["hash"]
                except (json.JSONDecodeError, KeyError):
                    pass
        return last

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields, "prev": self._last}
            body = json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str)
            entry["hash"] = hashlib.sha256(body.encode()).hexdigest()
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str) + "\n")
            self._last = entry["hash"]
            return entry

    def verify(self) -> tuple[bool, int]:
        """Return (chain intact, entries checked)."""
        prev, n = GENESIS, 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                e = json.loads(line)
                claimed = e.pop("hash", None)
                if e.get("prev") != prev:
                    return False, n
                body = json.dumps(e, sort_keys=True, ensure_ascii=False, default=str)
                if hashlib.sha256(body.encode()).hexdigest() != claimed:
                    return False, n
                prev, n = claimed, n + 1
        return True, n

    def tail(self, count: int = 50) -> list[dict[str, Any]]:
        lines = self.path.read_text(encoding="utf-8").splitlines()[-count:]
        return [json.loads(l) for l in lines if l.strip()]
