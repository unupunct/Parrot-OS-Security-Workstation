"""Backup and recovery of the application database."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..database.repository import Database


@dataclass(frozen=True)
class BackupInfo:
    path: Path
    size: int
    created: datetime


class BackupError(RuntimeError):
    pass


class BackupService:
    def __init__(self, db: Database, backup_dir: Path, keep: int = 20) -> None:
        self._db = db
        self._dir = backup_dir
        self._keep = keep

    def create(self, label: str = "manual") -> Path:
        if self._db.path is None:
            raise BackupError("in-memory database cannot be backed up")
        self._dir.mkdir(parents=True, exist_ok=True)
        safe = "".join(c for c in label if c.isalnum() or c in "-_")[:20] or "backup"
        dest = self._dir / f"wifi-center-{datetime.now():%Y%m%d-%H%M%S-%f}-{safe}.db"
        self._db.backup_to(dest)
        self._prune()
        return dest

    def list(self) -> list[BackupInfo]:
        items = [
            BackupInfo(p, p.stat().st_size, datetime.fromtimestamp(p.stat().st_mtime))
            for p in self._dir.glob("wifi-center-*.db")
        ]
        return sorted(items, key=lambda b: b.path.name, reverse=True)

    @staticmethod
    def verify(path: Path) -> bool:
        try:
            conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
            try:
                return conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    def stage_restore(self, backup: Path) -> None:
        """Validate a backup and stage it; it replaces the live DB on next start."""
        if self._db.path is None:
            raise BackupError("in-memory database cannot be restored")
        backup = backup.resolve()
        if backup.parent != self._dir.resolve():
            raise BackupError("backup must be inside the backup directory")
        if not self.verify(backup):
            raise BackupError("backup failed integrity check")
        self.create("pre-restore")
        pending = self._db.path.with_suffix(".restore-pending")
        pending.write_bytes(backup.read_bytes())

    def _prune(self) -> None:
        for old in self.list()[self._keep:]:
            old.path.unlink(missing_ok=True)
