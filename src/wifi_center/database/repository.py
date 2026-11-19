"""SQLite access: connection management, transactions and versioned migrations."""
from __future__ import annotations

import logging
import re
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

log = logging.getLogger(__name__)
MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_NAME_RE = re.compile(r"^(\d{3})_[a-z0-9_]+\.sql$")


class MigrationError(RuntimeError):
    pass


def discover_migrations(directory: Path = MIGRATIONS_DIR) -> list[tuple[int, str, Path]]:
    found = []
    for p in sorted(directory.glob("*.sql")):
        m = _NAME_RE.match(p.name)
        if not m:
            raise MigrationError(f"bad migration filename: {p.name}")
        found.append((int(m.group(1)), p.stem, p))
    versions = [v for v, _, _ in found]
    if versions != list(range(1, len(versions) + 1)):
        raise MigrationError(f"migration numbering must be contiguous from 001: {versions}")
    return found


class Database:
    """Thread-safe wrapper around one SQLite connection (serialised by a lock)."""

    def __init__(self, path: Path | str, migrations_dir: Path = MIGRATIONS_DIR) -> None:
        self.path = Path(path) if str(path) != ":memory:" else None
        self._lock = threading.RLock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._apply_pending_restore()
        self._conn = sqlite3.connect(
            str(path), check_same_thread=False, isolation_level=None  # explicit transactions
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if self.path is not None:
            self._conn.execute("PRAGMA journal_mode = WAL")
        self.migrate(migrations_dir)

    # -- restore staged by BackupService, applied before the connection opens --
    def _apply_pending_restore(self) -> None:
        pending = self.path.with_suffix(".restore-pending")  # type: ignore[union-attr]
        if pending.exists():
            for suffix in ("-wal", "-shm"):
                Path(str(self.path) + suffix).unlink(missing_ok=True)
            shutil.move(str(pending), str(self.path))
            log.warning("applied staged database restore")

    # -- migrations --
    def migrate(self, directory: Path = MIGRATIONS_DIR) -> int:
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version INTEGER PRIMARY KEY, name TEXT NOT NULL, "
                "applied_at TEXT NOT NULL DEFAULT (datetime('now')))"
            )
            current = self._conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()[0]
            migrations = discover_migrations(directory)
            if current > len(migrations):
                raise MigrationError(
                    f"database schema v{current} is newer than this application (v{len(migrations)})"
                )
            for version, name, path in migrations:
                if version <= current:
                    continue
                sql = path.read_text(encoding="utf-8")
                self._conn.execute("BEGIN")
                try:
                    # executescript would auto-commit; split statements ourselves
                    for stmt in _split_statements(sql):
                        self._conn.execute(stmt)
                    self._conn.execute(
                        "INSERT INTO schema_migrations(version, name) VALUES (?, ?)", (version, name)
                    )
                    self._conn.execute("COMMIT")
                except Exception as e:
                    self._conn.execute("ROLLBACK")
                    raise MigrationError(f"migration {name} failed: {e}") from e
                log.info("applied migration %s", name)
                current = version
            return current

    def schema_version(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()[0]

    # -- queries --
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run a write statement in its own transaction; returns lastrowid."""
        with self.transaction() as c:
            return c.execute(sql, params).lastrowid or 0

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def backup_to(self, dest: Path) -> None:
        with self._lock:
            target = sqlite3.connect(str(dest))
            try:
                self._conn.backup(target)
            finally:
                target.close()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _split_statements(sql: str) -> list[str]:
    """Split on ';' using sqlite3.complete_statement so triggers/strings survive."""
    out, buf = [], ""
    for line in sql.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            if buf.strip():
                out.append(buf.strip())
            buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out
