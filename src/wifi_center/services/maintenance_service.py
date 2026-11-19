"""Maintenance history: every proposed, applied, skipped or failed system maintenance operation."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from ..database.repository import Database

RESULTS = ("success", "failed", "cancelled", "not executed", "dry run")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class MaintenanceService:
    def __init__(self, db: Database) -> None:
        self._db = db

    def record(self, name: str, op_type: str, result: str, *, packages: list[str] | None = None,
               files_removed: int | None = None, errors: str = "", log_ref: str = "",
               started_at: str | None = None) -> int:
        if result not in RESULTS:
            raise ValueError(f"result must be one of {RESULTS}")
        now = _now()
        return self._db.execute(
            "INSERT INTO maintenance_history(name, op_type, started_at, finished_at, packages_changed, files_removed, "
            "result, errors, log_ref) VALUES (?,?,?,?,?,?,?,?,?)",
            (name, op_type, started_at or now, now, "\n".join(packages or []) or None, files_removed, result,
             errors or None, log_ref or None))

    def entries(self, op_type: str | None = None, result: str | None = None, limit: int = 1000) -> list[dict]:
        sql, params = "SELECT * FROM maintenance_history WHERE 1=1", []
        if op_type:
            sql, params = sql + " AND op_type = ?", [*params, op_type]
        if result:
            sql, params = sql + " AND result = ?", [*params, result]
        return [dict(r) for r in self._db.query(sql + " ORDER BY id DESC LIMIT ?", [*params, limit])]

    def last(self, op_type: str, result: str = "success") -> dict | None:
        r = self._db.query_one("SELECT * FROM maintenance_history WHERE op_type = ? AND result = ? ORDER BY id DESC LIMIT 1",
                               (op_type, result))
        return dict(r) if r else None

    def export(self, fmt: str) -> str:
        rows = self.entries()
        if fmt == "json":
            return json.dumps(rows, indent=2)
        if fmt == "csv":
            buf = io.StringIO()
            cols = ["id", "name", "op_type", "started_at", "finished_at", "result", "packages_changed", "files_removed",
                    "errors", "log_ref"]
            w = csv.writer(buf, lineterminator="\n")
            w.writerow(cols)
            for r in rows:
                w.writerow(["'" + str(v) if isinstance(v, str) and v[:1] in "=+-@" else v for v in (r[c] for c in cols)])
            return buf.getvalue()
        raise ValueError("format must be 'csv' or 'json'")
