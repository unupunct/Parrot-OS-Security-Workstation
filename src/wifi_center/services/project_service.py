"""Assessment projects: authorized scope, findings with remediation tracking, notes, evidence and references."""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from ..database.repository import Database
from ..security.input_validation import ValidationError, validate_absolute_path, validate_cidr, validate_hostname, validate_ip

SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = ("open", "in_progress", "resolved", "accepted")
MAX_EVIDENCE_HASH_BYTES = 2 * 1024 ** 3


class ScopeError(PermissionError):
    pass


@dataclass(frozen=True)
class ScopeCheck:
    target: str
    in_scope: bool
    reason: str = ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_target(value: str) -> tuple[str, str]:
    """-> (normalised value, kind) for an IP, CIDR or hostname; raises ValidationError."""
    v = value.strip()
    if "/" in v:
        return validate_cidr(v), "cidr"
    try:
        return validate_ip(v), "ip"
    except ValidationError:
        return validate_hostname(v), "host"


class ProjectService:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ---------------- projects ----------------
    def create(self, name: str, kind: str = "assessment") -> int:
        name = name.strip()
        if not name or len(name) > 120:
            raise ValidationError("project name must be 1-120 characters")
        return self._db.execute("INSERT INTO projects(name, kind) VALUES (?, ?)", (name, kind))

    def list(self) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM projects ORDER BY updated_at DESC, id DESC")]

    def get(self, project_id: int) -> dict | None:
        r = self._db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
        return dict(r) if r else None

    def delete(self, project_id: int) -> None:
        """Removes the project record and its database content. Evidence files on disk are never touched."""
        self._db.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    def touch(self, project_id: int) -> None:
        self._db.execute("UPDATE projects SET updated_at = datetime('now') WHERE id = ?", (project_id,))

    # ---------------- scope ----------------
    def add_scope(self, project_id: int, target: str, note: str = "") -> str:
        value, kind = classify_target(target)
        self._db.execute("INSERT OR IGNORE INTO scope_entries(project_id, target, kind, note) VALUES (?,?,?,?)",
                         (project_id, value, kind, note))
        self.touch(project_id)
        return value

    def remove_scope(self, project_id: int, target: str) -> None:
        self._db.execute("DELETE FROM scope_entries WHERE project_id=? AND target=?", (project_id, target))

    def scope(self, project_id: int) -> list[dict]:
        return [dict(r) for r in self._db.query(
            "SELECT target, kind, note, added_at FROM scope_entries WHERE project_id=? ORDER BY id", (project_id,))]

    def check_scope(self, project_id: int, targets: Iterable[str]) -> list[ScopeCheck]:
        """Names are matched exactly (no DNS lookups); IPs and CIDRs must lie inside a scope CIDR/IP."""
        entries = self.scope(project_id)
        nets = [ipaddress.ip_network(e["target"], strict=False) for e in entries if e["kind"] in ("ip", "cidr")]
        hosts = {e["target"] for e in entries if e["kind"] == "host"}
        out = []
        for t in targets:
            try:
                value, kind = classify_target(t)
            except ValidationError as e:
                out.append(ScopeCheck(t, False, str(e)))
                continue
            if kind == "host":
                ok = value in hosts
            else:
                net = ipaddress.ip_network(value, strict=False)
                ok = any(net.version == n.version and net.subnet_of(n) for n in nets)
            out.append(ScopeCheck(value, ok, "" if ok else "outside the authorized scope"))
        return out

    # ---------------- findings ----------------
    def add_finding(self, project_id: int, title: str, severity: str, description: str = "",
                    recommendation: str = "", source_tool: str = "", location: str = "",
                    source_ref: str = "") -> int:
        if severity not in SEVERITIES:
            raise ValidationError(f"severity must be one of {SEVERITIES}")
        if not title.strip():
            raise ValidationError("finding title is required")
        fid = self._db.execute(
            "INSERT INTO findings(project_id, title, severity, description, recommendation, source_tool, location, "
            "source_ref) VALUES (?,?,?,?,?,?,?,?)",
            (project_id, title.strip()[:300], severity, description, recommendation, source_tool, location, source_ref))
        self.touch(project_id)
        return fid

    def update_finding(self, finding_id: int, **fields: str) -> None:
        allowed = {"title", "severity", "status", "description", "recommendation", "remediation_notes", "due_date",
                   "location"}
        bad = set(fields) - allowed
        if bad:
            raise ValidationError(f"cannot update: {sorted(bad)}")
        if "severity" in fields and fields["severity"] not in SEVERITIES:
            raise ValidationError("invalid severity")
        if "status" in fields and fields["status"] not in STATUSES:
            raise ValidationError("invalid status")
        if not fields:
            return
        sets = ", ".join(f"{k} = ?" for k in fields)
        self._db.execute(f"UPDATE findings SET {sets}, updated_at = datetime('now') WHERE id = ?",
                         (*fields.values(), finding_id))

    def findings(self, project_id: int, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM findings WHERE project_id = ?"
        params: list = [project_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += (" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                "WHEN 'low' THEN 3 ELSE 4 END, id")
        return [dict(r) for r in self._db.query(sql, params)]

    def delete_finding(self, finding_id: int) -> None:
        self._db.execute("DELETE FROM findings WHERE id = ?", (finding_id,))

    def severity_summary(self, project_id: int) -> dict[str, int]:
        rows = self._db.query("SELECT severity, COUNT(*) n FROM findings WHERE project_id=? AND status != 'resolved' "
                              "GROUP BY severity", (project_id,))
        return {r["severity"]: r["n"] for r in rows}

    # ---------------- notes / evidence / references ----------------
    def add_note(self, project_id: int, body: str) -> None:
        if body.strip():
            self._db.execute("INSERT INTO project_notes(project_id, body) VALUES (?,?)", (project_id, body.strip()))
            self.touch(project_id)

    def notes(self, project_id: int) -> list[dict]:
        return [dict(r) for r in self._db.query(
            "SELECT * FROM project_notes WHERE project_id=? ORDER BY id DESC", (project_id,))]

    def add_evidence(self, project_id: int, path: str, description: str = "", finding_id: int | None = None) -> int:
        """Reference (do not copy) an evidence file; its SHA-256 is recorded for integrity checks."""
        p = validate_absolute_path(path, kind="file")
        if p.stat().st_size > MAX_EVIDENCE_HASH_BYTES:
            raise ValidationError("file too large to hash")
        return self._db.execute("INSERT INTO evidence(project_id, finding_id, path, sha256, description) "
                                "VALUES (?,?,?,?,?)", (project_id, finding_id, str(p), sha256_file(p), description))

    def evidence(self, project_id: int) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM evidence WHERE project_id=? ORDER BY id DESC",
                                                (project_id,))]

    def verify_evidence(self, evidence_id: int) -> str:
        """-> 'ok' | 'changed' | 'missing'"""
        r = self._db.query_one("SELECT path, sha256 FROM evidence WHERE id=?", (evidence_id,))
        if not r or not Path(r["path"]).is_file():
            return "missing"
        return "ok" if sha256_file(Path(r["path"])) == r["sha256"] else "changed"

    def add_reference(self, project_id: int, url: str, label: str = "") -> str:
        u = urlparse(url.strip())
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValidationError("references must be http(s) URLs")
        clean = u.geturl()
        self._db.execute("INSERT OR IGNORE INTO project_refs(project_id, url, label) VALUES (?,?,?)",
                         (project_id, clean, label))
        return clean

    def references(self, project_id: int) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM project_refs WHERE project_id=? ORDER BY id",
                                                (project_id,))]

    def remove_reference(self, project_id: int, url: str) -> None:
        self._db.execute("DELETE FROM project_refs WHERE project_id=? AND url=?", (project_id, url))
