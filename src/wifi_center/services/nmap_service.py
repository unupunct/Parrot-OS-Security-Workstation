"""Nmap workflow: scope-checked scan planning, result import, history, comparison and export."""
from __future__ import annotations

import csv
import io
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..database.repository import Database
from ..integrations.base import LaunchRequest, ToolIntegration
from ..integrations.nmap_args import SCAN_PROFILES, XML_DIRNAME, XML_PREFIX, XML_SUFFIX, validate_target
from ..security.input_validation import ValidationError
from .nmap_parsers import MAX_BYTES, ParseError, ScanResult, parse_any
from .project_service import ProjectService, ScopeError, sha256_file


@dataclass
class PlannedScan:
    request: LaunchRequest
    xml_path: Path
    targets: list[str]
    profile: str
    project_id: int


@dataclass
class ScanDiff:
    new_hosts: list[str] = field(default_factory=list)
    gone_hosts: list[str] = field(default_factory=list)
    changes: list[dict] = field(default_factory=list)   # {address, opened, closed, changed}

    @property
    def is_empty(self) -> bool:
        return not (self.new_hosts or self.gone_hosts or self.changes)


class NmapService:
    def __init__(self, db: Database, projects: ProjectService, scans_dir: Path) -> None:
        self._db = db
        self._projects = projects
        self.scans_dir = scans_dir

    # ---------------- planning (scope enforcement) ----------------
    def plan_scan(self, integration: ToolIntegration, project_id: int, targets: list[str], profile: str,
                  confirmed: bool) -> PlannedScan:
        if not confirmed:
            raise ScopeError("explicit scope confirmation is required before scanning")
        if profile not in SCAN_PROFILES:
            raise ValidationError(f"unknown scan profile: {profile}")
        if not self._projects.get(project_id):
            raise ValidationError("choose a project (its authorized scope defines what may be scanned)")
        clean = []
        for t in targets:
            t = t.strip()
            if t:
                clean.append(validate_target(t))
        if not clean:
            raise ValidationError("enter at least one target")
        bad = [c for c in self._projects.check_scope(project_id, clean) if not c.in_scope]
        if bad:
            raise ScopeError("not in the project's authorized scope: " + ", ".join(c.target for c in bad))
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        xml = (self.scans_dir / f"{XML_PREFIX}{uuid.uuid4().hex}{XML_SUFFIX}").resolve()
        assert xml.parent.name == XML_DIRNAME
        req = integration.launch_supported_operation("scan", {"profile": profile, "targets": clean,
                                                              "xml_path": str(xml)})
        return PlannedScan(req, xml, clean, profile, project_id)

    # ---------------- import ----------------
    def import_result(self, result: ScanResult, project_id: int | None, source_file: str = "", sha256: str = "",
                      kind: str = "import", target: str = "") -> int:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._db.transaction() as c:
            sid = c.execute(
                "INSERT INTO scans(project_id, tool, kind, target, args, started_at, finished_at, source_file, "
                "source_sha256, host_count) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (project_id, "nmap", kind, target, result.args, result.started, result.finished,
                 source_file, sha256, len(result.hosts))).lastrowid
            for h in result.hosts:
                c.execute("INSERT INTO scan_hosts(scan_id, address, hostname, mac, vendor, os_guess, status) "
                          "VALUES (?,?,?,?,?,?,?)", (sid, h.address, h.hostname, h.mac, h.vendor, h.os_guess, h.status))
                for p in h.ports:
                    c.execute("INSERT INTO scan_ports(scan_id, address, port, proto, state, service, product, version) "
                              "VALUES (?,?,?,?,?,?,?,?)", (sid, h.address, p.port, p.proto, p.state, p.service,
                                                           p.product, p.version))
                if h.status == "up":  # feed the network inventory used by the topology views
                    c.execute(
                        "INSERT INTO network_devices(project_id, address, hostname, mac, vendor, os_guess, "
                        "services_json, source, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(address, source, COALESCE(project_id,0)) DO UPDATE SET hostname=excluded.hostname, "
                        "mac=excluded.mac, vendor=excluded.vendor, os_guess=excluded.os_guess, "
                        "services_json=excluded.services_json, last_seen=excluded.last_seen",
                        (project_id, h.address, h.hostname, h.mac, h.vendor, h.os_guess,
                         json.dumps([p.label() for p in h.open_ports]), "nmap", now, now))
        if project_id:
            self._projects.touch(project_id)
        return sid

    def import_text(self, text: str, project_id: int | None, source_file: str = "") -> int:
        return self.import_result(parse_any(text), project_id, source_file)

    def import_file(self, path: str, project_id: int | None) -> int:
        p = Path(path)
        if not p.is_absolute() or not p.is_file():
            raise ValidationError("choose an existing file")
        if p.stat().st_size > MAX_BYTES:
            raise ParseError("file too large")
        digest = sha256_file(p)
        dup = self._db.query_one("SELECT id FROM scans WHERE source_sha256 = ? AND COALESCE(project_id,0) = ?",
                                 (digest, project_id or 0))
        if dup:
            return dup["id"]  # importing the same file twice does not duplicate history
        result = parse_any(p.read_text(encoding="utf-8", errors="replace"))
        return self.import_result(result, project_id, str(p), digest)

    def finish_planned(self, planned: PlannedScan) -> int:
        """Import the XML produced by a completed scan."""
        p = planned.xml_path
        if not p.is_file():
            raise ParseError("the scan produced no output file")
        result = parse_any(p.read_text(encoding="utf-8", errors="replace"))
        return self.import_result(result, planned.project_id, str(p), sha256_file(p), "scan",
                                  " ".join(planned.targets))

    # ---------------- queries ----------------
    def scans(self, project_id: int | None = None) -> list[dict]:
        sql, params = "SELECT * FROM scans", []
        if project_id:
            sql, params = sql + " WHERE project_id = ?", [project_id]
        return [dict(r) for r in self._db.query(sql + " ORDER BY id DESC", params)]

    def hosts(self, scan_id: int) -> list[dict]:
        out = []
        for h in self._db.query("SELECT * FROM scan_hosts WHERE scan_id=? ORDER BY address", (scan_id,)):
            d = dict(h)
            d["ports"] = [dict(p) for p in self._db.query(
                "SELECT port, proto, state, service, product, version FROM scan_ports WHERE scan_id=? AND address=? "
                "ORDER BY port", (scan_id, h["address"]))]
            out.append(d)
        return out

    def delete_scan(self, scan_id: int) -> None:
        self._db.execute("DELETE FROM scans WHERE id=?", (scan_id,))

    # ---------------- comparison ----------------
    def _open_map(self, scan_id: int) -> dict[str, dict[str, str]]:
        m: dict[str, dict[str, str]] = {}
        for h in self._db.query("SELECT address FROM scan_hosts WHERE scan_id=? AND status='up'", (scan_id,)):
            m[h["address"]] = {}
        for p in self._db.query("SELECT address, port, proto, service, product, version FROM scan_ports "
                                "WHERE scan_id=? AND state='open'", (scan_id,)):
            label = " ".join(x for x in (p["service"], p["product"], p["version"]) if x)
            m.setdefault(p["address"], {})[f"{p['port']}/{p['proto']}"] = label
        return m

    def compare(self, older_id: int, newer_id: int) -> ScanDiff:
        a, b = self._open_map(older_id), self._open_map(newer_id)
        diff = ScanDiff(new_hosts=sorted(set(b) - set(a)), gone_hosts=sorted(set(a) - set(b)))
        for addr in sorted(set(a) & set(b)):
            pa, pb = a[addr], b[addr]
            opened = sorted(set(pb) - set(pa))
            closed = sorted(set(pa) - set(pb))
            changed = sorted((k, pa[k], pb[k]) for k in set(pa) & set(pb) if pa[k] != pb[k])
            if opened or closed or changed:
                diff.changes.append({"address": addr, "opened": opened, "closed": closed, "changed": changed})
        return diff

    # ---------------- export ----------------
    def export(self, scan_id: int, fmt: str) -> str:
        hosts = self.hosts(scan_id)
        if fmt == "json":
            return json.dumps({"scan": dict(self._db.query_one("SELECT * FROM scans WHERE id=?", (scan_id,)) or {}),
                               "hosts": hosts}, indent=2, default=str)
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["address", "hostname", "mac", "vendor", "os_guess", "status", "port", "proto", "state",
                        "service", "product", "version"])
            for h in hosts:
                rows = h["ports"] or [{}]
                for p in rows:
                    w.writerow([_safe(v) for v in (h["address"], h["hostname"], h["mac"], h["vendor"], h["os_guess"],
                                                   h["status"], p.get("port", ""), p.get("proto", ""),
                                                   p.get("state", ""), p.get("service", ""), p.get("product", ""),
                                                   p.get("version", ""))])
            return buf.getvalue()
        raise ValueError("format must be 'csv' or 'json'")


def _safe(v):
    """Neutralise spreadsheet formula injection from remote-controlled banner text."""
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
