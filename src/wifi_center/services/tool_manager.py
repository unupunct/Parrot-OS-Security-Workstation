"""Tool Integration Manager: scans integrations, persists results, owns per-tool configuration."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..database.repository import Database
from ..integrations.base import (DependencyStatus, Detection, Health, HealthStatus, SystemProbe,
                                 ToolIntegration, ToolProfile)
from ..integrations.catalog import PROFILES
from ..integrations.registry import build_integration
from ..security.input_validation import ValidationError, validate_absolute_path, validate_executable

log = logging.getLogger(__name__)
CONFIG_KEYS = ("install_path", "executable_override")


@dataclass
class ToolStatus:
    profile: ToolProfile
    detection: Detection
    version: str | None
    health: HealthStatus
    dependencies: list[DependencyStatus] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    config_problems: list[str] = field(default_factory=list)
    checked_at: str = ""

    @property
    def installed(self) -> bool:
        return self.detection.installed

    @property
    def missing_dependencies(self) -> list[DependencyStatus]:
        return [d for d in self.dependencies if not d.satisfied]


class ToolManager:
    def __init__(self, db: Database, probe: SystemProbe | None = None) -> None:
        self._db = db
        self._probe = probe or SystemProbe()
        self._status: dict[str, ToolStatus] = {}

    # ---- configuration ----
    def get_config(self, tool_id: str) -> dict[str, Any]:
        row = self._db.query_one("SELECT config_json FROM tools WHERE id = ?", (tool_id,))
        try:
            data = json.loads(row["config_json"]) if row else {}
        except json.JSONDecodeError:
            data = {}
        return {k: v for k, v in data.items() if k in CONFIG_KEYS and isinstance(v, str)}

    def set_config(self, tool_id: str, install_path: str = "", executable_override: str = "") -> None:
        profile = self.profile(tool_id)
        cfg: dict[str, str] = {}
        if install_path.strip():
            cfg["install_path"] = str(validate_absolute_path(install_path.strip(), kind="dir"))
        if executable_override.strip():
            cfg["executable_override"] = str(validate_executable(executable_override.strip()))
        self._ensure_row(profile)
        self._db.execute("UPDATE tools SET config_json = ? WHERE id = ?", (json.dumps(cfg), tool_id))
        self._status.pop(tool_id, None)

    # ---- scanning ----
    @staticmethod
    def profile(tool_id: str) -> ToolProfile:
        for p in PROFILES:
            if p.id == tool_id:
                return p
        raise KeyError(tool_id)

    def integration(self, tool_id: str) -> ToolIntegration:
        return build_integration(tool_id, self._probe, self.get_config(tool_id))

    def scan_tool(self, tool_id: str) -> ToolStatus:
        integ = self.integration(tool_id)
        detection = integ.detect_installation()
        version = integ.get_version() if detection.installed else None
        deps = integ.check_dependencies()
        health = integ.get_health_status()
        status = ToolStatus(
            profile=integ.profile, detection=detection, version=version, health=health,
            dependencies=deps, config=dict(integ.config),
            config_problems=integ.validate_configuration(),
            checked_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        self._persist(status)
        self._status[tool_id] = status
        return status

    def scan_all(self) -> list[ToolStatus]:
        results = []
        for p in PROFILES:
            try:
                results.append(self.scan_tool(p.id))
            except Exception:  # one broken integration must not stop the scan
                log.exception("scan of %s failed", p.id)
        return results

    def statuses(self) -> list[ToolStatus]:
        return [self._status[p.id] for p in PROFILES if p.id in self._status]

    def cached(self, tool_id: str) -> ToolStatus | None:
        return self._status.get(tool_id)

    # ---- persistence ----
    def _ensure_row(self, p: ToolProfile) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO tools(id, name, category, executable) VALUES (?, ?, ?, ?)",
            (p.id, p.name, p.category, p.executables[0] if p.executables else None))

    def _persist(self, s: ToolStatus) -> None:
        p = s.profile
        self._ensure_row(p)
        prev = self._db.query_one("SELECT version FROM tools WHERE id = ?", (p.id,))
        with self._db.transaction() as c:
            c.execute(
                "UPDATE tools SET name=?, category=?, executable=?, install_path=?, installed=?, version=?, "
                "integration_status=?, last_checked=? WHERE id=?",
                (p.name, p.category, p.executables[0] if p.executables else None, s.detection.path,
                 int(s.installed), s.version, s.health.level.value, s.checked_at, p.id))
            if s.version and (prev is None or prev["version"] != s.version):
                c.execute("INSERT INTO tool_versions(tool_id, version) VALUES (?, ?)", (p.id, s.version))
            c.execute("INSERT INTO integration_health(tool_id, status, detail) VALUES (?, ?, ?)",
                      (p.id, s.health.level.value, s.health.detail))
            c.execute("DELETE FROM integration_health WHERE tool_id = ? AND id NOT IN "
                      "(SELECT id FROM integration_health WHERE tool_id = ? ORDER BY id DESC LIMIT 50)",
                      (p.id, p.id))

    def summary(self) -> dict[str, int]:
        """Counts from the database (so the dashboard works before a scan this session)."""
        row = self._db.query_one(
            "SELECT COUNT(*) total, COALESCE(SUM(installed),0) installed, "
            "COALESCE(SUM(integration_status='error'),0) errors, "
            "COALESCE(SUM(integration_status='warning'),0) warnings, "
            "COALESCE(SUM(integration_status='ok'),0) healthy, "
            "COUNT(last_checked) scanned FROM tools")
        return dict(row)
