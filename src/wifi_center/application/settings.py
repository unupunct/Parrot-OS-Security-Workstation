"""Validated, database-backed user settings."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..database.repository import Database

_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


@dataclass(frozen=True)
class Spec:
    default: Any
    validate: Callable[[Any], bool]


def _is_bool(v: Any) -> bool:
    return isinstance(v, bool)


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


SPECS: dict[str, Spec] = {
    "general.restore_last_workspace": Spec(True, _is_bool),
    "general.last_page": Spec("overview", _is_str),
    "general.resources_dir": Spec("", _is_str),  # "" = default location
    "appearance.accent": Spec("#00FF66", lambda v: _is_str(v) and bool(_HEX.match(v))),
    "logging.level": Spec("INFO", lambda v: v in ("DEBUG", "INFO", "WARNING", "ERROR")),
    "ui.window_geometry": Spec("", _is_str),  # base64 from saveGeometry
    "ui.splitter_sizes": Spec([260, 1000], lambda v: isinstance(v, list) and all(isinstance(i, int) for i in v)),
    "ui.collapsed_categories": Spec([], lambda v: isinstance(v, list) and all(isinstance(i, str) for i in v)),
    "notifications.enabled": Spec(True, _is_bool),
    "ui.animation_intensity": Spec("high", lambda v: v in ("low", "normal", "high")),
    "ui.reduced_motion": Spec(False, _is_bool),
    "ui.startup_animation": Spec(True, _is_bool),
    "ui.dashboard_layout": Spec([], lambda v: isinstance(v, list) and all(
        isinstance(i, dict) and isinstance(i.get("id"), str) and isinstance(i.get("span"), int) for i in v)),
    "ui.dashboard_splitter": Spec([], lambda v: isinstance(v, list) and all(isinstance(i, int) for i in v)),
    "ui.favorite_tools": Spec([], lambda v: isinstance(v, list) and all(isinstance(i, str) for i in v)),
}


class SettingsError(ValueError):
    pass


class Settings:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, key: str) -> Any:
        spec = SPECS.get(key)
        if spec is None:
            raise SettingsError(f"unknown setting: {key}")
        row = self._db.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is None:
            return spec.default
        try:
            value = json.loads(row["value"])
        except json.JSONDecodeError:
            return spec.default
        return value if spec.validate(value) else spec.default

    def set(self, key: str, value: Any) -> None:
        spec = SPECS.get(key)
        if spec is None:
            raise SettingsError(f"unknown setting: {key}")
        if not spec.validate(value):
            raise SettingsError(f"invalid value for {key}: {value!r}")
        self._db.execute(
            "INSERT INTO settings(key, value, updated_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, json.dumps(value)),
        )

    def resources_dir(self, default: Path) -> Path:
        custom = self.get("general.resources_dir")
        return Path(custom) if custom else default
