"""Filesystem locations used by the application.

`WIFI_CENTER_HOME` overrides everything (used by tests and portable installs).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AppPaths:
    config_dir: Path
    data_dir: Path
    log_dir: Path
    backup_dir: Path
    db_path: Path
    default_resources_dir: Path

    def ensure(self) -> "AppPaths":
        for d in (self.config_dir, self.data_dir, self.log_dir, self.backup_dir):
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
        return self


def resolve_paths() -> AppPaths:
    override = os.environ.get("WIFI_CENTER_HOME")
    home = Path.home()
    if override:
        root = Path(override)
        config, data = root / "config", root / "data"
    elif os.name == "posix":
        config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "wifi-center"
        data = Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share")) / "wifi-center"
    else:  # development on Windows/macOS
        config = data = home / ".wifi-center"
    return AppPaths(
        config_dir=config,
        data_dir=data,
        log_dir=data / "logs",
        backup_dir=data / "backups",
        db_path=data / "wifi-center.db",
        default_resources_dir=home / "WIFI-Center" / "Resources" / "Wordlists",
    )
