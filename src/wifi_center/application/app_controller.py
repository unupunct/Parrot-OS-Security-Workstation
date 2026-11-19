"""Composition root: builds the database, settings and services once."""
from __future__ import annotations

import logging
from pathlib import Path

from ..database.repository import Database
from ..services.adapter_service import AdapterService
from ..services.backup_service import BackupService
from ..services.system_service import SystemService
from .event_bus import EventBus
from .logging_setup import setup_logging
from .paths import AppPaths, resolve_paths
from .service_registry import ServiceRegistry
from .settings import Settings

log = logging.getLogger(__name__)


class AppController:
    def __init__(self, paths: AppPaths | None = None, db_path: Path | str | None = None,
                 console_log: bool = True) -> None:
        self.paths = (paths or resolve_paths()).ensure()
        self.db = Database(db_path if db_path is not None else self.paths.db_path)
        self.settings = Settings(self.db)
        setup_logging(self.paths.log_dir, self.settings.get("logging.level"), console=console_log)
        self.bus = EventBus()
        self.services = ServiceRegistry()
        self.services.register(SystemService, SystemService())
        self.services.register(AdapterService, AdapterService())
        self.services.register(
            BackupService,
            BackupService(self.db, self.paths.backup_dir),
        )
        log.info("WIFI Center started (schema v%s)", self.db.schema_version())

    def shutdown(self) -> None:
        log.info("shutting down")
        self.db.close()
