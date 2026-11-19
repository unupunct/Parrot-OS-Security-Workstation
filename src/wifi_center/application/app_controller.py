"""Composition root: builds the database, settings and services once."""
from __future__ import annotations

import logging
from pathlib import Path

from ..database.repository import Database
from ..services.adapter_service import AdapterService
from ..services.apt_service import AptService
from ..services.backup_service import BackupService
from ..services.cleanup_service import CleanupService
from ..services.maintenance_service import MaintenanceService
from ..services.package_service import PackageService
from ..services.privileged_service import UnavailableBackend
from ..services.software_sources import SoftwareSources
from ..services.system_info_service import SystemInfoService
from ..security.audit_log import AuditLog
from ..services.operation_manager import OperationManager
from ..services.bluetooth_service import BluetoothService
from ..services.bloodhound_service import BloodHoundService
from ..services.network_inventory import NetworkInventoryService
from ..services.nmap_service import NmapService
from ..services.notification_service import NotificationService
from ..services.osint_service import OsintService
from ..services.packet_service import PacketService
from ..services.project_service import ProjectService
from ..services.report_import import ReportImportService
from ..services.resource_library import LibraryService
from ..services.system_service import SystemService
from ..services.wireless_service import WirelessService
from ..services.tool_manager import ToolManager
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
        self.wireless = WirelessService(self.db)
        self.packets = PacketService()
        self.inventory = NetworkInventoryService(self.db, self.wireless.oui)
        self.notifications = NotificationService(self.db)
        self.bluetooth = BluetoothService(self.db)
        self.projects = ProjectService(self.db)
        self.nmap = NmapService(self.db, self.projects, self.paths.data_dir / "scans")
        self.report_import = ReportImportService(self.db, self.projects)
        self.bloodhound = BloodHoundService()
        self.osint = OsintService(self.db)
        self.wordlists = LibraryService(
            self.db, lambda: self.settings.resources_dir(self.paths.default_resources_dir), "wordlists")
        self.local_resources = LibraryService(
            self.db, lambda: Path(self.settings.get("general.local_resources_dir")
                                  or self.paths.default_resources_dir.parent / "Local"), "local")
        self.maintenance = MaintenanceService(self.db)
        from ..services.helper_client import make_backend
        self.privileged = make_backend() or UnavailableBackend()     # Polkit-guarded helper when QtDBus is present
        self.apt = AptService()
        self.packages = PackageService(self.apt)
        self.sysinfo = SystemInfoService(self.services.get(SystemService), self.apt)
        from ..services.hardware_info import HardwareInfoService
        self.hwinfo = HardwareInfoService()
        from ..bluetooth.adapter import BluetoothAdapterManager
        from ..bluetooth.bluez import UnavailableBluez, make_api
        from ..bluetooth.diagnostics import BluetoothDiagnostics
        from ..bluetooth.inventory import BluetoothInventory
        from ..bluetooth.scanner import BluetoothScanner
        from ..bluetooth.signal_monitor import BluetoothSignalMonitor
        self.btapi = make_api()                                   # None when dbus-python is missing (the legacy scanner is used then)
        _bt = self.btapi or UnavailableBluez()
        self.btadapters = BluetoothAdapterManager(_bt)
        self.btscanner = BluetoothScanner(_bt)
        self.btinventory = BluetoothInventory(self.db)
        self.btmonitor = BluetoothSignalMonitor(self.btscanner)
        self.btdiag = BluetoothDiagnostics(_bt, self.btadapters, self.btscanner)
        self._bt = _bt
        from ..services.package_tools import PackageTools
        self.pkgtools = PackageTools(self.apt)
        from ..services.docs_service import DocsService
        self.docs = DocsService()
        from ..services.lan_scanner import LanScanner
        from ..services.network_discovery import NetworkDiscoveryEngine
        self.netdisc = NetworkDiscoveryEngine(self.db, self.wireless.oui, projects=self.projects)
        self.lan = LanScanner(self.wireless.oui, known=lambda: self.settings.get("lan.devices"),
                              save_known=lambda d: self.settings.set("lan.devices", d))
        self.software = SoftwareSources(self.apt)
        self.cleanup = CleanupService(self.maintenance, self.apt, self.privileged,
                                      app_log_dir=self.paths.log_dir)
        self.audit = AuditLog(self.paths.log_dir / "audit.log")
        from ..bluetooth.auditor import BluetoothSecurityAuditor
        from ..bluetooth.ble import BLEExplorer
        from ..bluetooth.devices import BluetoothDeviceManager
        from ..bluetooth.inspector import BluetoothDeviceInspector
        self.btdevices = BluetoothDeviceManager(self._bt, self.btinventory, self.audit.record)
        self.btinspector = BluetoothDeviceInspector(self._bt, self.btinventory)
        self.btble = BLEExplorer(self._bt, self.btinventory, self.audit.record)
        self.btauditor = BluetoothSecurityAuditor(self._bt, self.db, self.btinventory, self.btdevices, self.btble, self.audit.record)
        from ..bluetooth.packets import BluetoothPacketAnalyzer
        from ..bluetooth.reports import BluetoothReportGenerator
        self.btpackets = BluetoothPacketAnalyzer(self.paths.data_dir / "bluetooth-captures")
        self.btreports = BluetoothReportGenerator(self.btinventory, self.btauditor)
        self.tools = ToolManager(self.db)
        self.operations = OperationManager(self.db, self.audit)
        self.audit.record("app.start")
        log.info("WIFI Center started (schema v%s)", self.db.schema_version())

    def shutdown(self) -> None:
        log.info("shutting down")
        self.operations.shutdown()
        from PySide6.QtCore import QThreadPool
        QThreadPool.globalInstance().waitForDone(5000)  # let background tasks finish before closing the DB
        self.audit.record("app.stop")
        self.db.close()
