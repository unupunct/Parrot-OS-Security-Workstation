"""Main window: sidebar, top bar, animated page stack, command palette, live status. Persists layout."""
from __future__ import annotations

import webbrowser

from PySide6.QtCore import QByteArray, QTimer, Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QMainWindow, QSplitter, QStackedWidget, QVBoxLayout, QWidget

from .. import APP_NAME
from ..application.app_controller import AppController
from ..services.adapter_service import AdapterService
from ..services.backup_service import BackupService
from ..services.system_service import SystemService
from ..workers.task import run_in_background
from .dashboard import Dashboard
from .design.motion import Motion, fade_in
from .design.overlay import StartupOverlay
from .design.tokens import T
from .navigation import find_item
from .pages.activity_page import ActivityPage
from .pages.assessment_pages import AssessmentPage, PasswordAuditPage, WebSecurityPage
from .pages.bluetooth_page import BluetoothPage
from .pages.discovery_pages import NetworkDiscoveryPage, NetworkMappingPage
from .pages.kismet_page import KismetPage
from .pages.packets_page import PacketsPage
from .pages.osint_pages import OsintWorkspacePage
from .pages.planned import PlannedPage
from .pages.resource_pages import DocumentationPage, ResourceLibraryPage
from .pages.settings_page import SettingsPage
from .pages.spectrum_page import SpectrumPage
from .pages.terminal_page import TerminalPage
from .pages.tool_config_page import ToolConfigPage
from .pages.tools_page import ToolsPage
from .pages.wireless_pages import AdapterPage, DiscoveryPage
from .palette import Command, CommandPalette, build_commands
from .sidebar import Sidebar
from .theme import build_stylesheet
from .topbar import TopBar


class MainWindow(QMainWindow):
    def __init__(self, app: AppController, startup_animation: bool | None = None) -> None:
        super().__init__()
        self.app = app
        self.setWindowTitle(APP_NAME)
        self.resize(1440, 860)
        self.setMinimumSize(980, 620)
        Motion.instance().configure(app.settings.get("ui.animation_intensity"), app.settings.get("ui.reduced_motion"))

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        self.topbar = TopBar(app.notifications)
        v.addWidget(self.topbar)

        accent = app.settings.get("appearance.accent")
        self.sidebar = Sidebar(app.settings.get("ui.collapsed_categories"), accent)
        self.stack = QStackedWidget()
        holder = QWidget()
        hl = QVBoxLayout(holder)
        hl.setContentsMargins(20, 16, 20, 16)
        hl.addWidget(self.stack)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.sidebar)
        self.splitter.addWidget(holder)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setCollapsible(0, False)
        self.splitter.setCollapsible(1, False)
        self.splitter.setSizes([T.sidebar_width, 1100])
        v.addWidget(self.splitter, 1)

        self._pages: dict[str, QWidget] = {}
        self.current_page = ""
        self._closed = False

        self.palette = CommandPalette(self, self._commands)
        self.sidebar.page_selected.connect(self.show_page)
        self.topbar.navigate.connect(self.sidebar.select_page)
        self.topbar.open_palette.connect(self.palette.open)
        self.topbar.open_settings.connect(lambda: self.sidebar.select_page("settings_general"))
        QShortcut(QKeySequence("Ctrl+K"), self, self.palette.open)
        QShortcut(QKeySequence("Ctrl+,"), self, lambda: self.sidebar.select_page("settings_general"))
        QShortcut(QKeySequence("F5"), self, self._refresh_current)
        for i, pid in enumerate(("overview", "wireless_discovery", "tools_all", "terminal"), start=1):
            QShortcut(QKeySequence(f"Ctrl+{i}"), self, lambda p=pid: self.sidebar.select_page(p))

        app.operations.changed.connect(self._ops_changed)
        app.operations.finished.connect(self._op_finished)
        self._monitor = QTimer(self)
        self._monitor.setInterval(5000)
        self._monitor.timeout.connect(self._poll_status)
        self._monitor.start()

        self._restore_layout()
        start = "overview"
        if app.settings.get("general.restore_last_workspace"):
            last = app.settings.get("general.last_page")
            if find_item(last):
                start = last
        self.sidebar.select_page(start)
        # local-only detection scans at startup; results land in the DB and refresh the dashboard/badges
        run_in_background(app.tools.scan_all, lambda _r: self._tools_scanned())
        self._poll_status()
        self._poll_updates()
        want_overlay = app.settings.get("ui.startup_animation") if startup_animation is None else startup_animation
        if want_overlay and Motion.instance().enabled:
            self._overlay = StartupOverlay(self.centralWidget(), accent)

    # ================= navigation =================
    def show_page(self, page_id: str) -> None:
        item = find_item(page_id)
        if item is None:
            return
        key = self._page_key(page_id)
        page = self._pages.get(key)
        created = page is None
        if created:
            page = self._create_page(page_id)
            self._pages[key] = page
            self.stack.addWidget(page)
        if isinstance(page, SettingsPage):
            page.show_tab_for(page_id)
        changed = self.stack.currentWidget() is not page
        self.stack.setCurrentWidget(page)
        self.current_page = page_id
        self.topbar.set_page(page_id)
        if changed and not created:
            fade_in(page, 150)  # content reveal; first-time pages build themselves

    @staticmethod
    def _page_key(page_id: str) -> str:
        if page_id in ("settings_general", "settings_appearance", "settings_backup"):
            return "settings"
        if page_id == "settings_integrations":
            return "tools_config"
        return page_id

    def _create_page(self, page_id: str) -> QWidget:
        if page_id == "overview":
            return Dashboard(self.app, self.topbar.set_connectivity, self.sidebar.select_page)
        if self._page_key(page_id) == "settings":
            sp = SettingsPage(self.app)
            sp.accent_changed.connect(self.apply_accent)
            return sp
        modes = {"tools_all": "all", "tools_installed": "installed", "tools_missing": "missing"}
        if page_id in modes:
            return ToolsPage(self.app, modes[page_id], self.open_operation, self._tools_scanned, self._configure_tool)
        if page_id in ("tools_config", "settings_integrations"):
            return ToolConfigPage(self.app)
        factories = {
            "wifi_center": lambda: AdapterPage(self.app),
            "wireless_discovery": lambda: DiscoveryPage(self.app, self._wifi_scanned),
            "kismet": lambda: KismetPage(self.app), "spectrum": lambda: SpectrumPage(self.app),
            "bluetooth": lambda: BluetoothPage(self.app), "packets": lambda: PacketsPage(self.app),
            "terminal": lambda: TerminalPage(self.app),
            "activity": lambda: ActivityPage(self.app, self.open_operation),
            "net_discovery": lambda: NetworkDiscoveryPage(self.app),
            "net_mapping": lambda: NetworkMappingPage(self.app),
            "assessment": lambda: AssessmentPage(self.app),
            "web_security": self._make_web_security,
            "password_audit": lambda: PasswordAuditPage(self.app),
            "wordlists": lambda: ResourceLibraryPage(self.app, "wordlists"),
            "local_resources": lambda: ResourceLibraryPage(self.app, "local"),
            "docs": lambda: DocumentationPage(self.app),
            "osint": lambda: OsintWorkspacePage(self.app, "explorer"),
            "osint_user": lambda: OsintWorkspacePage(self.app, "username"),
            "osint_email": lambda: OsintWorkspacePage(self.app, "email"),
            "osint_domain": lambda: OsintWorkspacePage(self.app, "domain"),
            "osint_ip": lambda: OsintWorkspacePage(self.app, "ip"),
        }
        if page_id in factories:
            return factories[page_id]()
        return PlannedPage(find_item(page_id))  # type: ignore[arg-type]

    def _make_web_security(self) -> QWidget:
        page = WebSecurityPage(self.app)
        page.navigate = self.sidebar.select_page
        page.operation_started = self.open_operation
        return page

    def _configure_tool(self, tool_id: str) -> None:
        self.sidebar.select_page("tools_config")
        page = self._pages.get("tools_config")
        if isinstance(page, ToolConfigPage):
            page.select_tool(tool_id)

    def open_operation(self, op_id: int) -> None:
        self.sidebar.select_page("terminal")
        page = self._pages.get("terminal")
        if isinstance(page, TerminalPage):
            page.select_operation(op_id)

    def _refresh_current(self) -> None:
        page = self._pages.get(self._page_key(self.current_page))
        if isinstance(page, Dashboard):
            page.refresh_all()

    # ================= live status =================
    def _poll_status(self) -> None:
        if self._closed:
            return
        sys_ = self.app.services.get(SystemService)
        self.topbar.set_connectivity(sys_.has_connectivity())
        run_in_background(self.app.services.get(AdapterService).detect, self._adapters_polled, lambda e: None)

    def _adapters_polled(self, adapters) -> None:
        if self._closed:
            return
        if not self.app.services.get(AdapterService).supported():
            self.topbar.set_wifi("Wi-Fi n/a", T.text_muted)
        elif not adapters:
            self.topbar.set_wifi("No adapter", T.text_muted)
        else:
            a = adapters[0]
            self.topbar.set_wifi(f"{a.interface} {a.state}", T.success if a.state == "up" else T.warning)

    def _poll_updates(self) -> None:
        run_in_background(self.app.services.get(SystemService).pending_updates, self._updates_polled, lambda e: None)
        QTimer.singleShot(10 * 60 * 1000, lambda: None if self._closed else self._poll_updates())

    def _updates_polled(self, res) -> None:
        if self._closed:
            return
        n = (res or {}).get("upgrade", 0)
        self.sidebar.set_badge("sys_updates", str(n) if n else None, "warning")

    def _ops_changed(self) -> None:
        if self._closed:
            return
        running = len(self.app.operations.active_operations())
        self.topbar.set_operations(running)
        self.sidebar.set_badge("activity", str(running) if running else None, "info")

    def _op_finished(self, op_id: int, status: str) -> None:
        if self._closed:
            return
        op = self.app.operations.get(op_id)
        if not op:
            return
        level = {"succeeded": "success", "launched": "success"}.get(
            status, "warning" if status in ("cancelled", "timeout") else "error")
        self.app.notifications.add(f"{op.name}: {status}", "", level)
        self.topbar.refresh_notification_count()

    # ================= command palette =================
    def _commands(self) -> list[Command]:
        actions = {
            "scan-tools": ("Scan installed tools", lambda: run_in_background(
                self.app.tools.scan_all, lambda _r: self._tools_scanned()), "Local detection only"),
            "refresh": ("Refresh dashboard", lambda: (self.sidebar.select_page("overview"), self._refresh_current()), ""),
            "backup": ("Create database backup", self._backup, "Saved to the backup directory"),
            "motion": ("Toggle reduced motion", self._toggle_reduced_motion, "Turns continuous animations on/off"),
        }
        return build_commands(self.app, self.sidebar.select_page, self._open_tool, self._run_tool_op,
                              webbrowser.open, actions)

    def _open_tool(self, tool_id: str) -> None:
        self.sidebar.select_page("tools_all")
        page = self._pages.get("tools_all")
        if isinstance(page, ToolsPage):
            page.select_tool(tool_id)

    def _run_tool_op(self, tool_id: str, op_id: str) -> None:
        from ..security.operation_policy import PolicyViolation
        try:
            st = self.app.tools.cached(tool_id)
            req = self.app.tools.integration(tool_id).launch_supported_operation(op_id, None)
            oid = self.app.operations.start(st.profile if st else self.app.tools.profile(tool_id), req)
        except (ValueError, PolicyViolation) as e:
            self.app.notifications.add(f"Cannot launch {tool_id}", str(e), "error")
            self.topbar.refresh_notification_count()
            return
        self.open_operation(oid)

    def _backup(self) -> None:
        try:
            p = self.app.services.get(BackupService).create("manual")
            self.app.notifications.add("Database backup created", p.name, "success")
        except Exception as e:  # reported, never fatal
            self.app.notifications.add("Backup failed", str(e), "error")
        self.topbar.refresh_notification_count()

    def _toggle_reduced_motion(self) -> None:
        new = not self.app.settings.get("ui.reduced_motion")
        self.app.settings.set("ui.reduced_motion", new)
        Motion.instance().configure(self.app.settings.get("ui.animation_intensity"), new)
        self.app.notifications.add("Reduced motion " + ("on" if new else "off"), "", "info")
        self.topbar.refresh_notification_count()

    # ================= data callbacks =================
    def _wifi_scanned(self) -> None:
        if self._closed:
            return
        dash = self._pages.get("overview")
        if isinstance(dash, Dashboard):
            dash.refresh_db()
        spec = self._pages.get("spectrum")
        if isinstance(spec, SpectrumPage):
            spec.refresh()

    def _tools_scanned(self) -> None:
        if self._closed:
            return
        dash = self._pages.get("overview")
        if isinstance(dash, Dashboard):
            dash.refresh_db()
        for key in ("tools_all", "tools_installed", "tools_missing"):
            page = self._pages.get(key)
            if isinstance(page, ToolsPage):
                page.reload()
        s = self.app.tools.summary()
        self.sidebar.set_badge("tools_missing", str(s["errors"]) if s["errors"] else None, "error")

    def apply_accent(self, accent: str) -> None:
        QApplication.instance().setStyleSheet(build_stylesheet(accent))  # type: ignore[union-attr]
        self.sidebar.set_accent(accent)

    # ================= layout persistence =================
    def _restore_layout(self) -> None:
        geo = self.app.settings.get("ui.window_geometry")
        if geo:
            self.restoreGeometry(QByteArray.fromBase64(geo.encode()))
        sizes = self.app.settings.get("ui.splitter_sizes")
        if len(sizes) == 2 and all(s > 0 for s in sizes):
            self.splitter.setSizes(sizes)

    def closeEvent(self, e) -> None:  # noqa: N802
        self._closed = True
        self._monitor.stop()
        s = self.app.settings
        s.set("ui.window_geometry", bytes(self.saveGeometry().toBase64()).decode())
        s.set("ui.splitter_sizes", [int(x) for x in self.splitter.sizes()])
        s.set("ui.collapsed_categories", self.sidebar.collapsed_categories())
        if self.current_page:
            s.set("general.last_page", self.current_page)
        super().closeEvent(e)
