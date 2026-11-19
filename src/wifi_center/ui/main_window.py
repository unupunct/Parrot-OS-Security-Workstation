"""Main window: top bar, collapsible sidebar, page stack. Persists layout in settings."""
from __future__ import annotations

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QMainWindow, QSplitter, QStackedWidget, QVBoxLayout, QWidget

from .. import APP_NAME
from ..application.app_controller import AppController
from .dashboard import Dashboard
from .navigation import find_item
from ..workers.task import run_in_background
from .pages.activity_page import ActivityPage
from .pages.bluetooth_page import BluetoothPage
from .pages.kismet_page import KismetPage
from .pages.packets_page import PacketsPage
from .pages.planned import PlannedPage
from .pages.settings_page import SettingsPage
from .pages.spectrum_page import SpectrumPage
from .pages.terminal_page import TerminalPage
from .pages.tool_config_page import ToolConfigPage
from .pages.tools_page import ToolsPage
from .pages.wireless_pages import AdapterPage, DiscoveryPage
from .sidebar import Sidebar
from .theme import build_stylesheet
from .topbar import TopBar


class MainWindow(QMainWindow):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.setWindowTitle(APP_NAME)
        self.resize(1360, 840)
        self.setMinimumSize(900, 600)

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        self.topbar = TopBar(app.db)
        v.addWidget(self.topbar)

        self.sidebar = Sidebar(app.settings.get("ui.collapsed_categories"))
        self.stack = QStackedWidget()
        holder = QWidget()
        hl = QVBoxLayout(holder)
        hl.setContentsMargins(20, 16, 20, 16)
        hl.addWidget(self.stack)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.sidebar)
        self.splitter.addWidget(holder)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setCollapsible(1, False)
        v.addWidget(self.splitter, 1)

        self._pages: dict[str, QWidget] = {}
        self._settings_page: SettingsPage | None = None
        self.current_page = ""
        self._closed = False

        self.sidebar.page_selected.connect(self.show_page)
        self.topbar.navigate.connect(self.sidebar.select_page)
        self.topbar.open_settings.connect(lambda: self.sidebar.select_page("settings_general"))
        QShortcut(QKeySequence("Ctrl+K"), self, self.topbar.focus_search)
        QShortcut(QKeySequence("Ctrl+,"), self, lambda: self.sidebar.select_page("settings_general"))
        QShortcut(QKeySequence("F5"), self, self._refresh_current)

        self._restore_layout()
        start = "overview"
        if app.settings.get("general.restore_last_workspace"):
            last = app.settings.get("general.last_page")
            if find_item(last):
                start = last
        self.sidebar.select_page(start)
        # Local-only detection scan at startup; results land in the DB and refresh the dashboard.
        run_in_background(app.tools.scan_all, lambda _r: self._tools_scanned())

    # ---- navigation ----
    def show_page(self, page_id: str) -> None:
        item = find_item(page_id)
        if item is None:
            return
        page = self._pages.get(self._page_key(page_id))
        if page is None:
            page = self._create_page(page_id)
            self._pages[self._page_key(page_id)] = page
            self.stack.addWidget(page)
        if isinstance(page, SettingsPage):
            page.show_tab_for(page_id)
        self.stack.setCurrentWidget(page)
        self.current_page = page_id
        self.topbar.set_workspace(item.title)

    @staticmethod
    def _page_key(page_id: str) -> str:
        if page_id in ("settings_general", "settings_appearance", "settings_backup"):
            return "settings"
        if page_id == "settings_integrations":
            return "tools_config"
        return page_id

    def open_operation(self, op_id: int) -> None:
        self.sidebar.select_page("terminal")
        page = self._pages.get("terminal")
        if isinstance(page, TerminalPage):
            page.select_operation(op_id)

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

    def _create_page(self, page_id: str) -> QWidget:
        if page_id == "overview":
            return Dashboard(self.app, self.topbar.set_connectivity)
        if self._page_key(page_id) == "settings":
            sp = SettingsPage(self.app)
            sp.accent_changed.connect(self.apply_accent)
            return sp
        modes = {"tools_all": "all", "tools_installed": "installed", "tools_missing": "missing"}
        if page_id in modes:
            return ToolsPage(self.app, modes[page_id], self.open_operation, self._tools_scanned)
        if page_id == "tools_config" or page_id == "settings_integrations":
            return ToolConfigPage(self.app)
        wireless = {"wifi_center": lambda: AdapterPage(self.app),
                    "wireless_discovery": lambda: DiscoveryPage(self.app, self._wifi_scanned),
                    "kismet": lambda: KismetPage(self.app), "spectrum": lambda: SpectrumPage(self.app),
                    "bluetooth": lambda: BluetoothPage(self.app), "packets": lambda: PacketsPage(self.app)}
        if page_id in wireless:
            return wireless[page_id]()
        if page_id == "terminal":
            return TerminalPage(self.app)
        if page_id == "activity":
            return ActivityPage(self.app, self.open_operation)
        return PlannedPage(find_item(page_id))  # type: ignore[arg-type]

    def _refresh_current(self) -> None:
        page = self._pages.get(self._page_key(self.current_page))
        if isinstance(page, Dashboard):
            page.refresh_all()

    def apply_accent(self, accent: str) -> None:
        QApplication.instance().setStyleSheet(build_stylesheet(accent))  # type: ignore[union-attr]

    # ---- layout persistence ----
    def _restore_layout(self) -> None:
        geo = self.app.settings.get("ui.window_geometry")
        if geo:
            self.restoreGeometry(QByteArray.fromBase64(geo.encode()))
        sizes = self.app.settings.get("ui.splitter_sizes")
        if len(sizes) == 2 and all(s > 0 for s in sizes):
            self.splitter.setSizes(sizes)

    def closeEvent(self, e) -> None:  # noqa: N802
        self._closed = True
        s = self.app.settings
        s.set("ui.window_geometry", bytes(self.saveGeometry().toBase64()).decode())
        s.set("ui.splitter_sizes", [int(x) for x in self.splitter.sizes()])
        s.set("ui.collapsed_categories", self.sidebar.collapsed_categories())
        if self.current_page:
            s.set("general.last_page", self.current_page)
        super().closeEvent(e)
