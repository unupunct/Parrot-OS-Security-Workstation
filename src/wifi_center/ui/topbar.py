"""MATRIX PRO top bar: title + breadcrumbs, search/command-palette trigger, live status chips."""
from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QHBoxLayout, QFrame, QLabel, QPushButton, QToolButton, QVBoxLayout, QWidget

from .design.components import Badge, StatusChip
from .design.icons import icon
from .design.tokens import T
from .navigation import category_of, find_item
from .notifications import NotificationPanel, NotificationService


class TopBar(QFrame):
    open_palette = Signal()
    open_settings = Signal()
    navigate = Signal(str)

    def __init__(self, notifications: NotificationService) -> None:
        super().__init__()
        self.setObjectName("topbar")
        self.setFixedHeight(T.topbar_height)
        self.notifications = notifications
        lay = QHBoxLayout(self)
        lay.setContentsMargins(22, 0, 18, 0)
        lay.setSpacing(10)

        left = QVBoxLayout()
        left.setSpacing(0)
        left.setContentsMargins(0, 8, 0, 8)
        self.crumbs = QLabel("")
        self.crumbs.setObjectName("crumbs")
        self.heading = QLabel("Overview")
        self.heading.setObjectName("pageHeading")
        self.subtitle = QLabel("")
        self.subtitle.setObjectName("pageSub")
        self.subtitle.hide()
        for w in (self.crumbs, self.heading):
            left.addWidget(w)
        left.addWidget(self.subtitle)
        lay.addLayout(left, 2)

        self.search = QPushButton("  Search pages, tools, projects…")
        self.search.setObjectName("searchField")
        self.search.setIcon(icon("search", T.text_muted, 16))
        self.search.setMinimumWidth(260)
        self.search.setMaximumWidth(460)
        self.search.setFixedHeight(36)
        self.search.setToolTip("Command palette (Ctrl+K)")
        self.search.setCursor(Qt.CursorShape.IBeamCursor)
        self.search.clicked.connect(self.open_palette)
        kb = QLabel("Ctrl K", self.search)
        kb.setObjectName("faint")
        kb.setStyleSheet(f"border: 1px solid {T.border}; border-radius: 4px; padding: 1px 5px;")
        self._kb = kb
        lay.addWidget(self.search, 3)

        lay.addStretch(1)
        self.net_chip = StatusChip("Checking…", T.text_muted)
        self.wifi_chip = StatusChip("No adapter", T.text_muted)
        self.ops_chip = StatusChip("Idle", T.text_muted)
        self.priv_chip = StatusChip("Unprivileged", T.text_muted, icon_name="shield")
        self.priv_chip.setToolTip("Privileged session indicator. The GUI always runs as your normal user.")
        for c in (self.net_chip, self.wifi_chip, self.ops_chip, self.priv_chip):
            lay.addWidget(c)
        self.net_chip.setToolTip("Local connectivity (no packets are sent to check this)")
        self.wifi_chip.setToolTip("Wireless adapter state")
        self.ops_chip.setToolTip("Running operations (click for the Activity Monitor)")
        self.ops_chip.clicked.connect(lambda: self.navigate.emit("activity"))
        self.wifi_chip.clicked.connect(lambda: self.navigate.emit("wifi_center"))
        self.net_chip.clicked.connect(lambda: self.navigate.emit("overview"))
        self.priv_chip.clicked.connect(lambda: self.navigate.emit("root_access"))

        self.bell = QToolButton()
        self.bell.setIcon(icon("bell", T.text_secondary, 18))
        self.bell.setToolTip("Notifications")
        self.bell.setFixedSize(36, 32)
        self.bell.clicked.connect(self._show_notifications)
        self.bell_badge = Badge("", "error", self.bell)
        self.bell_badge.hide()
        self.gear = QToolButton()
        self.gear.setIcon(icon("settings", T.text_secondary, 18))
        self.gear.setToolTip("Settings (Ctrl+,)")
        self.gear.setFixedSize(36, 32)
        self.gear.clicked.connect(self.open_settings)
        lay.addWidget(self.bell)
        lay.addWidget(self.gear)

        self.panel = NotificationPanel(notifications, self)
        self.panel.changed.connect(self.refresh_notification_count)
        notifications.listeners.append(self.refresh_notification_count)
        self.refresh_notification_count()

    @property
    def workspace(self) -> QLabel:  # compatibility alias
        return self.heading

    # ---- title / breadcrumbs ----
    def set_page(self, page_id: str) -> None:
        item = find_item(page_id)
        if not item:
            return
        self.heading.setText(item.title)
        cat = category_of(page_id) or ""
        group = cat.title().replace(" Os", " OS")
        self.crumbs.setText(f"WIFI Center  ›  {group}  ›  {item.title}")
        self.subtitle.setText(item.summary)
        self.subtitle.setVisible(bool(item.summary))

    def set_workspace(self, title: str) -> None:  # compatibility with older callers
        self.heading.setText(title)

    # ---- indicators (all driven by real data) ----
    def set_connectivity(self, online: bool) -> None:
        self.net_chip.set_state("Online" if online else "Offline", T.success if online else T.warning)

    def set_wifi(self, text: str, color: str) -> None:
        self.wifi_chip.set_state(text, color)

    def set_operations(self, running: int) -> None:
        if running:
            self.ops_chip.set_state(f"{running} running", T.info, pulse=True)
        else:
            self.ops_chip.set_state("Idle", T.text_muted)

    def set_privileged(self, active: bool, text: str | None = None) -> None:
        self.priv_chip.set_state(text or ("Privileged" if active else "Unprivileged"),
                                 T.warning if active else T.text_muted)

    def refresh_notification_count(self) -> None:
        n = self.notifications.unread()
        self.bell_badge.setText(str(min(n, 99)))
        self.bell_badge.adjustSize()
        self.bell_badge.setVisible(n > 0)
        self.bell_badge.move(self.bell.width() - self.bell_badge.width() - 1, 0)

    def _show_notifications(self) -> None:
        self.panel.popup_at(self.bell.mapToGlobal(QPoint(self.bell.width(), self.bell.height() + 6)))

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self._kb.adjustSize()
        self._kb.move(self.search.width() - self._kb.width() - 10, (self.search.height() - self._kb.height()) // 2)

    def focus_search(self) -> None:
        self.open_palette.emit()
