"""Contextual top bar: logo, workspace, global search, status, privilege, notifications, settings."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCompleter, QFrame, QHBoxLayout, QLabel, QLineEdit, QMenu,
                               QPushButton, QToolButton)

from ..database.repository import Database
from .navigation import all_items, find_item


class TopBar(QFrame):
    navigate = Signal(str)
    open_settings = Signal()

    def __init__(self, db: Database) -> None:
        super().__init__()
        self.setObjectName("topbar")
        self.setFixedHeight(48)
        self._db = db
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 14, 0)
        lay.setSpacing(12)

        logo = QLabel("WIFI CENTER")
        logo.setObjectName("logo")
        self.workspace = QLabel("Overview")
        self.workspace.setObjectName("workspace")

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search pages…  (Ctrl+K)")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(240)
        self.search.setMaximumWidth(420)
        titles = {f"{i.title}": i.id for i in all_items()}
        self._titles = titles
        comp = QCompleter(list(titles), self.search)
        comp.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        comp.setFilterMode(Qt.MatchFlag.MatchContains)
        self.search.setCompleter(comp)
        comp.activated.connect(self._go)
        self.search.returnPressed.connect(lambda: self._go(self.search.text()))

        self.status = QLabel("●  Starting…")
        self.status.setObjectName("statusPill")
        self.status.setToolTip("Local connectivity (no packets are sent to check this)")
        self.priv = QLabel("Unprivileged")
        self.priv.setObjectName("privPill")
        self.priv.setProperty("active", False)
        self.priv.setToolTip("Privileged session indicator. The GUI always runs as your normal user.")

        self.notif = QToolButton()
        self.notif.setText("Notifications")
        self.notif.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.notif.setMenu(QMenu(self.notif))
        self.notif.menu().aboutToShow.connect(self._fill_notifications)
        self.settings_btn = QPushButton("Settings")
        self.settings_btn.clicked.connect(self.open_settings)

        lay.addWidget(logo)
        lay.addWidget(self.workspace)
        lay.addStretch(1)
        lay.addWidget(self.search, 3)
        lay.addStretch(1)
        for w in (self.status, self.priv, self.notif, self.settings_btn):
            lay.addWidget(w)
        self.refresh_notification_count()

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def set_workspace(self, title: str) -> None:
        self.workspace.setText(title)

    def set_connectivity(self, online: bool) -> None:
        self.status.setText("●  Network up" if online else "●  No network")
        self.status.setStyleSheet("color: %s" % ("#00FF66" if online else "#F2B84B"))

    def _go(self, text: str) -> None:
        page = self._titles.get(text)
        if page is None:  # fall back to first case-insensitive match
            t = text.strip().lower()
            page = next((i.id for i in all_items() if t and t in i.title.lower()), None)
        if page:
            self.navigate.emit(page)
            self.search.clear()

    def refresh_notification_count(self) -> None:
        row = self._db.query_one("SELECT COUNT(*) AS n FROM notifications WHERE read = 0")
        n = row["n"] if row else 0
        self.notif.setText(f"Notifications ({n})" if n else "Notifications")

    def _fill_notifications(self) -> None:
        menu = self.notif.menu()
        menu.clear()
        rows = self._db.query("SELECT id, level, title, created_at, read FROM notifications "
                              "ORDER BY id DESC LIMIT 10")
        if not rows:
            a = menu.addAction("No notifications")
            a.setEnabled(False)
            return
        for r in rows:
            menu.addAction(f"[{r['level']}] {r['title']}  ({r['created_at']})")
        menu.addSeparator()
        menu.addAction("Mark all as read", self._mark_read)

    def _mark_read(self) -> None:
        self._db.execute("UPDATE notifications SET read = 1")
        self.refresh_notification_count()
