"""All Tools / Installed Tools / Missing Dependencies: catalog table plus a details panel."""
from __future__ import annotations

import html
from typing import Callable

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
                               QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...integrations.base import Health
from ...integrations.catalog import CATEGORIES
from ...security.operation_policy import PolicyViolation
from ...services.tool_manager import ToolStatus
from ...workers.task import run_in_background

esc = html.escape
HEALTH_COLOR = {Health.OK: "#00FF66", Health.WARNING: "#F2B84B", Health.ERROR: "#F05D5E", Health.MISSING: "#8D9C91"}
TITLES = {"all": "All Tools", "installed": "Installed Tools", "missing": "Missing Dependencies"}


class ToolsPage(QWidget):
    def __init__(self, app: AppController, mode: str, on_operation: Callable[[int], None],
                 on_scanned: Callable[[], None] | None = None) -> None:
        super().__init__()
        self.app, self.mode, self._on_operation, self._on_scanned = app, mode, on_operation, on_scanned
        self._shown: list[ToolStatus] = []
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        title = QLabel(TITLES[mode])
        title.setObjectName("pageTitle")
        head.addWidget(title)
        head.addStretch(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter tools…")
        self.search.setMaximumWidth(220)
        self.search.textChanged.connect(self.reload)
        self.category = QComboBox()
        self.category.addItem("All categories")
        self.category.addItems(CATEGORIES)
        self.category.currentIndexChanged.connect(self.reload)
        self.scan_btn = QPushButton("Scan tools")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setToolTip("Re-detect installations, versions and dependencies (local checks only)")
        self.scan_btn.clicked.connect(self.scan)
        for w in (self.search, self.category, self.scan_btn):
            head.addWidget(w)
        lay.addLayout(head)
        self.note = QLabel("")
        self.note.setObjectName("muted")
        lay.addWidget(self.note)

        split = QSplitter(Qt.Orientation.Horizontal)
        cols = ["Tool", "Category", "Status", "Version", "Health"]
        if mode == "missing":
            cols[3] = "Missing"
        self.table = QTableWidget(0, len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._show_details)
        split.addWidget(self.table)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(lambda u: QDesktopServices.openUrl(u))
        rl.addWidget(self.details, 1)
        self.btn_row = QHBoxLayout()
        rl.addLayout(self.btn_row)
        split.addWidget(right)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 1)
        self.reload()

    # ---- scanning ----
    def scan(self) -> None:
        self.scan_btn.setEnabled(False)
        self.note.setText("Scanning…")
        run_in_background(self.app.tools.scan_all, self._scanned,
                          lambda e: (self.note.setText(f"Scan failed: {e}"), self.scan_btn.setEnabled(True)))

    def _scanned(self, _result) -> None:
        self.scan_btn.setEnabled(True)
        self.reload()
        if self._on_scanned:
            self._on_scanned()

    # ---- table ----
    def _visible(self, statuses: list[ToolStatus]) -> list[ToolStatus]:
        q = self.search.text().strip().lower()
        cat = self.category.currentText() if self.category.currentIndex() > 0 else None
        out = []
        for s in statuses:
            if self.mode == "installed" and not s.installed:
                continue
            if self.mode == "missing" and s.installed and not s.missing_dependencies:
                continue
            if cat and s.profile.category != cat:
                continue
            if q and q not in s.profile.name.lower() and q not in s.profile.description.lower():
                continue
            out.append(s)
        return out

    def reload(self) -> None:
        statuses = self.app.tools.statuses()
        if not statuses:
            self.note.setText("No scan has been run yet. Press “Scan tools” to detect what is installed.")
        else:
            self.note.setText(f"Last scan: {statuses[0].checked_at.replace('T', ' ').removesuffix('+00:00')} UTC · "
                              f"{sum(s.installed for s in statuses)} of {len(statuses)} tools installed")
        selected = self._current_id()
        self._shown = self._visible(statuses)
        self.table.setRowCount(len(self._shown))
        for r, s in enumerate(self._shown):
            if self.mode == "missing":
                miss = [d.dependency.name for d in s.missing_dependencies]
                third = ", ".join(miss) if s.installed else "tool itself"
            else:
                third = s.version or ("—" if s.installed else "")
            cells = [s.profile.name, s.profile.category, "Installed" if s.installed else "Not installed",
                     third, s.health.level.value.title()]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 4:
                    item.setForeground(QColor(HEALTH_COLOR[s.health.level]))
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, s.profile.id)
                self.table.setItem(r, c, item)
            if s.profile.id == selected:
                self.table.selectRow(r)
        if not self._shown:
            self.details.setHtml("<p style='color:#8D9C91'>No tools to show"
                                 + ("." if statuses else " until a scan has run.") + "</p>")
            self._clear_buttons()
        elif self.table.currentRow() < 0:
            self.table.selectRow(0)

    def _current_id(self) -> str | None:
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def _current(self) -> ToolStatus | None:
        tid = self._current_id()
        return next((s for s in self._shown if s.profile.id == tid), None)

    # ---- details ----
    def _clear_buttons(self) -> None:
        while self.btn_row.count():
            w = self.btn_row.takeAt(0).widget()
            if w:
                w.deleteLater()

    def _show_details(self) -> None:
        s = self._current()
        self._clear_buttons()
        if s is None:
            return
        p = s.profile
        muted = lambda t: f"<span style='color:#8D9C91'>{t}</span>"
        color = HEALTH_COLOR[s.health.level]
        h = [f"<h2>{esc(p.name)}</h2><p>{esc(p.description)}</p>",
             f"<p><b style='color:{color}'>{esc(s.health.level.value.title())}</b> — {esc(s.health.detail)}</p>"]
        if p.restricted:
            h.append(f"<p style='color:#F2B84B'><b>Restricted integration.</b> {esc(p.restriction_note)}</p>")
        rows = [("Category", p.category), ("Executable", ", ".join(p.executables) or "—"),
                ("Install path", s.detection.path or ("installed via package manager" if s.installed else "—")),
                ("Detected via", s.detection.via or "—"), ("Version", s.version or "unknown"),
                ("License", p.license or "—"), ("Compatibility", p.compatibility),
                ("Last health check", s.checked_at.replace("T", " ") + " UTC" if s.checked_at else "—"),
                ("Launch methods", ", ".join(m.value for m in p.launch_methods) or "none (by design)" if p.restricted
                 else ", ".join(m.value for m in p.launch_methods) or "none yet")]
        h.append("<table cellpadding='3'>" + "".join(
            f"<tr><td>{muted(esc(k))}</td><td>{esc(v)}</td></tr>" for k, v in rows) + "</table>")
        if s.dependencies:
            h.append("<h4>Dependencies</h4><ul>" + "".join(
                f"<li>{'✔' if d.satisfied else ('○' if d.dependency.optional else '✖')} "
                f"{esc(d.dependency.name)}{' (optional)' if d.dependency.optional else ''} — {muted(esc(d.detail))}"
                f"{' · ' + muted(esc(d.dependency.purpose)) if d.dependency.purpose else ''}</li>"
                for d in s.dependencies) + "</ul>")
        h.append("<h4>Capabilities</h4><ul>" + "".join(
            f"<li>{esc(c)}</li>" for c in self.app.tools.integration(p.id).get_capabilities()) + "</ul>")
        h.append(f"<h4>Installation</h4><pre>{esc(p.install_hint)}</pre>"
                 f"{muted('Shown for reference. WIFI Center does not install packages until the privileged helper (Phase 8) is in place.')}")
        h.append(f"<p><a href='{esc(p.docs_url)}'>Documentation</a> · <a href='{esc(p.source_url)}'>Source</a></p>")
        last = self.app.db.query_one("SELECT name, status, started_at FROM operations WHERE tool_id = ? "
                                     "ORDER BY id DESC LIMIT 1", (p.id,))
        h.append("<h4>Last operation</h4>" + (f"{esc(last['name'])} — {esc(last['status'])} "
                 f"{muted(esc(last['started_at']))}" if last else muted("none")))
        self.details.setHtml("".join(h))

        for op in p.operations:
            b = QPushButton(op.title)
            b.setToolTip(op.description)
            b.setEnabled(s.installed)
            b.clicked.connect(lambda _=False, o=op.id: self._run(s, o))
            self.btn_row.addWidget(b)
        cp = QPushButton("Copy install command")
        cp.clicked.connect(lambda: QGuiApplication.clipboard().setText(p.install_hint))
        self.btn_row.addWidget(cp)
        self.btn_row.addStretch(1)

    def _run(self, s: ToolStatus, op_id: str) -> None:
        try:
            integ = self.app.tools.integration(s.profile.id)
            req = integ.launch_supported_operation(op_id, None)
            oid = self.app.operations.start(s.profile, req)
        except (ValueError, PolicyViolation) as e:
            self.note.setText(f"Cannot run: {e}")
            return
        self._on_operation(oid)
