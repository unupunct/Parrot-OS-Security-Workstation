"""Tool Universe: responsive card grid of every supported tool plus a detail panel.

Only actions the integration really supports are shown (launch / version come from the profile's declared
operations; restricted tools get none). Status badges reflect the last real scan.
"""
from __future__ import annotations

import html
from typing import Callable

from PySide6.QtCore import QEvent, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                               QScrollArea, QSizePolicy, QSplitter, QTextBrowser, QToolButton, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...integrations.base import Health, LaunchMethod
from ...integrations.catalog import CATEGORIES
from ...security.operation_policy import PolicyViolation
from ...services.tool_manager import ToolStatus
from ...workers.task import run_in_background
from ..design.components import Badge, LoadingIndicator, MatrixButton
from ..design.icons import icon_pixmap
from ..design.tokens import T

esc = html.escape
TITLES = {"all": "Tool Universe", "installed": "Installed Tools", "missing": "Missing Dependencies"}
CATEGORY_ICON = {CATEGORIES[0]: "wifi", CATEGORIES[1]: "bluetooth", CATEGORIES[2]: "discovery", CATEGORIES[3]: "web",
                 CATEGORIES[4]: "shield", CATEGORIES[5]: "key", CATEGORIES[6]: "network", CATEGORIES[7]: "tools"}
HEALTH_COLOR = {Health.OK: T.success, Health.WARNING: T.warning, Health.ERROR: T.danger, Health.MISSING: T.text_muted}
STATUS_FILTERS = ["All status", "Installed", "Missing", "Needs attention"]
SORTS = ["Name", "Category", "Status"]


def status_of(s: ToolStatus) -> str:
    if not s.installed:
        return "missing"
    return "attention" if s.health.level in (Health.WARNING, Health.ERROR) else "installed"


class ToolCard(QFrame):
    clicked = Signal(str)
    favorite_toggled = Signal(str)

    def __init__(self, status: ToolStatus, favorite: bool) -> None:
        super().__init__()
        self.tool_id = status.profile.id
        self.setObjectName("toolCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(140)             # every card the same height, whatever its text
        self.setMinimumWidth(220)
        self.setProperty("selected", False)
        p = status.profile
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 12, 12)
        lay.setSpacing(6)
        top = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon_pixmap(CATEGORY_ICON.get(p.category, "tools"), T.green if status.installed else T.text_muted,
                                 26, 2.0))
        top.addWidget(ic)
        name = QLabel(p.name)
        name.setStyleSheet("font-weight: 700; font-size: 14px;")
        name.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        top.addWidget(name, 1)
        if p.restricted:
            r = QLabel()
            r.setPixmap(icon_pixmap("shield", T.warning, 16, 2.0))
            r.setToolTip("Restricted integration: " + p.restriction_note)
            r.setFixedWidth(18)
            top.addWidget(r)
        self.star = QToolButton()
        self.star.setText("★" if favorite else "☆")
        self.star.setToolTip("Favorite")
        self.star.setFixedSize(26, 24)
        self.star.setStyleSheet(f"QToolButton {{ border: none; background: transparent; color: "
                                f"{T.warning if favorite else T.text_muted}; font-size: 15px; }}")
        self.star.clicked.connect(lambda: self.favorite_toggled.emit(self.tool_id))
        top.addWidget(self.star)
        lay.addLayout(top)
        text = p.description if len(p.description) <= 84 else p.description[:81].rstrip() + "…"
        desc = QLabel(text)
        desc.setObjectName("muted")
        desc.setWordWrap(True)
        desc.setToolTip(p.description)
        desc.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        desc.setMinimumHeight(36)
        lay.addWidget(desc)
        lay.addStretch(1)
        bottom = QHBoxLayout()
        cat = QLabel(p.category)
        cat.setObjectName("faint")
        cat.setToolTip(p.category)
        cat.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)  # may shrink; never forces width
        bottom.addWidget(cat, 1)
        st = status_of(status)
        text, level = {"installed": ("Installed", "info"), "attention": ("Needs attention", "warning"),
                       "missing": ("Missing", "error")}[st]
        if st == "missing":
            lbl = QLabel("Not installed")
            lbl.setObjectName("faint")
            bottom.addWidget(lbl)
        else:
            if status.version:
                v = QLabel(status.version[:18])
                v.setObjectName("faint")
                bottom.addWidget(v)
            bottom.addWidget(Badge(text, level))
        lay.addLayout(bottom)

    def set_selected(self, on: bool) -> None:
        self.setProperty("selected", on)
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, e) -> None:  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.tool_id)
        super().mousePressEvent(e)


class ToolDetailPanel(QFrame):
    """Detail view; buttons are created only for operations the integration supports."""

    run_requested = Signal(str, str)         # tool id, operation id
    configure_requested = Signal(str)
    check_requested = Signal(str)

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.setObjectName("panel")
        self.buttons: dict[str, QPushButton] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        self.view = QTextBrowser()
        self.view.setOpenLinks(False)
        self.view.anchorClicked.connect(QDesktopServices.openUrl)
        self.view.setFrameShape(QFrame.Shape.NoFrame)
        self.view.setStyleSheet("background: transparent; border: none;")
        lay.addWidget(self.view, 1)
        self.row = QGridLayout()
        self.row.setSpacing(8)
        lay.addLayout(self.row)
        self.show_empty()

    def text(self) -> str:
        return self.view.toPlainText()

    def show_empty(self) -> None:
        self._clear()
        self.view.setHtml(f"<p style='color:{T.text_secondary}'>Select a tool to see its status, dependencies and "
                          "supported actions.</p>")

    def _clear(self) -> None:
        self.buttons.clear()
        while self.row.count():
            w = self.row.takeAt(0).widget()
            if w:
                w.deleteLater()

    def _add_button(self, key: str, b: QPushButton) -> None:
        n = len(self.buttons)
        self.row.addWidget(b, n // 2, n % 2)
        self.buttons[key] = b

    def _button(self, key: str, text: str, icon_name: str, slot, tip: str = "") -> None:
        b = MatrixButton(text, "default", icon_name)
        b.setToolTip(tip)
        b.clicked.connect(slot)
        self._add_button(key, b)

    def show_status(self, s: ToolStatus) -> None:
        self._clear()
        p = s.profile
        muted = lambda t: f"<span style='color:{T.text_secondary}'>{t}</span>"
        color = HEALTH_COLOR[s.health.level]
        h = [f"<h2 style='margin:0'>{esc(p.name)}</h2><p style='color:{T.text_secondary}'>{esc(p.description)}</p>",
             f"<p><b style='color:{color}'>{esc(s.health.level.value.title())}</b> — {esc(s.health.detail)}</p>"]
        if p.restricted:
            h.append(f"<p style='color:{T.warning}'><b>Restricted integration.</b> {esc(p.restriction_note)}</p>")
        methods = ", ".join(m.value for m in p.launch_methods) or ("none (by design)" if p.restricted else "none yet")
        when = s.checked_at.replace("T", " ").removesuffix("+00:00") + " UTC" if s.checked_at else "—"
        rows = [("Category", p.category), ("Version", s.version or "unknown"),
                ("Executable", ", ".join(p.executables) or "—"),
                ("Install path", s.detection.path or ("via package manager" if s.installed else "—")),
                ("Detected via", s.detection.via or "—"), ("License", p.license or "—"),
                ("Compatibility", p.compatibility), ("Launch methods", methods), ("Last health check", when)]
        h.append("<table cellpadding='3'>" + "".join(
            f"<tr><td>{muted(esc(k))}</td><td>{esc(v)}</td></tr>" for k, v in rows) + "</table>")
        if s.dependencies:
            h.append("<h4>Dependencies</h4><ul>" + "".join(
                f"<li>{'✔' if d.satisfied else ('○' if d.dependency.optional else '✖')} "
                f"{esc(d.dependency.name)}{' (optional)' if d.dependency.optional else ''} — {muted(esc(d.detail))}"
                f"{' · ' + muted(esc(d.dependency.purpose)) if d.dependency.purpose else ''}</li>"
                for d in s.dependencies) + "</ul>")
        if s.config:
            h.append("<h4>Configuration</h4><ul>" + "".join(
                f"<li>{muted(esc(k))}: {esc(v)}</li>" for k, v in s.config.items()) + "</ul>")
        h.append("<h4>Capabilities</h4><ul>" + "".join(
            f"<li>{esc(c)}</li>" for c in self.app.tools.integration(p.id).get_capabilities()) + "</ul>")
        h.append(f"<h4>Installation</h4><pre>{esc(p.install_hint)}</pre>"
                 + muted("Shown for reference: WIFI Center never installs tools silently. Packages can be installed from "
                         "the Package Manager (through the privileged helper, with a confirmation), or run the command yourself."))
        recent = self.app.db.query("SELECT name, status, started_at FROM operations WHERE tool_id = ? "
                                   "ORDER BY id DESC LIMIT 3", (p.id,))
        h.append("<h4>Recent activity</h4>" + ("<br>".join(
            f"{esc(r['name'])} — {esc(r['status'])} {muted(esc(r['started_at']))}" for r in recent) or muted("none")))
        self.view.setHtml("".join(h))

        for op in p.operations:  # only operations the integration declares (parameterised ones live in their workspace)
            if op.dynamic:
                continue
            desktop = op.method == LaunchMethod.DESKTOP
            b = MatrixButton(op.title, "primary" if desktop else "default", "launch" if desktop else "info")
            b.setToolTip(op.description)
            b.setEnabled(s.installed)
            b.clicked.connect(lambda _=False, t=p.id, o=op.id: self.run_requested.emit(t, o))
            self._add_button("launch" if desktop else op.id, b)
        self._button("configure", "Configure", "config", lambda: self.configure_requested.emit(p.id),
                     "Set a custom executable or install folder")
        self._button("check", "Check dependencies", "installed", lambda: self.check_requested.emit(p.id),
                     "Re-detect this tool")
        self._button("docs", "Open documentation", "docs", lambda: QDesktopServices.openUrl(QUrl(p.docs_url)),
                     p.docs_url)
        self._button("copy", "Copy install command", "package",
                     lambda: QGuiApplication.clipboard().setText(p.install_hint))


class ToolsPage(QWidget):
    CARD_WIDTH = 300

    def __init__(self, app: AppController, mode: str, on_operation: Callable[[int], None],
                 on_scanned: Callable[[], None] | None = None,
                 on_configure: Callable[[str], None] | None = None) -> None:
        super().__init__()
        self.app, self.mode = app, mode
        self._on_operation, self._on_scanned = on_operation, on_scanned
        self._on_configure = on_configure or (lambda _t: None)
        self.cards: dict[str, ToolCard] = {}
        self._visible_ids: list[str] = []
        self._selected: str | None = None
        self._cols = 0
        self._favorites = set(app.settings.get("ui.favorite_tools"))

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        title = QLabel(TITLES[mode])
        title.setObjectName("pageTitle")
        head.addWidget(title)
        self.loader = LoadingIndicator("nodes", 16)
        head.addWidget(self.loader)
        head.addStretch(1)
        self.scan_btn = MatrixButton("Scan tools", "primary", "reset")
        self.scan_btn.setToolTip("Re-detect installations, versions and dependencies (local checks only)")
        self.scan_btn.clicked.connect(self.scan)
        head.addWidget(self.scan_btn)
        lay.addLayout(head)

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search tools…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.reload)
        self.category = QComboBox()
        self.category.addItem("All categories")
        self.category.addItems(CATEGORIES)
        self.category.currentIndexChanged.connect(self.reload)
        self.status_filter = QComboBox()
        self.status_filter.addItems(STATUS_FILTERS)
        self.status_filter.setCurrentIndex({"all": 0, "installed": 1, "missing": 2}[mode])
        self.status_filter.currentIndexChanged.connect(self.reload)
        self.sort = QComboBox()
        self.sort.addItems([f"Sort: {s}" for s in SORTS])
        self.sort.currentIndexChanged.connect(self.reload)
        self.fav_only = QPushButton("★ Favorites")
        self.fav_only.setCheckable(True)
        self.fav_only.toggled.connect(self.reload)
        bar.addWidget(self.search, 2)
        for w in (self.category, self.status_filter, self.sort, self.fav_only):
            bar.addWidget(w)
        lay.addLayout(bar)
        self.note = QLabel("")
        self.note.setObjectName("muted")
        lay.addWidget(self.note)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.grid_host = QWidget()
        self.scroll.setWidget(self.grid_host)
        self.grid_host.setAutoFillBackground(False)
        self.grid = QGridLayout(self.grid_host)
        self.grid.setContentsMargins(0, 0, 8, 0)
        self.grid.setSpacing(T.gap)
        self.empty = QLabel("")
        self.empty.setObjectName("muted")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll.viewport().installEventFilter(self)   # re-flow the card grid when the viewport resizes
        split.addWidget(self.scroll)
        self.detail = ToolDetailPanel(app)
        self.detail.run_requested.connect(self._run)
        self.detail.configure_requested.connect(self._on_configure)
        self.detail.check_requested.connect(self._check)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([700, 480])
        lay.addWidget(split, 1)
        self.reload()

    # ---- scanning ----
    def scan(self) -> None:
        self.scan_btn.setEnabled(False)
        self.loader.start()
        self.note.setText("Scanning…")
        run_in_background(self.app.tools.scan_all, self._scanned,
                          lambda e: (self.note.setText(f"Scan failed: {e}"), self.scan_btn.setEnabled(True),
                                     self.loader.stop()))

    def _scanned(self, _result) -> None:
        self.scan_btn.setEnabled(True)
        self.loader.stop()
        self.reload()
        if self._on_scanned:
            self._on_scanned()

    def _check(self, tool_id: str) -> None:
        def done(_s) -> None:
            self.loader.stop()
            self.reload()
            if self._on_scanned:
                self._on_scanned()
        self.loader.start()
        run_in_background(lambda: self.app.tools.scan_tool(tool_id), done,
                          lambda e: (self.loader.stop(), self.note.setText(f"Check failed: {e}")))

    # ---- filtering / grid ----
    def _matches(self, s: ToolStatus) -> bool:
        st = status_of(s)
        idx = self.status_filter.currentIndex()
        if (idx == 1 and st == "missing") or (idx == 2 and st != "missing") or (idx == 3 and st != "attention"):
            return False
        if self.category.currentIndex() > 0 and s.profile.category != self.category.currentText():
            return False
        if self.fav_only.isChecked() and s.profile.id not in self._favorites:
            return False
        q = self.search.text().strip().lower()
        return not q or q in s.profile.name.lower() or q in s.profile.description.lower() \
            or q in s.profile.category.lower()

    def _sorted(self, items: list[ToolStatus]) -> list[ToolStatus]:
        key = {0: lambda s: s.profile.name.lower(), 1: lambda s: (s.profile.category, s.profile.name.lower()),
               2: lambda s: ({"attention": 0, "installed": 1, "missing": 2}[status_of(s)], s.profile.name.lower())}
        out = sorted(items, key=key[self.sort.currentIndex()])
        return sorted(out, key=lambda s: s.profile.id not in self._favorites)  # favorites first (stable)

    def visible_ids(self) -> list[str]:
        return list(self._visible_ids)

    def reload(self) -> None:
        statuses = self.app.tools.statuses()
        if not statuses:
            self.note.setText("No scan has been run yet. Press “Scan tools” to detect what is installed.")
        else:
            when = statuses[0].checked_at.replace("T", " ").removesuffix("+00:00")
            self.note.setText(f"Last scan {when} UTC · {sum(s.installed for s in statuses)} of {len(statuses)} "
                              "tools installed")
        shown = self._sorted([s for s in statuses if self._matches(s)])
        self._visible_ids = [s.profile.id for s in shown]
        while self.grid.count():
            w = self.grid.takeAt(0).widget()
            if w is not None and w is not self.empty:
                w.deleteLater()
        self.cards = {}
        for s in shown:
            card = ToolCard(s, s.profile.id in self._favorites)
            card.clicked.connect(self.select_tool)
            card.favorite_toggled.connect(self._toggle_favorite)
            self.cards[s.profile.id] = card
        self._cols = 0
        self._layout_cards()
        if not shown:
            self.empty.setText("No tools match your filters." if statuses else "Run a scan to see your tools.")
            self.grid.addWidget(self.empty, 0, 0)
            self.empty.show()
        else:
            self.empty.hide()
        if self._selected in self.cards:
            self.cards[self._selected].set_selected(True)
            self._show_detail(self._selected)
        elif shown:
            self.select_tool(shown[0].profile.id)
        else:
            self._selected = None
            self.detail.show_empty()

    def _layout_cards(self) -> None:
        cols = max(1, (self.scroll.viewport().width() - 8) // self.CARD_WIDTH)
        if cols == self._cols and self.grid.count() == len(self.cards):
            return
        self._cols = cols
        while self.grid.count():
            self.grid.takeAt(0)
        for i, sid in enumerate(self._visible_ids):
            self.grid.addWidget(self.cards[sid], i // cols, i % cols)
        for c in range(8):  # reset stale stretch from a previous (wider) layout
            self.grid.setColumnStretch(c, 1 if c < cols else 0)
        rows = (len(self._visible_ids) + cols - 1) // cols
        for r in range(max(rows + 2, 60)):   # reset stale stretch: only the spacer row below the cards may grow
            self.grid.setRowStretch(r, 1 if r == rows else 0)

    def eventFilter(self, obj, ev) -> bool:  # noqa: N802
        if obj is self.scroll.viewport() and ev.type() == QEvent.Type.Resize and self.cards:
            self._layout_cards()
        return super().eventFilter(obj, ev)

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        if self.cards:
            self._layout_cards()

    # ---- selection ----
    def select_tool(self, tool_id: str) -> None:
        if tool_id not in self.cards:  # clear filters so a palette jump always lands on the tool
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
            self.category.blockSignals(True)
            self.category.setCurrentIndex(0)
            self.category.blockSignals(False)
            self.status_filter.blockSignals(True)
            self.status_filter.setCurrentIndex(0)
            self.status_filter.blockSignals(False)
            self.fav_only.blockSignals(True)
            self.fav_only.setChecked(False)
            self.fav_only.blockSignals(False)
            self._selected = tool_id
            self.reload()
            return
        if self._selected in self.cards:
            self.cards[self._selected].set_selected(False)
        self._selected = tool_id
        self.cards[tool_id].set_selected(True)
        self.scroll.ensureWidgetVisible(self.cards[tool_id])
        self._show_detail(tool_id)

    def _show_detail(self, tool_id: str) -> None:
        s = self.app.tools.cached(tool_id)
        if s:
            self.detail.show_status(s)

    def _toggle_favorite(self, tool_id: str) -> None:
        self._favorites ^= {tool_id}
        self.app.settings.set("ui.favorite_tools", sorted(self._favorites))
        self.reload()

    def _run(self, tool_id: str, op_id: str) -> None:
        s = self.app.tools.cached(tool_id)
        try:
            integ = self.app.tools.integration(tool_id)
            req = integ.launch_supported_operation(op_id, None)
            oid = self.app.operations.start(s.profile if s else self.app.tools.profile(tool_id), req)
        except (ValueError, PolicyViolation) as e:
            self.note.setText(f"Cannot run: {e}")
            return
        self._on_operation(oid)
