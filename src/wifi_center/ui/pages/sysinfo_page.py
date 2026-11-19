"""System Information, Speccy-style: a category list on the left, a summary of every component (with live temperature
badges and usage bars) and a detail view per component on the right. Read-only; nothing here needs or asks for root."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QFrame, QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QProgressBar,
                               QScrollArea, QSplitter, QStackedWidget, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services.hardware_info import Group, Section, temp_level
from ...workers.task import run_in_background
from ..design.components import LoadingIndicator, MatrixButton
from ..design.icons import icon_pixmap
from ..design.tokens import T
from .parrot_pages import SystemInfoPage as OsServicesPage

esc = html.escape
LEVEL_COLOR = {"ok": T.green, "warm": T.warning, "hot": T.danger, "none": T.text_muted}


def temp_badge(t: float | None) -> QLabel | None:
    if t is None:
        return None
    c = LEVEL_COLOR[temp_level(t)]
    lbl = QLabel(f"{t:.0f} °C")
    lbl.setStyleSheet(f"color: {c}; border: 1px solid {c}; border-radius: 9px; padding: 1px 9px; font-weight: 700;")
    lbl.setToolTip("Reported by the kernel's hardware monitor. Green is normal, amber warm, red hot.")
    return lbl


def usage_bar(percent: float) -> QProgressBar:
    bar = QProgressBar()
    bar.setRange(0, 1000)
    bar.setValue(int(max(0.0, min(100.0, percent)) * 10))
    bar.setTextVisible(False)
    bar.setFixedHeight(8)
    c = T.green if percent < 75 else T.warning if percent < 90 else T.danger
    bar.setStyleSheet(f"QProgressBar {{ background: #0B120D; border: 1px solid {T.border}; border-radius: 4px; }}"
                      f"QProgressBar::chunk {{ background: {c}; border-radius: 3px; }}")
    return bar


class SummaryCard(QFrame):
    """One component on the summary page: icon, name in accent colour, headline, temperature badge."""

    def __init__(self, section: Section, on_open) -> None:
        super().__init__()
        self.setObjectName("panel")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._open = on_open
        self._id = section.id
        row = QHBoxLayout(self)
        row.setContentsMargins(16, 12, 16, 12)
        ic = QLabel()
        ic.setPixmap(icon_pixmap(section.icon, T.green, 28, 2.0))
        ic.setFixedWidth(40)
        row.addWidget(ic)
        col = QVBoxLayout()
        col.setSpacing(2)
        title = QLabel(section.title.upper())
        title.setStyleSheet(f"color: {T.green}; font-weight: 800; letter-spacing: 1px; font-size: 11px;")
        head = QLabel(section.headline)
        head.setStyleSheet("font-size: 14px; font-weight: 600;")
        head.setWordWrap(True)
        head.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        col.addWidget(title)
        col.addWidget(head)
        # one supporting line from the first group, like Speccy's sub-lines
        sub = next((g for g in section.groups if g.items), None)
        if sub and section.id in ("graphics", "storage", "optical", "audio", "peripherals", "network", "board"):
            extra = [f"{i.label}: {i.value}" for i in sub.items[:3] if i.value]
            if extra:
                s = QLabel("  ·  ".join(extra))
                s.setObjectName("muted")
                s.setWordWrap(True)
                col.addWidget(s)
        bar = next((g.bar for g in section.groups if g.bar is not None), None)
        if section.id in ("cpu", "memory") and bar is not None:
            col.addWidget(usage_bar(bar))
        row.addLayout(col, 1)
        b = temp_badge(section.temp)
        if b:
            row.addWidget(b, 0, Qt.AlignmentFlag.AlignTop)

    def mousePressEvent(self, e) -> None:  # noqa: N802
        self._open(self._id)
        super().mousePressEvent(e)


class GroupBox(QFrame):
    def __init__(self, g: Group) -> None:
        super().__init__()
        self.setObjectName("panel")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        top = QHBoxLayout()
        t = QLabel(g.title)
        t.setStyleSheet(f"color: {T.green}; font-weight: 700; font-size: 13px;")
        t.setWordWrap(True)
        top.addWidget(t, 1)
        b = temp_badge(g.temp)
        if b:
            top.addWidget(b)
        lay.addLayout(top)
        if g.bar is not None:
            lay.addWidget(usage_bar(g.bar))
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(4)
        for r, it in enumerate(g.items):
            k = QLabel(it.label)
            k.setObjectName("muted")
            v = QLabel(it.value or "—")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(k, r, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(v, r, 1)
        grid.setColumnStretch(1, 1)
        lay.addLayout(grid)


def _scroll(inner: QWidget) -> QScrollArea:
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.Shape.NoFrame)
    sa.setStyleSheet("QScrollArea { background: transparent; border: none; }")
    sa.viewport().setAutoFillBackground(False)
    inner.setObjectName("siInner")
    inner.setStyleSheet("#siInner { background: transparent; }")
    sa.setWidget(inner)
    return sa


class SystemInfoPage(QWidget):
    OS_ENTRY = "OS and services"

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.sections: list[Section] = []
        self._busy = False
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("System Information")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("ring", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        self.stamp = QLabel("")
        self.stamp.setObjectName("muted")
        head.addWidget(self.stamp)
        b = MatrixButton("Refresh", icon_name="reset")
        b.clicked.connect(self.refresh)
        head.addWidget(b)
        lay.addLayout(head)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.nav = QListWidget()
        self.nav.setMaximumWidth(230)
        self.nav.setMinimumWidth(180)
        self.nav.currentRowChanged.connect(self._select)
        split.addWidget(self.nav)
        self.stack = QStackedWidget()
        split.addWidget(self.stack)
        split.setStretchFactor(1, 1)
        split.setChildrenCollapsible(False)
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setObjectName("muted")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)

        self.os_page = OsServicesPage(app)             # the existing OS / storage / services / repositories tabs
        self._timer = QTimer(self)
        self._timer.setInterval(8000)
        self._timer.timeout.connect(self._auto)
        self._timer.start()
        self.refresh()

    # ------------------------------------------------------------------ loading
    def _auto(self) -> None:
        if self.isVisible() and not self._busy:
            self.refresh(quiet=True)

    def refresh(self, quiet: bool = False) -> None:
        if self._busy:
            return
        self._busy = True
        if not quiet:
            self.loader.start()
        run_in_background(self.app.hwinfo.collect, self._show, self._failed)

    def _failed(self, err: str) -> None:
        self._busy = False
        self.loader.stop()
        self.msg.setText(f"Could not read the hardware: {err}")

    def _show(self, sections: list[Section]) -> None:
        self._busy = False
        self.loader.stop()
        self.sections = sections
        keep = self.nav.currentRow()
        cur = self.stack.currentWidget()
        scroll_pos = cur.verticalScrollBar().value() if isinstance(cur, QScrollArea) else 0
        self.nav.blockSignals(True)
        self.nav.clear()
        for name, icon in [("Summary", "dashboard")] + [(s.title, s.icon) for s in sections] + [(self.OS_ENTRY, "info")]:
            it = QListWidgetItem(name)
            it.setIcon(QIcon(icon_pixmap(icon, T.green, 18, 2.0)))
            self.nav.addItem(it)
        self.nav.blockSignals(False)
        while self.stack.count():
            w = self.stack.widget(0)
            self.stack.removeWidget(w)
            if w is not self.os_page:
                w.deleteLater()
        summary = QWidget()
        sl = QVBoxLayout(summary)
        sl.setSpacing(10)
        for s in sections:
            sl.addWidget(SummaryCard(s, self.open_section))
        sl.addStretch(1)
        self.stack.addWidget(_scroll(summary))
        for s in sections:
            page = QWidget()
            pl = QVBoxLayout(page)
            pl.setSpacing(10)
            title = QLabel(s.title)
            title.setStyleSheet("font-size: 18px; font-weight: 700;")
            pl.addWidget(title)
            hl = QLabel(s.headline)
            hl.setObjectName("muted")
            hl.setWordWrap(True)
            pl.addWidget(hl)
            if not s.groups:
                pl.addWidget(QLabel("Nothing to show: the kernel reports no device of this kind."))
            for g in s.groups:
                pl.addWidget(GroupBox(g))
            if s.note:
                n = QLabel(s.note)
                n.setObjectName("muted")
                n.setWordWrap(True)
                pl.addWidget(n)
            pl.addStretch(1)
            self.stack.addWidget(_scroll(page))
        self.stack.addWidget(self.os_page)
        self.nav.setCurrentRow(keep if 0 <= keep < self.nav.count() else 0)
        self.stack.setCurrentIndex(max(self.nav.currentRow(), 0))
        new = self.stack.currentWidget()
        if isinstance(new, QScrollArea) and scroll_pos:
            QTimer.singleShot(0, lambda: new.verticalScrollBar().setValue(scroll_pos))
        from datetime import datetime
        self.stamp.setText("Updated " + datetime.now().strftime("%H:%M:%S") + " · refreshes every 8 s")
        self.msg.setText("")

    def _select(self, row: int) -> None:
        if 0 <= row < self.stack.count():
            self.stack.setCurrentIndex(row)

    def open_section(self, section_id: str) -> None:
        for i, s in enumerate(self.sections, start=1):
            if s.id == section_id:
                self.nav.setCurrentRow(i)
                return
