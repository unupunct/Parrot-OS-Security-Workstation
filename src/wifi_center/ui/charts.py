"""Themed pyqtgraph helpers and shared table utilities."""
from __future__ import annotations

from datetime import datetime

import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem

BG = "#111B15"
FG = "#8D9C91"
GRID = "#1F2E25"
SERIES = ["#00FF66", "#00D5C8", "#F2B84B", "#4DA3FF", "#F05D5E", "#B58CFF", "#FF8FD1", "#C6E86B"]


def make_plot(title: str = "", x_label: str = "", y_label: str = "") -> pg.PlotWidget:
    p = pg.PlotWidget()
    p.setBackground(BG)
    p.setMenuEnabled(False)
    item = p.getPlotItem()
    if title:
        item.setTitle(title, color=FG, size="10pt")
    for axis in ("left", "bottom"):
        a = item.getAxis(axis)
        a.setPen(pg.mkPen(GRID))
        a.setTextPen(pg.mkPen(FG))
    if x_label:
        item.setLabel("bottom", x_label, color=FG)
    if y_label:
        item.setLabel("left", y_label, color=FG)
    item.showGrid(x=True, y=True, alpha=0.15)
    return p


def color(i: int) -> str:
    return SERIES[i % len(SERIES)]


class NumItem(QTableWidgetItem):
    """Table item that sorts numerically (text shown can differ from the sort key)."""

    def __init__(self, text: str, key: float | None) -> None:
        super().__init__(text)
        self._key = float("-inf") if key is None else float(key)

    def __lt__(self, other: object) -> bool:
        if isinstance(other, NumItem):
            return self._key < other._key
        return super().__lt__(other)  # type: ignore[arg-type]


def make_table(headers: list[str], stretch_last: bool = True) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setAlternatingRowColors(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    t.horizontalHeader().setStretchLastSection(stretch_last)
    return t


def fmt_ts(iso: str | None) -> str:
    """UTC ISO timestamp -> local 'YYYY-MM-DD HH:MM:SS'."""
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return iso


def signal_bars(dbm: float | None) -> str:
    if dbm is None:
        return ""
    n = 4 if dbm >= -55 else 3 if dbm >= -65 else 2 if dbm >= -75 else 1 if dbm >= -85 else 0
    return "▰" * n + "▱" * (4 - n)


def set_align_center(item: QTableWidgetItem) -> QTableWidgetItem:
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    return item
