"""Responsive, user-rearrangeable widget board (order and width persisted by the caller)."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QToolButton, QVBoxLayout, QWidget

from .design.tokens import T


def columns_for_width(width: int) -> int:
    return 4 if width >= 1500 else 3 if width >= 1100 else 2 if width >= 760 else 1


class BoardItem(QFrame):
    """Wraps a widget with an edit toolbar that is only visible in edit mode."""

    def __init__(self, item_id: str, title: str, widget: QWidget) -> None:
        super().__init__()
        self.item_id, self.widget = item_id, widget
        self.setObjectName("boardItem")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        self.bar = QWidget()
        bl = QHBoxLayout(self.bar)
        bl.setContentsMargins(4, 0, 4, 0)
        bl.setSpacing(4)
        name = QLabel(title)
        name.setObjectName("faint")
        bl.addWidget(name)
        bl.addStretch(1)
        self.btn_left = self._btn("◀", "Move earlier")
        self.btn_right = self._btn("▶", "Move later")
        self.btn_narrow = self._btn("−", "Narrower")
        self.btn_wide = self._btn("+", "Wider")
        for b in (self.btn_left, self.btn_right, self.btn_narrow, self.btn_wide):
            bl.addWidget(b)
        self.bar.hide()
        lay.addWidget(self.bar)
        lay.addWidget(widget, 1)

    @staticmethod
    def _btn(text: str, tip: str) -> QToolButton:
        b = QToolButton()
        b.setText(text)
        b.setToolTip(tip)
        b.setFixedSize(26, 22)
        return b


class WidgetBoard(QWidget):
    layout_changed = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._items: list[BoardItem] = []
        self._spans: dict[str, int] = {}
        self._cols = 0
        self._edit = False
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(T.gap)

    # ---- content ----
    def add(self, item_id: str, title: str, widget: QWidget, span: int = 1) -> None:
        it = BoardItem(item_id, title, widget)
        it.btn_left.clicked.connect(lambda: self.move(item_id, -1))
        it.btn_right.clicked.connect(lambda: self.move(item_id, 1))
        it.btn_narrow.clicked.connect(lambda: self.resize_item(item_id, -1))
        it.btn_wide.clicked.connect(lambda: self.resize_item(item_id, 1))
        self._items.append(it)
        self._spans[item_id] = span
        self._relayout(force=True)

    def order(self) -> list[str]:
        return [i.item_id for i in self._items]

    def spans(self) -> dict[str, int]:
        return dict(self._spans)

    def layout_state(self) -> list[dict]:
        return [{"id": i.item_id, "span": self._spans[i.item_id]} for i in self._items]

    def apply_state(self, state: list[dict]) -> None:
        """Restore saved order/spans; unknown ids are ignored and new panels keep their default position."""
        known = {i.item_id: i for i in self._items}
        ordered = [known[s["id"]] for s in state if s.get("id") in known]
        rest = [i for i in self._items if i not in ordered]
        self._items = ordered + rest
        for s in state:
            if s.get("id") in known and 1 <= int(s.get("span", 1)) <= 4:
                self._spans[s["id"]] = int(s["span"])
        self._relayout(force=True)

    # ---- editing ----
    def set_edit_mode(self, on: bool) -> None:
        self._edit = on
        for i in self._items:
            i.bar.setVisible(on)

    def move(self, item_id: str, delta: int) -> None:
        idx = next((k for k, i in enumerate(self._items) if i.item_id == item_id), None)
        if idx is None or not 0 <= idx + delta < len(self._items):
            return
        self._items[idx], self._items[idx + delta] = self._items[idx + delta], self._items[idx]
        self._relayout(force=True)
        self.layout_changed.emit()

    def resize_item(self, item_id: str, delta: int) -> None:
        cur = self._spans.get(item_id, 1)
        new = max(1, min(4, cur + delta))
        if new != cur:
            self._spans[item_id] = new
            self._relayout(force=True)
            self.layout_changed.emit()

    # ---- responsive layout ----
    def columns(self) -> int:
        return columns_for_width(self.width())

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self._relayout()

    def _relayout(self, force: bool = False) -> None:
        cols = self.columns()
        if cols == self._cols and not force:
            return
        self._cols = cols
        while self.grid.count():
            self.grid.takeAt(0)
        row = col = 0
        for it in self._items:
            span = min(self._spans.get(it.item_id, 1), cols)
            if col + span > cols:
                row, col = row + 1, 0
            self.grid.addWidget(it, row, col, 1, span)
            col += span
            if col >= cols:
                row, col = row + 1, 0
        for c in range(4):
            self.grid.setColumnStretch(c, 1 if c < cols else 0)
