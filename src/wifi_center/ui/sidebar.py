"""Collapsible navigation sidebar."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem

from .navigation import NAVIGATION

ID_ROLE = Qt.ItemDataRole.UserRole


class Sidebar(QTreeWidget):
    page_selected = Signal(str)

    def __init__(self, collapsed: list[str] | None = None) -> None:
        super().__init__()
        self.setObjectName("sidebar")
        self.setHeaderHidden(True)
        self.setIndentation(10)
        self.setMinimumWidth(190)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._items: dict[str, QTreeWidgetItem] = {}
        self._cats: dict[str, QTreeWidgetItem] = {}
        collapsed = collapsed or []
        bold = QFont(self.font())
        bold.setBold(True)
        bold.setPointSizeF(max(8.0, bold.pointSizeF() - 1))
        for cat in NAVIGATION:
            top = QTreeWidgetItem([cat.title])
            top.setFlags(Qt.ItemFlag.ItemIsEnabled)  # category rows are headers only
            top.setFont(0, bold)
            self.addTopLevelItem(top)
            self._cats[cat.title] = top
            for it in cat.items:
                child = QTreeWidgetItem([it.title])
                child.setData(0, ID_ROLE, it.id)
                child.setToolTip(0, it.summary)
                top.addChild(child)
                self._items[it.id] = child
            top.setExpanded(cat.title not in collapsed)
        self.currentItemChanged.connect(self._on_current)
        self.itemClicked.connect(self._on_clicked)

    def _on_current(self, cur: QTreeWidgetItem | None, _prev) -> None:
        if cur is not None and cur.data(0, ID_ROLE):
            self.page_selected.emit(cur.data(0, ID_ROLE))

    def _on_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        if item.parent() is None:
            item.setExpanded(not item.isExpanded())

    def select_page(self, page_id: str) -> None:
        item = self._items.get(page_id)
        if item is not None:
            item.parent().setExpanded(True)
            self.setCurrentItem(item)

    def collapsed_categories(self) -> list[str]:
        return [t for t, it in self._cats.items() if not it.isExpanded()]
