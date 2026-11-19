"""Honest placeholder for pages whose development phase has not shipped yet."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from ..navigation import NavItem


class PlannedPage(QWidget):
    def __init__(self, item: NavItem) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addStretch(1)
        t = QLabel(item.title)
        t.setObjectName("pageTitle")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        s = QLabel(item.summary)
        s.setObjectName("muted")
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        n = QLabel(f"Not implemented yet — scheduled for development phase {item.phase}.\n"
                   "Nothing on this page is simulated.")
        n.setAlignment(Qt.AlignmentFlag.AlignCenter)
        n.setObjectName("warn")
        for w in (t, s, n):
            lay.addWidget(w)
        lay.addStretch(2)
