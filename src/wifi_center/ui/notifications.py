"""Notification centre popup backed by the `notifications` table."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from ..services.notification_service import NotificationService
from .charts import fmt_ts
from .design.components import MatrixButton, StatusDot
from .design.tokens import T


LEVEL_COLOR = {"info": T.info, "success": T.success, "warning": T.warning, "error": T.danger}


class NotificationPanel(QFrame):
    """Popup list of recent notifications (a persistent record, not only toasts)."""

    changed = Signal()

    def __init__(self, service: NotificationService, parent=None) -> None:
        super().__init__(parent, Qt.WindowType.Popup)
        self.service = service
        self.setObjectName("palette")
        self.setFixedWidth(380)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        head = QHBoxLayout()
        t = QLabel("NOTIFICATIONS")
        t.setObjectName("panelTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.mark = MatrixButton("Mark all read")
        self.mark.clicked.connect(self._mark)
        head.addWidget(self.mark)
        lay.addLayout(head)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFixedHeight(320)
        self.body = QWidget()
        self.body_lay = QVBoxLayout(self.body)
        self.body_lay.setContentsMargins(0, 0, 0, 0)
        self.body_lay.setSpacing(8)
        self.scroll.setWidget(self.body)
        lay.addWidget(self.scroll)

    def refresh(self) -> None:
        while self.body_lay.count():
            w = self.body_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        rows = self.service.recent()
        if not rows:
            e = QLabel("You're all caught up.\nOperation results, scan completions and warnings appear here.")
            e.setObjectName("muted")
            e.setWordWrap(True)
            self.body_lay.addWidget(e)
        for r in rows:
            row = QWidget()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            dot = StatusDot(LEVEL_COLOR.get(r["level"], T.info), size=10)
            col = QVBoxLayout()
            title = QLabel(("<b>%s</b>" if not r["read"] else "%s") % r["title"].replace("<", "&lt;"))
            title.setWordWrap(True)
            col.addWidget(title)
            if r["body"]:
                b = QLabel(r["body"])
                b.setObjectName("muted")
                b.setWordWrap(True)
                col.addWidget(b)
            ts = QLabel(fmt_ts(r["created_at"].replace(" ", "T") + "+00:00"))
            ts.setObjectName("faint")
            col.addWidget(ts)
            rl.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
            rl.addLayout(col, 1)
            self.body_lay.addWidget(row)
        self.body_lay.addStretch(1)

    def _mark(self) -> None:
        self.service.mark_all_read()
        self.refresh()
        self.changed.emit()

    def popup_at(self, global_pos) -> None:
        self.refresh()
        self.adjustSize()
        self.move(global_pos.x() - self.width(), global_pos.y())
        self.show()
