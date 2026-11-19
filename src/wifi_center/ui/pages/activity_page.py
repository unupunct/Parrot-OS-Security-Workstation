"""Activity Monitor: running and recent operations."""
from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ...application.app_controller import AppController


class ActivityPage(QWidget):
    def __init__(self, app: AppController, on_open: Callable[[int], None]) -> None:
        super().__init__()
        self.app, self._on_open = app, on_open
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Activity Monitor")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.cancel_btn = QPushButton("Cancel selected")
        self.cancel_btn.clicked.connect(self._cancel)
        self.open_btn = QPushButton("Open output")
        self.open_btn.clicked.connect(self._open)
        head.addWidget(self.cancel_btn)
        head.addWidget(self.open_btn)
        lay.addLayout(head)
        self.empty = QLabel("No operations have been started in this session.")
        self.empty.setObjectName("muted")
        lay.addWidget(self.empty)
        cols = ["#", "Operation", "Tool", "Started (UTC)", "Runtime", "Status"]
        self.table = QTableWidget(0, len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.cellDoubleClicked.connect(lambda *_: self._open())
        lay.addWidget(self.table, 1)
        sub = QLabel("Privileged operations (what the helper did for you, from its audit log)")
        sub.setObjectName("muted")
        lay.addWidget(sub)
        self.priv = QTableWidget(0, 4)
        self.priv.setHorizontalHeaderLabels(["Time (UTC)", "Event", "Operation", "Result"])
        self.priv.verticalHeader().setVisible(False)
        self.priv.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.priv.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.priv, 1)
        self._priv_tick = 0
        app.operations.changed.connect(self.refresh)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(1000)
        self.refresh()

    def _selected_id(self) -> int | None:
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return int(it.text()) if it else None

    def _cancel(self) -> None:
        oid = self._selected_id()
        if oid is not None:
            self.app.operations.cancel(oid)

    def _open(self) -> None:
        oid = self._selected_id()
        if oid is not None:
            self._on_open(oid)

    def _refresh_priv(self) -> None:
        b = self.app.privileged
        if not (b.available() and hasattr(b, "recent")):
            self.priv.setRowCount(0)
            return

        def fill(rows: list, err: str) -> None:
            self.priv.setRowCount(len(rows))
            for r, e in enumerate(rows):
                for c, v in enumerate([str(e.get("ts", "")).replace("T", " ")[:19], e.get("event", ""),
                                       e.get("summary", ""), e.get("status", "")]):
                    self.priv.setItem(r, c, QTableWidgetItem(str(v)))
        b.recent(30, fill)

    def refresh(self) -> None:
        self._priv_tick += 1
        if self._priv_tick % 5 == 1:          # the helper is asked every 5 s, not every second
            self._refresh_priv()
        ops = self.app.operations.operations()
        self.empty.setVisible(not ops)
        sel = self._selected_id()
        self.table.setRowCount(len(ops))
        for r, o in enumerate(ops):
            vals = [str(o.id), o.name, o.tool_id or "app", o.started_at.replace("T", " "),
                    f"{o.runtime:.0f}s", o.status + (f" ({o.exit_code})" if o.exit_code not in (None, 0) else "")]
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))
            if sel == o.id:
                self.table.selectRow(r)
