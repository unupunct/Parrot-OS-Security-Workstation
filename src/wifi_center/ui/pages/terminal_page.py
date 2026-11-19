"""Integrated Terminal: the application's operation log viewer (not a general-purpose shell)."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QGuiApplication, QTextCharFormat, QTextCursor, QTextDocument
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPlainTextEdit, QPushButton, QSplitter, QVBoxLayout,
                               QWidget)

from ...application.app_controller import AppController
from ...services.operation_manager import OperationState
from ..design.tokens import T

COLORS = {"stdout": T.text, "stderr": T.danger, "info": T.cyan}
STATUS_COLOR = {"running": T.info, "succeeded": T.green, "launched": T.green, "failed": T.danger,
                "cancelled": T.warning, "timeout": T.warning, "interrupted": T.warning}


class TerminalPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.ops = app.operations
        self._current: int | None = None
        lay = QVBoxLayout(self)
        t = QLabel("Integrated Terminal")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        sub = QLabel("Operation log: output of operations started by WIFI Center. This is not a general-purpose "
                     "shell; nothing typed here is executed.")
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        lay.addWidget(sub)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.list = QListWidget()
        self.list.setMinimumWidth(240)
        self.list.currentRowChanged.connect(self._select)
        split.addWidget(self.list)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.meta = QLabel("No operation selected.")
        self.meta.setObjectName("muted")
        self.meta.setWordWrap(True)
        rl.addWidget(self.meta)
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search output (Enter = next)")
        self.search.returnPressed.connect(self._find)
        self.search_msg = QLabel("")
        self.search_msg.setObjectName("muted")
        self.cancel_btn = QPushButton("Cancel operation")
        self.cancel_btn.clicked.connect(self._cancel)
        copy = QPushButton("Copy output")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.view.toPlainText()))
        save = QPushButton("Save log…")
        save.clicked.connect(self._save)
        for w in (self.search, self.search_msg, self.cancel_btn, copy, save):
            bar.addWidget(w)
        rl.addLayout(bar)
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(MAX_BLOCKS)
        self.view.setStyleSheet("font-family: 'JetBrains Mono','DejaVu Sans Mono','Consolas',monospace;")
        rl.addWidget(self.view, 1)
        split.addWidget(right)
        split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)

        self._ids: list[int] = []
        self.ops.started.connect(lambda _id: self._refresh_list(select=_id))
        self.ops.output.connect(self._on_output)
        self.ops.finished.connect(lambda *_: self._on_changed())
        self._tick = QTimer(self)
        self._tick.timeout.connect(self._update_meta)
        self._tick.start(1000)
        self._refresh_list()

    # ---- list ----
    def select_operation(self, op_id: int) -> None:
        self._refresh_list(select=op_id)

    def _refresh_list(self, select: int | None = None) -> None:
        keep = select if select is not None else self._current
        ops = self.ops.operations()
        self._ids = [o.id for o in ops]
        self.list.blockSignals(True)
        self.list.clear()
        for o in ops:
            it = QListWidgetItem(f"#{o.id} {o.name}\n{o.status}")
            it.setForeground(QColor(STATUS_COLOR.get(o.status, T.text)))
            self.list.addItem(it)
        self.list.blockSignals(False)
        if keep in self._ids:
            self.list.setCurrentRow(self._ids.index(keep))
            self._select(self._ids.index(keep))
        elif self._ids:
            self.list.setCurrentRow(0)
            self._select(0)

    def _on_changed(self) -> None:
        self._refresh_list()

    # ---- output ----
    def _select(self, row: int) -> None:
        if row < 0 or row >= len(self._ids):
            return
        self._current = self._ids[row]
        op = self.ops.get(self._current)
        self.view.clear()
        if op:
            for stream, line in op.lines:
                self._append(stream, line)
        self._update_meta()

    def _append(self, stream: str, line: str) -> None:
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(COLORS.get(stream, T.text)))
        cur = self.view.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        cur.insertText(line + "\n", fmt)
        self.view.setTextCursor(cur)
        self.view.ensureCursorVisible()

    def _on_output(self, op_id: int, stream: str, line: str) -> None:
        if op_id == self._current:
            self._append(stream, line)

    def _op(self) -> OperationState | None:
        return self.ops.get(self._current) if self._current is not None else None

    def _update_meta(self) -> None:
        op = self._op()
        if not op:
            return
        if op.active:
            import time
            op.runtime = time.monotonic() - op.started_monotonic
        self.cancel_btn.setEnabled(op.active)
        self.meta.setText(
            f"<b>{op.name}</b> · status <span style='color:{STATUS_COLOR.get(op.status, T.text)}'>{op.status}</span>"
            f" · started {op.started_at.replace('T', ' ')} · runtime {op.runtime:.1f}s"
            + (f" · exit code {op.exit_code}" if op.exit_code is not None else ""))
        self.meta.setTextFormat(Qt.TextFormat.RichText)

    # ---- actions ----
    def _cancel(self) -> None:
        if self._current is not None:
            self.ops.cancel(self._current)

    def _find(self) -> None:
        text = self.search.text()
        if not text:
            return
        if not self.view.find(text):
            cur = self.view.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.Start)
            self.view.setTextCursor(cur)
            self.search_msg.setText("" if self.view.find(text) else "not found")
        else:
            self.search_msg.setText("")

    def _save(self) -> None:
        op = self._op()
        if not op:
            return
        name, _ = QFileDialog.getSaveFileName(self, "Save log", str(Path.home() / f"operation-{op.id}.log"),
                                              "Log files (*.log *.txt)")
        if name:
            Path(name).write_text(self.view.toPlainText(), encoding="utf-8")
            self.app.audit.record("log.saved", id=op.id, path=name)


MAX_BLOCKS = 20000
