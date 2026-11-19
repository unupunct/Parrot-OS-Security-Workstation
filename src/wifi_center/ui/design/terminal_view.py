"""In-app terminal output: a read-only, terminal-styled view that shows commands and their live output.

Nothing typed here is ever executed; it only displays what WIFI Center (or the privileged helper) runs. Drop-in
replacement for a read-only QPlainTextEdit: appendPlainText / setPlainText / clear keep working."""
from __future__ import annotations

import re

from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit

from .tokens import T

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
MAX_LINES = 6000


class TerminalView(QPlainTextEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(MAX_LINES)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        f = QFont("monospace")
        f.setStyleHint(QFont.StyleHint.Monospace)
        f.setPointSize(10)
        self.setFont(f)
        self.setStyleSheet(f"QPlainTextEdit {{ background: #050805; color: {T.text}; border: 1px solid {T.border}; "
                           "border-radius: 8px; padding: 8px; selection-background-color: #14502c; }")
        self.setMinimumHeight(110)

    # ---- writing ----
    def _write(self, text: str, color: str | None, bold: bool = False) -> None:
        cur = self.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color or T.text))
        if bold:
            fmt.setFontWeight(QFont.Weight.Bold)
        if self.document().characterCount() > 1:
            cur.insertText("\n")
        cur.insertText(text, fmt)
        self.setTextCursor(cur)
        self.ensureCursorVisible()

    def command(self, cmd: str, note: str = "") -> None:
        """Echo the command being run, like a prompt line."""
        self._write(f"$ {cmd}" + (f"   # {note}" if note else ""), T.green, True)

    def info(self, text: str) -> None:
        self._write(text, T.cyan)

    def ok(self, text: str) -> None:
        self._write(text, T.green)

    def error(self, text: str) -> None:
        self._write(text, T.danger)

    def warn(self, text: str) -> None:
        self._write(text, T.warning)

    # ---- QPlainTextEdit-compatible API (used by existing callers) ----
    def appendPlainText(self, text: str) -> None:  # noqa: N802
        for line in ANSI.sub("", str(text)).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            if line.startswith("[stderr]"):
                self._write(line[8:].lstrip(), T.warning)
            elif line.startswith(("E:", "Err:", "ERROR")):
                self._write(line, T.danger)
            elif line.startswith(("W:", "Warning")):
                self._write(line, T.warning)
            else:
                self._write(line, None)

    def setPlainText(self, text: str) -> None:  # noqa: N802
        self.clear()
        self.appendPlainText(text)
