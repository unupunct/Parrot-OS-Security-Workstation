"""Per-tool configuration: custom executable and install folder (validated before saving)."""
from __future__ import annotations

from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QPushButton, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...integrations.catalog import PROFILES
from ...security.input_validation import ValidationError
from ..design.tokens import T


class ToolConfigPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        t = QLabel("Tool Configuration")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        intro = QLabel("Point WIFI Center at a tool that is not on your PATH, such as a git checkout. "
                       "Paths must be absolute and must exist. Nothing is executed when you save.")
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        lay.addWidget(intro)
        self.tool = QComboBox()
        for p in PROFILES:
            self.tool.addItem(p.name, p.id)
        self.tool.currentIndexChanged.connect(self._load)
        form = QFormLayout()
        form.addRow("Tool", self.tool)
        self.install_path = QLineEdit()
        self.install_path.setPlaceholderText("Folder of a git checkout (optional)")
        b1 = QPushButton("Browse…")
        b1.clicked.connect(self._pick_dir)
        r1 = QHBoxLayout()
        r1.addWidget(self.install_path, 1)
        r1.addWidget(b1)
        form.addRow("Install folder", r1)
        self.exe = QLineEdit()
        self.exe.setPlaceholderText("Absolute path of the executable (optional)")
        b2 = QPushButton("Browse…")
        b2.clicked.connect(self._pick_file)
        r2 = QHBoxLayout()
        r2.addWidget(self.exe, 1)
        r2.addWidget(b2)
        form.addRow("Executable override", r2)
        lay.addLayout(form)
        row = QHBoxLayout()
        save = QPushButton("Save and re-check")
        save.setObjectName("primary")
        save.clicked.connect(self._save)
        clear = QPushButton("Clear")
        clear.clicked.connect(self._clear)
        row.addWidget(save)
        row.addWidget(clear)
        row.addStretch(1)
        lay.addLayout(row)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        lay.addStretch(1)
        self._load()

    def select_tool(self, tool_id: str) -> None:
        i = self.tool.findData(tool_id)
        if i >= 0:
            self.tool.setCurrentIndex(i)

    def _tid(self) -> str:
        return self.tool.currentData()

    def _load(self) -> None:
        cfg = self.app.tools.get_config(self._tid())
        self.install_path.setText(cfg.get("install_path", ""))
        self.exe.setText(cfg.get("executable_override", ""))
        self.msg.setText("")

    def _pick_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Install folder", self.install_path.text())
        if d:
            self.install_path.setText(d)

    def _pick_file(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, "Executable", self.exe.text())
        if f:
            self.exe.setText(f)

    def _save(self) -> None:
        try:
            self.app.tools.set_config(self._tid(), self.install_path.text(), self.exe.text())
        except ValidationError as e:
            self.msg.setObjectName("err")
            self.msg.setStyleSheet(f"color:{T.danger}")
            self.msg.setText(f"Not saved: {e}")
            return
        s = self.app.tools.scan_tool(self._tid())
        self.msg.setStyleSheet("")
        self.msg.setText(f"Saved. {s.profile.name}: {s.health.level.value} — {s.health.detail}")
        self.app.audit.record("config.tool", tool=self._tid())

    def _clear(self) -> None:
        self.install_path.clear()
        self.exe.clear()
        self._save()
