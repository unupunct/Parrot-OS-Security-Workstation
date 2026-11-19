"""Shared widgets for the Network Security workspace: active-project bar and a few helpers."""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QInputDialog, QLabel,
                               QLineEdit, QMessageBox, QPushButton, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...security.input_validation import ValidationError
from ..design.components import MatrixButton
from ..design.tokens import T

SEV_COLOR = {"critical": T.danger, "high": "#FF8A5B", "medium": T.warning, "low": T.info, "info": T.text_secondary}


class ProjectBar(QWidget):
    """Select / create the active assessment project (remembered in settings)."""

    project_changed = Signal(int)

    def __init__(self, app: AppController, allow_none: bool = False) -> None:
        super().__init__()
        self.app = app
        self.allow_none = allow_none
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(QLabel("Project"))
        self.combo = QComboBox()
        self.combo.setMinimumWidth(240)
        self.combo.currentIndexChanged.connect(self._changed)
        lay.addWidget(self.combo)
        self.new_btn = MatrixButton("New project…", icon_name="project")
        self.new_btn.clicked.connect(self._new)
        lay.addWidget(self.new_btn)
        lay.addStretch(1)
        self.reload()

    def project_id(self) -> int | None:
        return self.combo.currentData()

    def reload(self, select: int | None = None) -> None:
        want = select if select is not None else (self.project_id() or self.app.settings.get("projects.active") or None)
        self.combo.blockSignals(True)
        self.combo.clear()
        if self.allow_none:
            self.combo.addItem("All projects", None)
        for p in self.app.projects.list():
            self.combo.addItem(p["name"], p["id"])
        idx = self.combo.findData(want) if want else -1
        self.combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.combo.blockSignals(False)
        if self.combo.count() == 0:
            self.combo.setPlaceholderText("No project yet")
        self._changed()

    def _changed(self) -> None:
        pid = self.project_id()
        if pid:
            self.app.settings.set("projects.active", int(pid))
        self.project_changed.emit(int(pid) if pid else 0)

    def _new(self) -> None:
        name, ok = QInputDialog.getText(self, "New project", "Project name:")
        if not ok:
            return
        try:
            pid = self.app.projects.create(name)
        except ValidationError as e:
            QMessageBox.warning(self, "New project", str(e))
            return
        self.app.audit.record("project.create", id=pid)
        self.reload(select=pid)


def confirm_dialog(parent: QWidget, title: str, text: str, ok_text: str = "Confirm",
                   require_checkbox: str | None = None, danger: bool = False) -> bool:
    """Consistent confirmation dialog. With `require_checkbox` the user must tick it before confirming."""
    from PySide6.QtWidgets import QCheckBox
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setMinimumWidth(520)
    lay = QVBoxLayout(dlg)
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setTextFormat(__import__("PySide6.QtCore", fromlist=["Qt"]).Qt.TextFormat.RichText)
    lay.addWidget(lbl)
    box = None
    if require_checkbox:
        box = QCheckBox(require_checkbox)
        lay.addWidget(box)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
    ok = buttons.addButton(ok_text, QDialogButtonBox.ButtonRole.AcceptRole)
    ok.setObjectName("danger" if danger else "primary")
    if box is not None:
        ok.setEnabled(False)
        box.toggled.connect(ok.setEnabled)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    lay.addWidget(buttons)
    return dlg.exec() == QDialog.DialogCode.Accepted
