"""Settings workspace: General, Appearance, Logging, Backup & Recovery."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QCheckBox, QColorDialog, QComboBox, QFileDialog, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget, QMessageBox,
                               QPushButton, QTabWidget, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services.backup_service import BackupError, BackupService
from ..theme import ACCENT_PRESETS

TAB_FOR_PAGE = {"settings_general": 0, "settings_appearance": 1, "settings_backup": 2}


class SettingsPage(QWidget):
    accent_changed = Signal(str)

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        title = QLabel("Settings")
        title.setObjectName("pageTitle")
        lay.addWidget(title)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._general(), "General")
        self.tabs.addTab(self._appearance(), "Appearance")
        self.tabs.addTab(self._backup(), "Backup && Recovery")
        lay.addWidget(self.tabs)

    def show_tab_for(self, page_id: str) -> None:
        self.tabs.setCurrentIndex(TAB_FOR_PAGE.get(page_id, 0))

    # ---- General ----
    def _general(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        s = self.app.settings
        self.restore = QCheckBox("Reopen the last workspace on startup")
        self.restore.setChecked(s.get("general.restore_last_workspace"))
        self.restore.toggled.connect(lambda v: s.set("general.restore_last_workspace", v))
        form.addRow(self.restore)

        self.res_dir = QLineEdit(str(s.resources_dir(self.app.paths.default_resources_dir)))
        self.res_dir.setReadOnly(True)
        pick = QPushButton("Choose…")
        pick.clicked.connect(self._pick_resources)
        row = QHBoxLayout()
        row.addWidget(self.res_dir, 1)
        row.addWidget(pick)
        form.addRow("Resource directory", row)

        self.level = QComboBox()
        self.level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.level.setCurrentText(s.get("logging.level"))
        self.level.currentTextChanged.connect(lambda v: s.set("logging.level", v))
        form.addRow("Log level (applies on restart)", self.level)
        form.addRow("Log directory", QLabel(str(self.app.paths.log_dir)))
        form.addRow("Database", QLabel(str(self.app.db.path)))
        return w

    def _pick_resources(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose resource directory", self.res_dir.text())
        if d:
            self.app.settings.set("general.resources_dir", d)
            self.res_dir.setText(d)

    # ---- Appearance ----
    def _appearance(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        form.addRow("Theme", QLabel("Matrix Dark (the only theme currently available)"))
        self.accent = QComboBox()
        self.accent.addItems(list(ACCENT_PRESETS))
        self.accent.addItem("Custom…")
        cur = self.app.settings.get("appearance.accent")
        for i, hexv in enumerate(ACCENT_PRESETS.values()):
            if hexv.lower() == cur.lower():
                self.accent.setCurrentIndex(i)
        self.accent.activated.connect(self._accent_picked)
        form.addRow("Accent colour", self.accent)
        return w

    def _accent_picked(self, idx: int) -> None:
        presets = list(ACCENT_PRESETS.values())
        if idx < len(presets):
            value = presets[idx]
        else:
            c = QColorDialog.getColor(parent=self, title="Accent colour")
            if not c.isValid():
                return
            value = c.name().upper()
        self.app.settings.set("appearance.accent", value)
        self.accent_changed.emit(value)

    # ---- Backup ----
    def _backup(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.bsvc = self.app.services.get(BackupService)
        lay.addWidget(QLabel(f"Backups are stored in {self.app.paths.backup_dir}"))
        self.blist = QListWidget()
        lay.addWidget(self.blist)
        row = QHBoxLayout()
        b1 = QPushButton("Create backup now")
        b1.setObjectName("primary")
        b1.clicked.connect(self._create_backup)
        b2 = QPushButton("Restore selected…")
        b2.clicked.connect(self._restore)
        row.addWidget(b1)
        row.addWidget(b2)
        row.addStretch(1)
        lay.addLayout(row)
        self.bmsg = QLabel("")
        self.bmsg.setObjectName("muted")
        lay.addWidget(self.bmsg)
        self._reload_backups()
        return w

    def _reload_backups(self) -> None:
        self.blist.clear()
        for b in self.bsvc.list():
            self.blist.addItem(f"{b.path.name}   ({b.size // 1024} KiB)")
        self._paths = [b.path for b in self.bsvc.list()]

    def _create_backup(self) -> None:
        try:
            p = self.bsvc.create("manual")
            self.bmsg.setText(f"Created {p.name}")
        except Exception as e:
            self.bmsg.setText(f"Backup failed: {e}")
        self._reload_backups()

    def _restore(self) -> None:
        row = self.blist.currentRow()
        if row < 0:
            self.bmsg.setText("Select a backup first.")
            return
        ok = QMessageBox.question(
            self, "Restore backup",
            "The selected backup will replace the current database the next time WIFI Center starts. "
            "A safety backup of the current database is created first.\n\nContinue?")
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            self.bsvc.stage_restore(self._paths[row])
            self.bmsg.setText("Restore staged. Restart WIFI Center to apply it.")
        except BackupError as e:
            self.bmsg.setText(f"Restore refused: {e}")
        self._reload_backups()
