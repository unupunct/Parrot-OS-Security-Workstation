"""Kismet Monitor: service health, REST data (loopback only), `.kismet` log import and management."""
from __future__ import annotations

import html
import json
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget)
from PySide6.QtWidgets import QTableWidgetItem

from ...application.app_controller import AppController
from ...security.input_validation import ValidationError
from ...services import kismet_service as ks
from ...services.kismet_service import KismetClient, KismetError
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.tokens import T


def _human(n: int) -> str:
    return f"{n / 1024 / 1024:.1f} MiB" if n >= 1024 * 1024 else f"{n / 1024:.0f} KiB"


class KismetPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.client: KismetClient | None = None
        self._devices: list[ks.KismetDevice] = []
        lay = QVBoxLayout(self)
        t = QLabel("Kismet Monitor")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        self.health = QLabel("")
        self.health.setWordWrap(True)
        lay.addWidget(self.health)
        tabs = QTabWidget()
        tabs.addTab(self._live_tab(), "Live (REST API)")
        tabs.addTab(self._logs_tab(), "Logs")
        lay.addWidget(tabs, 1)
        self.refresh_health()

    # ---------- health ----------
    def refresh_health(self) -> None:
        det = self.app.tools.cached("kismet") or self.app.tools.scan_tool("kismet")
        state = ks.service_state()
        if not det.installed:
            msg = f"<b style='color:{T.warning}'>Kismet is not installed.</b> Install it with <code>sudo apt install kismet</code>."
        else:
            msg = (f"Kismet {html.escape(det.version or 'version unknown')} installed · systemd unit "
                   f"<code>kismet</code>: <b>{html.escape(state)}</b> (Kismet is often started manually, "
                   "so “inactive” does not mean it is not running).")
        self.health.setText(msg)

    # ---------- live ----------
    def _live_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        form = QFormLayout()
        self.url = QLineEdit(ks.DEFAULT_URL)
        self.user = QLineEdit()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.setPlaceholderText("kept in memory only, never saved")
        form.addRow("Server URL (loopback only)", self.url)
        form.addRow("Username", self.user)
        form.addRow("Password", self.pw)
        lay.addLayout(form)
        row = QHBoxLayout()
        self.connect_btn = QPushButton("Connect and fetch")
        self.connect_btn.setObjectName("primary")
        self.connect_btn.clicked.connect(self._connect)
        self.import_btn = QPushButton("Import Wi-Fi APs as observations")
        self.import_btn.setEnabled(False)
        self.import_btn.clicked.connect(self._import_devices)
        row.addWidget(self.connect_btn)
        row.addWidget(self.import_btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.live_msg = QLabel("Not connected. Nothing is contacted until you press Connect.")
        self.live_msg.setObjectName("muted")
        self.live_msg.setWordWrap(True)
        lay.addWidget(self.live_msg)
        self.status_view = QPlainTextEdit()
        self.status_view.setReadOnly(True)
        self.status_view.setMaximumHeight(110)
        lay.addWidget(self.status_view)
        lay.addWidget(QLabel("Devices seen in the last 5 minutes"))
        self.dev_table = make_table(["Name", "MAC", "Type", "Channel", "Signal (dBm)", "Encryption", "Manufacturer"])
        self.dev_table.setSortingEnabled(True)
        lay.addWidget(self.dev_table, 2)
        lay.addWidget(QLabel("Alerts"))
        self.alert_table = make_table(["Time", "Severity", "Alert", "Details"])
        lay.addWidget(self.alert_table, 1)
        return w

    def _connect(self) -> None:
        try:
            self.client = KismetClient(self.url.text().strip(), self.user.text(), self.pw.text())
        except ValidationError as e:
            self.live_msg.setText(f"Not connected: {e}")
            return
        client = self.client
        self.connect_btn.setEnabled(False)
        self.live_msg.setText("Connecting…")
        self.app.audit.record("kismet.connect", url=client.base_url)

        def work():
            return client.status(), client.devices(300), client.alerts()

        run_in_background(work, self._fetched, self._failed)

    def _failed(self, err: str) -> None:
        self.connect_btn.setEnabled(True)
        self.live_msg.setText(err)

    def _fetched(self, result) -> None:
        status, devices, alerts = result
        self.connect_btn.setEnabled(True)
        self._devices = devices
        self.live_msg.setText(f"Connected: {len(devices)} devices, {len(alerts)} alerts.")
        text = json.dumps(status, indent=1)
        self.status_view.setPlainText(text[:4000])
        self.dev_table.setSortingEnabled(False)
        self.dev_table.setRowCount(len(devices))
        for r, d in enumerate(devices):
            for c, v in enumerate([d.name or "<unnamed>", d.mac, d.dev_type, d.channel,
                                   "" if d.signal_dbm is None else f"{d.signal_dbm:.0f}", d.crypt, d.manufacturer]):
                self.dev_table.setItem(r, c, QTableWidgetItem(v))
        self.dev_table.setSortingEnabled(True)
        self.alert_table.setRowCount(len(alerts))
        for r, a in enumerate(alerts):
            ts = "" if a.timestamp is None else str(int(a.timestamp))
            for c, v in enumerate([ts, "" if a.severity is None else str(a.severity), a.header, a.text]):
                self.alert_table.setItem(r, c, QTableWidgetItem(v))
        self.import_btn.setEnabled(any(d.is_wifi_ap for d in devices))

    def _import_devices(self) -> None:
        aps = [ks.to_access_point(d) for d in self._devices if d.is_wifi_ap]
        n = self.app.wireless.record(aps, source="kismet")
        self.app.audit.record("kismet.import", source="rest", count=n)
        self.live_msg.setText(f"Imported {n} Wi-Fi access points into observations (source: kismet).")

    # ---------- logs ----------
    def _logs_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        existing = [d for d in ks.default_log_dirs() if d.is_dir()]
        self.log_dir = QLineEdit(str(existing[0]) if existing else str(Path.home() / ".kismet"))
        pick = QPushButton("Browse…")
        pick.clicked.connect(self._pick_dir)
        reload_ = QPushButton("Reload")
        reload_.clicked.connect(self._reload_logs)
        row.addWidget(QLabel("Log directory"))
        row.addWidget(self.log_dir, 1)
        row.addWidget(pick)
        row.addWidget(reload_)
        lay.addLayout(row)
        self.log_table = make_table(["File", "Size", "Modified"])
        lay.addWidget(self.log_table, 1)
        btns = QHBoxLayout()
        self.imp_log = QPushButton("Import selected .kismet log")
        self.imp_log.clicked.connect(self._import_log)
        self.del_log = QPushButton("Delete selected…")
        self.del_log.clicked.connect(self._delete_log)
        op = QPushButton("Open folder")
        op.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(self.log_dir.text())))
        for b in (self.imp_log, self.del_log, op):
            btns.addWidget(b)
        btns.addStretch(1)
        lay.addLayout(btns)
        self.log_msg = QLabel("Logs are only read. Deleting needs your explicit confirmation.")
        self.log_msg.setObjectName("muted")
        self.log_msg.setWordWrap(True)
        lay.addWidget(self.log_msg)
        self._reload_logs()
        return w

    def _pick_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Kismet log directory", self.log_dir.text())
        if d:
            self.log_dir.setText(d)
            self._reload_logs()

    def _reload_logs(self) -> None:
        self._logs = ks.list_logs(Path(self.log_dir.text()))
        self.log_table.setRowCount(len(self._logs))
        for r, l in enumerate(self._logs):
            for c, v in enumerate([l["name"], _human(l["size"]), fmt_ts(l["modified"])]):
                self.log_table.setItem(r, c, QTableWidgetItem(v))
        if not self._logs:
            self.log_msg.setText("No Kismet logs found in this directory.")

    def _selected_log(self) -> dict | None:
        r = self.log_table.currentRow()
        return self._logs[r] if 0 <= r < len(self._logs) else None

    def _import_log(self) -> None:
        log = self._selected_log()
        if not log:
            self.log_msg.setText("Select a log first.")
            return
        try:
            devices = ks.read_kismet_log(Path(log["path"]))
        except KismetError as e:
            self.log_msg.setText(str(e))
            return
        aps = [ks.to_access_point(d) for d in devices if d.is_wifi_ap]
        n = self.app.wireless.record(aps, source="kismet")
        self.app.audit.record("kismet.import", source=log["name"], count=n)
        self.log_msg.setText(f"Imported {n} Wi-Fi access points from {log['name']} "
                             f"({len(devices)} devices in the log, other types not imported).")

    def _delete_log(self) -> None:
        log = self._selected_log()
        if not log:
            self.log_msg.setText("Select a log first.")
            return
        ok = QMessageBox.warning(self, "Delete Kismet log",
                                 f"Permanently delete {log['name']} ({_human(log['size'])})?\nThis cannot be undone.",
                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                                 QMessageBox.StandardButton.Cancel)
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            ks.delete_log(Path(self.log_dir.text()), log["name"])
            self.app.audit.record("kismet.log_deleted", name=log["name"])
            self.log_msg.setText(f"Deleted {log['name']}.")
        except (ValidationError, OSError) as e:
            self.log_msg.setText(f"Not deleted: {e}")
        self._reload_logs()
