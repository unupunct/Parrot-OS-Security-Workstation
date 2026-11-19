"""Bluetooth Lab: adapter detection, BlueZ discovery, known devices and import of existing results."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton,
                               QSpinBox, QTableWidgetItem, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services.bluetooth_service import BluetoothService
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.tokens import T


class BluetoothPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.svc: BluetoothService = app.bluetooth
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Bluetooth Lab")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.secs = QSpinBox()
        self.secs.setRange(3, 60)
        self.secs.setValue(10)
        self.secs.setSuffix(" s")
        self.known_btn = QPushButton("Refresh known devices")
        self.known_btn.clicked.connect(self._known)
        self.disc_btn = QPushButton("Discover nearby…")
        self.disc_btn.setObjectName("primary")
        self.disc_btn.clicked.connect(self._discover)
        imp = QPushButton("Import CSV…")
        imp.clicked.connect(self._import)
        for w in (self.secs, self.disc_btn, self.known_btn, imp):
            head.addWidget(w)
        lay.addLayout(head)
        note = QLabel("Uses BlueZ (bluetoothctl) only. Discovery, device information and connection status are "
                      "read-only; no pairing, connecting, spoofing or data access is implemented.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        self.info = QLabel("")
        self.info.setWordWrap(True)
        lay.addWidget(self.info)
        self.table = make_table(["Address", "Name", "Manufacturer", "Paired", "Connected", "RSSI", "Source", "Last seen"])
        self.table.setSortingEnabled(True)
        lay.addWidget(self.table, 1)
        self.diag = QPlainTextEdit()
        self.diag.setReadOnly(True)
        self.diag.setMaximumHeight(110)
        lay.addWidget(self.diag)
        self.status = QLabel("")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.refresh_info()
        self.reload()

    def refresh_info(self) -> None:
        tools = self.svc.tools()
        adapters = self.svc.adapters()
        have_ctl = bool(tools["bluetoothctl"])
        ctl = self.svc.controller() if have_ctl else None
        parts = [f"Adapters: {', '.join(adapters) or 'none detected'}"]
        if ctl:
            parts.append(f"controller {ctl.address} “{ctl.name}” · powered: {ctl.powered} · discoverable: {ctl.discoverable}")
        elif have_ctl:
            parts.append("bluetoothctl found but no controller is available")
        else:
            parts.append(f"<span style='color:{T.warning}'>bluetoothctl (BlueZ) not installed: "
                         "<code>sudo apt install bluez</code></span>")
        self.info.setText(" · ".join(parts))
        self.disc_btn.setEnabled(have_ctl)
        self.known_btn.setEnabled(have_ctl)
        lines = [f"{name}: {path or 'not found'}" for name, path in tools.items()]
        self.diag.setPlainText("Diagnostic tools\n" + "\n".join(lines) + "\n\nrfkill: " + self.svc.rfkill())

    def _maker(self, address: str) -> str:
        """Manufacturer from the address prefix. Random (private) addresses, used by most phones and gadgets, carry none."""
        try:
            first = int(address.split(":")[0], 16)
        except ValueError:
            return ""
        if first & 0xC0 in (0xC0, 0x40):
            return "private address"
        return self.app.wireless.oui.vendor(address) or ""

    def reload(self) -> None:
        rows = self.svc.stored()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        tri = lambda v: "" if v is None else "yes" if v else "no"
        for r, d in enumerate(rows):
            vals = [d["address"], d["name"] or "", self._maker(d["address"]), tri(d["paired"]), tri(d["connected"]),
                    "" if d["rssi"] is None else str(d["rssi"]), d["source"], fmt_ts(d["last_seen"])]
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))
        self.table.setSortingEnabled(True)
        if not rows:
            self.status.setText("No devices stored yet.")

    def _known(self) -> None:
        self.known_btn.setEnabled(False)
        self.status.setText("Querying BlueZ…")
        run_in_background(self.svc.known_devices, lambda devs: self._store(devs, "bluez-known"), self._err)

    def _discover(self) -> None:
        secs = self.secs.value()
        ok = QMessageBox.question(
            self, "Bluetooth discovery",
            f"Start Bluetooth discovery for {secs} seconds?\n\nThis makes your adapter actively scan for nearby "
            "devices. Only do this where you are permitted to.")
        if ok != QMessageBox.StandardButton.Yes:
            return
        self.disc_btn.setEnabled(False)
        self.status.setText(f"Discovering for {secs} s… (the dongle is scanning; results appear when it finishes)")
        self.app.audit.record("bluetooth.discover", seconds=secs)
        run_in_background(lambda: self.svc.discover(secs), lambda devs: self._store(devs, "bluez-discovery"), self._err)

    def _store(self, devices, source: str) -> None:
        self.svc.record(devices, source)
        self.status.setText(f"{len(devices)} devices recorded ({source}).")
        self.refresh_info()
        self.reload()

    def _err(self, e: str) -> None:
        self.status.setText(f"Failed: {e}")
        self.refresh_info()

    def _import(self) -> None:
        name, _ = QFileDialog.getOpenFileName(self, "Import device list", "", "CSV (*.csv *.txt)")
        if not name:
            return
        try:
            n = self.svc.import_csv(Path(name).read_text(encoding="utf-8", errors="replace"), "import")
        except OSError as e:
            self.status.setText(f"Cannot read file: {e}")
            return
        self.app.audit.record("bluetooth.import", path=name, count=n)
        self.status.setText(f"Imported {n} devices (rows without a valid address were skipped).")
        self.reload()
