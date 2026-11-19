"""Bluetooth Lab: a Bluetooth diagnostics and device-management workstation built on BlueZ's D-Bus API.

The page is a shell with eleven sections. Dashboard and Device Scanner live here; Signal Monitor, Adapter Diagnostics and Device
Inventory are in bluetooth_lab_tools.py; the sections that act on a device (manager, inspector, BLE explorer, auditor) are in bluetooth_lab_stage2.py; the
packet analyzer / reports arrive in the next stages and say so. If BlueZ cannot be reached over D-Bus the scanner falls back to the
original bluetoothctl scanner (still part of the page)."""
from __future__ import annotations

import html
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QProgressBar, QSpinBox, QStackedWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...bluetooth import registry as reg
from ...bluetooth.adapter import friendly_settings
from ...bluetooth.models import AdapterInfo, BluetoothError, DeviceInfo
from ...bluetooth.scanner import MODE_LABEL, ScanResult
from ...workers.task import run_in_background
from ..charts import NumItem, fmt_ts, make_table, signal_bars
from ..design.components import LoadingIndicator, MatrixButton, Panel
from ..design.icons import icon_pixmap
from ..design.terminal_view import TerminalView
from ..design.tokens import T
from .netsec_common import confirm_dialog

esc = html.escape
SECTIONS = (("dashboard", "Dashboard"), ("scanner", "Device Scanner"), ("manager", "Device Manager"), ("inspector", "Device Inspector"),
            ("ble", "BLE Explorer"), ("auditor", "Security Auditor"), ("signal", "Signal Monitor"), ("packets", "Packet Analyzer"),
            ("diag", "Adapter Diagnostics"), ("inventory", "Device Inventory"), ("reports", "Reports"))
NEXT_STAGE = {"packets": "HCI capture with btmon and decoding with tshark (needs a privileged-helper operation).",
              "reports": "HTML and PDF reports from the inventory and the auditor's findings."}
QUALITY_COLOR = {"good": T.green, "fair": T.warning, "weak": T.danger, "unknown": T.text_muted}


class LabState(QObject):
    """State shared by the sections: adapters, the selected adapter, the current scan and the activity log."""
    adapters_changed = Signal()
    scan_started = Signal(str)
    scan_updated = Signal(object)
    scan_finished = Signal(object)
    scan_failed = Signal(str)
    log = Signal(str, str)                         # level, text

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.adapters: list[AdapterInfo] = []
        self.current: str = ""                     # adapter path
        self.result: ScanResult | None = None
        self.devices: list[DeviceInfo] = []
        self.cancel: threading.Event | None = None
        self.mode = "both"

    @property
    def running(self) -> bool:
        return self.cancel is not None

    def adapter(self) -> AdapterInfo | None:
        return next((a for a in self.adapters if a.path == self.current), None)

    def refresh_adapters(self) -> None:
        def done(res) -> None:
            self.adapters = res
            if self.current not in {a.path for a in res}:
                best = next((a for a in res if a.powered and a.ble), None) or next((a for a in res if a.powered), None) or (res[0] if res else None)
                self.current = best.path if best else ""
            self.adapters_changed.emit()
        run_in_background(self.app.btadapters.list, done, lambda e: (self.log.emit("error", f"Cannot list adapters: {e}"),
                                                                     setattr(self, "adapters", []), self.adapters_changed.emit()))

    def start_scan(self, mode: str, seconds: int) -> None:
        a = self.adapter()
        if self.running or a is None:
            return
        self.mode, self.cancel = mode, threading.Event()
        cancel, scanner = self.cancel, self.app.btscanner
        self.scan_started.emit(mode)
        self.log.emit("info", f"Scan started on {a.name}: {MODE_LABEL[mode]}, {seconds} s")
        self.app.audit.record("bluetooth.scan", adapter=a.name, mode=mode, seconds=seconds)
        bridge = self

        def work() -> None:
            try:
                res = scanner.scan(a.path, mode, seconds, on_update=lambda ds: bridge.scan_updated.emit(list(ds)), cancel=cancel,
                                   supports_classic=a.classic, supports_ble=a.ble)
                self.app.btinventory.record_scan(res)
                bridge.scan_finished.emit(res)
            except BluetoothError as e:
                bridge.scan_failed.emit(str(e))
            except Exception as e:                    # reported, never silent
                bridge.scan_failed.emit(f"Unexpected error: {e}")
        threading.Thread(target=work, name="bt-scan", daemon=True).start()

    def stop_scan(self) -> None:
        if self.cancel:
            self.cancel.set()
            self.log.emit("info", "Stopping the scan…")

    def finish(self, res: ScanResult | None) -> None:
        self.cancel = None
        if res is not None:
            self.result, self.devices = res, res.devices
            self.log.emit("ok", f"Scan {'stopped' if res.cancelled else 'finished'}: {len(res.devices)} device(s) in {res.duration_s:.0f} s")


class BluetoothLabPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.state = LabState(app)
        self.state.scan_updated.connect(self._live)
        self.state.scan_finished.connect(lambda r: (self.state.finish(r), self.scan_done.emit()))
        self.state.scan_failed.connect(self._failed)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.nav = QListWidget()
        self.nav.setFixedWidth(250)
        self.nav.setSpacing(2)
        for key, title in SECTIONS:
            it = QListWidgetItem(title + ("   ·  next stage" if key in NEXT_STAGE else ""))
            it.setData(Qt.ItemDataRole.UserRole, key)
            if key in NEXT_STAGE:
                it.setForeground(QColor(T.text_muted))
            self.nav.addItem(it)
        lay.addWidget(self.nav)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)
        from .bluetooth_lab_tools import AdapterDiagnosticsView, InventoryView, SignalMonitorView
        self.dashboard = DashboardView(self)
        self.scanner = ScannerView(self)
        self.signal = SignalMonitorView(self)
        self.diag = AdapterDiagnosticsView(self)
        self.inventory = InventoryView(self)
        from .bluetooth_lab_stage2 import AuditorView, BLEExplorerView, DeviceManagerView, InspectorView
        self.views: dict[str, QWidget] = {"dashboard": self.dashboard, "scanner": self.scanner, "signal": self.signal, "diag": self.diag,
                                          "inventory": self.inventory, "manager": DeviceManagerView(self), "inspector": InspectorView(self),
                                          "ble": BLEExplorerView(self), "auditor": AuditorView(self)}
        for key, _ in SECTIONS:
            w = self.views.get(key) or self._next_stage(key)
            self.views[key] = w
            self.stack.addWidget(w)
        self.nav.currentRowChanged.connect(lambda r: self.stack.setCurrentIndex(r))
        self.nav.setCurrentRow(0)
        self.state.adapters_changed.connect(lambda: None)
        self.state.refresh_adapters()

    scan_done = Signal()

    def _next_stage(self, key: str) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        title = dict(SECTIONS)[key]
        t = QLabel(title)
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        msg = QLabel(f"{NEXT_STAGE[key]}\n\nThis section is built in the next stage of the Bluetooth Lab. It is not available yet, so nothing here can be "
                     "clicked: the dashboard, scanner, signal monitor, diagnostics and inventory already work.")
        msg.setWordWrap(True)
        msg.setObjectName("muted")
        lay.addWidget(msg)
        lay.addStretch(1)
        return w

    def _live(self, devices) -> None:
        self.state.devices = devices

    def _failed(self, err: str) -> None:
        self.state.finish(None)
        self.state.log.emit("error", err)
        self.scan_done.emit()

    def show_section(self, key: str) -> None:
        for i in range(self.nav.count()):
            if self.nav.item(i).data(Qt.ItemDataRole.UserRole) == key:
                self.nav.setCurrentRow(i)
                return


def card(title: str, value: str, sub: str = "", color: str = T.green) -> QFrame:
    f = QFrame()
    f.setObjectName("panel")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(14, 10, 14, 10)
    lay.setSpacing(2)
    t = QLabel(title.upper())
    t.setObjectName("panelTitle")
    v = QLabel(value)
    v.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {color};")
    v.setWordWrap(True)
    s = QLabel(sub)
    s.setObjectName("muted")
    s.setWordWrap(True)
    for w in (t, v, s):
        lay.addWidget(w)
    f.value, f.sub = v, s                         # type: ignore[attr-defined]
    return f


def chip(text: str, color: str) -> QLabel:
    c = QLabel(text)
    c.setStyleSheet(f"color: {color}; border: 1px solid {color}; border-radius: 11px; padding: 2px 12px; font-weight: 600;")
    return c


# ====================================================================== Dashboard
class DashboardView(QWidget):
    def __init__(self, lab: BluetoothLabPage) -> None:
        super().__init__()
        self.lab, self.state = lab, lab.state
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon_pixmap("bluetooth", T.green, 38, 2.0))
        head.addWidget(ic)
        tl = QVBoxLayout()
        tl.setSpacing(0)
        t = QLabel("Bluetooth Lab")
        t.setObjectName("pageTitle")
        sub = QLabel("Adapter status, scanning and diagnostics · BlueZ over D-Bus")
        sub.setObjectName("muted")
        tl.addWidget(t)
        tl.addWidget(sub)
        head.addLayout(tl)
        self.loader = LoadingIndicator("radar", 24)
        head.addWidget(self.loader)
        head.addStretch(1)
        head.addWidget(QLabel("Adapter"))
        self.adapter_combo = QComboBox()
        self.adapter_combo.setMinimumWidth(260)
        self.adapter_combo.currentIndexChanged.connect(self._adapter_picked)
        head.addWidget(self.adapter_combo)
        lay.addLayout(head)

        cards = QHBoxLayout()
        self.c_adapter = card("Adapter", "—", "")
        self.c_chip = card("Chipset", "—", "", T.cyan)
        self.c_ver = card("Bluetooth version", "—", "", T.text)
        self.c_found = card("Devices discovered", "0", "in the last scan")
        self.c_conn = card("Connected devices", "0", "right now", T.cyan)
        self.c_scan = card("Scan status", "idle", "", T.text)
        for c in (self.c_adapter, self.c_chip, self.c_ver, self.c_found, self.c_conn, self.c_scan):
            cards.addWidget(c, 1)
        lay.addLayout(cards)

        mid = QHBoxLayout()
        info = Panel("Selected adapter")
        self.info = QGridLayout()
        self.info.setHorizontalSpacing(18)
        self.info.setVerticalSpacing(2)
        iw = QWidget()
        iw.setLayout(self.info)
        info.add(iw, 1)
        self.chips = QHBoxLayout()
        cw = QWidget()
        cw.setLayout(self.chips)
        info.add(cw)
        mid.addWidget(info, 3)

        ctrl = Panel("Scan controls")
        row = QHBoxLayout()
        self.b_classic = MatrixButton("Scan Classic Bluetooth")
        self.b_ble = MatrixButton("Scan BLE")
        self.b_both = MatrixButton("Scan Both", "primary", "discovery")
        for b, m in ((self.b_classic, "classic"), (self.b_ble, "ble"), (self.b_both, "both")):
            b.clicked.connect(lambda _=False, mode=m: self._start(mode))
            row.addWidget(b)
        rw = QWidget()
        rw.setLayout(row)
        ctrl.add(rw)
        row2 = QHBoxLayout()
        self.b_stop = MatrixButton("Stop Scan", "danger")
        self.b_stop.clicked.connect(self.state.stop_scan)
        self.b_rescan = MatrixButton("Rescan")
        self.b_rescan.clicked.connect(lambda: self._start(self.state.mode))
        self.b_export = MatrixButton("Export Scan Results…")
        self.b_export.clicked.connect(self._export)
        self.b_power = MatrixButton("Power on")
        self.b_power.clicked.connect(self._power)
        for b in (self.b_stop, self.b_rescan, self.b_export, self.b_power):
            row2.addWidget(b)
        r2 = QWidget()
        r2.setLayout(row2)
        ctrl.add(r2)
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Duration"))
        self.secs = QSpinBox()
        self.secs.setRange(3, 120)
        self.secs.setValue(10)
        self.secs.setSuffix(" s")
        row3.addWidget(self.secs)
        row3.addStretch(1)
        r3 = QWidget()
        r3.setLayout(row3)
        ctrl.add(r3)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.setRange(0, 0)
        self.progress.hide()
        ctrl.add(self.progress)
        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        self.hint.setObjectName("muted")
        ctrl.add(self.hint)
        mid.addWidget(ctrl, 2)
        lay.addLayout(mid, 2)

        logp = Panel("Activity log")
        self.log = TerminalView()
        self.log.setMinimumHeight(120)
        self.log.info("Bluetooth Lab ready. Scanning only listens: it never connects, pairs or sends anything to a device.")
        logp.add(self.log, 1)
        lay.addWidget(logp, 1)

        self.state.adapters_changed.connect(self.refresh)
        self.state.scan_started.connect(lambda m: self._running(True))
        self.state.scan_updated.connect(self._live)
        self.lab.scan_done.connect(lambda: self._running(False))
        self.state.log.connect(self._log)
        self.refresh()

    def _log(self, level: str, text: str) -> None:
        {"ok": self.log.ok, "error": self.log.error, "warn": self.log.warn}.get(level, self.log.info)(text)

    def _adapter_picked(self) -> None:
        path = self.adapter_combo.currentData()
        if path and path != self.state.current:
            self.state.current = path
            self.refresh()

    def refresh(self) -> None:
        a = self.state.adapter()
        self.adapter_combo.blockSignals(True)
        self.adapter_combo.clear()
        for x in self.state.adapters:
            self.adapter_combo.addItem(f"{x.name} · {x.address} · {'on' if x.powered else 'off'}", x.path)
        i = self.adapter_combo.findData(self.state.current)
        self.adapter_combo.setCurrentIndex(max(i, 0))
        self.adapter_combo.blockSignals(False)
        while self.info.count():
            w = self.info.takeAt(0).widget()
            if w is not None:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        while self.chips.count():
            w = self.chips.takeAt(0).widget()
            if w is not None:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        if a is None:
            self.c_adapter.value.setText("none")
            self.c_adapter.sub.setText("No Bluetooth controller is visible to BlueZ (see Adapter Diagnostics)")
            for c in (self.c_chip, self.c_ver):
                c.value.setText("—")
            self._buttons()
            return
        self.c_adapter.value.setText(a.name + (" · on" if a.powered else " · OFF"))
        self.c_adapter.value.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {T.green if a.powered else T.danger};")
        self.c_adapter.sub.setText(a.address)
        self.c_chip.value.setText(a.manufacturer or "unknown")
        self.c_chip.sub.setText(a.usb_name or a.usb_id or "")
        self.c_ver.value.setText(a.hci_version or "unknown")
        self.c_ver.sub.setText("HCI/LMP version reported by the controller")
        rows = [("Controller address", a.address), ("Alias", a.alias), ("Bus / driver", f"{a.bus or '?'} · {a.driver or '?'}"),
                ("USB device", f"{a.usb_id} {a.usb_name}".strip() or "—"), ("Firmware", a.firmware), ("Roles", ", ".join(a.roles) or "—"),
                ("Features", ", ".join(a.lmp_features[:8]) or "unknown"), ("Settings", ", ".join(friendly_settings(a.current_settings)) or "unknown")]
        for r, (k, v) in enumerate(rows):
            kl = QLabel(k)
            kl.setObjectName("muted")
            vl = QLabel(v)
            vl.setWordWrap(True)
            vl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.info.addWidget(kl, r, 0, Qt.AlignmentFlag.AlignTop)
            self.info.addWidget(vl, r, 1)
        self.info.setColumnStretch(1, 1)
        self.chips.addWidget(chip("Classic: " + {True: "available", False: "not supported", None: "unknown"}[a.classic], T.green if a.classic else T.text_muted))
        self.chips.addWidget(chip("BLE: " + {True: "available", False: "not supported", None: "unknown"}[a.ble], T.green if a.ble else T.text_muted))
        self.chips.addStretch(1)
        self._buttons()
        self._counts()

    def _counts(self) -> None:
        ds = self.state.devices
        self.c_found.value.setText(str(len(ds)))
        self.c_conn.value.setText(str(sum(d.connected for d in ds)))

    def _buttons(self) -> None:
        a, running = self.state.adapter(), self.state.running
        ok = a is not None and a.powered and not running
        self.b_classic.setEnabled(ok and a.classic is not False)
        self.b_ble.setEnabled(ok and a.ble is not False)
        self.b_both.setEnabled(ok)
        self.b_rescan.setEnabled(ok and self.state.result is not None)
        self.b_stop.setEnabled(running)
        self.b_export.setEnabled(bool(self.state.devices))
        self.b_power.setVisible(a is not None and not a.powered)
        self.b_power.setEnabled(a is not None and not running)
        if a is None:
            self.hint.setText("No adapter: plug in a Bluetooth dongle or start the bluetooth service.")
        elif not a.powered:
            self.hint.setText("This adapter is powered off. Power it on to scan.")
        else:
            notes = []
            if a.classic is False:
                notes.append("Classic scanning is not available on this adapter.")
            if a.ble is False:
                notes.append("BLE scanning is not available on this adapter (Bluetooth " + (a.hci_version or "?") + " controller).")
            self.hint.setText(" ".join(notes))

    def _start(self, mode: str) -> None:
        self.state.start_scan(mode, self.secs.value())

    def _running(self, on: bool) -> None:
        self.progress.setVisible(on)
        self.c_scan.value.setText("scanning" if on else "idle")
        self.c_scan.value.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {T.warning if on else T.text};")
        self.c_scan.sub.setText(MODE_LABEL[self.state.mode] if on else (f"last: {MODE_LABEL[self.state.result.mode]}" if self.state.result else ""))
        if on:
            self.loader.start()
        else:
            self.loader.stop()
            self.state.refresh_adapters()
        self._buttons()
        self._counts()

    def _live(self, devices) -> None:
        self.c_found.value.setText(str(len(devices)))
        self.c_conn.value.setText(str(sum(d.connected for d in devices)))

    def _power(self) -> None:
        a = self.state.adapter()
        if not a:
            return
        if not confirm_dialog(self, "Power on adapter", f"<p>Power on <b>{esc(a.name)}</b> ({esc(a.address)})?</p><p>This only enables the controller; it "
                              "does not connect to anything.</p>", "Power on"):
            return
        self.app_power(a, True)

    def app_power(self, a: AdapterInfo, on: bool) -> None:
        app = self.lab.app
        app.audit.record("bluetooth.power", adapter=a.name, on=on)

        def work():
            app.btadapters.set_powered(a.path, on)

        run_in_background(work, lambda _r: (self.log.ok(f"{a.name} powered {'on' if on else 'off'}"), self.state.refresh_adapters()),
                          lambda e: self.log.error(f"Power change failed: {e}"))

    def _export(self) -> None:
        ds = self.state.devices
        if not ds:
            return
        name, _ = QFileDialog.getSaveFileName(self, "Export scan results", str(Path.home() / "bluetooth-scan.csv"), "CSV (*.csv);;JSON (*.json)")
        if not name:
            return
        rows = []
        for d in ds:
            rows.append({"address": d.address, "name": d.display_name, "technology": d.technology, "device_type": d.device_type,
                         "manufacturer": d.manufacturer, "rssi": d.rssi, "signal": d.signal_quality, "paired": d.paired,
                         "connected": d.connected, "trusted": d.trusted, "address_type": d.address_type, "services": "; ".join(d.uuid_labels)})
        if name.lower().endswith(".json"):
            import json
            Path(name).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        else:
            import csv
            import io
            buf = io.StringIO()
            w = csv.DictWriter(buf, fieldnames=list(rows[0]), lineterminator="\n")
            w.writeheader()
            for r in rows:
                w.writerow({k: ("'" + str(v) if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in r.items()})
            Path(name).write_text(buf.getvalue(), encoding="utf-8")
        self.lab.app.audit.record("bluetooth.export", path=name, rows=len(rows))
        self.log.ok(f"Exported {len(rows)} device(s) to {name}")


# ====================================================================== Device Scanner
COLS = ["Name", "MAC address", "Type", "Technology", "Manufacturer", "RSSI", "Signal", "Advertised services", "First seen", "Last seen",
        "Connected", "Paired", "Trusted"]


class ScannerView(QWidget):
    def __init__(self, lab: BluetoothLabPage) -> None:
        super().__init__()
        self.lab, self.state, self.app = lab, lab.state, lab.app
        self.devices: list[DeviceInfo] = []
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Device Scanner")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.count = QLabel("")
        self.count.setObjectName("muted")
        head.addWidget(self.count)
        head.addStretch(1)
        self.b_known = MatrixButton("Known to BlueZ")
        self.b_known.setToolTip("Devices BlueZ already remembers (paired or recently seen), without scanning")
        self.b_known.clicked.connect(self._known)
        head.addWidget(self.b_known)
        lay.addLayout(head)
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, MAC, manufacturer, type, service…")
        self.search.textChanged.connect(self._fill)
        self.f_tech = QComboBox()
        self.f_tech.addItems(["All technologies", "Classic", "BLE", "Dual Mode", "Unknown"])
        self.f_sig = QComboBox()
        self.f_sig.addItems(["Any signal", "good", "fair", "weak", "unknown"])
        self.f_stat = QComboBox()
        self.f_stat.addItems(["Any status", "Paired", "Connected", "Trusted", "Named only"])
        for w in (self.f_tech, self.f_sig, self.f_stat):
            w.currentIndexChanged.connect(self._fill)
        for w in (self.search, self.f_tech, self.f_sig, self.f_stat):
            bar.addWidget(w)
        bar.setStretch(0, 1)
        lay.addLayout(bar)
        self.table = make_table(COLS)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._select)
        lay.addWidget(self.table, 3)
        self.detail = QLabel("Run a scan from the Dashboard (or press a scan button there); results appear here live.")
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.TextFormat.RichText)
        self.detail.setObjectName("muted")
        lay.addWidget(self.detail)
        self.fallback = None
        self.state.scan_updated.connect(self._live)
        self.lab.scan_done.connect(lambda: self._set(self.state.devices))
        if self.app.btapi is None:
            from .bluetooth_page import BluetoothPage              # the original bluetoothctl scanner stays available
            self.fallback = BluetoothPage(self.app)
            lay.addWidget(QLabel("BlueZ's D-Bus interface is not available (python3-dbus missing?). The original bluetoothctl scanner is shown below."))
            lay.addWidget(self.fallback, 3)

    def _live(self, devices) -> None:
        self._set(devices)

    def _known(self) -> None:
        a = self.state.adapter()
        if not a:
            self.detail.setText("No adapter selected.")
            return
        run_in_background(lambda: self.app.btscanner.devices(a.path), lambda ds: (self._set(ds), self.detail.setText(f"{len(ds)} device(s) known to BlueZ (not a new scan).")),
                          lambda e: self.detail.setText(f"Failed: {e}"))

    def _set(self, devices: list[DeviceInfo]) -> None:
        self.devices = list(devices)
        self._fill()

    def _visible(self) -> list[DeviceInfo]:
        q = self.search.text().strip().lower()
        out = self.devices
        if self.f_tech.currentIndex() > 0:
            out = [d for d in out if d.technology == self.f_tech.currentText()]
        if self.f_sig.currentIndex() > 0:
            out = [d for d in out if d.signal_quality == self.f_sig.currentText()]
        st = self.f_stat.currentText()
        if st == "Paired":
            out = [d for d in out if d.paired]
        elif st == "Connected":
            out = [d for d in out if d.connected]
        elif st == "Trusted":
            out = [d for d in out if d.trusted]
        elif st == "Named only":
            out = [d for d in out if d.display_name]
        if q:
            out = [d for d in out if q in " ".join((d.address, d.display_name, d.manufacturer, d.device_type, d.technology, *d.uuid_labels)).lower()]
        return out

    def _fill(self) -> None:
        rows = self._visible()
        inv = {r["address"]: r for r in self.app.btinventory.devices()}
        sel = self._current_address()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, d in enumerate(rows):
            rec = inv.get(d.address, {})
            name = rec.get("custom_name") or d.display_name
            labels = d.uuid_labels
            vals = [(name or "(unnamed)", None), (d.address, None), (d.device_type, None), (d.technology, None), (d.manufacturer or "—", None),
                    ("—" if d.rssi is None else f"{d.rssi} dBm", d.rssi if d.rssi is not None else -999),
                    (signal_bars(d.rssi) + " " + d.signal_quality, d.rssi if d.rssi is not None else -999),
                    ("; ".join(labels[:3]) + (f" (+{len(labels) - 3})" if len(labels) > 3 else "") if labels else "—", None),
                    (fmt_ts(rec["first_seen"]) if rec else "—", None), (fmt_ts(rec["last_seen"]) if rec else "—", None),
                    ("yes" if d.connected else "no", None), ("yes" if d.paired else "no", None), ("yes" if d.trusted else "no", None)]
            for c, (text, key) in enumerate(vals):
                it = NumItem(text, key) if c in (5, 6) else QTableWidgetItem(text)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, d.address)
                    if not name:
                        it.setForeground(QColor(T.text_muted))
                if c == 6:
                    it.setForeground(QColor(QUALITY_COLOR[d.signal_quality]))
                if c == 11 and d.paired:
                    it.setForeground(QColor(T.green))
                self.table.setItem(r, c, it)
            if d.address == sel:
                self.table.selectRow(r)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()
        self.count.setText(f"{len(rows)} of {len(self.devices)} device(s)")

    def _current_address(self) -> str | None:
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def _select(self) -> None:
        addr = self._current_address()
        d = next((x for x in self.devices if x.address == addr), None)
        if d is None:
            return
        labels = d.uuid_labels
        self.detail.setText(
            f"<b>{esc(d.display_name or '(unnamed)')}</b> &nbsp; {esc(d.address)} &nbsp;·&nbsp; {esc(d.technology)} ({esc(d.device_type)}) &nbsp;·&nbsp; "
            f"address: {esc(d.address_privacy)}<br><span style='color:{T.text_secondary}'>Manufacturer: {esc(d.manufacturer or 'not advertised')} · services: "
            f"{esc('; '.join(labels) or 'none advertised')}<br>Technology and type are inferred from what the device advertises. "
            "RSSI is signal strength, not distance.</span>")
