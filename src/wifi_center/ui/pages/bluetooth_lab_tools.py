"""Bluetooth Lab sections: Signal Monitor, Adapter Diagnostics and Device Inventory."""
from __future__ import annotations

import html
import threading
from datetime import datetime
from pathlib import Path

import pyqtgraph as pg
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPlainTextEdit, QSplitter, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from ...bluetooth.inventory import CATEGORIES
from ...bluetooth.models import BluetoothError
from ...bluetooth.signal_monitor import GRANULARITY_NOTE, NOTE
from ...workers.task import run_in_background
from ..charts import FG, color, fmt_ts, make_plot, make_table
from ..design.components import MatrixButton, Panel
from ..design.terminal_view import TerminalView
from ..design.tokens import T
from .netsec_common import confirm_dialog

esc = html.escape


# ====================================================================== Signal Monitor
class SignalMonitorView(QWidget):
    def __init__(self, lab) -> None:
        super().__init__()
        self.lab, self.state, self.app = lab, lab.state, lab.app
        self.monitor = self.app.btmonitor
        self._cancel: threading.Event | None = None
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Signal Monitor")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        head.addWidget(QLabel("Sampling interval"))
        self.interval = QDoubleSpinBox()
        self.interval.setRange(0.5, 30.0)
        self.interval.setSingleStep(0.5)
        self.interval.setValue(1.0)
        self.interval.setSuffix(" s")
        head.addWidget(self.interval)
        self.b_start = MatrixButton("Start monitoring", "primary", "play")
        self.b_start.clicked.connect(self.start)
        self.b_stop = MatrixButton("Stop")
        self.b_stop.clicked.connect(self.stop)
        self.b_clear = MatrixButton("Clear history")
        self.b_clear.clicked.connect(self._clear)
        for b in (self.b_start, self.b_stop, self.b_clear):
            head.addWidget(b)
        lay.addLayout(head)
        note = QLabel(NOTE + " A reading that stops changing may be stale; a device with no reading is shown as unavailable, never as a value. " + GRANULARITY_NOTE)
        note.setObjectName("warn")
        note.setWordWrap(True)
        lay.addWidget(note)

        split = QSplitter(Qt.Orientation.Horizontal)
        left = Panel("Devices to watch")
        self.only_sel = QCheckBox("Only the devices ticked below (otherwise everything in range)")
        left.add(self.only_sel)
        self.devs = QListWidget()
        self.devs.setMaximumWidth(330)
        left.add(self.devs, 1)
        b = MatrixButton("Reload from last scan")
        b.clicked.connect(self.reload_devices)
        left.add(b)
        split.addWidget(left)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.plot = make_plot("", "", "RSSI (dBm)")
        self.plot.getPlotItem().setAxisItems({"bottom": pg.DateAxisItem(orientation="bottom")})
        self.plot.setYRange(-100, -20)
        self.plot.getPlotItem().showGrid(x=True, y=True, alpha=0.15)
        self.empty = QLabel("Start monitoring to see live signal strength.\nThe graph shows real readings only; nothing is drawn for devices that report none.")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setObjectName("muted")
        self.empty.setWordWrap(True)
        from PySide6.QtWidgets import QStackedWidget
        self.stack = QStackedWidget()
        self.stack.addWidget(self.plot)
        self.stack.addWidget(self.empty)
        self.stack.setCurrentWidget(self.empty)
        rl.addWidget(self.stack, 3)
        self.table = make_table(["Device", "Current", "Min", "Max", "Average", "Reported fluctuation", "Reported stability", "Readings / unavailable", "Status"])
        self.table.itemSelectionChanged.connect(self._presence)
        rl.addWidget(self.table, 2)
        self.presence = QLabel("")
        self.presence.setObjectName("muted")
        self.presence.setWordWrap(True)
        rl.addWidget(self.presence)
        split.addWidget(right)
        split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.redraw)
        self.lab.scan_done.connect(self.reload_devices)
        self._sync()
        self.reload_devices()

    def reload_devices(self) -> None:
        keep = {self.devs.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.devs.count()) if self.devs.item(i).checkState() == Qt.CheckState.Checked}
        self.devs.clear()
        inv = {r["address"]: r for r in self.app.btinventory.devices()}
        for d in self.state.devices:
            name = (inv.get(d.address) or {}).get("custom_name") or d.display_name or "(unnamed)"
            it = QListWidgetItem(f"{name}  ·  {d.address}")
            it.setData(Qt.ItemDataRole.UserRole, d.address)
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked if d.address in keep else Qt.CheckState.Unchecked)
            self.devs.addItem(it)

    def _sync(self) -> None:
        running = self._cancel is not None
        self.b_start.setEnabled(not running)
        self.b_stop.setEnabled(running)
        self.interval.setEnabled(not running)

    def start(self) -> None:
        a = self.state.adapter()
        if a is None or not a.powered:
            self.msg.setText("Select a powered adapter on the Dashboard first.")
            return
        if self.state.running:
            self.msg.setText("A scan is running; stop it first (BlueZ allows one discovery per adapter).")
            return
        addrs = [self.devs.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.devs.count())
                 if self.devs.item(i).checkState() == Qt.CheckState.Checked] if self.only_sel.isChecked() else None
        if self.only_sel.isChecked() and not addrs:
            self.msg.setText("Tick at least one device, or untick the filter to watch everything in range.")
            return
        self._cancel = threading.Event()
        cancel = self._cancel
        interval = float(self.interval.value())
        self.app.audit.record("bluetooth.monitor", adapter=a.name, interval=interval, devices=len(addrs) if addrs else "all")

        def work() -> None:
            self.monitor.start(a.path, interval, addrs, "both", a.classic, a.ble)
            self.monitor.run(cancel)

        def failed(e: str) -> None:
            self._cancel = None
            self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>")
            self._sync()
        run_in_background(work, lambda _r: (setattr(self, "_cancel", None), self._sync(), self.redraw()), failed)
        self.msg.setText("Monitoring…")
        self.timer.start(1000)
        self._sync()

    def stop(self) -> None:
        if self._cancel:
            self._cancel.set()
            self.msg.setText("Stopping…")

    def _clear(self) -> None:
        self.monitor.clear()
        self.redraw()

    def redraw(self) -> None:
        series = self.monitor.ranked()
        if not series or not any(s.samples for s in series):
            self.stack.setCurrentWidget(self.empty)
            self.table.setRowCount(0)
            return
        self.stack.setCurrentWidget(self.plot)
        self.plot.clear()
        shown = [s for s in series if any(x.rssi is not None for x in s.samples)][:10]
        inv = {r["address"]: r for r in self.app.btinventory.devices()}
        for i, s in enumerate(shown):
            pts = [(x.t, x.rssi) for x in s.samples if x.rssi is not None]
            if pts:
                self.plot.plot([p[0] for p in pts], [p[1] for p in pts], pen=pg.mkPen(color(i), width=2))
                lab = pg.TextItem((inv.get(s.address) or {}).get("custom_name") or s.name or s.address[-8:], color=color(i), anchor=(0, 0.5))
                lab.setPos(*pts[-1])
                self.plot.addItem(lab)
        sel = self._selected()
        self.table.setRowCount(len(series))
        for r, s in enumerate(series):
            st = self.monitor.stats(s.address)
            name = (inv.get(s.address) or {}).get("custom_name") or s.name or "(unnamed)"
            if st is None or st.current is None and st.readings == 0:
                vals = [f"{name}  {s.address}", "—", "—", "—", "—", "—", "unknown", f"0 / {st.samples if st else 0}", "no reading (unavailable)"]
            else:
                status = "possibly stale" if st.stale else ("live" if st.current is not None else "no current reading")
                vals = [f"{name}  {s.address}", "—" if st.current is None else f"{st.current} dBm", f"{st.minimum}", f"{st.maximum}", f"{st.average:.1f}",
                        f"{st.fluctuation:.1f} dB", st.stability, f"{st.readings} / {st.unavailable}", status]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, s.address)
                if c == 8:
                    it.setForeground(QColor(T.warning if "stale" in v or "no" in v else T.green))
                self.table.setItem(r, c, it)
            if s.address == sel:
                self.table.selectRow(r)
        self.table.resizeColumnsToContents()
        if self._cancel is None:
            self.timer.stop()

    def _selected(self) -> str | None:
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def _presence(self) -> None:
        a = self._selected()
        if not a:
            return
        spans = self.monitor.presence(a)
        fmt = lambda t: datetime.fromtimestamp(t).strftime("%H:%M:%S")                       # noqa: E731
        self.presence.setText("Presence: " + (", ".join(f"{fmt(p.start)} → " + ("now" if p.open else fmt(p.end)) for p in spans[-6:]) or "no readings yet")
                              + ". “Gone” only means no reading was received.")


# ====================================================================== Adapter Diagnostics
class AdapterDiagnosticsView(QWidget):
    def __init__(self, lab) -> None:
        super().__init__()
        self.lab, self.state, self.app = lab, lab.state, lab.app
        self.report = None
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Adapter Diagnostics")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.b_run = MatrixButton("Run diagnostics", "primary", "play")
        self.b_run.clicked.connect(self.run)
        self.b_export = MatrixButton("Export log…")
        self.b_export.clicked.connect(self._export)
        self.b_power = MatrixButton("Power off / on…")
        self.b_power.clicked.connect(self._power)
        self.b_reset = MatrixButton("Reset adapter…", "danger")
        self.b_reset.clicked.connect(self._reset)
        for b in (self.b_run, self.b_export, self.b_power, self.b_reset):
            head.addWidget(b)
        lay.addLayout(head)
        self.table = make_table(["Controller", "Address", "Chipset", "Bluetooth", "Power", "Driver / bus", "USB device", "Classic", "BLE"], stretch_col=6)
        self.table.itemSelectionChanged.connect(self._pick)
        self.table.setMaximumHeight(170)
        lay.addWidget(self.table)
        self.findings = QTextBrowser()
        self.findings.setMaximumHeight(140)
        lay.addWidget(self.findings)
        self.out = TerminalView()
        lay.addWidget(self.out, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.b_export.setEnabled(False)
        self.run()

    def run(self) -> None:
        self.b_run.setEnabled(False)
        self.out.clear()
        self.out.command("bluetooth diagnostics", "read-only")
        run_in_background(self.app.btdiag.report, self._shown, lambda e: (self.b_run.setEnabled(True), self.out.error(f"Failed: {e}")))

    def _shown(self, rep) -> None:
        self.b_run.setEnabled(True)
        self.report = rep
        self.b_export.setEnabled(True)
        self.table.setRowCount(len(rep.adapters))
        for r, a in enumerate(rep.adapters):
            for c, v in enumerate([a.name, a.address, a.manufacturer or "unknown", a.hci_version or "?", "on" if a.powered else "OFF", f"{a.driver or '?'} / {a.bus or '?'}",
                                   f"{a.usb_id} {a.usb_name}".strip() or "—", {True: "yes", False: "no", None: "?"}[a.classic], {True: "yes", False: "no", None: "?"}[a.ble]]):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, a.path)
                if c == 4:
                    it.setForeground(QColor(T.green if a.powered else T.danger))
                self.table.setItem(r, c, it)
        mark = {"ok": ("✔", T.green), "info": ("ℹ", T.cyan), "warning": ("⚠", T.warning), "error": ("✖", T.danger)}
        self.findings.setHtml("".join(f"<p><span style='color:{mark[i.level][1]}'>{mark[i.level][0]}</span> {esc(i.text)}</p>" for i in rep.issues))
        self.out.appendPlainText(rep.to_text())
        self.table.resizeColumnsToContents()

    def _target(self):
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        path = it.data(Qt.ItemDataRole.UserRole) if it else self.state.current
        return next((a for a in (self.report.adapters if self.report else self.state.adapters) if a.path == path), None)

    def _pick(self) -> None:
        a = self._target()
        self.b_power.setEnabled(a is not None)
        self.b_reset.setEnabled(a is not None and a.powered)

    def _export(self) -> None:
        if not self.report:
            return
        name, _ = QFileDialog.getSaveFileName(self, "Export diagnostics log", str(Path.home() / "bluetooth-diagnostics.txt"), "Text (*.txt);;JSON (*.json)")
        if not name:
            return
        Path(name).write_text(self.report.to_json() if name.lower().endswith(".json") else self.report.to_text(), encoding="utf-8")
        self.app.audit.record("bluetooth.export_diagnostics", path=name)
        self.msg.setText(f"Log saved to {name} (no keys or secrets are included).")

    def _power(self) -> None:
        a = self._target()
        if not a:
            return
        on = not a.powered
        live = [] if on else self.app.btdiag.connected_devices(a.path)
        if live:
            self.msg.setText(f"<span style='color:{T.danger}'>{len(live)} device(s) are connected through {esc(a.name)}; disconnect them before powering it off.</span>")
            return
        if not confirm_dialog(self, "Change adapter power", f"<p>Power <b>{'on' if on else 'off'}</b> {esc(a.name)} ({esc(a.address)})?</p>", "Power " + ("on" if on else "off")):
            return
        self.app.audit.record("bluetooth.power", adapter=a.name, on=on)
        run_in_background(lambda: self.app.btadapters.set_powered(a.path, on, 0), lambda _r: (self.msg.setText(f"{a.name} powered {'on' if on else 'off'}."), self.state.refresh_adapters(), self.run()),
                          lambda e: self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>"))

    def _reset(self) -> None:
        a = self._target()
        if not a:
            return
        live = self.app.btdiag.connected_devices(a.path)
        if live:
            self.msg.setText(f"<span style='color:{T.danger}'>Not reset: {len(live)} device(s) are connected through {esc(a.name)}. Disconnect them first.</span>")
            return
        if not confirm_dialog(self, "Reset adapter", f"<p>Power-cycle <b>{esc(a.name)}</b> ({esc(a.address)})?</p><p>The adapter is switched off and on again "
                              "through BlueZ. Scans and connections through it stop briefly. Pairings are not removed.</p>", "Reset adapter", danger=True):
            return
        self.app.audit.record("bluetooth.reset", adapter=a.name)

        def done(res) -> None:
            self.msg.setText(("✔ " if res.ok else "✖ ") + res.message)
            self.state.refresh_adapters()
            self.run()
        run_in_background(lambda: self.app.btdiag.reset_adapter(a.path, confirmed=True), done, lambda e: self.msg.setText(str(e)))


# ====================================================================== Device Inventory
class InventoryView(QWidget):
    def __init__(self, lab) -> None:
        super().__init__()
        self.lab, self.state, self.app = lab, lab.state, lab.app
        self.inv = self.app.btinventory
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Device Inventory")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.count = QLabel("")
        self.count.setObjectName("muted")
        head.addWidget(self.count)
        head.addStretch(1)
        for text, slot in (("Possible duplicates", self._duplicates), ("Export CSV…", lambda: self._export("csv")), ("Export JSON…", lambda: self._export("json"))):
            b = MatrixButton(text)
            b.clicked.connect(slot)
            head.addWidget(b)
        lay.addLayout(head)
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search address, name, manufacturer, notes, tags…")
        self.search.textChanged.connect(self.reload)
        self.f_tech = QComboBox()
        self.f_tech.addItems(["All technologies", "Classic", "BLE", "Dual Mode", "Unknown"])
        self.f_cat = QComboBox()
        self.f_cat.addItem("All categories")
        self.f_cat.addItems([c for c in CATEGORIES if c])
        self.f_auth = QComboBox()
        self.f_auth.addItems(["Any authorization", "Authorized", "Not marked"])
        self.sort = QComboBox()
        self.sort.addItem("Last seen", "last_seen")
        self.sort.addItem("First seen", "first_seen")
        self.sort.addItem("Name", "name")
        self.sort.addItem("Signal", "rssi")
        self.sort.addItem("Address", "address")
        for w in (self.f_tech, self.f_cat, self.f_auth, self.sort):
            w.currentIndexChanged.connect(self.reload)
        for w in (self.search, self.f_tech, self.f_cat, self.f_auth, self.sort):
            bar.addWidget(w)
        bar.setStretch(0, 1)
        lay.addLayout(bar)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.table = make_table(["Name", "Address", "Category", "Technology", "Manufacturer", "Tags", "Auth.", "First seen", "Last seen", "Last RSSI"], stretch_col=0)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._select)
        split.addWidget(self.table)
        side = Panel("Selected device")
        self.name = QLineEdit()
        self.name.setPlaceholderText("Your name for this device")
        self.cat = QComboBox()
        self.cat.addItems(list(CATEGORIES))
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("tags, separated by commas")
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Notes")
        self.notes.setMaximumHeight(90)
        self.auth = QCheckBox("This device is mine or I am authorised to test it")
        self.auth.setToolTip("Security assessments only run against devices marked here. Nothing is ever tested automatically.")
        for w in (self.name, self.cat, self.tags, self.notes, self.auth):
            side.add(w)
        row = QHBoxLayout()
        self.b_save = MatrixButton("Save", "primary")
        self.b_save.clicked.connect(self._save)
        self.b_forget = MatrixButton("Forget device…", "danger")
        self.b_forget.clicked.connect(self._forget)
        row.addWidget(self.b_save)
        row.addWidget(self.b_forget)
        rw = QWidget()
        rw.setLayout(row)
        side.add(rw)
        self.hist = QTextBrowser()
        side.add(self.hist, 1)
        split.addWidget(side)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 3)
        cmp = Panel("Compare scans")
        crow = QHBoxLayout()
        self.scan_a, self.scan_b = QComboBox(), QComboBox()
        self.b_cmp = MatrixButton("Compare")
        self.b_cmp.clicked.connect(self._compare)
        for w in (QLabel("Earlier"), self.scan_a, QLabel("Later"), self.scan_b, self.b_cmp):
            crow.addWidget(w)
        crow.addStretch(1)
        cw = QWidget()
        cw.setLayout(crow)
        cmp.add(cw)
        self.cmp_out = QTextBrowser()
        self.cmp_out.setMaximumHeight(130)
        self.cmp_out.setPlainText("Pick two scans. “Not seen” never means a device is gone: it may simply not have advertised.")
        cmp.add(self.cmp_out)
        lay.addWidget(cmp)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.lab.scan_done.connect(self.reload)
        self.reload()

    def reload(self) -> None:
        sel = self._address()
        rows = self.inv.devices(self.search.text(), self.f_tech.currentText() if self.f_tech.currentIndex() else "",
                                self.f_cat.currentText() if self.f_cat.currentIndex() else "", "",
                                None if self.f_auth.currentIndex() == 0 else self.f_auth.currentIndex() == 1, self.sort.currentData())
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, d in enumerate(rows):
            vals = [d["custom_name"] or d["name"] or "(unnamed)", d["address"], d["category"], d["technology"], d["manufacturer"] or "—", d["tags"],
                    "✔" if d["authorized"] else "", fmt_ts(d["first_seen"]), fmt_ts(d["last_seen"]), "—" if d["last_rssi"] is None else f"{d['last_rssi']} dBm"]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, d["address"])
                self.table.setItem(r, c, it)
            if d["address"] == sel:
                self.table.selectRow(r)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()
        self.count.setText(f"{len(rows)} device(s) stored on this computer")
        scans = self.inv.scans()
        for combo in (self.scan_a, self.scan_b):
            keep = combo.currentData()
            combo.clear()
            for s in scans:
                combo.addItem(f"#{s['id']} · {fmt_ts(s['started_at'])} · {s['mode']} · {s['devices_found']} dev", s["id"])
            i = combo.findData(keep)
            if i >= 0:
                combo.setCurrentIndex(i)
        if len(scans) > 1 and self.scan_a.currentIndex() == self.scan_b.currentIndex():
            self.scan_a.setCurrentIndex(1)

    def _address(self) -> str | None:
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def _select(self) -> None:
        a = self._address()
        d = self.inv.device(a) if a else None
        if not d:
            return
        self.name.setText(d["custom_name"])
        self.cat.setCurrentText(d["category"])
        self.tags.setText(d["tags"])
        self.notes.setPlainText(d["notes"])
        self.auth.setChecked(bool(d["authorized"]))
        sight = self.inv.sightings(a, 200)
        rssis = [s["rssi"] for s in sight if s["rssi"] is not None]
        adv = self.inv.adv_changes(a)
        ev = self.inv.events(a, 10)
        h = [f"<p><b>{len(sight)}</b> sighting(s); first {esc(fmt_ts(d['first_seen']))}, last {esc(fmt_ts(d['last_seen']))}." +
             (f" Signal {min(rssis)} … {max(rssis)} dBm." if rssis else " No signal readings stored.") + "</p>",
             f"<p>Address type: {esc(d['address_type'] or 'unknown')} · technology {esc(d['technology'])} (inferred)</p>"]
        h.append("<h4>Advertisement changes</h4>" + ("<ul>" + "".join(f"<li>{esc(fmt_ts(c['ts']))}: {esc(c['summary'])}</li>" for c in adv[:8]) + "</ul>" if adv else "<p>none observed</p>"))
        h.append("<h4>Connection history</h4>" + ("<ul>" + "".join(f"<li>{esc(fmt_ts(e['ts']))}: {esc(e['event'])} · {esc(e['result'])}</li>" for e in ev) + "</ul>" if ev else "<p>none recorded</p>"))
        self.hist.setHtml("".join(h))

    def _save(self) -> None:
        a = self._address()
        if not a:
            return
        try:
            self.inv.set_info(a, self.name.text(), self.notes.toPlainText(), self.cat.currentText(), self.tags.text(), self.auth.isChecked())
        except ValueError as e:
            self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>")
            return
        self.app.audit.record("bluetooth.inventory_edit", address=a, authorized=self.auth.isChecked())
        self.msg.setText("Saved.")
        self.reload()

    def _forget(self) -> None:
        a = self._address()
        if not a:
            return
        if not confirm_dialog(self, "Forget device", f"<p>Remove <b>{esc(a)}</b> from this inventory, with its stored sightings and notes?</p><p>This does NOT "
                              "touch pairing information in Bluetooth, files or anything on the device. It cannot be undone.</p>", "Forget", danger=True):
            return
        self.inv.forget(a)
        self.app.audit.record("bluetooth.inventory_forget", address=a)
        self.reload()
        self.hist.clear()

    def _duplicates(self) -> None:
        groups = self.inv.duplicates()
        if not groups:
            self.msg.setText("No possible duplicates: no name is shared by several private addresses.")
            return
        lines = "".join("<p><b>" + esc(g[0]["custom_name"] or g[0]["name"]) + "</b> (" + esc(g[0]["manufacturer"] or "unknown manufacturer") + "): " +
                        ", ".join(esc(d["address"]) for d in g) + "</p>" for g in groups)
        self.hist.setHtml("<h4>Possible duplicates</h4>" + lines + f"<p style='color:{T.text_secondary}'>Phones and trackers rotate their private "
                          "address, so one device can appear under several. This is a hint, not proof.</p>")

    def _compare(self) -> None:
        a, b = self.scan_a.currentData(), self.scan_b.currentData()
        if a is None or b is None or a == b:
            self.cmp_out.setPlainText("Pick two different scans.")
            return
        lo, hi = sorted((a, b))
        res = self.inv.compare(lo, hi)

        def blk(title: str, items: list[str]) -> str:
            return f"<b>{esc(title)} ({len(items)})</b>" + ("<ul>" + "".join(f"<li>{esc(i)}</li>" for i in items[:30]) + "</ul>" if items else "<br>")
        self.cmp_out.setHtml(blk("New in the later scan", [f"{r['address']} {r['name'] or ''}" for r in res["new"]]) +
                             blk("Not seen in the later scan (not proof they are gone)", [f"{r['address']} {r['name'] or ''}" for r in res["not_seen"]]) +
                             blk("Changed", [f"{r['address']}: {n}" for r, n in res["changed"]]))

    def _export(self, fmt: str) -> None:
        rows = self.inv.devices(self.search.text(), self.f_tech.currentText() if self.f_tech.currentIndex() else "",
                                self.f_cat.currentText() if self.f_cat.currentIndex() else "")
        name, _ = QFileDialog.getSaveFileName(self, "Export inventory", str(Path.home() / f"bluetooth-inventory.{fmt}"), f"{fmt.upper()} (*.{fmt})")
        if not name:
            return
        Path(name).write_text(self.inv.export_csv(rows) if fmt == "csv" else self.inv.export_json(rows), encoding="utf-8")
        self.app.audit.record("bluetooth.export_inventory", path=name, rows=len(rows))
        self.msg.setText(f"Exported {len(rows)} device(s) to {name}")
