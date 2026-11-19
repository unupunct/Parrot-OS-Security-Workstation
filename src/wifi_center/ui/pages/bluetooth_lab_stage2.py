"""Bluetooth Lab sections that act on one device: Device Manager, Device Inspector, BLE Explorer and Security Auditor.

Everything that changes state or touches the device asks first (confirm dialog naming the device and the action). These sections are
tested against an in-memory BlueZ; they have not been exercised against real hardware yet and say so on screen."""
from __future__ import annotations

import html
import threading

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QSplitter, QTableWidgetItem, QTextBrowser,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ...bluetooth import ble as blemod
from ...bluetooth.auditor import BluetoothSecurityAuditor
from ...bluetooth.models import SEVERITIES, BluetoothError, DeviceInfo
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.components import MatrixButton, Panel
from ..design.tokens import T
from .netsec_common import confirm_dialog

esc = html.escape
UNTESTED = ("Built and tested against a simulated BlueZ. It has not been exercised with real devices yet: treat results from hardware as "
            "unverified and report anything odd.")
SEV_COLOR = {"informational": T.text_muted, "low": T.cyan, "medium": T.warning, "high": T.danger, "critical": T.danger}
STATUS_LABEL = {"confirmed": "confirmed", "observation": "observation (declared, not tested)", "unknown": "unknown (cannot be determined)"}


def banner(text: str) -> QLabel:
    b = QLabel(text)
    b.setWordWrap(True)
    b.setStyleSheet(f"color: {T.warning}; border: 1px solid {T.warning}; border-radius: 6px; padding: 6px 10px;")
    return b


# ====================================================================== pairing prompts (agent thread -> UI thread)
class PairingPrompts(QObject):
    """Bridges BlueZ's agent requests (they arrive on a D-Bus thread and must be answered) to dialogs on the UI thread. Implements
    bluez.AgentHandler. Passkeys and PINs are shown to or typed by the user only; they are never stored or logged."""
    request = Signal(object)
    notice = Signal(str)

    def __init__(self, parent_widget: QWidget, timeout: float = 55.0) -> None:
        super().__init__()
        self.w, self.timeout = parent_widget, timeout
        self.request.connect(self._handle)

    def _ask(self, kind: str, address: str, value=None):
        req = {"kind": kind, "address": address, "value": value, "answer": None, "event": threading.Event()}
        self.request.emit(req)
        req["event"].wait(self.timeout)
        return req["answer"]

    def _handle(self, req: dict) -> None:                     # UI thread
        try:
            k, a, v = req["kind"], req["address"], req["value"]
            if k == "confirm":
                what = f"<p>Does <b>{v:06d}</b> match the code shown on <b>{esc(a)}</b>?</p>" if v else f"<p>Allow <b>{esc(a)}</b> to pair?</p>"
                req["answer"] = confirm_dialog(self.w, "Pairing request", what + "<p>Only accept if you started this pairing.</p>", "Accept")
            elif k == "service":
                req["answer"] = confirm_dialog(self.w, "Allow service", f"<p><b>{esc(a)}</b> asks to use service <code>{esc(str(v))}</code>.</p>", "Allow")
            elif k == "pin":
                text, ok = QInputDialog.getText(self.w, "PIN code", f"PIN for {a} (the device's manual or label has it):")
                req["answer"] = text if ok and text else None
            elif k == "passkey":
                n, ok = QInputDialog.getInt(self.w, "Passkey", f"Passkey shown on {a}:", 0, 0, 999999)
                req["answer"] = n if ok else None
        finally:
            req["event"].set()

    # AgentHandler
    def request_confirmation(self, address: str, passkey: int) -> bool:
        return bool(self._ask("confirm", address, passkey))

    def request_pin(self, address: str):
        return self._ask("pin", address)

    def request_passkey(self, address: str):
        return self._ask("passkey", address)

    def display_passkey(self, address: str, passkey: int) -> None:
        self.notice.emit(f"Type {passkey:06d} on {address} to finish pairing.")

    def display_pin(self, address: str, pin: str) -> None:
        self.notice.emit(f"Enter the PIN {pin} on {address}.")

    def authorize_service(self, address: str, uuid: str) -> bool:
        return bool(self._ask("service", address, uuid))

    def cancel(self) -> None:
        self.notice.emit("The device cancelled the pairing request.")


# ====================================================================== shared base
class DeviceSection(QWidget):
    """A section with a device picker on top: devices BlueZ knows about (read straight from BlueZ)."""
    devices_loaded = Signal()

    def __init__(self, lab, title: str, subtitle: str) -> None:
        super().__init__()
        self.lab, self.app = lab, lab.app
        self.devs: list[DeviceInfo] = []
        self.lay = QVBoxLayout(self)
        head = QHBoxLayout()
        box = QVBoxLayout()
        box.setSpacing(0)
        t = QLabel(title)
        t.setObjectName("pageTitle")
        s = QLabel(subtitle)
        s.setObjectName("muted")
        s.setWordWrap(True)
        box.addWidget(t)
        box.addWidget(s)
        head.addLayout(box, 1)
        self.picker = QComboBox()
        self.picker.setMinimumWidth(330)
        self.picker.currentIndexChanged.connect(self._picked)
        self.b_refresh = MatrixButton("Refresh devices")
        self.b_refresh.clicked.connect(self.refresh_devices)
        head.addWidget(QLabel("Device"))
        head.addWidget(self.picker)
        head.addWidget(self.b_refresh)
        self.lay.addLayout(head)
        self.lay.addWidget(banner(UNTESTED))
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        self.lab.scan_done.connect(self.refresh_devices)

    def say(self, text: str, error: bool = False) -> None:
        self.msg.setText(f"<span style='color:{T.danger if error else T.green}'>{esc(text)}</span>")
        self.lab.state.log.emit("error" if error else "info", text)

    def refresh_devices(self) -> None:
        keep = self.address()

        def done(devs) -> None:
            self.devs = devs
            self.picker.blockSignals(True)
            self.picker.clear()
            for d in devs:
                flags = "".join(("●" if d.connected else "", "🔗" if d.paired else ""))
                self.picker.addItem(f"{d.display_name or '(unnamed)'}  ·  {d.address}  {flags}".rstrip(), d.address)
            i = self.picker.findData(keep) if keep else -1
            self.picker.setCurrentIndex(i if i >= 0 else (0 if devs else -1))
            self.picker.blockSignals(False)
            self.devices_loaded.emit()
            self._picked()
        run_in_background(self.app.btdevices.known, done, lambda e: (self.say(f"Cannot list devices: {e}", True), done([])))

    def address(self) -> str:
        return self.picker.currentData() or ""

    def current(self) -> DeviceInfo | None:
        a = self.address()
        return next((d for d in self.devs if d.address == a), None)

    def _picked(self) -> None:                                  # overridden
        pass

    def showEvent(self, e) -> None:                             # noqa: N802
        super().showEvent(e)
        if not self.devs:
            self.refresh_devices()


# ====================================================================== Device Manager
class DeviceManagerView(DeviceSection):
    def __init__(self, lab) -> None:
        super().__init__(lab, "Device Manager", "Pair, connect, disconnect, trust and remove devices through BlueZ. Every action asks first and is "
                                                "recorded in the device's connection history.")
        self.mgr = self.app.btdevices
        self.prompts = PairingPrompts(self)
        self.prompts.notice.connect(lambda t: self.say(t))
        self.table = make_table(["Name", "Address", "Technology", "Paired", "Trusted", "Connected", "Signal", "Type"], stretch_col=0)
        self.table.itemSelectionChanged.connect(self._row_picked)
        self.lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.buttons: dict[str, MatrixButton] = {}
        for key, label, kind in (("pair", "Pair…", "primary"), ("connect", "Connect…", ""), ("disconnect", "Disconnect…", ""), ("trust", "Trust…", ""),
                                 ("untrust", "Untrust…", ""), ("remove", "Remove pairing…", "danger"), ("inspect", "Inspect", "")):
            b = MatrixButton(label, kind) if kind else MatrixButton(label)
            b.clicked.connect(lambda _=False, k=key: self.act(k))
            self.buttons[key] = b
            row.addWidget(b)
        row.addStretch(1)
        self.lay.addLayout(row)
        self.note = QLabel("")
        self.note.setObjectName("muted")
        self.note.setWordWrap(True)
        self.lay.addWidget(self.note)
        self.lay.addWidget(self.msg)
        self.devices_loaded.connect(self._fill)

    def _fill(self) -> None:
        keep = self.address()
        self.table.setRowCount(len(self.devs))
        for r, d in enumerate(self.devs):
            vals = [d.display_name or "(unnamed)", d.address, d.technology, "yes" if d.paired else "no", "yes" if d.trusted else "no",
                    "yes" if d.connected else "no", "—" if d.rssi is None else f"{d.rssi} dBm", d.device_type]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, d.address)
                self.table.setItem(r, c, it)
            if d.address == keep:
                self.table.selectRow(r)

    def _row_picked(self) -> None:
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        if it:
            i = self.picker.findData(it.data(Qt.ItemDataRole.UserRole))
            if i >= 0 and i != self.picker.currentIndex():
                self.picker.setCurrentIndex(i)

    def _picked(self) -> None:
        d = self.current()
        for key, b in self.buttons.items():
            b.setEnabled(False)
        if d is None:
            self.note.setText("No device selected. Run a scan in Device Scanner, then Refresh devices.")
            return
        self.buttons["pair"].setEnabled(not d.paired)
        self.buttons["connect"].setEnabled(not d.connected)
        self.buttons["disconnect"].setEnabled(d.connected)
        self.buttons["trust"].setEnabled(not d.trusted)
        self.buttons["untrust"].setEnabled(d.trusted)
        self.buttons["remove"].setEnabled(not d.connected and (d.paired or d.trusted or d.bonded))
        self.buttons["inspect"].setEnabled(True)
        self.note.setText("Remove pairing asks BlueZ to forget the device; it never deletes files. Disconnect a device before removing its pairing."
                          if d.connected else "Remove pairing asks BlueZ to forget the device; it never deletes files.")

    PROMPTS = {
        "pair": ("Pair", "Pair with {n}? You may be asked to confirm a code, and the device may need to be in pairing mode.", "Pair"),
        "connect": ("Connect", "Connect to {n}? It will be able to use the services it offers while connected.", "Connect"),
        "disconnect": ("Disconnect", "Disconnect {n}?", "Disconnect"),
        "trust": ("Trust", "Trust {n}? A trusted device may reconnect on its own without asking you.", "Trust"),
        "untrust": ("Untrust", "Stop trusting {n}? It will have to ask before connecting.", "Untrust"),
        "remove": ("Remove pairing", "Remove the pairing with {n}? Its bond is deleted from Bluetooth on this computer; it can be paired again later.", "Remove"),
    }

    def act(self, key: str) -> None:
        d = self.current()
        if d is None:
            return
        if key == "inspect":
            self.lab.show_section("inspector")
            self.lab.views["inspector"].select(d.address)
            return
        title, text, verb = self.PROMPTS[key]
        name = f"{d.display_name or 'this device'} ({d.address})"
        if not confirm_dialog(self, title, "<p>" + esc(text.format(n=name)) + "</p>", verb, danger=(key == "remove")):
            return
        a = d.address
        fn = {"pair": lambda: self.mgr.pair(a, True, self.prompts), "connect": lambda: self.mgr.connect(a, True),
              "disconnect": lambda: self.mgr.disconnect(a, True), "trust": lambda: self.mgr.set_trusted(a, True, True),
              "untrust": lambda: self.mgr.set_trusted(a, False, True), "remove": lambda: self.mgr.remove_pairing(a, True)}[key]
        for b in self.buttons.values():
            b.setEnabled(False)
        self.say(f"{title}: {a}…")

        def done(res) -> None:
            self.say(res.message, not res.ok)
            self.refresh_devices()
        run_in_background(fn, done, lambda e: (self.say(str(e), True), self.refresh_devices()))


# ====================================================================== Device Inspector
class InspectorView(DeviceSection):
    def __init__(self, lab) -> None:
        super().__init__(lab, "Device Inspector", "Everything BlueZ and the inventory know about one device. Read-only: it never connects.")
        self.view = QTextBrowser()
        self.lay.addWidget(self.view, 1)
        self.lay.addWidget(self.msg)

    def select(self, address: str) -> None:
        i = self.picker.findData(address)
        if i >= 0:
            self.picker.setCurrentIndex(i)

    def _picked(self) -> None:
        a = self.address()
        if not a:
            self.view.setHtml("<p>No device selected. Scan first, then refresh the device list.</p>")
            return
        run_in_background(lambda: self.app.btinspector.inspect(a), self._show, lambda e: self.say(str(e), True))

    def _show(self, ins) -> None:
        d = ins.device
        rows = "".join(f"<tr><td style='color:{T.text_secondary};padding-right:18px'>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in ins.properties())
        h = [f"<h3>{esc(d.display_name or '(unnamed)')} · {esc(d.address)}</h3><table>{rows}</table>"]
        h.append("<h4>Profiles and advertised services</h4>" + (("<ul>" + "".join(f"<li>{esc(p)}</li>" for p in ins.profiles) + "</ul>") if ins.profiles else "<p>none reported</p>"))
        h.append("<h4>Resolved GATT services</h4>" + (("<ul>" + "".join(f"<li>{esc(s['name'])} <span style='color:{T.text_muted}'>{esc(s['uuid'])}</span></li>"
                                                                       for s in ins.gatt_services) + "</ul>") if ins.gatt_services else "<p>none (the device is not connected)</p>"))
        if ins.inventory:
            i = ins.inventory
            h.append(f"<h4>Inventory</h4><p>First seen {esc(fmt_ts(i['first_seen']))}, last seen {esc(fmt_ts(i['last_seen']))}. "
                     f"Category: {esc(i['category'] or '—')}. Authorised for testing: {'yes' if i['authorized'] else 'no'}.</p>")
        h.append("<h4>Connection history</h4>" + (("<ul>" + "".join(f"<li>{esc(fmt_ts(e['ts']))}: {esc(e['event'])} · {esc(e['result'])}" +
                                                                      (f" · {esc(e['detail'])}" if e["detail"] else "") + "</li>" for e in ins.history[:30]) + "</ul>")
                                                    if ins.history else "<p>nothing recorded yet</p>"))
        if ins.notes:
            h.append(f"<p style='color:{T.warning}'>" + "<br>".join(esc(n) for n in ins.notes) + "</p>")
        self.view.setHtml("".join(h))


# ====================================================================== BLE Explorer
class BLEExplorerView(DeviceSection):
    note_value = Signal(bytes)

    def __init__(self, lab) -> None:
        super().__init__(lab, "BLE Explorer", "Browse a connected device's GATT services and characteristics. Reading is the default; writing needs an authorised "
                                              "device, an explicit selection and a confirmation.")
        self.ble = self.app.btble
        self.chars: dict[str, blemod.GattCharacteristic] = {}
        self.sel: blemod.GattCharacteristic | None = None
        self.note_value.connect(self._notified)
        bar = QHBoxLayout()
        self.b_load = MatrixButton("Load GATT database", "primary")
        self.b_load.clicked.connect(self.load)
        bar.addWidget(self.b_load)
        bar.addStretch(1)
        self.lay.addLayout(bar)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Service / characteristic", "UUID", "Properties"])
        self.tree.setColumnWidth(0, 300)
        self.tree.itemSelectionChanged.connect(self._select)
        split.addWidget(self.tree)
        side = Panel("Selected characteristic")
        self.info = QTextBrowser()
        self.info.setMaximumHeight(140)
        side.add(self.info)
        row = QHBoxLayout()
        self.b_read = MatrixButton("Read")
        self.b_read.clicked.connect(self.read)
        self.b_sub = MatrixButton("Subscribe")
        self.b_sub.clicked.connect(self.toggle_sub)
        row.addWidget(self.b_read)
        row.addWidget(self.b_sub)
        row.addStretch(1)
        rw = QWidget()
        rw.setLayout(row)
        side.add(rw)
        self.value = QTextBrowser()
        side.add(self.value, 1)
        wrow = QHBoxLayout()
        self.hex = QLineEdit()
        self.hex.setPlaceholderText("Hex bytes to write, e.g. 01 0A FF")
        self.resp = QCheckBox("wait for response")
        self.resp.setChecked(True)
        self.b_write = MatrixButton("Write…", "danger")
        self.b_write.clicked.connect(self.write)
        for w in (self.hex, self.resp, self.b_write):
            wrow.addWidget(w)
        ww = QWidget()
        ww.setLayout(wrow)
        side.add(ww)
        self.wnote = QLabel("")
        self.wnote.setObjectName("muted")
        self.wnote.setWordWrap(True)
        side.add(self.wnote)
        split.addWidget(side)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        self.lay.addWidget(split, 1)
        self.lay.addWidget(self.msg)
        self._buttons()

    def hideEvent(self, e) -> None:                             # noqa: N802
        self.ble.unsubscribe_all()                              # never leave notifications running in the background
        super().hideEvent(e)

    def _picked(self) -> None:
        self.ble.unsubscribe_all()
        self.tree.clear()
        self.chars.clear()
        self.sel = None
        self.info.clear()
        self.value.clear()
        self._buttons()
        d = self.current()
        self.b_load.setEnabled(bool(d))
        if d is not None and not d.connected:
            self.say("This device is not connected. Connect it in the Device Manager first; the explorer never connects by itself.", True)
        else:
            self.msg.setText("")

    def load(self) -> None:
        a = self.address()
        if not a:
            return
        self.say(f"Reading the GATT database of {a}…")
        run_in_background(lambda: self.ble.tree(a), self._loaded, lambda e: self.say(str(e), True))

    def _loaded(self, services) -> None:
        self.tree.clear()
        self.chars.clear()
        for s in services:
            si = QTreeWidgetItem([s.name, s.uuid, "primary" if s.primary else "secondary"])
            if s.denied:
                si.setText(2, f"{si.text(2)} · firmware-update service: never written")
            self.tree.addTopLevelItem(si)
            for c in s.characteristics:
                ci = QTreeWidgetItem([c.name + ("  ⚠" if c.sensitive else ""), c.uuid, c.flag_text()])
                ci.setData(0, Qt.ItemDataRole.UserRole, c.path)
                self.chars[c.path] = c
                si.addChild(ci)
                for d in c.descriptors:
                    ci.addChild(QTreeWidgetItem([d.name, d.uuid, "descriptor"]))
            si.setExpanded(True)
        self.say(f"{len(services)} service(s), {len(self.chars)} characteristic(s). Nothing was read from the device yet.")

    def _select(self) -> None:
        items = self.tree.selectedItems()
        path = items[0].data(0, Qt.ItemDataRole.UserRole) if items else None
        self.sel = self.chars.get(path) if path else None
        self.value.clear()
        c = self.sel
        if c is None:
            self.info.clear()
        else:
            extra = []
            if c.sensitive:
                extra.append(f"<span style='color:{T.warning}'>This is a {esc(c.sensitive)} characteristic: it identifies the device or its owner.</span>")
            if c.protected:
                extra.append("It requires encryption or authentication; BlueZ may refuse the read unless the device is paired.")
            if c.denied:
                extra.append(f"<span style='color:{T.danger}'>{esc(c.denied)}: writes are never sent here.</span>")
            self.info.setHtml(f"<b>{esc(c.name)}</b><br>{esc(c.uuid)}<br>Properties: {esc(c.flag_text())}<br>" + "<br>".join(extra))
        self._buttons()

    def _buttons(self) -> None:
        c = self.sel
        self.b_read.setEnabled(bool(c and c.readable))
        self.b_sub.setEnabled(bool(c and c.can_notify))
        self.b_sub.setText("Unsubscribe" if c and self.ble.is_subscribed(c) else "Subscribe")
        why = self.ble.write_blockers(self.address(), c) if c else ["select a characteristic"]
        self.b_write.setEnabled(not why)
        self.hex.setEnabled(not why)
        self.wnote.setText("Writing is unavailable: " + "; ".join(why) + "." if why else
                           "Writing sends data to the device and can change its behaviour. Only do this on your own device.")

    def read(self) -> None:
        c = self.sel
        if not c:
            return
        run_in_background(lambda: self.ble.read(c), lambda data: self._show_value(c, data, "read"), lambda e: self.say(str(e), True))

    def _show_value(self, c, data: bytes, how: str) -> None:
        txt = blemod.decode_value(c.uuid, data)
        self.value.append(f"<b>{esc(how)}</b> {esc(blemod.hex_dump(data) or '(empty)')}" + (f" — {esc(txt)}" if txt else ""))
        self.lab.state.log.emit("info", f"{c.name}: {len(data)} byte(s) {how}")

    def toggle_sub(self) -> None:
        c = self.sel
        if not c:
            return
        try:
            if self.ble.is_subscribed(c):
                self.ble.unsubscribe(c)
            else:
                self.ble.subscribe(c, lambda data: self.note_value.emit(data))
        except BluetoothError as e:
            self.say(str(e), True)
        self._buttons()

    def _notified(self, data: bytes) -> None:
        if self.sel is not None:
            self._show_value(self.sel, data, "notification")

    def write(self) -> None:
        c = self.sel
        if not c:
            return
        try:
            data = blemod.parse_hex(self.hex.text())
        except ValueError as e:
            self.say(str(e), True)
            return
        a = self.address()
        dev = self.current()
        if not confirm_dialog(self, "Write to device",
                              f"<p>Send <b>{len(data)} byte(s)</b> <code>{esc(blemod.hex_dump(data))}</code> to</p><p><b>{esc(c.name)}</b><br><code>{esc(c.uuid)}</code><br>"
                              f"on <b>{esc((dev.display_name if dev else '') or a)}</b> ({esc(a)})?</p><p>This can change how the device behaves. It is your responsibility "
                              "that this is your own device.</p>", "Write", danger=True):
            return
        resp = self.resp.isChecked()
        run_in_background(lambda: self.ble.write(a, c, data, True, resp), lambda r: (self.say(r.message, not r.ok)), lambda e: self.say(str(e), True))



# ====================================================================== Security Auditor
class AuditorView(DeviceSection):
    def __init__(self, lab) -> None:
        super().__init__(lab, "Security Auditor", "Evidence-based findings for devices you own or are authorised to assess. The standard audit only reads what "
                                                  "BlueZ already holds; nothing is sent to the device.")
        self.aud = self.app.btauditor
        self.findings: list = []
        self.lay.addWidget(self._legend())
        bar = QHBoxLayout()
        self.deep = QCheckBox("Deep audit: read characteristics from the connected device (reads only; never writes, never guesses keys)")
        self.b_run = MatrixButton("Run audit", "primary")
        self.b_run.clicked.connect(self.run)
        self.b_clear = MatrixButton("Clear stored findings…", "danger")
        self.b_clear.clicked.connect(self.clear)
        self.history = QComboBox()
        self.history.currentIndexChanged.connect(self._load_history)
        bar.addWidget(self.deep, 1)
        bar.addWidget(self.history)
        bar.addWidget(self.b_run)
        bar.addWidget(self.b_clear)
        self.lay.addLayout(bar)
        self.gate = QLabel("")
        self.gate.setWordWrap(True)
        self.lay.addWidget(self.gate)
        self.summary = QLabel("")
        self.lay.addWidget(self.summary)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.table = make_table(["Severity", "Status", "Finding"], stretch_col=2)
        self.table.itemSelectionChanged.connect(self._detail)
        split.addWidget(self.table)
        self.detail = QTextBrowser()
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        self.lay.addWidget(split, 1)
        self.lay.addWidget(self.msg)

    def _legend(self) -> QLabel:
        l = QLabel("<b>confirmed</b>: verified from this computer (BlueZ reported it, or a read you approved succeeded) · <b>observation</b>: the device declares "
                   "or advertises it, not tested · <b>unknown</b>: cannot be determined here. Severity runs informational → critical; advertised data alone is "
                   "never rated critical.")
        l.setObjectName("muted")
        l.setWordWrap(True)
        return l

    def _picked(self) -> None:
        a = self.address()
        self.findings = []
        self.table.setRowCount(0)
        self.detail.clear()
        self.summary.clear()
        self.history.blockSignals(True)
        self.history.clear()
        if a:
            for r in self.aud.audits(a):
                self.history.addItem(f"#{r['id']} · {fmt_ts(r['started_at'])} · {'deep' if r['deep'] else 'standard'}", r["id"])
        self.history.blockSignals(False)
        ok = bool(a) and self.aud.authorised(a)
        self.b_run.setEnabled(ok)
        self.b_clear.setEnabled(bool(a) and self.history.count() > 0)
        self.gate.setText("" if ok else ("<span style='color:%s'>This device is not marked as yours / authorised. Mark it in Device Inventory first; audits never run "
                                         "against other people's devices.</span>" % T.warning) if a else "")
        if self.history.count():
            self._load_history()

    def _load_history(self) -> None:
        aid = self.history.currentData()
        if aid is not None:
            self._show(self.aud.findings(aid))

    def run(self) -> None:
        a = self.address()
        if not a:
            return
        deep = self.deep.isChecked()
        if deep and not confirm_dialog(self, "Deep audit", f"<p>Read every readable characteristic of <b>{esc(a)}</b>?</p><p>This connects to the device's GATT "
                                       "database and sends read requests. It never writes data, tries PINs or keys, or attacks encryption. The device must already "
                                       "be connected.</p>", "Run deep audit"):
            return
        self.say(f"Auditing {a}…")
        run_in_background(lambda: self.aud.audit_device(a, deep, deep), self._done, lambda e: self.say(str(e), True))

    def _done(self, res) -> None:
        aid, findings = res
        self.say(f"Audit #{aid} finished: {len(findings)} finding(s).")
        self._picked()
        self.history.setCurrentIndex(0)
        self._show(findings)

    def _show(self, findings) -> None:
        self.findings = findings
        s = BluetoothSecurityAuditor.summary(findings)
        self.summary.setText("  ".join(f"<span style='color:{SEV_COLOR[k]}'><b>{v}</b> {k}</span>" for k, v in s.items() if v) or "no findings")
        self.table.setRowCount(len(findings))
        for r, f in enumerate(findings):
            for c, v in enumerate((f.severity, f.status, f.title)):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setForeground(QColor(SEV_COLOR[f.severity]))
                self.table.setItem(r, c, it)
        if findings:
            self.table.selectRow(0)

    def _detail(self) -> None:
        r = self.table.currentRow()
        if not (0 <= r < len(self.findings)):
            return
        f = self.findings[r]
        self.detail.setHtml(f"<h3>{esc(f.title)}</h3><p><b style='color:{SEV_COLOR[f.severity]}'>{esc(f.severity)}</b> · {esc(STATUS_LABEL[f.status])}</p>"
                            f"<h4>Evidence</h4><p>{esc(f.evidence)}</p><h4>What it means</h4><p>{esc(f.explanation)}</p><h4>What to do</h4><p>{esc(f.remediation)}</p>"
                            f"<p style='color:{T.text_muted}'>{esc(fmt_ts(f.timestamp))} · device {esc(f.device)}</p>")

    def clear(self) -> None:
        a = self.address()
        if a and confirm_dialog(self, "Clear findings", f"<p>Delete all stored audit results for <b>{esc(a)}</b>? This cannot be undone.</p>", "Delete", danger=True):
            self.aud.clear(a)
            self._picked()
            self.say("Stored findings deleted.")
