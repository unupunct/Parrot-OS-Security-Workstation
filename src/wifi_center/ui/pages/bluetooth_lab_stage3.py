"""Bluetooth Lab sections: Packet Analyzer and Reports.

The analyzer records this computer's own controller (HCI) through the privileged helper (btmon, after you authenticate) and reads
btsnoop captures in-process; tshark is optional. Reports are built from the inventory and the auditor's stored findings."""
from __future__ import annotations

import html
import shutil
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QSpinBox, QSplitter,
                               QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from ...bluetooth.models import BluetoothError
from ...bluetooth.packets import REDACTED, BluetoothPacketAnalyzer
from ...bluetooth.reports import FORMATS
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.components import MatrixButton, Panel
from ..design.terminal_view import TerminalView
from ..design.tokens import T
from .bluetooth_lab_stage2 import banner
from .netsec_common import confirm_dialog

esc = html.escape
MAX_ROWS = 5000


class _Bridge(QObject):
    """Moves output lines and the finished result from the helper's callbacks onto the UI thread."""
    line = Signal(str)


# ====================================================================== Packet Analyzer
class PacketAnalyzerView(QWidget):
    def __init__(self, lab) -> None:
        super().__init__()
        self.lab, self.app = lab, lab.app
        self.an = self.app.btpackets
        self.analysis = None
        self.path = ""
        self.rows = []
        self._lines: list[str] = []
        lay = QVBoxLayout(self)
        t = QLabel("Packet Analyzer")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        lay.addWidget(banner(BluetoothPacketAnalyzer.SCOPE_NOTE))
        self.tools = QLabel("")
        self.tools.setObjectName("muted")
        self.tools.setWordWrap(True)
        lay.addWidget(self.tools)

        bar = QHBoxLayout()
        self.ctrl = QComboBox()
        self.secs = QSpinBox()
        self.secs.setRange(5, 300)
        self.secs.setValue(30)
        self.secs.setSuffix(" s")
        self.b_cap = MatrixButton("Capture…", "primary")
        self.b_cap.clicked.connect(self.capture)
        self.b_open = MatrixButton("Open capture…")
        self.b_open.clicked.connect(self.open_file)
        self.saved = QComboBox()
        self.saved.setMinimumWidth(240)
        self.saved.activated.connect(lambda _i: self.load(self.saved.currentData()))
        self.b_del = MatrixButton("Delete…", "danger")
        self.b_del.clicked.connect(self.delete)
        for w in (QLabel("Controller"), self.ctrl, QLabel("Length"), self.secs, self.b_cap, self.b_open, QLabel("Saved"), self.saved, self.b_del):
            bar.addWidget(w)
        bar.addStretch(1)
        lay.addLayout(bar)
        self.log = TerminalView()
        self.log.setMaximumHeight(110)
        lay.addWidget(self.log)

        self.summary = QTextBrowser()
        self.summary.setMaximumHeight(150)
        lay.addWidget(self.summary)
        fbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter packets (text in the summary, layer or tag)")
        self.search.textChanged.connect(self.fill)
        self.layer = QComboBox()
        self.layer.addItems(["All layers", "HCI", "ACL", "L2CAP", "ATT", "SMP", "note"])
        self.layer.currentIndexChanged.connect(self.fill)
        self.b_csv = MatrixButton("Export CSV")
        self.b_csv.clicked.connect(lambda: self.export("csv"))
        self.b_json = MatrixButton("Export JSON")
        self.b_json.clicked.connect(lambda: self.export("json"))
        self.b_save = MatrixButton("Save .btsnoop…")
        self.b_save.clicked.connect(self.save_copy)
        self.b_pcapng = MatrixButton("Export PCAPNG…")
        self.b_pcapng.clicked.connect(self.pcapng)
        self.b_tshark = MatrixButton("Decode with tshark")
        self.b_tshark.clicked.connect(self.tshark)
        fbar.addWidget(self.search, 1)
        for w in (self.layer, self.b_csv, self.b_json, self.b_save, self.b_pcapng, self.b_tshark):
            fbar.addWidget(w)
        lay.addLayout(fbar)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.table = make_table(["No.", "Time", "Layer", "Direction", "Summary", "Len"], stretch_col=4)
        self.table.itemSelectionChanged.connect(self._detail)
        split.addWidget(self.table)
        self.detail = QTextBrowser()
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.lab.state.adapters_changed.connect(self._controllers)
        self._controllers()
        self._saved()
        self._buttons()

    # ------------------------------------------------------------------ helpers
    def say(self, text: str, error: bool = False) -> None:
        self.msg.setText(f"<span style='color:{T.danger if error else T.green}'>{esc(text)}</span>")
        self.lab.state.log.emit("error" if error else "info", text)

    def _controllers(self) -> None:
        keep = self.ctrl.currentText()
        self.ctrl.clear()
        for a in self.lab.state.adapters:
            self.ctrl.addItem(a.name)
        i = self.ctrl.findText(keep)
        if i >= 0:
            self.ctrl.setCurrentIndex(i)
        t = self.an.tools()
        helper = getattr(self.app, "privileged", None)
        helper_ok = bool(helper and getattr(helper, "available", lambda: False)())
        self.tools.setText(f"btmon (capture, run by the privileged helper): {'found' if t['btmon'] else 'not installed — sudo apt install bluez'} · "
                           f"privileged helper: {'available' if helper_ok else 'not available — see Root Access'} · "
                           f"tshark (optional, full dissection and PCAPNG): {'found' if t['tshark'] else 'not installed — sudo apt install tshark'}")
        self._buttons()

    def _buttons(self) -> None:
        have = self.analysis is not None
        t = self.an.tools()
        self.b_cap.setEnabled(self.ctrl.count() > 0)
        for b in (self.b_csv, self.b_json, self.b_save):
            b.setEnabled(have)
        self.b_pcapng.setEnabled(have and bool(t["tshark"]))
        self.b_tshark.setEnabled(have and bool(t["tshark"]))
        self.b_del.setEnabled(self.saved.count() > 0)

    def _saved(self) -> None:
        self.saved.clear()
        for r in self.an.list():
            self.saved.addItem(f"{r['name']}  ·  {r['size'] // 1024 or 1} KiB", r["path"])

    # ------------------------------------------------------------------ capture (privileged)
    def capture(self) -> None:
        name, secs = self.ctrl.currentText(), self.secs.value()
        if not name:
            return
        from ...privileged.protocol import PrivilegedOp
        from ...services.privileged_service import run_privileged
        if not confirm_dialog(self, "Capture Bluetooth traffic",
                              f"<p>Record the HCI traffic of <b>{esc(name)}</b> for <b>{secs} seconds</b>?</p><p>This is <b>this computer's</b> controller only. It needs "
                              "administrator authentication, runs <code>btmon</code> through the privileged helper, and the capture can contain pairing secrets: it is "
                              "stored privately (mode 0600) and key material is redacted on screen and in exports.</p><p>Only capture your own devices.</p>", "Capture"):
            return
        op = PrivilegedOp("bt_capture", iface=name, seconds=secs)
        self.app.audit.record("bluetooth.capture", controller=name, seconds=secs)
        self.log.clear()
        self.log.command(op.summary(), "run by the privileged helper after you authenticate")
        self.b_cap.setEnabled(False)
        self._lines = []
        bridge = _Bridge()
        self._bridge = bridge                                       # keep alive while the helper reports back
        bridge.line.connect(self._on_line)

        def out(line: str) -> None:
            bridge.line.emit(line)
        run_privileged(self.app.privileged, op, out, self._captured)

    def _on_line(self, line: str) -> None:
        self._lines.append(line)
        if len(self._lines) <= 400:                                  # the live view is a courtesy; the capture file has everything
            self.log.appendPlainText(line)

    def _captured(self, res) -> None:
        self._buttons()
        path = next((l.split("capture-file:", 1)[1].strip() for l in reversed(self._lines) if "capture-file:" in l), "")
        if not path:
            (self.log.error)(res.message)
            self.say(res.message, True)
            return
        (self.log.ok if res.ok else self.log.warn)(res.message)
        try:
            stored = self.an.adopt(path)
        except BluetoothError as e:
            self.say(str(e), True)
            return
        self._saved()
        self.saved.setCurrentIndex(self.saved.findData(str(stored)))
        self.load(str(stored))

    # ------------------------------------------------------------------ files
    def open_file(self) -> None:
        name, _ = QFileDialog.getOpenFileName(self, "Open Bluetooth capture", str(Path.home()), "btsnoop captures (*.btsnoop *.log *.cfa);;All files (*)")
        if name:
            self.load(name)

    def load(self, path: str | None) -> None:
        if not path:
            return
        self.say(f"Reading {Path(path).name}…")
        run_in_background(lambda: self.an.analyze(path), lambda a: self._loaded(path, a), lambda e: self.say(str(e), True))

    def _loaded(self, path: str, a) -> None:
        self.analysis, self.path = a, path
        self.lab.state.analysis = a
        notes = "".join(f"<li>{esc(n)}</li>" for n in a.notes)
        self.summary.setHtml(f"<pre>{esc(a.summary_text())}</pre>" + (f"<ul>{notes}</ul>" if notes else ""))
        self.fill()
        self._buttons()
        self.say(f"{Path(path).name}: {len(a.packets)} packet(s).")

    def delete(self) -> None:
        p = self.saved.currentData()
        if p and confirm_dialog(self, "Delete capture", f"<p>Delete <b>{esc(Path(p).name)}</b>? This cannot be undone.</p>", "Delete", danger=True):
            try:
                self.an.delete(p)
            except BluetoothError as e:
                self.say(str(e), True)
                return
            self._saved()
            self._buttons()

    # ------------------------------------------------------------------ table
    def fill(self) -> None:
        a = self.analysis
        self.table.setRowCount(0)
        self.detail.clear()
        if a is None:
            return
        q, layer = self.search.text().strip().lower(), self.layer.currentText()
        self.rows = [p for p in a.packets if (layer == "All layers" or p.layer == layer) and
                     (not q or q in p.summary.lower() or q in p.layer.lower() or any(q in t for t in p.tags))]
        shown = self.rows[:MAX_ROWS]
        self.table.setRowCount(len(shown))
        for r, p in enumerate(shown):
            row = p.as_row()
            for c, v in enumerate((row["no"], row["time"], row["layer"], row["direction"], row["summary"], row["length"])):
                self.table.setItem(r, c, QTableWidgetItem(str(v)))
        if len(self.rows) > MAX_ROWS:
            self.say(f"Showing the first {MAX_ROWS} of {len(self.rows)} matching packets; narrow the filter or export everything.")

    def _detail(self) -> None:
        r = self.table.currentRow()
        if not (0 <= r < len(self.rows)):
            return
        p = self.rows[r]
        self.detail.setHtml(f"<h4>#{p.index} · {esc(p.layer)} · {esc(p.direction or '—')}</h4><p>{esc(p.summary)}</p>"
                            f"<p style='font-family:monospace'>{esc(p.hex())}</p>" +
                            (f"<p style='color:{T.warning}'>Key material: shown as {esc(REDACTED)} here and in exports.</p>" if p.secret else "") +
                            (f"<p>Tags: {esc(', '.join(p.tags))}</p>" if p.tags else ""))

    # ------------------------------------------------------------------ export
    def export(self, fmt: str) -> None:
        if self.analysis is None:
            return
        name, _ = QFileDialog.getSaveFileName(self, "Export packet summary", str(Path.home() / f"bluetooth-capture.{fmt}"), f"{fmt.upper()} (*.{fmt})")
        if name:
            Path(name).write_text(self.analysis.export_csv() if fmt == "csv" else self.analysis.export_json(), encoding="utf-8", newline="")
            self.app.audit.record("bluetooth.export_capture", path=name, fmt=fmt)
            self.say(f"Exported {len(self.analysis.packets)} packet summaries (key material redacted) to {name}")

    def save_copy(self) -> None:
        name, _ = QFileDialog.getSaveFileName(self, "Save capture", str(Path.home() / Path(self.path).name), "btsnoop (*.btsnoop)")
        if name:
            shutil.copyfile(self.path, name)
            self.say(f"Saved a copy to {name}. The raw file contains pairing secrets if a pairing was captured: keep it private.")

    def pcapng(self) -> None:
        name, _ = QFileDialog.getSaveFileName(self, "Export PCAPNG", str(Path.home() / "bluetooth-capture.pcapng"), "PCAPNG (*.pcapng)")
        if not name:
            return
        run_in_background(lambda: self.an.convert_pcapng(self.path, name), lambda _r: self.say(f"Converted to {name}. The raw data (including any secrets) is unredacted."),
                          lambda e: self.say(str(e), True))

    def tshark(self) -> None:
        flt = self.search.text().strip() if self.layer.currentIndex() == 0 and self.search.text().startswith(("bt", "hci", "l2cap", "smp")) else ""
        self.say("Running tshark…")
        run_in_background(lambda: self.an.tshark_decode(self.path, flt), lambda text: (self.detail.setPlainText(text or "(no packets matched)"), self.say("tshark finished.")),
                          lambda e: self.say(str(e), True))


# ====================================================================== Reports
class ReportsView(QWidget):
    def __init__(self, lab) -> None:
        super().__init__()
        self.lab, self.app = lab, lab.app
        self.gen = self.app.btreports
        lay = QVBoxLayout(self)
        t = QLabel("Reports")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        s = QLabel("Build HTML, PDF, JSON or CSV reports from the inventory and the Security Auditor's stored findings. Each finding keeps its status "
                   "(confirmed, observation, unknown), evidence and remediation. Keys, PINs and capture payloads are never included.")
        s.setObjectName("muted")
        s.setWordWrap(True)
        lay.addWidget(s)
        split = QSplitter(Qt.Orientation.Horizontal)
        side = Panel("Devices in the report")
        self.devs = QListWidget()
        side.add(self.devs, 1)
        row = QHBoxLayout()
        b_all, b_none = MatrixButton("All"), MatrixButton("None")
        b_all.clicked.connect(lambda: self._check(True))
        b_none.clicked.connect(lambda: self._check(False))
        row.addWidget(b_all)
        row.addWidget(b_none)
        row.addStretch(1)
        rw = QWidget()
        rw.setLayout(row)
        side.add(rw)
        self.title = QLineEdit("Bluetooth Security Report")
        self.notes = QCheckBox("Include my notes")
        self.cap = QCheckBox("Include the summary of the capture open in Packet Analyzer")
        self.fmt = QComboBox()
        self.fmt.addItems([f.upper() for f in FORMATS])
        for w in (QLabel("Title"), self.title, self.notes, self.cap, QLabel("Format"), self.fmt):
            side.add(w)
        b_prev = MatrixButton("Preview")
        b_prev.clicked.connect(self.preview)
        b_gen = MatrixButton("Generate…", "primary")
        b_gen.clicked.connect(self.generate)
        brow = QHBoxLayout()
        brow.addWidget(b_prev)
        brow.addWidget(b_gen)
        bw = QWidget()
        bw.setLayout(brow)
        side.add(bw)
        split.addWidget(side)
        self.view = QTextBrowser()
        split.addWidget(self.view)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 3)
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.lab.scan_done.connect(self.reload)
        self.reload()

    def showEvent(self, e) -> None:                                  # noqa: N802
        super().showEvent(e)
        self.reload()

    def say(self, text: str, error: bool = False) -> None:
        self.msg.setText(f"<span style='color:{T.danger if error else T.green}'>{esc(text)}</span>")

    def reload(self) -> None:
        checked = set(self._addresses())
        first = self.devs.count() == 0
        self.devs.clear()
        for d in self.app.btinventory.devices(sort="name"):
            it = QListWidgetItem(f"{d['custom_name'] or d['name'] or '(unnamed)'}  ·  {d['address']}" + ("  ✔ authorised" if d["authorized"] else ""))
            it.setData(Qt.ItemDataRole.UserRole, d["address"])
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked if first or d["address"] in checked else Qt.CheckState.Unchecked)
            self.devs.addItem(it)

    def _check(self, on: bool) -> None:
        for i in range(self.devs.count()):
            self.devs.item(i).setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)

    def _addresses(self) -> list[str]:
        return [self.devs.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.devs.count()) if self.devs.item(i).checkState() == Qt.CheckState.Checked]

    def _report(self):
        analysis = getattr(self.lab.state, "analysis", None) if self.cap.isChecked() else None
        return self.gen.build(self._addresses(), self.notes.isChecked(), analysis, self.title.text().strip() or "Bluetooth Security Report")

    def preview(self) -> None:
        if not self._addresses():
            self.say("Tick at least one device.", True)
            return
        self.view.setHtml(self.gen.to_html(self._report()))

    def generate(self) -> None:
        addrs = self._addresses()
        if not addrs:
            self.say("Tick at least one device.", True)
            return
        fmt = self.fmt.currentText().lower()
        name, _ = QFileDialog.getSaveFileName(self, "Save report", str(Path.home() / f"bluetooth-report.{fmt}"), f"{fmt.upper()} (*.{fmt})")
        if not name:
            return
        report = self._report()

        def done(p: Path) -> None:
            self.app.audit.record("bluetooth.report", path=str(p), fmt=fmt, devices=len(addrs))
            self.say(f"Report saved to {p}")
        if fmt == "pdf":                                              # Qt text rendering belongs on the UI thread
            try:
                done(self.gen.write(report, name, fmt))
            except BluetoothError as e:
                self.say(str(e), True)
            return
        run_in_background(lambda: self.gen.write(report, name, fmt), done, lambda e: self.say(str(e), True))
