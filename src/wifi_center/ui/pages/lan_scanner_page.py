"""LAN Scanner: find every device on your own network (Advanced-IP-Scanner style).

Only subnets attached to this computer can be scanned (enforced in the service). The sweep uses ping and the ARP table; it
never port-scans by itself. "Check common ports" tests a short well-known list on the ONE device you select."""
from __future__ import annotations

import html
import threading
import webbrowser

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QProgressBar, QSplitter,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services import lan_scanner as ls
from ...workers.task import run_in_background
from ..charts import make_table
from ..design.components import LoadingIndicator, MatrixButton
from ..design.tokens import T
from ..widgets import human_duration  # noqa: F401  (kept for consistency with other pages)

esc = html.escape
COLS = ["", "IP address", "Name", "MAC address", "Manufacturer", "Ping", "Notes", "Open ports"]


class _Progress(QWidget):
    """Thread-safe bridge: worker threads emit, the GUI thread updates the bar."""
    changed = Signal(int, int, int)


class LanScannerPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.devices: list[ls.Device] = []
        self._cancel: threading.Event | None = None
        self._nets: list[ls.LocalNet] = []
        self._bridge = _Progress()
        self._bridge.changed.connect(self._on_progress)

        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("LAN Scanner")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("scan", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        lay.addLayout(head)
        note = QLabel("Finds the devices on a network attached to this computer, using ping and the ARP table. It only scans your "
                      "own networks, never checks ports by itself, and remembers devices so new ones stand out.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)

        bar = QHBoxLayout()
        self.net = QComboBox()
        self.net.setMinimumWidth(320)
        self.b_scan = MatrixButton("Scan", "primary", "discovery")
        self.b_scan.clicked.connect(self.scan)
        self.b_stop = MatrixButton("Stop")
        self.b_stop.clicked.connect(self._stop)
        self.b_stop.setEnabled(False)
        self.b_csv = MatrixButton("Export CSV…")
        self.b_csv.clicked.connect(self._export)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by IP, name, MAC or manufacturer…")
        self.search.textChanged.connect(self._fill)
        for w in (QLabel("Network"), self.net, self.b_scan, self.b_stop, self.search, self.b_csv):
            bar.addWidget(w)
        bar.setStretch(4, 1)
        lay.addLayout(bar)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.setRange(0, 100)
        lay.addWidget(self.progress)
        self.summary = QLabel("Choose a network and press Scan.")
        lay.addWidget(self.summary)

        split = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table(COLS, stretch_col=2)
        self.table.setSortingEnabled(False)
        self.table.itemSelectionChanged.connect(self._select)
        self.table.setColumnWidth(0, 28)
        split.addWidget(self.table)
        split.addWidget(self._detail())
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setObjectName("muted")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self._load_networks()

    # ------------------------------------------------------------------ setup
    @property
    def scanner(self) -> ls.LanScanner:
        return self.app.lan

    def _load_networks(self) -> None:
        seen: set[str] = set()
        self._nets = [n for n in self.scanner.networks() if not (n.network in seen or seen.add(n.network))]   # one entry per subnet
        self.net.clear()
        for n in self._nets:
            self.net.addItem(n.label, n.network)
        if not self._nets:
            self.summary.setText("No private network is attached to this computer, so there is nothing to scan.")
            self.b_scan.setEnabled(False)

    def _detail(self) -> QWidget:
        box = QFrame()
        box.setObjectName("panel")
        lay = QVBoxLayout(box)
        self.d_head = QLabel("Select a device to see its details.")
        self.d_head.setTextFormat(Qt.TextFormat.RichText)
        self.d_head.setWordWrap(True)
        lay.addWidget(self.d_head)
        row = QHBoxLayout()
        self.label = QLineEdit()
        self.label.setPlaceholderText("Your name for this device (saved by MAC address)")
        self.b_save = MatrixButton("Save name")
        self.b_save.clicked.connect(self._save_label)
        self.b_ip = MatrixButton("Copy IP")
        self.b_ip.clicked.connect(lambda: self._copy("ip"))
        self.b_mac = MatrixButton("Copy MAC")
        self.b_mac.clicked.connect(lambda: self._copy("mac"))
        self.b_ping = MatrixButton("Ping")
        self.b_ping.clicked.connect(self._ping)
        self.b_ports = MatrixButton("Check common ports")
        self.b_ports.clicked.connect(self._ports)
        self.b_web = MatrixButton("Open in browser")
        self.b_web.clicked.connect(self._web)
        row.addWidget(self.label, 1)
        for w in (self.b_save, self.b_ip, self.b_mac, self.b_ping, self.b_ports, self.b_web):
            row.addWidget(w)
        lay.addLayout(row)
        self._buttons = (self.label, self.b_save, self.b_ip, self.b_mac, self.b_ping, self.b_ports, self.b_web)
        for w in self._buttons:
            w.setEnabled(False)
        return box

    # ------------------------------------------------------------------ scanning
    def scan(self) -> None:
        cidr = self.net.currentData()
        if not cidr or self._cancel is not None:
            return
        self._cancel = threading.Event()
        cancel = self._cancel
        self.b_scan.setEnabled(False)
        self.b_stop.setEnabled(True)
        self.loader.start()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.summary.setText(f"Scanning {cidr}…")
        self.msg.setText("")
        self.app.audit.record("lan.scan", network=cidr)
        nets = self._nets
        run_in_background(lambda: self.scanner.scan(cidr, nets, lambda d, t, f: self._bridge.changed.emit(d, t, f), cancel),
                          lambda devs: self._done(devs, cancel.is_set()), self._failed)

    def _on_progress(self, done: int, total: int, found: int) -> None:
        self.progress.setValue(int(done * 100 / max(total, 1)))
        self.summary.setText(f"Scanning… {done} of {total} addresses probed, {found} answered")

    def _stop(self) -> None:
        if self._cancel is not None:
            self._cancel.set()
            self.summary.setText("Stopping…")

    def _finish_ui(self) -> None:
        self._cancel = None
        self.loader.stop()
        self.b_scan.setEnabled(bool(self._nets))
        self.b_stop.setEnabled(False)

    def _failed(self, err: str) -> None:
        self._finish_ui()
        self.summary.setText("Scan failed.")
        self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(err))}</span>")

    def _done(self, devices: list[ls.Device], cancelled: bool) -> None:
        self._finish_ui()
        if cancelled:
            self.summary.setText("Scan stopped; the previous result is kept.")
            return
        self.devices = devices
        self.progress.setValue(100)
        new = sum("new" in d.tags for d in devices)
        self.summary.setText(f"{len(devices)} device(s) found" + (f", {new} new since the last scan" if new else "") + ".")
        self._fill()

    # ------------------------------------------------------------------ table
    def _visible(self) -> list[ls.Device]:
        q = self.search.text().strip().lower()
        if not q:
            return self.devices
        return [d for d in self.devices if q in " ".join((d.ip, d.hostname, d.label, d.mac, d.vendor, *d.tags)).lower()]

    def _fill(self) -> None:
        keep = self._current_ip()
        rows = self._visible()
        self.table.setRowCount(len(rows))
        for r, d in enumerate(rows):
            color = T.cyan if "gateway" in d.tags else T.green if "this computer" in d.tags else T.warning if "new" in d.tags else None
            name = d.label or d.hostname or "—"
            ping = "—" if d.rtt_ms is None else f"{d.rtt_ms:.1f} ms"
            ports = ", ".join(f"{p}/{n}" if n else str(p) for p, n in d.ports)
            notes = ", ".join(t.upper() if t == "new" else t for t in d.tags)
            for c, text in enumerate(["●", d.ip, name, d.mac or "—", d.vendor or "—", ping, notes, ports]):
                it = QTableWidgetItem(text)
                if c == 0:
                    it.setForeground(QColor(T.green if d.rtt_ms is not None else T.warning))
                    it.setToolTip("answered ping" if d.rtt_ms is not None else "found by ARP (does not answer ping)")
                elif color:
                    it.setForeground(QColor(color))
                self.table.setItem(r, c, it)
            if d.ip == keep:
                self.table.selectRow(r)

    def _current_ip(self) -> str | None:
        r = self.table.currentRow()
        it = self.table.item(r, 1) if r >= 0 else None
        return it.text() if it else None

    def _current(self) -> ls.Device | None:
        ip = self._current_ip()
        return next((d for d in self.devices if d.ip == ip), None)

    def _select(self) -> None:
        d = self._current()
        for w in self._buttons:
            w.setEnabled(d is not None)
        if d is None:
            self.d_head.setText("Select a device to see its details.")
            return
        self.b_mac.setEnabled(bool(d.mac))
        self.b_save.setEnabled(bool(d.mac))
        self.label.setEnabled(bool(d.mac))
        self.b_web.setEnabled(any(p in ls.WEB_PORTS for p, _ in d.ports))
        self.label.setText(d.label)
        seen = f"first seen {esc(d.first_seen[:10])}, last seen {esc(d.last_seen[:16].replace('T', ' '))} UTC" if d.first_seen else ""
        self.d_head.setText(f"<b>{esc(d.ip)}</b> &nbsp; {esc(d.hostname or 'no DNS name')} &nbsp;·&nbsp; {esc(d.mac or 'no MAC')} "
                            f"&nbsp;·&nbsp; {esc(d.vendor or 'unknown manufacturer')}<br><span style='color:{T.text_secondary}'>{seen}</span>")

    # ------------------------------------------------------------------ per-device actions
    def _copy(self, what: str) -> None:
        d = self._current()
        if d:
            QGuiApplication.clipboard().setText(d.ip if what == "ip" else d.mac)
            self.msg.setText(f"Copied {d.ip if what == 'ip' else d.mac}")

    def _save_label(self) -> None:
        d = self._current()
        if d and d.mac:
            self.scanner.set_label(d.mac, self.label.text())
            d.label = self.label.text().strip()[:60]
            self._fill()
            self.msg.setText("Name saved.")

    def _ping(self) -> None:
        d = self._current()
        if not d:
            return
        self.msg.setText(f"Pinging {d.ip}…")
        run_in_background(lambda: ls.ping_once(d.ip, 1.5),
                          lambda rtt: self.msg.setText(f"{d.ip}: " + (f"{rtt:.1f} ms" if rtt is not None else "no reply")),
                          lambda e: self.msg.setText(str(e)))

    def _ports(self) -> None:
        d = self._current()
        if not d:
            return
        self.app.audit.record("lan.check_ports", ip=d.ip)
        self.loader.start()
        self.msg.setText(f"Checking {len(ls.COMMON_PORTS)} well-known ports on {d.ip}…")
        nets = self._nets

        def done(res) -> None:
            self.loader.stop()
            d.ports = res
            self._fill()
            self._select()
            self.msg.setText(f"{d.ip}: " + (", ".join(f"{p}/{n or 'open'}" for p, n in res) if res else "none of the checked ports are open."))
        run_in_background(lambda: self.scanner.check_ports(d.ip, nets=nets), done,
                          lambda e: (self.loader.stop(), self.msg.setText(str(e))))

    def _web(self) -> None:
        d = self._current()
        port = next((p for p in ls.WEB_PORTS if d and any(p == q for q, _ in d.ports)), None)
        if d and port:
            scheme = "https" if port in (443, 8443) else "http"
            webbrowser.open(f"{scheme}://{d.ip}" + ("" if port in (80, 443) else f":{port}"))

    def _export(self) -> None:
        if not self.devices:
            self.msg.setText("Scan first; there is nothing to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export devices", "lan-devices.csv", "CSV (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(ls.to_csv(self.devices))
            self.msg.setText(f"Exported {len(self.devices)} device(s) to {path}")
