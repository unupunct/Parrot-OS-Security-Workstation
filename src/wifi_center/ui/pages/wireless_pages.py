"""Wi-Fi Center (adapter manager) and Wireless Discovery."""
from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QPlainTextEdit, QPushButton, QSplitter, QTableWidgetItem,
                               QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services.adapter_service import AdapterService, WirelessAdapter
from ...services.wireless_service import ScanError
from ...workers.task import run_in_background
import pyqtgraph as pg
from PySide6.QtWidgets import QTabWidget

from ..charts import NumItem, color, fmt_ts, make_plot, make_table, signal_bars
from ..design.components import LoadingIndicator, StatusChip
from ..design.tokens import T
from ..radar import RadarWidget

esc = html.escape


class AdapterPage(QWidget):
    """Read-only adapter inventory and driver diagnostics."""

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.svc = app.services.get(AdapterService)
        self._adapters: list[WirelessAdapter] = []
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Wi-Fi Center")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.refresh_btn = QPushButton("Detect adapters")
        self.refresh_btn.setObjectName("primary")
        self.refresh_btn.clicked.connect(self.refresh)
        head.addWidget(self.refresh_btn)
        lay.addLayout(head)
        note = QLabel("Adapter manager. Changing interface state (monitor mode, up/down) needs root and is not "
                      "available until the privileged helper arrives in Phase 8; this page only reads state.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self._show)
        split.addWidget(self.list)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.details = QTextBrowser()
        rl.addWidget(self.details, 2)
        row = QHBoxLayout()
        self.diag_btn = QPushButton("Run driver diagnostics")
        self.diag_btn.clicked.connect(self._diagnostics)
        row.addWidget(self.diag_btn)
        row.addStretch(1)
        rl.addLayout(row)
        self.diag = QPlainTextEdit()
        self.diag.setReadOnly(True)
        self.diag.setStyleSheet("font-family: 'DejaVu Sans Mono','Consolas',monospace;")
        rl.addWidget(self.diag, 3)
        split.addWidget(right)
        split.setStretchFactor(1, 3)
        lay.addWidget(split, 1)
        self.refresh()

    def refresh(self) -> None:
        self.refresh_btn.setEnabled(False)
        self.details.setPlainText("Detecting…")
        run_in_background(self.svc.detect, self._loaded, lambda e: (self.details.setPlainText(f"Failed: {e}"),
                                                                    self.refresh_btn.setEnabled(True)))

    def _loaded(self, adapters: list[WirelessAdapter]) -> None:
        self.refresh_btn.setEnabled(True)
        self._adapters = adapters
        self.list.clear()
        for a in adapters:
            self.list.addItem(f"{a.interface}  ({a.state})")
        if not self.svc.supported():
            self.details.setPlainText("Adapter detection requires Linux (/sys/class/net).")
        elif not adapters:
            self.details.setPlainText("No wireless adapters detected.\n\nIf you expect one: check that it is plugged "
                                      "in, that its driver is loaded, and that rfkill is not blocking it.")
        else:
            self.list.setCurrentRow(0)

    def _current(self) -> WirelessAdapter | None:
        r = self.list.currentRow()
        return self._adapters[r] if 0 <= r < len(self._adapters) else None

    def _show(self, _row: int) -> None:
        a = self._current()
        if not a:
            return
        mon = {True: "supported", False: "not supported", None: "unknown (needs the iw tool)"}[a.monitor_capable]
        ids = f"{a.vendor_id}:{a.product_id}" if a.vendor_id and a.product_id else "unknown"
        rows = [("Interface", a.interface), ("State", a.state), ("MAC address", a.mac or "unknown"),
                ("Driver", a.driver or "unknown"), ("Manufacturer", a.manufacturer or "unknown"),
                ("Vendor:device ID", ids), ("Bands", ", ".join(a.bands) or "unknown"), ("Monitor mode", mon),
                ("Connected network", a.connected_ssid or "not connected"), ("PHY", a.phy or "unknown")]
        self.details.setHtml("<table cellpadding='4'>" + "".join(
            f"<tr><td style='color:{T.text_secondary}'>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in rows) + "</table>"
            f"<p style='color:{T.text_secondary}'>Chipset is not reported by the kernel; the vendor:device ID above identifies it.</p>")
        self.diag.clear()

    def _diagnostics(self) -> None:
        a = self._current()
        if not a:
            return
        self.diag.setPlainText("Running read-only diagnostics…")
        run_in_background(lambda: self.svc.diagnostics(a.interface),
                          lambda res: self.diag.setPlainText("\n\n".join(f"### {t}\n{o}" for t, o in res)),
                          lambda e: self.diag.setPlainText(f"Failed: {e}"))


COLS = ["SSID", "BSSID", "Ch", "Freq (MHz)", "Signal", "dBm", "Encryption", "Auth", "Vendor", "First seen", "Last seen"]


class DiscoveryPage(QWidget):
    def __init__(self, app: AppController, on_scanned=None) -> None:
        super().__init__()
        self.app = app
        self.svc = app.wireless
        self._rows: list[dict] = []
        self._on_scanned = on_scanned
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Wireless Discovery")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.iface = QComboBox()
        self.iface.setToolTip("Interface to scan (auto = let NetworkManager choose)")
        self.iface.addItem("auto", "")
        self.scan_btn = QPushButton("Scan now")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.setToolTip("Run a standard Wi-Fi scan (the same request your network menu makes)")
        self.scan_btn.clicked.connect(self.scan)
        self.auto = QCheckBox("Auto-scan every 20 s")
        self.auto.toggled.connect(self._toggle_auto)
        for w in (self.iface, self.auto, self.scan_btn):
            head.addWidget(w)
        lay.addLayout(head)

        strip = QHBoxLayout()
        self.chip_adapter = StatusChip("Adapter: detecting…", T.text_muted)
        self.chip_bands = StatusChip("Bands: ?", T.text_muted)
        self.chip_monitor = StatusChip("Monitoring: not active", T.text_muted)
        self.chip_monitor.setToolTip("WIFI Center scans in managed mode. Monitor-mode control arrives with the "
                                     "privileged helper (Phase 8).")
        self.loader = LoadingIndicator("radar", 26)
        for c in (self.chip_adapter, self.chip_bands, self.chip_monitor, self.loader):
            strip.addWidget(c)
        strip.addStretch(1)
        lay.addLayout(strip)

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search SSID, BSSID, vendor…")
        self.search.textChanged.connect(self.reload_view)
        self.band = QComboBox()
        self.band.addItems(["All bands", "2.4 GHz", "5 GHz", "6 GHz"])
        self.band.currentIndexChanged.connect(self.reload_view)
        self.enc = QComboBox()
        self.enc.addItems(["All security", "Open", "WEP", "WPA", "WPA2", "WPA3", "802.1X"])
        self.enc.currentIndexChanged.connect(self.reload_view)
        self.scope = QComboBox()
        self.scope.addItems(["Last scan", "All stored observations"])
        self.scope.currentIndexChanged.connect(self.reload_view)
        for w in (self.search, self.band, self.enc, self.scope):
            bar.addWidget(w)
        ex = QPushButton("Export…")
        ex.clicked.connect(self._export)
        bar.addWidget(ex)
        lay.addLayout(bar)
        self.status = QLabel("")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        # ---- laboratory layout: table | radar + details, instruments below
        self.table = make_table(COLS)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._history)
        self.radar = RadarWidget()
        self.radar.ap_selected.connect(self._select_by_id)
        self.details = QTextBrowser()
        self.details.setMinimumHeight(90)
        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(self.radar)
        right.addWidget(self.details)
        right.setStretchFactor(0, 3)
        top = QSplitter(Qt.Orientation.Horizontal)
        top.addWidget(self.table)
        top.addWidget(right)
        top.setStretchFactor(0, 3)
        top.setStretchFactor(1, 2)
        top.setSizes([760, 420])

        self.plot = make_plot("Signal history of the selected network", "scan #", "dBm")
        self.chan_plot = make_plot("Channel distribution (current view)", "channel", "networks")
        self.timeline_plot = make_plot("Activity timeline: access points seen per scan", "scan #", "networks")
        self.instruments = QTabWidget()
        self.instruments.addTab(self.plot, "Signal history")
        self.instruments.addTab(self.chan_plot, "Channel distribution")
        self.instruments.addTab(self.timeline_plot, "Activity timeline")
        self.instruments.setMinimumHeight(140)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(top)
        split.addWidget(self.instruments)
        split.setStretchFactor(0, 3)
        split.setSizes([520, 230])
        lay.addWidget(split, 1)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.scan)
        self._fill_ifaces()
        self.reload_view()

    # ---- interfaces ----
    def _fill_ifaces(self) -> None:
        def done(adapters) -> None:
            for a in adapters:
                self.iface.addItem(a.interface, a.interface)
            if adapters:
                a = adapters[0]
                self.chip_adapter.set_state(f"{a.interface} · {a.state} · {a.driver or 'driver ?'}",
                                            T.success if a.state == "up" else T.warning)
                self.chip_bands.set_state("Bands: " + (", ".join(a.bands) or "unknown"), T.cyan)
                mon = {True: "monitor capable", False: "no monitor mode", None: "monitor unknown"}[a.monitor_capable]
                self.chip_monitor.set_state(f"Monitoring: inactive · {mon}", T.text_muted)
            else:
                self.chip_adapter.set_state("No wireless adapter detected", T.text_muted)
        run_in_background(self.app.services.get(AdapterService).detect, done, lambda e: None)

    # ---- scanning ----
    def _toggle_auto(self, on: bool) -> None:
        self._timer.start(20000) if on else self._timer.stop()
        if on:
            self.scan()

    def scan(self) -> None:
        if not self.scan_btn.isEnabled():
            return
        iface = self.iface.currentData() or None
        self.scan_btn.setEnabled(False)
        self.loader.start()
        self.status.setText("Scanning…")

        def work():
            aps = self.svc.scan(iface)
            self.svc.record(aps)
            self.app.audit.record("wifi.scan", interface=iface or "auto", found=len(aps))
            return len(aps)

        run_in_background(work, self._scanned, self._scan_failed)

    def _scanned(self, n: int) -> None:
        self.scan_btn.setEnabled(True)
        self.loader.stop()
        self.status.setText(f"Scan complete: {n} access points." + ("" if self.svc.oui.available else
                            "  Vendor names unavailable (install the ieee-data package)."))
        self.reload_view()
        if self._on_scanned:
            self._on_scanned()

    def _scan_failed(self, err: str) -> None:
        self.scan_btn.setEnabled(True)
        self.loader.stop()
        self.status.setText(f"Scan failed: {err}")

    # ---- table ----
    def _filtered(self) -> list[dict]:
        rows = self.svc.observations()
        if self.scope.currentIndex() == 0:
            latest = self.svc.latest_scan_ts()
            rows = [r for r in rows if r["source"] != "wifi-scan" or r["last_seen"] == latest] if latest else []
        q = self.search.text().strip().lower()
        if q:
            rows = [r for r in rows if q in (r["ssid"] or "").lower() or q in r["bssid"].lower()
                    or q in (r["vendor"] or "").lower()]
        if self.band.currentIndex() > 0:
            rows = [r for r in rows if r["band"] == self.band.currentText()]
        if self.enc.currentIndex() > 0:
            want = self.enc.currentText()
            rows = [r for r in rows if want in (r["encryption"] or "") or want == (r["auth"] or "")]
        return rows

    def reload_view(self) -> None:
        self._rows = self._filtered()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self._rows))
        for r, o in enumerate(self._rows):
            cells = [
                (o["ssid"] or "<hidden>", None), (o["bssid"], None),
                (str(o["channel"] or ""), o["channel"]), (str(o["frequency_mhz"] or ""), o["frequency_mhz"]),
                (signal_bars(o["signal_dbm"]), o["signal_dbm"]),
                ("" if o["signal_dbm"] is None else f"{o['signal_dbm']:.0f}", o["signal_dbm"]),
                (o["encryption"] or "", None), (o["auth"] or "", None), (o["vendor"] or "", None),
                (fmt_ts(o["first_seen"]), None), (fmt_ts(o["last_seen"]), None)]
            for c, (text, key) in enumerate(cells):
                item = NumItem(text, key) if c in (2, 3, 4, 5) else QTableWidgetItem(text)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, o["id"])
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)
        self.radar.set_observations(self._rows)
        self._draw_instruments()
        if not self._rows and not self.status.text().startswith(("Scan", "Scanning")):
            self.status.setText("No observations yet. Press “Scan now” (needs NetworkManager or iw and a wireless adapter).")
        self.table.resizeColumnsToContents()

    def _select_by_id(self, obs_id: int) -> None:
        for r in range(self.table.rowCount()):
            if self.table.item(r, 0).data(Qt.ItemDataRole.UserRole) == obs_id:
                self.table.selectRow(r)
                return

    def _draw_instruments(self) -> None:
        from collections import Counter
        self.chan_plot.clear()
        counts = Counter(o["channel"] for o in self._rows if o["channel"])
        chans = sorted(counts)
        if chans:
            self.chan_plot.addItem(pg.BarGraphItem(x=list(range(len(chans))), height=[counts[c] for c in chans],
                                                   width=0.7, brush=color(0), pen=None))
            self.chan_plot.getAxis("bottom").setTicks([[(i, str(c)) for i, c in enumerate(chans)]])
        self.timeline_plot.clear()
        tl = self.svc.scan_timeline()
        if tl:
            self.timeline_plot.addItem(pg.BarGraphItem(x=list(range(1, len(tl) + 1)), height=[n for _, n in tl],
                                                       width=0.7, brush=color(1), pen=None))

    def _history(self) -> None:
        self.plot.clear()
        r = self.table.currentRow()
        item = self.table.item(r, 0) if r >= 0 else None
        if not item:
            return
        oid = item.data(Qt.ItemDataRole.UserRole)
        self.radar.set_selected(oid)
        row = next((o for o in self._rows if o["id"] == oid), None)
        if row:
            self._show_details(row)
        samples = [s for s in self.svc.history(oid) if s["signal_dbm"] is not None]
        if samples:
            self.plot.plot(list(range(1, len(samples) + 1)), [s["signal_dbm"] for s in samples],
                           pen=color(0), symbol="o", symbolSize=6, symbolBrush=color(0))

    def _show_details(self, o: dict) -> None:
        pct = f" ({o['signal_pct']:.0f} %)" if o.get("signal_pct") is not None else ""
        rows = [("SSID", o["ssid"] or "<hidden>"), ("BSSID", o["bssid"]), ("Vendor", o["vendor"] or "unknown"),
                ("Channel / band", f"{o['channel']} · {o['band']} · {o['frequency_mhz']} MHz"),
                ("Signal", f"{o['signal_dbm']:.0f} dBm{pct}" if o["signal_dbm"] is not None else "—"),
                ("Security", f"{o['encryption']}" + (f" / {o['auth']}" if o["auth"] else "")),
                ("First seen", fmt_ts(o["first_seen"])), ("Last seen", fmt_ts(o["last_seen"])),
                ("Source", o["source"])]
        self.details.setHtml("<table cellpadding='3'>" + "".join(
            f"<tr><td style='color:{T.text_secondary}'>{esc(k)}</td><td>{esc(str(v))}</td></tr>" for k, v in rows)
            + "</table>")

    def _export(self) -> None:
        if not self._rows:
            self.status.setText("Nothing to export.")
            return
        name, flt = QFileDialog.getSaveFileName(self, "Export observations", str(Path.home() / "wifi-observations.csv"),
                                                "CSV (*.csv);;JSON (*.json)")
        if not name:
            return
        fmt = "json" if name.lower().endswith(".json") else "csv"
        Path(name).write_text(self.svc.export(self._rows, fmt), encoding="utf-8")
        self.app.audit.record("wifi.export", path=name, rows=len(self._rows))
        self.status.setText(f"Exported {len(self._rows)} rows to {name}")
