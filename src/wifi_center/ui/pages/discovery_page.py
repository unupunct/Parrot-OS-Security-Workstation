"""Wireless Discovery: scan, analyze, monitor. Scanning and storage are unchanged (WirelessService); this module is the
visualisation layer. Every chart is computed from stored scan data (see services/wireless_analytics.py); with no data a chart
shows an empty state instead of invented values."""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

import pyqtgraph as pg
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QSplitter,
                               QStackedWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services import wireless_analytics as wa
from ...services.adapter_service import AdapterService
from ...workers.task import run_in_background
from ..charts import FG, NumItem, fmt_ts, make_plot, make_table, signal_bars
from ..design.components import LoadingIndicator, MatrixButton, Panel, StatusChip
from ..design.icons import icon_pixmap
from ..design.tokens import T
from ..radar import BAND_COLORS, RadarWidget

esc = html.escape
COLS = ["SSID", "BSSID", "Ch", "Freq (MHz)", "Signal", "dBm", "Encryption", "Auth", "Vendor", "First seen", "Last seen"]
LEVEL_COLOR = {"low": T.green, "medium": T.warning, "high": T.danger}


class ChartCard(QFrame):
    """A titled chart with badges and a proper empty state (a message instead of a blank or fabricated graph)."""

    def __init__(self, title: str, icon: str, plot: pg.PlotWidget) -> None:
        super().__init__()
        self.setObjectName("panel")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(6)
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon_pixmap(icon, T.green, 20, 2.0))
        head.addWidget(ic)
        t = QLabel(title)
        t.setStyleSheet("font-weight: 700; font-size: 14px;")
        head.addWidget(t)
        head.addStretch(1)
        self.badges = QHBoxLayout()
        self.badges.setSpacing(8)
        head.addLayout(self.badges)
        lay.addLayout(head)
        self.stack = QStackedWidget()
        self.plot = plot
        self.empty = QLabel("")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setWordWrap(True)
        self.empty.setObjectName("muted")
        self.stack.addWidget(plot)
        self.stack.addWidget(self.empty)
        lay.addWidget(self.stack, 1)
        self.footer = QLabel("")
        self.footer.setTextFormat(Qt.TextFormat.RichText)
        self.footer.setWordWrap(True)
        lay.addWidget(self.footer)

    def set_empty(self, message: str | None) -> None:
        if message:
            self.empty.setText(message)
            self.stack.setCurrentWidget(self.empty)
        else:
            self.stack.setCurrentWidget(self.plot)

    def set_badges(self, items: list[tuple[str, str]]) -> None:
        while self.badges.count():
            w = self.badges.takeAt(0).widget()
            if w is not None:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        for text, col in items:
            b = QLabel(text)
            b.setStyleSheet(f"color: {col}; border: 1px solid {col}; border-radius: 10px; padding: 1px 10px; font-weight: 600;")
            self.badges.addWidget(b)


def _time_axis(plot: pg.PlotWidget) -> None:
    plot.getPlotItem().setAxisItems({"bottom": pg.DateAxisItem(orientation="bottom")})
    a = plot.getPlotItem().getAxis("bottom")
    a.setPen(pg.mkPen(T.border))
    a.setTextPen(pg.mkPen(FG))


def _epoch(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return 0.0


class DiscoveryPage(QWidget):
    def __init__(self, app: AppController, on_scanned=None) -> None:
        super().__init__()
        self.app = app
        self.svc = app.wireless
        self._rows: list[dict] = []
        self._on_scanned = on_scanned
        lay = QVBoxLayout(self)

        # ---- header
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon_pixmap("wifi", T.green, 38, 2.0))
        head.addWidget(ic)
        tl = QVBoxLayout()
        tl.setSpacing(0)
        t = QLabel("Wireless Discovery")
        t.setObjectName("pageTitle")
        sub = QLabel("Scan · Analyze · Monitor")
        sub.setObjectName("muted")
        tl.addWidget(t)
        tl.addWidget(sub)
        head.addLayout(tl)
        self.loader = LoadingIndicator("radar", 26)
        head.addWidget(self.loader)
        head.addStretch(1)
        self.auto = QCheckBox("Auto-scan every 20 s")
        self.auto.toggled.connect(self._toggle_auto)
        self.scan_btn = MatrixButton("Scan now", "primary", "play")
        self.scan_btn.setToolTip("Run a standard Wi-Fi scan (the same request your network menu makes)")
        self.scan_btn.clicked.connect(self.scan)
        head.addWidget(self.auto)
        head.addWidget(self.scan_btn)
        lay.addLayout(head)

        # ---- status chips and filters
        strip = QHBoxLayout()
        self.iface = QComboBox()
        self.iface.setToolTip("Interface to scan (auto = let NetworkManager choose)")
        self.iface.addItem("auto", "")
        self.chip_adapter = StatusChip("Adapter: detecting…", T.text_muted)
        self.chip_bands = StatusChip("Bands: ?", T.text_muted)
        self.chip_monitor = StatusChip("Monitoring: not active", T.text_muted)
        self.chip_monitor.setToolTip("Scans run in managed mode. Switch an adapter to monitor mode in Wi-Fi Center (through the privileged helper).")
        self.band = QComboBox()
        self.band.addItems(["All bands", "2.4 GHz", "5 GHz", "6 GHz"])
        self.band.currentIndexChanged.connect(self.reload_view)
        self.enc = QComboBox()
        self.enc.addItems(["All security", "Open", "WEP", "WPA", "WPA2", "WPA3", "802.1X"])
        self.enc.currentIndexChanged.connect(self.reload_view)
        self.scope = QComboBox()
        self.scope.addItems(["Last scan", "All stored observations"])
        self.scope.currentIndexChanged.connect(self.reload_view)
        ex = MatrixButton("Export…", icon_name="folder")
        ex.clicked.connect(self._export)
        for w in (self.iface, self.chip_adapter, self.chip_bands, self.chip_monitor):
            strip.addWidget(w)
        strip.addStretch(1)
        for w in (self.band, self.enc, self.scope, ex):
            strip.addWidget(w)
        lay.addLayout(strip)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search SSID, BSSID, vendor…")
        self.search.textChanged.connect(self.reload_view)
        lay.addWidget(self.search)
        self.status = QLabel("")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)

        # ---- middle: network table | radar + selected network
        self.table = make_table(COLS)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._history)
        self.radar = RadarWidget()
        self.radar.color_mode = "band"
        self.radar.ap_selected.connect(self._select_by_id)
        radar_card = Panel("Wi-Fi Radar")
        radar_card.add(self.radar, 1)
        sel_card = Panel("Selected network")
        self.details = QTextBrowser()
        self.details.setFrameShape(QFrame.Shape.NoFrame)
        self.details.setMinimumHeight(110)
        self.details.setPlainText("Select a network in the table or on the radar.")
        sel_card.add(self.details, 1)
        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(radar_card)
        right.addWidget(sel_card)
        right.setStretchFactor(0, 3)
        right.setStretchFactor(1, 2)
        top = QSplitter(Qt.Orientation.Horizontal)
        top.addWidget(self.table)
        top.addWidget(right)
        top.setStretchFactor(0, 3)
        top.setStretchFactor(1, 2)
        top.setSizes([780, 480])

        # ---- bottom: three data-driven charts
        self.plot = make_plot("", "", "dBm")
        _time_axis(self.plot)
        self.plot.setYRange(-100, -20)
        self.plot.getPlotItem().showGrid(x=True, y=True, alpha=0.15)
        self.chan_plot = make_plot("", "channel", "% of networks")
        self.chan_plot.getPlotItem().showGrid(y=True, alpha=0.15)
        self.timeline_plot = make_plot("", "", "networks")
        _time_axis(self.timeline_plot)
        self.timeline_plot.getPlotItem().showGrid(y=True, alpha=0.15)
        self.hist_card = ChartCard("Signal History", "activity", self.plot)
        self.chan_card = ChartCard("Channel Distribution", "spectrum", self.chan_plot)
        self.time_card = ChartCard("Activity Timeline", "history", self.timeline_plot)
        charts = QWidget()
        cl = QHBoxLayout(charts)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(12)
        for c in (self.hist_card, self.chan_card, self.time_card):
            cl.addWidget(c, 1)
        charts.setMinimumHeight(190)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(top)
        split.addWidget(charts)
        split.setStretchFactor(0, 3)
        split.setSizes([520, 250])
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
                    item.setForeground(QColor(BAND_COLORS.get(o["band"] or "", T.text)))
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

    # ---- charts (all from stored data) ----
    def _draw_instruments(self) -> None:
        self._draw_channels()
        self._draw_timeline()
        self._history()

    def _draw_channels(self) -> None:
        plot = self.chan_plot
        plot.clear()
        occ = wa.channel_occupancy(self._rows)
        if not occ:
            self.chan_card.set_empty("No networks in the current view.\nRun a scan to see channel occupancy.")
            self.chan_card.set_badges([])
            self.chan_card.footer.setText("")
            return
        self.chan_card.set_empty(None)
        xs, heights, brushes, pens, ticks, x = [], [], [], [], [], 0.0
        prev_band = occ[0].band
        for c in occ:
            if c.band != prev_band:
                x += 0.8                                       # a gap between bands keeps 2.4 and 5 GHz visibly apart
                prev_band = c.band
            xs.append(x)
            heights.append(c.percent)
            brushes.append(pg.mkColor(BAND_COLORS.get(c.band, T.text_muted)))
            pens.append(pg.mkPen(LEVEL_COLOR[c.level], width=3 if c.level != "low" else 1))
            ticks.append((x, str(c.channel)))
            x += 1.0
        plot.addItem(pg.BarGraphItem(x=xs, height=heights, width=0.7, brushes=brushes, pens=pens))
        for xi, c in zip(xs, occ):
            lab = pg.TextItem(f"{c.percent:.0f}%", color=T.text, anchor=(0.5, 1.0))
            lab.setPos(xi, c.percent)
            plot.addItem(lab)
        plot.getAxis("bottom").setTicks([ticks])
        plot.setYRange(0, max(heights) * 1.25)
        plot.setXRange(-0.8, x - 0.2)
        high = [c for c in occ if c.level == "high"]
        self.chan_card.set_badges([("2.4 GHz", BAND_COLORS["2.4 GHz"]), ("5 GHz", BAND_COLORS["5 GHz"])])
        self.chan_card.footer.setText(
            f"<span style='color:{T.text_secondary}'>Outline = interference from OTHER networks overlapping the channel: "
            f"<span style='color:{T.green}'>low</span> · <span style='color:{T.warning}'>medium</span> · "
            f"<span style='color:{T.danger}'>high</span>."
            + (f" Heavily shared: {', '.join('ch ' + str(c.channel) for c in high[:4])}." if high else "") + "</span>")

    def _draw_timeline(self) -> None:
        plot = self.timeline_plot
        plot.clear()
        summaries = wa.summarize_scans(self.svc.scans(60))
        if not summaries:
            self.time_card.set_empty("No scans recorded yet.\nEvery scan adds a bar here.")
            self.time_card.set_badges([])
            self.time_card.footer.setText("")
            return
        self.time_card.set_empty(None)
        xs = [_epoch(s.ts) for s in summaries]
        gap = min((b - a for a, b in zip(xs, xs[1:]) if b > a), default=20.0)
        width = max(min(gap * 0.7, 3600.0), 1.0)
        for band in wa.BANDS:
            pass
        base = [0.0] * len(xs)
        for band in wa.BANDS:
            hs = [float(s.counts.get(band, 0)) for s in summaries]
            if not any(hs):
                continue
            plot.addItem(pg.BarGraphItem(x=xs, y0=base, height=hs, width=width, brush=pg.mkColor(BAND_COLORS[band]), pen=None))
            base = [b + h for b, h in zip(base, hs)]
        plot.setYRange(0, max(base) * 1.2 if max(base) else 1)
        events = [e for s in summaries for e in s.events]
        appeared = sum(e.kind == "appeared" for e in events)
        gone = sum(e.kind == "disappeared" for e in events)
        changed = sum(e.kind == "changed" for e in events)
        self.time_card.set_badges([("2.4 GHz", BAND_COLORS["2.4 GHz"]), ("5 GHz", BAND_COLORS["5 GHz"])])
        recent = events[-4:][::-1]
        mark = {"appeared": ("+", T.green), "disappeared": ("−", T.danger), "changed": ("±", T.warning)}
        lines = "".join(f"<br><span style='color:{mark[e.kind][1]}'>{mark[e.kind][0]}</span> {esc(e.ssid)} {e.kind} "
                        f"<span style='color:{T.text_secondary}'>({e.band}{' · ' + esc(e.detail) if e.detail else ''}) "
                        f"{esc(e.ts[11:19])}</span>" for e in recent)
        self.time_card.footer.setText(
            f"<span style='color:{T.text_secondary}'>{len(summaries)} scan(s): {appeared} appeared, {gone} disappeared, "
            f"{changed} signal changes (≥ {wa.CHANGE_DB:.0f} dB).</span>{lines}")

    def _history(self) -> None:
        self.plot.clear()
        r = self.table.currentRow()
        item = self.table.item(r, 0) if r >= 0 else None
        if not item:
            self.radar.set_selected(None)
            self.hist_card.set_empty("Select a network to see its signal history.")
            self.hist_card.set_badges([])
            self.hist_card.footer.setText("")
            return
        oid = item.data(Qt.ItemDataRole.UserRole)
        self.radar.set_selected(oid)
        row = next((o for o in self._rows if o["id"] == oid), None)
        if row:
            self._show_details(row)
        samples = [s for s in self.svc.history(oid) if s["signal_dbm"] is not None]
        stats = wa.signal_stats([s["signal_dbm"] for s in samples])
        if not stats:
            self.hist_card.set_empty("No signal readings stored for this network yet.")
            self.hist_card.set_badges([])
            return
        self.hist_card.set_empty(None)
        xs = [_epoch(s["ts"]) for s in samples]
        ys = [s["signal_dbm"] for s in samples]
        col = pg.mkColor(BAND_COLORS.get((row or {}).get("band") or "", T.green))
        fill = pg.mkColor(col)
        fill.setAlpha(70)
        self.plot.addItem(pg.PlotCurveItem(xs, ys, pen=pg.mkPen(col, width=2), brush=fill, fillLevel=-100))
        self.plot.addItem(pg.ScatterPlotItem(xs, ys, size=7, brush=pg.mkBrush(col), pen=pg.mkPen(None)))
        self.hist_card.set_badges([(f"Now {stats.current:.0f} dBm", col.name()), (f"Avg {stats.average:.0f}", T.text_secondary)])
        self.hist_card.footer.setText(f"<span style='color:{T.text_secondary}'>{stats.samples} stored reading(s) · min "
                                      f"{stats.minimum:.0f} dBm · max {stats.maximum:.0f} dBm</span>")

    def _show_details(self, o: dict) -> None:
        latest = self.svc.latest_scan_ts()
        online = o["source"] != "wifi-scan" or o["last_seen"] == latest
        pct = f" ({o['signal_pct']:.0f} %)" if o.get("signal_pct") is not None else ""
        sig = f"{o['signal_dbm']:.0f} dBm{pct} {signal_bars(o['signal_dbm'])}" if o["signal_dbm"] is not None else "—"
        band_col = BAND_COLORS.get(o["band"] or "", T.text_muted)
        chip = (f"<span style='color:{T.green}'>● Online</span>" if online else
                f"<span style='color:{T.warning}'>● Not in the last scan</span>")
        rows = [("BSSID", o["bssid"]), ("Channel", f"{o['channel']} ({o['frequency_mhz']} MHz) · {o['band']}"), ("Signal", sig),
                ("Security", f"{o['encryption']}" + (f" / {o['auth']}" if o["auth"] else "")), ("Vendor", o["vendor"] or "unknown"),
                ("First / last seen", f"{fmt_ts(o['first_seen'])} / {fmt_ts(o['last_seen'])}")]
        self.details.setHtml(
            f"<p style='font-size:15px'><b style='color:{band_col}'>{esc(o['ssid'] or '<hidden>')}</b> &nbsp; {chip}</p>"
            "<table cellpadding='2'>" + "".join(
                f"<tr><td style='color:{T.text_secondary}'>{esc(k)}</td><td>{esc(str(v))}</td></tr>" for k, v in rows) + "</table>")

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
