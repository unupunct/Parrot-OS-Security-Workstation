"""Spectrum Analyzer: visualisations of Wi-Fi *scan observations* (not physical RF measurements)."""
from __future__ import annotations

from collections import Counter

import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPushButton,
                               QSplitter, QTabWidget, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ..charts import FG, color, make_plot

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
              149, 153, 157, 161, 165]
WIDTH_MHZ = {"2.4 GHz": 22, "5 GHz": 20, "6 GHz": 20}
RANGE = {"2.4 GHz": (2397, 2487), "5 GHz": (5160, 5340), "6 GHz": (5940, 6440)}


class SpectrumPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.svc = app.wireless
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Spectrum Analyzer")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.band = QComboBox()
        self.band.addItems(["2.4 GHz", "5 GHz", "6 GHz"])
        self.band.currentIndexChanged.connect(self.refresh)
        b = QPushButton("Refresh")
        b.setToolTip("Re-read the stored Wi-Fi scan results (run a scan in Wireless Discovery first)")
        b.clicked.connect(self.refresh)
        head.addWidget(self.band)
        head.addWidget(b)
        lay.addLayout(head)
        banner = QLabel("These charts are built from Wi-Fi scan observations (what access points announce). They are "
                        "NOT a physical RF spectrum measurement: an ordinary Wi-Fi adapter cannot show non-Wi-Fi "
                        "interference, and no spectrum-analysis hardware (e.g. an SDR) is supported yet.")
        banner.setWordWrap(True)
        banner.setObjectName("warn")
        lay.addWidget(banner)
        self.info = QLabel("")
        self.info.setObjectName("muted")
        lay.addWidget(self.info)

        self.tabs = QTabWidget()
        self.dist = make_plot("Access points per channel", "channel", "networks")
        self.overlap = make_plot("Channel overlap (signal vs frequency)", "frequency (MHz)", "signal (dBm)")
        self.overlap.setYRange(-100, -20)
        self.tabs.addTab(self.dist, "Channel distribution")
        self.tabs.addTab(self.overlap, "Frequency band / overlap")
        hist = QWidget()
        hl = QHBoxLayout(hist)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.nets = QListWidget()
        self.nets.setMaximumWidth(280)
        self.nets.itemSelectionChanged.connect(self._draw_history)
        self.nets.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.hist_plot = make_plot("Signal over scans", "scan #", "signal (dBm)")
        split.addWidget(self.nets)
        split.addWidget(self.hist_plot)
        split.setStretchFactor(1, 1)
        hl.addWidget(split)
        self.tabs.addTab(hist, "Historical signal")
        lay.addWidget(self.tabs, 1)
        self._obs: list[dict] = []
        self.refresh()

    def _latest(self) -> list[dict]:
        latest = self.svc.latest_scan_ts()
        rows = [r for r in self.svc.observations() if r["source"] == "wifi-scan" and r["last_seen"] == latest]
        band = self.band.currentText()
        return [r for r in rows if r["band"] == band]

    def refresh(self) -> None:
        self._obs = self._latest()
        band = self.band.currentText()
        if not self._obs:
            self.info.setText(f"No {band} observations from the last scan. Run a scan in Wireless Discovery.")
        else:
            self.info.setText(f"{len(self._obs)} networks in the last scan ({band}).")
        self._draw_distribution(band)
        self._draw_overlap(band)
        self._fill_networks()

    def _draw_distribution(self, band: str) -> None:
        self.dist.clear()
        counts = Counter(o["channel"] for o in self._obs if o["channel"])
        chans = CHANNELS_24 if band == "2.4 GHz" else CHANNELS_5 if band == "5 GHz" else sorted(counts) or [1]
        chans = sorted(set(chans) | set(counts))
        xs = list(range(len(chans)))
        self.dist.addItem(pg.BarGraphItem(x=xs, height=[counts.get(c, 0) for c in chans], width=0.7,
                                          brush=color(0), pen=None))
        self.dist.getAxis("bottom").setTicks([[(i, str(c)) for i, c in enumerate(chans)]])
        self.dist.setYRange(0, max(counts.values(), default=1) + 1)

    def _draw_overlap(self, band: str) -> None:
        self.overlap.clear()
        lo, hi = RANGE[band]
        self.overlap.setXRange(lo, hi)
        w = WIDTH_MHZ[band] / 2
        for i, o in enumerate(sorted(self._obs, key=lambda r: r["signal_dbm"] or -100)):
            f, s = o["frequency_mhz"], o["signal_dbm"]
            if not f or s is None:
                continue
            c = pg.mkColor(color(i))
            fill = pg.mkColor(c)
            fill.setAlpha(50)
            curve = pg.PlotCurveItem([f - w, f - w + 2, f + w - 2, f + w], [-100, s, s, -100],
                                     pen=pg.mkPen(c, width=1.5), brush=fill, fillLevel=-100)
            self.overlap.addItem(curve)
            label = pg.TextItem(o["ssid"] or "<hidden>", color=FG, anchor=(0.5, 1.0))
            label.setPos(f, s)
            self.overlap.addItem(label)

    def _fill_networks(self) -> None:
        self.nets.blockSignals(True)
        self.nets.clear()
        for o in sorted(self._obs, key=lambda r: r["signal_dbm"] or -100, reverse=True):
            it = QListWidgetItem(f"{o['ssid'] or '<hidden>'}  ({o['bssid'][-8:]})")
            it.setData(Qt.ItemDataRole.UserRole, o["id"])
            self.nets.addItem(it)
        self.nets.blockSignals(False)
        for i in range(min(3, self.nets.count())):
            self.nets.item(i).setSelected(True)
        self._draw_history()

    def _draw_history(self) -> None:
        self.hist_plot.clear()
        self.hist_plot.addLegend(labelTextColor=FG)
        for i, item in enumerate(self.nets.selectedItems()):
            samples = [s for s in self.svc.history(item.data(Qt.ItemDataRole.UserRole)) if s["signal_dbm"] is not None]
            if samples:
                self.hist_plot.plot(list(range(1, len(samples) + 1)), [s["signal_dbm"] for s in samples],
                                    pen=color(i), symbol="o", symbolSize=5, symbolBrush=color(i),
                                    name=item.text())
