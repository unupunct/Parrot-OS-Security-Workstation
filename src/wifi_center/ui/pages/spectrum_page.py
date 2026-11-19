"""Wi-Fi Analyzer: channel graph, signal history, ranked access-point list and channel rating, all built from real Wi-Fi *scan
observations* (what access points announce), not from a physical RF measurement."""
from __future__ import annotations

from datetime import datetime

import pyqtgraph as pg
from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFrame, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPushButton,
                               QTabWidget, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...workers.task import run_in_background
from ..charts import FG, color, make_plot
from ..design.tokens import T

BANDS = ("2.4 GHz", "5 GHz", "6 GHz")
CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
              149, 153, 157, 161, 165]
FLOOR_DBM = -100.0
HALF_WIDTH = {"2.4 GHz": 2.2, "5 GHz": 2.0, "6 GHz": 2.0}      # in channel units (5 MHz each): 22 MHz / 20 MHz wide


# ------------------------------------------------------------------ pure helpers (tested)
def channel_x(freq_mhz: int | None, channel: int | None, band: str) -> float | None:
    """Position on the channel axis (the channel number; 2.4 GHz channel 14 sits at 2484 MHz)."""
    if freq_mhz:
        if band == "2.4 GHz":
            return 14.0 if freq_mhz == 2484 else (freq_mhz - 2407) / 5.0
        if band == "5 GHz":
            return (freq_mhz - 5000) / 5.0
        return (freq_mhz - 5950) / 5.0
    return float(channel) if channel else None


def slot_x(channel: float) -> float:
    """5 GHz channels are 20 MHz apart, so each gets an equal-width slot on the graph (the empty gaps between the
    allocated ranges are not drawn). A channel between two standard ones lands proportionally between their slots."""
    chans = CHANNELS_5
    if channel <= chans[0]:
        return 0.0
    if channel >= chans[-1]:
        return float(len(chans) - 1)
    for i in range(len(chans) - 1):
        if chans[i] <= channel <= chans[i + 1]:
            return i + (channel - chans[i]) / (chans[i + 1] - chans[i])
    return 0.0


def arch(center: float, dbm: float, half: float, n: int = 28) -> tuple[list[float], list[float]]:
    """A smooth arch from the floor up to `dbm` and back, like the Android Wi-Fi Analyzer curves."""
    xs, ys = [], []
    for i in range(n + 1):
        u = -1 + 2 * i / n
        xs.append(center + u * half)
        ys.append(FLOOR_DBM + (dbm - FLOOR_DBM) * (1 - u * u) ** 0.8)
    return xs, ys


def signal_level(dbm: float | None) -> str:
    if dbm is None:
        return "none"
    return "good" if dbm >= -60 else "fair" if dbm >= -75 else "weak"


def level_color(dbm: float | None) -> str:
    return {"good": T.green, "fair": T.warning, "weak": T.danger, "none": T.text_muted}[signal_level(dbm)]


def congestion(channel: float, aps: list[tuple[float, float]]) -> float:
    """How loaded a 20 MHz channel is: every network whose channel overlaps it counts, stronger and closer counts more.
    `aps` = (channel position, dBm). Overlap falls to zero 4 channel units (20 MHz) away."""
    total = 0.0
    for pos, dbm in aps:
        overlap = max(0.0, 1.0 - abs(pos - channel) / 4.0)
        strength = max(0.0, min(1.0, (dbm - FLOOR_DBM) / 70.0))        # -100 dBm -> 0, -30 dBm -> 1
        total += overlap * (0.25 + 0.75 * strength)
    return total


def best_channels(band: str, aps: list[tuple[float, float]]) -> list[tuple[int, float]]:
    """Candidate channels ranked least congested first. In 2.4 GHz only the non-overlapping 1/6/11 are recommended."""
    cands = [1, 6, 11] if band == "2.4 GHz" else [c for c in CHANNELS_5 if c not in (165,)] if band == "5 GHz" else []
    return sorted(((c, congestion(float(c), aps)) for c in cands), key=lambda t: (t[1], t[0]))


def parse_ts(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return 0.0


# ------------------------------------------------------------------ widgets
class Gauge(QWidget):
    """Circular signal gauge: a 270 degree ring filled by signal strength, dBm in the middle."""

    def __init__(self, dbm: float | None = None, size: int = 54) -> None:
        super().__init__()
        self.dbm = dbm
        self.setFixedSize(size, size)

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(5, 5, self.width() - 10, self.height() - 10)
        p.setPen(QPen(QColor(T.border), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(r, int(225 * 16), int(-270 * 16))
        if self.dbm is not None:
            frac = max(0.0, min(1.0, (self.dbm - FLOOR_DBM) / 70.0))
            p.setPen(QPen(QColor(level_color(self.dbm)), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawArc(r, int(225 * 16), int(-270 * frac * 16))
            f = QFont(self.font())
            f.setPixelSize(13)
            f.setBold(True)
            p.setFont(f)
            p.setPen(QColor(T.text))
            p.drawText(self.rect().adjusted(0, -4, 0, -4), Qt.AlignmentFlag.AlignCenter, f"{self.dbm:.0f}")
            f.setPixelSize(8)
            f.setBold(False)
            p.setFont(f)
            p.setPen(QColor(T.text_muted))
            p.drawText(self.rect().adjusted(0, 16, 0, 0), Qt.AlignmentFlag.AlignCenter, "dBm")
        p.end()


class Sparkline(QWidget):
    def __init__(self, values: list[float], col: str) -> None:
        super().__init__()
        self.values, self.col = values, col
        self.setFixedSize(84, 34)

    def paintEvent(self, _e) -> None:  # noqa: N802
        if len(self.values) < 2:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width() - 2, self.height() - 2
        lo, hi = -100.0, -30.0
        pts = [(1 + i * w / (len(self.values) - 1), 1 + h * (1 - (max(lo, min(hi, v)) - lo) / (hi - lo)))
               for i, v in enumerate(self.values)]
        poly = QPolygonF([self._pt(x, y) for x, y in pts] + [self._pt(w + 1, h + 1), self._pt(1, h + 1)])
        c = QColor(self.col)
        fill = QColor(c)
        fill.setAlpha(50)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(fill)
        p.drawPolygon(poly)
        p.setPen(QPen(c, 1.4))
        for a, b in zip(pts, pts[1:]):
            p.drawLine(self._pt(*a), self._pt(*b))
        p.end()

    @staticmethod
    def _pt(x, y):
        from PySide6.QtCore import QPointF
        return QPointF(x, y)


class ApCard(QFrame):
    def __init__(self, ap: dict, col: str, samples: list[float]) -> None:
        super().__init__()
        self.setObjectName("panel")
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 8, 12, 8)
        info = QVBoxLayout()
        info.setSpacing(1)
        open_net = (ap.get("encryption") or "").lower() in ("", "open")
        name = QLabel(("[open]  " if open_net else "") + (ap.get("ssid") or "<hidden>"))
        name.setStyleSheet(f"color: {T.warning if open_net else col}; font-weight: 700; font-size: 14px;")
        info.addWidget(name)
        f = ap.get("frequency_mhz")
        lines = [f"MAC: {ap['bssid']}", f"Freq: {f or '?'} MHz (ch {ap.get('channel') or '?'})"]
        if ap.get("vendor"):
            lines.append(str(ap["vendor"]))
        for t in lines:
            lab = QLabel(t)
            lab.setObjectName("muted")
            info.addWidget(lab)
        enc = QLabel(" ".join(x for x in (ap.get("encryption"), ap.get("auth")) if x) or "OPEN")
        enc.setStyleSheet(f"color: {T.warning if open_net else T.cyan}; font-size: 11px; font-weight: 600;")
        info.addWidget(enc)
        row.addLayout(info, 1)
        row.addWidget(Sparkline(samples, level_color(ap.get("signal_dbm"))))
        row.addWidget(Gauge(ap.get("signal_dbm")))


# ------------------------------------------------------------------ page
class SpectrumPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.svc = app.wireless
        self._obs: list[dict] = []
        self._selected: int | None = None
        self._scanning = False
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Wi-Fi Analyzer")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.band = QComboBox()
        self.band.addItems(list(BANDS))
        self.band.currentIndexChanged.connect(self.refresh)
        self.live = QCheckBox("Live (scan every 10 s)")
        self.live.toggled.connect(self._toggle_live)
        self.scan_btn = QPushButton("Scan now")
        self.scan_btn.setToolTip("Run a Wi-Fi scan and refresh every view")
        self.scan_btn.clicked.connect(self.scan)
        b = QPushButton("Refresh")
        b.setToolTip("Re-read the stored Wi-Fi scan results")
        b.clicked.connect(self.refresh)
        for w in (self.band, self.live, self.scan_btn, b):
            head.addWidget(w)
        lay.addLayout(head)
        banner = QLabel("These views are built from Wi-Fi scan observations (what access points announce). They are "
                        "NOT a physical RF spectrum measurement: an ordinary Wi-Fi adapter cannot show non-Wi-Fi "
                        "interference, and no spectrum-analysis hardware (e.g. an SDR) is supported yet. Channel width is "
                        "drawn as 20 MHz because scans do not report it.")
        banner.setWordWrap(True)
        banner.setObjectName("warn")
        lay.addWidget(banner)
        self.info = QLabel("")
        self.info.setObjectName("muted")
        lay.addWidget(self.info)

        self.tabs = QTabWidget()
        self.graph = make_plot("", "channel", "signal (dBm)")
        self.graph.setYRange(-100, -20)
        self.graph.getPlotItem().showGrid(x=True, y=True, alpha=0.18)
        self.tabs.addTab(self.graph, "Channel graph")
        self.hist_plot = make_plot("", "", "signal (dBm)")
        self.hist_plot.getPlotItem().setAxisItems({"bottom": pg.DateAxisItem(orientation="bottom")})
        for axis in ("bottom",):
            a = self.hist_plot.getPlotItem().getAxis(axis)
            a.setPen(pg.mkPen(T.border))
            a.setTextPen(pg.mkPen(FG))
        self.hist_plot.setYRange(-100, -20)
        self.hist_plot.getPlotItem().showGrid(x=True, y=True, alpha=0.18)
        self.tabs.addTab(self.hist_plot, "Signal history")
        lst = QWidget()
        ll = QVBoxLayout(lst)
        bar = QHBoxLayout()
        self.chan_filter = QComboBox()
        self.chan_filter.addItem("All channels", None)
        self.chan_filter.currentIndexChanged.connect(self._fill_list)
        bar.addWidget(QLabel("Show"))
        bar.addWidget(self.chan_filter)
        bar.addStretch(1)
        bar.addWidget(QLabel("Sorted by signal strength"))
        ll.addLayout(bar)
        self.list = QListWidget()
        self.list.setSpacing(4)
        self.list.currentRowChanged.connect(self._pick)
        ll.addWidget(self.list, 1)
        self.tabs.addTab(lst, "Access points")
        rating = QWidget()
        rl = QVBoxLayout(rating)
        self.rec = QLabel("")
        self.rec.setWordWrap(True)
        self.rec.setTextFormat(Qt.TextFormat.RichText)
        rl.addWidget(self.rec)
        self.rating_plot = make_plot("Channel congestion (lower is better)", "channel", "load")
        rl.addWidget(self.rating_plot, 1)
        self.tabs.addTab(rating, "Channel rating")
        lay.addWidget(self.tabs, 1)
        self.msg = QLabel("")
        self.msg.setObjectName("muted")
        lay.addWidget(self.msg)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.scan)
        self.refresh()

    # ------------------------------------------------------------------ data
    def _latest(self) -> list[dict]:
        latest = self.svc.latest_scan_ts()
        rows = [r for r in self.svc.observations() if r["source"] == "wifi-scan" and r["last_seen"] == latest]
        return [r for r in rows if r["band"] == self.band.currentText()]

    def _toggle_live(self, on: bool) -> None:
        self._timer.start(10000) if on else self._timer.stop()
        if on:
            self.scan()

    def scan(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        self.scan_btn.setEnabled(False)
        self.msg.setText("Scanning…")

        def work() -> int:
            aps = self.svc.scan(None)
            self.svc.record(aps)
            self.app.audit.record("wifi.scan", interface="auto", found=len(aps), view="analyzer")
            return len(aps)

        def done(n: int) -> None:
            self._scanning = False
            self.scan_btn.setEnabled(True)
            self.msg.setText(f"Scan complete: {n} access points.")
            self.refresh()

        def failed(err: str) -> None:
            self._scanning = False
            self.scan_btn.setEnabled(True)
            self.msg.setText(f"Scan failed: {err}")
            self.live.setChecked(False)
        run_in_background(work, done, failed)

    def refresh(self) -> None:
        self._obs = [o for o in self._latest() if o.get("signal_dbm") is not None]
        band = self.band.currentText()
        if not self._obs:
            self.info.setText(f"No {band} observations from the last scan. Press Scan now.")
        else:
            self.info.setText(f"{len(self._obs)} networks in the last scan ({band}).")
        order = sorted(self._obs, key=lambda o: o["bssid"])
        self._colors = {o["id"]: color(i) for i, o in enumerate(order)}      # one stable colour per network in every view
        self._draw_graph()
        self._draw_history()
        self._fill_filter()
        self._fill_list()
        self._draw_rating()

    # ------------------------------------------------------------------ channel graph
    def _draw_graph(self) -> None:
        band = self.band.currentText()
        self.graph.clear()
        pos = [(channel_x(o["frequency_mhz"], o["channel"], band), o) for o in self._obs]
        pos = [(x, o) for x, o in pos if x is not None]
        if band == "2.4 GHz":
            lo, hi, ticks, half = -1.0, 17.0, [(c, str(c)) for c in range(1, 15)], HALF_WIDTH[band]
        elif band == "5 GHz":
            pos = [(slot_x(x), o) for x, o in pos]            # equal slots per 20 MHz channel
            used = [x for x, _ in pos] or [0.0, 6.0]
            lo, hi = max(min(used) - 3.0, -1.0), min(max(used) + 3.0, len(CHANNELS_5))
            ticks, half = [(i, str(c)) for i, c in enumerate(CHANNELS_5) if lo <= i <= hi], 0.46
        else:
            xs_ = sorted({x for x, _ in pos}) or [0.0]
            lo, hi, half = xs_[0] - 6.0, xs_[-1] + 6.0, HALF_WIDTH[band]
            ticks = [(int(round(x)), str(int(round(x)))) for x in xs_]
        self.graph.setXRange(lo, hi, padding=0)
        self.graph.getPlotItem().getAxis("bottom").setTicks([ticks])
        for x, o in sorted(pos, key=lambda t: t[1]["signal_dbm"]):
            c = pg.mkColor(self._colors[o["id"]])
            sel = o["id"] == self._selected
            fill = pg.mkColor(c)
            fill.setAlpha(110 if sel else 60)
            xs, ys = arch(x, o["signal_dbm"], half)
            self.graph.addItem(pg.PlotCurveItem(xs, ys, pen=pg.mkPen(c, width=3 if sel else 1.6), brush=fill, fillLevel=FLOOR_DBM))
            label = pg.TextItem(o["ssid"] or "<hidden>", color=c, anchor=(0.5, 1.0))
            label.setPos(x, o["signal_dbm"])
            label.setFont(QFont(self.font().family(), 8, QFont.Weight.Bold if sel else QFont.Weight.Normal))
            self.graph.addItem(label)

    # ------------------------------------------------------------------ signal history
    def _draw_history(self) -> None:
        self.hist_plot.clear()
        shown = sorted(self._obs, key=lambda o: -o["signal_dbm"])[:10]
        if self._selected is not None and all(o["id"] != self._selected for o in shown):
            shown += [o for o in self._obs if o["id"] == self._selected]
        for o in shown:
            samples = [s for s in self.svc.history(o["id"], 240) if s["signal_dbm"] is not None]
            if len(samples) < 1:
                continue
            c = pg.mkColor(self._colors[o["id"]])
            sel = o["id"] == self._selected
            xs = [parse_ts(s["ts"]) for s in samples]
            ys = [s["signal_dbm"] for s in samples]
            self.hist_plot.plot(xs, ys, pen=pg.mkPen(c, width=3 if sel else 1.6), name=o["ssid"] or o["bssid"][-8:])
            tail = pg.TextItem(o["ssid"] or "<hidden>", color=c, anchor=(0, 0.5))
            tail.setPos(xs[-1], ys[-1])
            self.hist_plot.addItem(tail)

    # ------------------------------------------------------------------ access point list
    def _fill_filter(self) -> None:
        keep = self.chan_filter.currentData()
        self.chan_filter.blockSignals(True)
        self.chan_filter.clear()
        self.chan_filter.addItem("All channels", None)
        for ch in sorted({o["channel"] for o in self._obs if o["channel"]}):
            n = sum(1 for o in self._obs if o["channel"] == ch)
            self.chan_filter.addItem(f"Channel {ch}  ({n})", ch)
        idx = self.chan_filter.findData(keep)
        self.chan_filter.setCurrentIndex(idx if idx >= 0 else 0)
        self.chan_filter.blockSignals(False)

    def _fill_list(self) -> None:
        self.list.blockSignals(True)
        self.list.clear()
        ch = self.chan_filter.currentData()
        rows = sorted((o for o in self._obs if ch is None or o["channel"] == ch), key=lambda o: -o["signal_dbm"])
        for o in rows:
            samples = [s["signal_dbm"] for s in self.svc.history(o["id"], 30) if s["signal_dbm"] is not None]
            card = ApCard(o, self._colors.get(o["id"], T.green), samples)
            it = QListWidgetItem()
            it.setData(Qt.ItemDataRole.UserRole, o["id"])
            it.setSizeHint(card.sizeHint())
            self.list.addItem(it)
            self.list.setItemWidget(it, card)
        self.list.blockSignals(False)

    def _pick(self, row: int) -> None:
        it = self.list.item(row) if row >= 0 else None
        self._selected = it.data(Qt.ItemDataRole.UserRole) if it else None
        self._draw_graph()
        self._draw_history()

    # ------------------------------------------------------------------ channel rating
    def _draw_rating(self) -> None:
        band = self.band.currentText()
        self.rating_plot.clear()
        aps = [(x, o["signal_dbm"]) for o in self._obs if (x := channel_x(o["frequency_mhz"], o["channel"], band)) is not None]
        cands = best_channels(band, aps)
        if not cands:
            self.rec.setText(f"<span style='color:{T.text_muted}'>No channel recommendation for {band}.</span>")
            return
        every = ([c for c in range(1, 14)] if band == "2.4 GHz" else [c for c, _ in cands])
        scores = {c: congestion(float(c), aps) for c in every}
        best, load = cands[0]
        note = " (channels 1, 6 and 11 are the only ones that do not overlap each other)" if band == "2.4 GHz" else ""
        self.rec.setText(f"<span style='font-size:15px'>Least congested channel: <b style='color:{T.green}'>{best}</b></span>"
                         f" <span style='color:{T.text_secondary}'>(load {load:.2f} against {len(aps)} visible network(s)){note}. "
                         "Based only on the networks this scan can see.</span>")
        xs = list(scores)
        top = max(scores.values(), default=1.0) or 1.0
        brushes = [T.green if c == best else T.warning if scores[c] > 0.66 * top else T.cyan for c in xs]
        self.rating_plot.addItem(pg.BarGraphItem(x=xs, height=[scores[c] for c in xs], width=0.7, brushes=brushes, pen=None))
        self.rating_plot.getPlotItem().getAxis("bottom").setTicks([[(c, str(c)) for c in xs]])
        self.rating_plot.setYRange(0, top * 1.15)
