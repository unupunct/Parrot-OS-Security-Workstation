"""Wireless radar: a visualisation of real scan observations.

Honesty note shown on the widget: a Wi-Fi scan has no direction information. Distance from the centre encodes
signal strength (strong = near the centre) and the angle encodes the channel's position in its band.
"""
from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QConicalGradient, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from .design.components import qcolor
from .design.motion import Animated, Motion
from .design.tokens import T

RINGS_DBM = (-40, -55, -70, -85)
MIN_DBM, MAX_DBM = -95.0, -30.0
SWEEP_DEG_PER_SEC = 90.0


def signal_radius(dbm: float) -> float:
    """0..1 fraction of the radar radius (strong signal -> small radius)."""
    d = min(max(dbm, MIN_DBM), MAX_DBM)
    return 0.06 + 0.92 * (MAX_DBM - d) / (MAX_DBM - MIN_DBM)


def channel_angle(channel: int | None, freq: int | None) -> float:
    """Degrees (0 = up, clockwise). Spreads a band's channels around the circle."""
    if freq and freq < 3000 and channel:
        return (min(max(channel, 1), 14) - 1) / 14 * 360.0
    if freq and freq < 5925 and channel:
        return ((channel - 32) % 140) / 140 * 360.0
    if channel:
        return (channel % 233) / 233 * 360.0
    return 0.0


def enc_color(enc: str | None) -> str:
    e = (enc or "").lower()
    if e in ("", "open"):
        return T.warning
    if "wep" in e:
        return T.danger
    return T.green if "wpa" in e else T.cyan


class RadarWidget(Animated, QWidget):
    fps_profile = {"low": 6, "normal": 12, "high": 20}
    ap_selected = Signal(int)          # observation id

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumSize(220, 200)
        self.setMouseTracking(True)
        self._aps: list[dict] = []
        self._angle = 0.0
        self._flash: dict[int, float] = {}
        self._selected: int | None = None
        self._hover: int | None = None
        self.animation_paused = False

    # ---- data ----
    def set_observations(self, rows: list[dict]) -> None:
        self._aps = [r for r in rows if r.get("signal_dbm") is not None]
        if self._selected not in {r["id"] for r in self._aps}:
            self._selected = None
        self.update()

    def set_selected(self, obs_id: int | None) -> None:
        self._selected = obs_id
        self.update()

    def count(self) -> int:
        return len(self._aps)

    # ---- geometry ----
    def _geom(self) -> tuple[QPointF, float]:
        side = min(self.width(), self.height())
        return QPointF(self.width() / 2, self.height() / 2), side / 2 - 22

    def marker_pos(self, ap: dict) -> QPointF:
        c, r = self._geom()
        ang = math.radians(channel_angle(ap.get("channel"), ap.get("frequency_mhz")) - 90)
        rad = signal_radius(ap["signal_dbm"]) * r
        return QPointF(c.x() + rad * math.cos(ang), c.y() + rad * math.sin(ang))

    # ---- animation ----
    def tick(self, dt: float) -> None:
        prev = self._angle
        self._angle = (self._angle + SWEEP_DEG_PER_SEC * dt) % 360
        for ap in self._aps:  # markers flash as the sweep passes over them
            a = channel_angle(ap.get("channel"), ap.get("frequency_mhz"))
            if prev <= a < prev + SWEEP_DEG_PER_SEC * dt + 0.01 or (prev > self._angle and (a >= prev or a < self._angle)):
                self._flash[ap["id"]] = 1.0
        for k in list(self._flash):
            self._flash[k] -= dt * 0.8
            if self._flash[k] <= 0:
                del self._flash[k]
        self.update()

    # ---- interaction ----
    def _hit(self, pos: QPointF) -> dict | None:
        best, bd = None, 12.0
        for ap in self._aps:
            p = self.marker_pos(ap)
            d = math.hypot(p.x() - pos.x(), p.y() - pos.y())
            if d < bd:
                best, bd = ap, d
        return best

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        hit = self._hit(e.position())
        hid = hit["id"] if hit else None
        if hid != self._hover:
            self._hover = hid
            self.setCursor(Qt.CursorShape.PointingHandCursor if hit else Qt.CursorShape.ArrowCursor)
            if hit:
                self.setToolTip(f"{hit.get('ssid') or '<hidden>'}\n{hit['bssid']}\nch {hit.get('channel')} · "
                                f"{hit['signal_dbm']:.0f} dBm · {hit.get('encryption') or ''}")
            self.update()

    def mousePressEvent(self, e) -> None:  # noqa: N802
        hit = self._hit(e.position())
        if hit and e.button() == Qt.MouseButton.LeftButton:
            self._selected = hit["id"]
            self.ap_selected.emit(hit["id"])
            self.update()

    # ---- painting ----
    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c, r = self._geom()
        p.fillRect(self.rect(), qcolor(T.background_secondary))
        # rings + labels
        f = QFont(self.font())
        f.setPixelSize(10)
        p.setFont(f)
        for dbm in RINGS_DBM:
            rr = signal_radius(dbm) * r
            p.setPen(QPen(qcolor(T.green, 0.22), 1))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(c, rr, rr)
            p.setPen(qcolor(T.text_muted))
            p.drawText(QPointF(c.x() + 4, c.y() - rr + 11), f"{dbm}")
        p.setPen(QPen(qcolor(T.green, 0.3), 1))
        p.drawEllipse(c, r, r)
        for k in range(12):
            a = math.radians(k * 30 - 90)
            p.setPen(QPen(qcolor(T.green, 0.12), 1))
            p.drawLine(c, QPointF(c.x() + r * math.cos(a), c.y() + r * math.sin(a)))
        # sweep
        animate = Motion.instance().enabled and not self.animation_paused
        if animate:
            g = QConicalGradient(c, 90 - self._angle)
            g.setColorAt(0.0, qcolor(T.green, 0.30))
            g.setColorAt(0.18, qcolor(T.green, 0.0))
            g.setColorAt(1.0, qcolor(T.green, 0.0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(g)
            p.drawEllipse(c, r, r)
            a = math.radians(self._angle - 90)
            p.setPen(QPen(qcolor(T.soft_green, 0.8), 1.5))
            p.drawLine(c, QPointF(c.x() + r * math.cos(a), c.y() + r * math.sin(a)))
        # markers
        for ap in self._aps:
            pt = self.marker_pos(ap)
            col = enc_color(ap.get("encryption"))
            fl = self._flash.get(ap["id"], 0.0)
            sel = ap["id"] == self._selected
            rad = 5 + (2 if ap["id"] == self._hover else 0)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(qcolor(col, 0.18 + 0.4 * fl))
            p.drawEllipse(pt, rad + 5 + 6 * fl, rad + 5 + 6 * fl)
            p.setBrush(qcolor(col))
            p.drawEllipse(pt, rad, rad)
            if sel:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(qcolor(T.soft_green), 2, Qt.PenStyle.DashLine))
                p.drawEllipse(pt, rad + 8, rad + 8)
                p.setPen(qcolor(T.text))
                p.drawText(QRectF(pt.x() - 70, pt.y() - 28, 140, 14), Qt.AlignmentFlag.AlignHCenter,
                           ap.get("ssid") or "<hidden>")
        # centre + key
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(qcolor(T.green))
        p.drawEllipse(c, 3.5, 3.5)
        p.setPen(qcolor(T.text_muted))
        p.drawText(QRectF(8, self.height() - 34, self.width() - 16, 30), Qt.AlignmentFlag.AlignLeft | Qt.TextFlag.TextWordWrap,
                   "Distance = signal strength · angle = channel position (a Wi-Fi scan has no direction)")
        if not self._aps:
            p.setPen(qcolor(T.text_secondary))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No observations yet\nRun a scan")
