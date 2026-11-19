"""Wireless radar: a visualisation of real scan observations.

Honesty note shown on the widget: a Wi-Fi scan has no direction information. Distance from the centre encodes
signal strength (strong = near the centre) and the angle encodes the channel's position in its band.

Look: a phosphor-style display. A static layer (bezel, compass ticks, range rings, scanlines, vignette) is cached; each
frame only draws the sweep with its glowing trail, the blips (bright when the sweep has just passed, then fading like
phosphor persistence, never fully off) and short expanding pings from the sweep.
"""
from __future__ import annotations

import math
import zlib

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QConicalGradient, QFont, QFontMetricsF, QPainter, QPen, QPixmap, QRadialGradient
from PySide6.QtWidgets import QWidget

from .design.components import qcolor
from .design.motion import Animated, Motion
from .design.tokens import T

RINGS_DBM = (-40, -55, -70, -85)
MIN_DBM, MAX_DBM = -95.0, -30.0
SWEEP_DEG_PER_SEC = 72.0
TRAIL_DEG = 85.0
MIN_GLOW = 0.38          # how bright a blip stays between sweeps
LEGEND = (("Open", T.warning), ("WEP", T.danger), ("WPA / WPA2", T.green), ("WPA3 / other", T.cyan))
BAND_COLORS = {"2.4 GHz": T.green, "5 GHz": "#3B9BFF", "6 GHz": "#B07CFF"}
BAND_LEGEND = (("2.4 GHz", BAND_COLORS["2.4 GHz"]), ("5 GHz", BAND_COLORS["5 GHz"]), ("6 GHz", BAND_COLORS["6 GHz"]),
               ("Open network (ring)", T.warning))


def band_of(ap: dict) -> str:
    f = ap.get("frequency_mhz") or 0
    return ap.get("band") or ("2.4 GHz" if 0 < f < 3000 else "5 GHz" if 3000 <= f < 5925 else "6 GHz" if f >= 5925 else "")


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


def display_angle(ap: dict) -> float:
    """Channel angle plus a tiny stable offset from the BSSID, so networks on one channel do not sit exactly on one ray."""
    jitter = (zlib.crc32(str(ap.get("bssid", "")).encode()) % 7) - 3.0
    return (channel_angle(ap.get("channel"), ap.get("frequency_mhz")) + jitter) % 360.0


def glow_factor(sweep_deg: float, blip_deg: float) -> float:
    """Phosphor persistence: 1.0 as the sweep passes, decaying to MIN_GLOW over the rest of the turn."""
    behind = (sweep_deg - blip_deg) % 360.0
    return MIN_GLOW + (1.0 - MIN_GLOW) * math.exp(-behind / 110.0)


class RadarWidget(Animated, QWidget):
    fps_profile = {"low": 8, "normal": 16, "high": 30}
    ap_selected = Signal(int)          # observation id

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumSize(240, 220)
        self.setMouseTracking(True)
        self._aps: list[dict] = []
        self._angle = 0.0
        self._flash: dict[int, float] = {}          # blip id -> ping progress 0..1 (expanding ring)
        self._selected: int | None = None
        self._hover: int | None = None
        self._static: QPixmap | None = None
        self._static_key: tuple = ()
        self.animation_paused = False
        self.color_mode = "security"           # "security" (colour = encryption) or "band" (colour = 2.4 / 5 / 6 GHz)

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

    def _ap_color(self, ap: dict) -> str:
        if self.color_mode == "band":
            return BAND_COLORS.get(band_of(ap), T.text_muted)
        return enc_color(ap.get("encryption"))

    def _is_open(self, ap: dict) -> bool:
        return (ap.get("encryption") or "").lower() in ("", "open")

    # ---- geometry ----
    def _geom(self) -> tuple[QPointF, float]:
        side = min(self.width(), self.height() - 26)
        return QPointF(self.width() / 2, (self.height() - 26) / 2 + 4), side / 2 - 24

    def marker_pos(self, ap: dict) -> QPointF:
        c, r = self._geom()
        ang = math.radians(display_angle(ap) - 90)
        rad = signal_radius(ap["signal_dbm"]) * r
        return QPointF(c.x() + rad * math.cos(ang), c.y() + rad * math.sin(ang))

    # ---- animation ----
    def tick(self, dt: float) -> None:
        prev = self._angle
        self._angle = (self._angle + SWEEP_DEG_PER_SEC * dt) % 360
        for ap in self._aps:                        # a ping starts when the sweep crosses a blip
            a = display_angle(ap)
            crossed = (prev <= a < self._angle) if prev <= self._angle else (a >= prev or a < self._angle)
            if crossed:
                self._flash[ap["id"]] = 0.0
        for k in list(self._flash):
            self._flash[k] += dt * 0.9
            if self._flash[k] >= 1.0:
                del self._flash[k]
        self.update()

    # ---- interaction ----
    def _hit(self, pos: QPointF) -> dict | None:
        best, bd = None, 13.0
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
                                f"{hit['signal_dbm']:.0f} dBm · {hit.get('encryption') or 'open'}")
            self.update()

    def mousePressEvent(self, e) -> None:  # noqa: N802
        hit = self._hit(e.position())
        if hit and e.button() == Qt.MouseButton.LeftButton:
            self._selected = hit["id"]
            self.ap_selected.emit(hit["id"])
            self.update()

    # ---- static layer ----
    def _build_static(self) -> QPixmap:
        dpr = self.devicePixelRatioF()
        pm = QPixmap(int(self.width() * dpr), int(self.height() * dpr))
        pm.setDevicePixelRatio(dpr)
        pm.fill(qcolor(T.background_secondary))
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c, r = self._geom()
        # phosphor screen: deep green in the middle, almost black at the edge
        bg = QRadialGradient(c, r * 1.08)
        bg.setColorAt(0.0, QColor(10, 40, 22))
        bg.setColorAt(0.75, QColor(5, 20, 12))
        bg.setColorAt(1.0, QColor(3, 9, 6))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(bg))
        p.drawEllipse(c, r + 10, r + 10)
        # bezel
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(qcolor(T.green, 0.55), 2))
        p.drawEllipse(c, r + 10, r + 10)
        p.setPen(QPen(qcolor(T.green, 0.22), 1))
        p.drawEllipse(c, r + 4, r + 4)
        # compass ticks (every 5 degrees, longer every 30) with labels
        f = QFont(self.font())
        f.setPixelSize(9)
        p.setFont(f)
        for deg in range(0, 360, 5):
            a = math.radians(deg - 90)
            long_tick = deg % 30 == 0
            r0, r1 = (r + 4, r + 10) if long_tick else (r + 7, r + 10)
            p.setPen(QPen(qcolor(T.green, 0.7 if long_tick else 0.3), 1))
            p.drawLine(QPointF(c.x() + r0 * math.cos(a), c.y() + r0 * math.sin(a)),
                       QPointF(c.x() + r1 * math.cos(a), c.y() + r1 * math.sin(a)))
            if long_tick:
                tx, ty = c.x() + (r + 19) * math.cos(a), c.y() + (r + 19) * math.sin(a)
                p.setPen(qcolor(T.text_muted))
                p.drawText(QRectF(tx - 12, ty - 6, 24, 12), Qt.AlignmentFlag.AlignCenter, str(deg))
        # range rings + crosshair
        p.setFont(f)
        for dbm in RINGS_DBM:
            rr = signal_radius(dbm) * r
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(qcolor(T.green, 0.30), 1, Qt.PenStyle.DotLine))
            p.drawEllipse(c, rr, rr)
            p.setPen(qcolor(T.soft_green, 0.75))
            p.drawText(QPointF(c.x() + 5, c.y() - rr - 2), f"{dbm} dBm")
        p.setPen(QPen(qcolor(T.green, 0.16), 1))
        for k in range(12):
            a = math.radians(k * 30 - 90)
            p.drawLine(c, QPointF(c.x() + r * math.cos(a), c.y() + r * math.sin(a)))
        # scanlines over the screen
        clip_r = r + 9
        p.setPen(QPen(QColor(0, 0, 0, 38), 1))
        y = int(c.y() - clip_r)
        while y < c.y() + clip_r:
            dx = math.sqrt(max(clip_r * clip_r - (y - c.y()) ** 2, 0))
            p.drawLine(QPointF(c.x() - dx, y), QPointF(c.x() + dx, y))
            y += 3
        # vignette
        vg = QRadialGradient(c, r + 10)
        vg.setColorAt(0.82, QColor(0, 0, 0, 0))
        vg.setColorAt(1.0, QColor(0, 0, 0, 120))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(vg))
        p.drawEllipse(c, r + 10, r + 10)
        p.end()
        return pm

    # ---- painting ----
    def paintEvent(self, _e) -> None:  # noqa: N802
        key = (self.width(), self.height(), round(self.devicePixelRatioF(), 2), T.green)
        if self._static is None or self._static_key != key:
            self._static, self._static_key = self._build_static(), key
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.drawPixmap(0, 0, self._static)
        c, r = self._geom()
        animate = Motion.instance().enabled and not self.animation_paused

        # sweep wedge with a long, soft phosphor trail and a bright leading edge
        if animate:
            g = QConicalGradient(c, 90 - self._angle)
            g.setColorAt(0.0, qcolor(T.green, 0.50))
            g.setColorAt(TRAIL_DEG / 360.0 * 0.35, qcolor(T.green, 0.22))
            g.setColorAt(TRAIL_DEG / 360.0, qcolor(T.green, 0.0))
            g.setColorAt(1.0, qcolor(T.green, 0.0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(g))
            p.drawEllipse(c, r, r)
            a = math.radians(self._angle - 90)
            tip = QPointF(c.x() + r * math.cos(a), c.y() + r * math.sin(a))
            p.setPen(QPen(qcolor(T.green, 0.35), 5))
            p.drawLine(c, tip)
            p.setPen(QPen(qcolor(T.soft_green, 0.95), 1.6))
            p.drawLine(c, tip)

        # blips
        fm = QFontMetricsF(self.font())
        strongest = sorted(self._aps, key=lambda a: -a["signal_dbm"])[:5]
        labelled = {a["id"] for a in strongest}
        placed: list[QRectF] = []
        for ap in sorted(self._aps, key=lambda a: a["signal_dbm"]):          # strong ones are drawn last (on top)
            pt = self.marker_pos(ap)
            col = self._ap_color(ap)
            glow = glow_factor(self._angle, display_angle(ap)) if animate else 0.8
            sel = ap["id"] == self._selected
            hov = ap["id"] == self._hover
            size = 3.5 + 3.5 * (1 - signal_radius(ap["signal_dbm"]))            # nearer/stronger = bigger
            size += 2 if hov or sel else 0
            hidden = not (ap.get("ssid") or "").strip()
            # soft glow halo
            halo = QRadialGradient(pt, size * 3.2)
            halo.setColorAt(0.0, qcolor(col, 0.55 * glow))
            halo.setColorAt(1.0, qcolor(col, 0.0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(halo))
            p.drawEllipse(pt, size * 3.2, size * 3.2)
            # expanding ping when the sweep has just crossed it
            ping = self._flash.get(ap["id"])
            if ping is not None:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(qcolor(col, 0.7 * (1 - ping)), 1.4))
                p.drawEllipse(pt, size + 22 * ping, size + 22 * ping)
            # the blip
            if hidden:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(qcolor(col, glow), 1.8))
            else:
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(qcolor(col, glow))
            p.drawEllipse(pt, size, size)
            if self.color_mode == "band" and self._is_open(ap):
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(qcolor(T.warning, 0.9), 1.6))
                p.drawEllipse(pt, size + 4, size + 4)
            if sel:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(qcolor(T.soft_green), 1.6, Qt.PenStyle.DashLine))
                p.drawEllipse(pt, size + 8, size + 8)
            # label: strongest networks, the selected one and the hovered one
            if ap["id"] in labelled or sel or hov:
                text = (ap.get("ssid") or "<hidden>")[:22]
                w = fm.horizontalAdvance(text) + 10
                box = QRectF(pt.x() - w / 2, pt.y() - size - 22, w, 15)
                if box.left() < 2:
                    box.moveLeft(2)
                if box.right() > self.width() - 2:
                    box.moveRight(self.width() - 2)
                if sel or hov or not any(box.intersects(b) for b in placed):
                    placed.append(box)
                    p.setPen(Qt.PenStyle.NoPen)
                    p.setBrush(QColor(3, 10, 6, 200))
                    p.drawRoundedRect(box, 4, 4)
                    p.setPen(qcolor(T.text if (sel or hov) else T.text_secondary))
                    p.drawText(box, Qt.AlignmentFlag.AlignCenter, text)

        # own position: the antenna, with a slow transmit ripple
        p.setBrush(Qt.BrushStyle.NoBrush)
        if animate:
            ripple = (self._angle % 120) / 120.0
            p.setPen(QPen(qcolor(T.green, 0.4 * (1 - ripple)), 1.2))
            p.drawEllipse(c, 6 + 16 * ripple, 6 + 16 * ripple)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(qcolor(T.soft_green))
        p.drawEllipse(c, 3.5, 3.5)

        # HUD (top-left), legend and honesty note (bottom)
        small = QFont(self.font())
        small.setPixelSize(10)
        p.setFont(small)
        if self._aps:
            top = strongest[0]
            p.setPen(qcolor(T.soft_green))
            p.drawText(QRectF(8, 6, 200, 28), Qt.AlignmentFlag.AlignLeft | Qt.TextFlag.TextWordWrap,
                       f"{len(self._aps)} networks\nstrongest {top['signal_dbm']:.0f} dBm")
        else:
            p.setPen(qcolor(T.text_secondary))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No observations yet\nRun a scan")
        x = 8.0
        y = self.height() - 22.0
        for name, color in (BAND_LEGEND if self.color_mode == "band" else LEGEND):
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(qcolor(color))
            p.drawEllipse(QPointF(x + 4, y + 5), 3.5, 3.5)
            p.setPen(qcolor(T.text_muted))
            w = fm.horizontalAdvance(name) + 6
            p.drawText(QRectF(x + 11, y - 1, w, 13), Qt.AlignmentFlag.AlignLeft, name)
            x += 11 + w + 8
        p.setPen(qcolor(T.text_muted))
        p.drawText(QRectF(8, self.height() - 12, self.width() - 16, 11), Qt.AlignmentFlag.AlignLeft,
                   "Visual signal map, not a locator: distance = signal strength, angle = channel (a Wi-Fi scan has no direction) · hollow = hidden SSID")
        p.end()
