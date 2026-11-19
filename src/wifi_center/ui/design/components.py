"""MATRIX PRO reusable components. Everything here pulls colours from `tokens.T`."""
from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import (QColor, QConicalGradient, QFont, QLinearGradient, QPainter, QPainterPath, QPen,
                           QRadialGradient)
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout, QWidget)

from .icons import icon, icon_pixmap
from .motion import Animated, Motion, animate_value
from .tokens import T


def qcolor(hex_color: str, alpha: float = 1.0) -> QColor:
    c = QColor(hex_color)
    c.setAlphaF(alpha)
    return c


# ---------------------------------------------------------------- buttons / badges
class MatrixButton(QPushButton):
    """kind: 'default' | 'primary' | 'danger'."""

    def __init__(self, text: str = "", kind: str = "default", icon_name: str | None = None, parent=None) -> None:
        super().__init__(text, parent)
        if kind != "default":
            self.setObjectName(kind)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        if icon_name:
            color = "#031208" if kind == "primary" else T.text_secondary
            self.setIcon(icon(icon_name, color, 16))
            self.setIconSize(QSize(16, 16))


class Badge(QLabel):
    def __init__(self, text: str = "", level: str = "info", parent=None) -> None:
        super().__init__(text, parent)
        self.set_level(level)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumWidth(18)
        self.setFixedHeight(16)

    def set_level(self, level: str) -> None:
        self.setObjectName({"warning": "badgeWarn", "error": "badgeErr"}.get(level, "badge"))
        self.style().unpolish(self)
        self.style().polish(self)


# ---------------------------------------------------------------- status
class StatusDot(Animated, QWidget):
    """Status indicator; `pulse=True` animates a soft halo (only while visible)."""

    def __init__(self, color: str = T.success, pulse: bool = False, size: int = 12, parent=None) -> None:
        super().__init__(parent)
        self._color, self._pulse, self._t = color, pulse, 0.0
        self.setFixedSize(size, size)

    def set_state(self, color: str, pulse: bool = False) -> None:
        self._color, self._pulse = color, pulse
        self.update()

    def tick(self, dt: float) -> None:
        if self._pulse:
            self._t = (self._t + dt) % 1.6
            self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2)
        r = self.width() * 0.22
        if self._pulse and Motion.instance().enabled:
            k = self._t / 1.6
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(qcolor(self._color, 0.35 * (1 - k)))
            p.drawEllipse(c, r + k * self.width() * 0.3, r + k * self.width() * 0.3)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(qcolor(self._color))
        p.drawEllipse(c, r, r)


class StatusChip(QFrame):
    """Clickable header indicator: dot/icon + text."""

    clicked = Signal()

    def __init__(self, text: str = "", color: str = T.text_muted, icon_name: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("statusChip")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(30)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 0, 12, 0)
        lay.setSpacing(7)
        self._icon = QLabel()
        self._icon.setFixedSize(16, 16)
        self._dot = StatusDot(color, size=10)
        self._text = QLabel(text)
        self._text.setObjectName("chipText")
        self._icon_name = icon_name
        if icon_name:
            lay.addWidget(self._icon)
        lay.addWidget(self._dot)
        lay.addWidget(self._text)
        self.set_state(text, color)

    def set_state(self, text: str, color: str, pulse: bool = False, tooltip: str = "") -> None:
        self._text.setText(text)
        self._dot.set_state(color, pulse)
        if self._icon_name:
            self._icon.setPixmap(icon_pixmap(self._icon_name, color, 16, 2.0))
        if tooltip:
            self.setToolTip(tooltip)

    def mousePressEvent(self, e) -> None:  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(e)


# ---------------------------------------------------------------- panels
class Panel(QFrame):
    """MatrixCard: titled surface with an optional header-action area."""

    def __init__(self, title: str = "", tooltip: str = "", parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(16, 14, 16, 14)
        self._lay.setSpacing(10)
        self.header = QHBoxLayout()
        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("panelTitle")
        self.header.addWidget(self.title_label)
        self.header.addStretch(1)
        self._lay.addLayout(self.header)
        if tooltip:
            self.setToolTip(tooltip)

    def add(self, w: QWidget, stretch: int = 0) -> QWidget:
        self._lay.addWidget(w, stretch)
        return w

    def add_header_widget(self, w: QWidget) -> QWidget:
        self.header.addWidget(w)
        return w

    def add_text(self, object_name: str = "") -> QLabel:
        lbl = QLabel()
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setWordWrap(True)
        lbl.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if object_name:
            lbl.setObjectName(object_name)
        self._lay.addWidget(lbl, 1)
        return lbl


MatrixCard = Panel


class MetricTile(QFrame):
    """Compact top-row tile: label, value, status colour accent and detail line. Clickable."""

    clicked = Signal()

    def __init__(self, title: str, icon_name: str, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("metricTile")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(86)
        self._icon_name = icon_name
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(12)
        self.icon = QLabel()
        self.icon.setFixedSize(34, 34)
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col = QVBoxLayout()
        col.setSpacing(1)
        self.title = QLabel(title.upper())
        self.title.setObjectName("panelTitle")
        self.value = QLabel("—")
        self.value.setObjectName("metricValue")
        self.detail = QLabel("")
        self.detail.setObjectName("faint")
        self.detail.setWordWrap(True)
        for w in (self.title, self.value, self.detail):
            col.addWidget(w)
        lay.addWidget(self.icon)
        lay.addLayout(col, 1)
        self.set(self.value.text(), "", T.green)

    def set(self, value: str, detail: str, color: str = T.green) -> None:
        self.value.setText(value)
        self.value.setStyleSheet(f"color: {color};")
        self.detail.setText(detail)
        self.icon.setPixmap(icon_pixmap(self._icon_name, color, 26, 2.0))

    def mousePressEvent(self, e) -> None:  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(e)


# ---------------------------------------------------------------- logo
class LogoWidget(QWidget):
    """WIFI CENTER identity: geometric hex-framed signal mark + wordmark + subtitle."""

    def __init__(self, accent: str = T.green, parent=None) -> None:
        super().__init__(parent)
        self.accent = accent
        self.setFixedHeight(76)

    def set_accent(self, accent: str) -> None:
        self.accent = accent
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QPointF(40, self.height() / 2)
        # hexagon frame
        hexp = QPainterPath()
        for i in range(6):
            a = math.radians(60 * i - 90)
            pt = QPointF(c.x() + 23 * math.cos(a), c.y() + 23 * math.sin(a))
            hexp.moveTo(pt) if i == 0 else hexp.lineTo(pt)
        hexp.closeSubpath()
        glow = QRadialGradient(c, 34)
        glow.setColorAt(0, qcolor(self.accent, 0.22))
        glow.setColorAt(1, qcolor(self.accent, 0.0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(glow)
        p.drawEllipse(c, 34, 34)
        p.setBrush(qcolor(T.panel_elevated))
        p.setPen(QPen(qcolor(self.accent, 0.9), 1.6))
        p.drawPath(hexp)
        # signal arcs + dot
        pen = QPen(qcolor(self.accent), 2.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        base = QPointF(c.x(), c.y() + 9)
        for r in (7, 13):
            p.drawArc(QRectF(base.x() - r, base.y() - r, 2 * r, 2 * r), 45 * 16, 90 * 16)
        p.setBrush(qcolor(self.accent))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(base, 2.4, 2.4)
        # wordmark
        f = QFont(self.font())
        f.setPixelSize(19)
        f.setWeight(QFont.Weight.Black)
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.4)
        p.setFont(f)
        p.setPen(qcolor(T.text))
        p.drawText(QPointF(76, c.y() - 1), "WIFI")
        w = p.fontMetrics().horizontalAdvance("WIFI ")
        p.setPen(qcolor(self.accent))
        p.drawText(QPointF(76 + w, c.y() - 1), "CENTER")
        f2 = QFont(self.font())
        f2.setPixelSize(9)
        f2.setWeight(QFont.Weight.DemiBold)
        f2.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.9)
        p.setFont(f2)
        p.setPen(qcolor(T.text_muted))
        p.drawText(QPointF(77, c.y() + 15), "PARROT SECURITY WORKSTATION")


# ---------------------------------------------------------------- loading animations
class LoadingIndicator(Animated, QWidget):
    """kind: 'radar' (rotating sweep) | 'ring' (pulsating ring) | 'scan' (horizontal scanning line) |
    'nodes' (sequenced node chain). Animates only while `active` and visible."""

    def __init__(self, kind: str = "radar", size: int = 42, parent=None) -> None:
        super().__init__(parent)
        self.kind, self._t, self._active = kind, 0.0, False
        self.setFixedSize(size if kind != "scan" else size * 3, size)
        self.setVisible(False)

    def start(self) -> None:
        self._active = True
        self.setVisible(True)

    def stop(self) -> None:
        self._active = False
        self.setVisible(False)

    @property
    def active(self) -> bool:
        return self._active

    def tick(self, dt: float) -> None:
        if self._active:
            self._t += dt
            self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        t = self._t if Motion.instance().enabled else 0.0
        if self.kind == "radar":
            c, r = QPointF(w / 2, h / 2), min(w, h) / 2 - 2
            p.setPen(QPen(qcolor(T.green, 0.5), 1))
            for k in (1, 0.66, 0.33):
                p.drawEllipse(c, r * k, r * k)
            g = QConicalGradient(c, -(t * 200) % 360)
            g.setColorAt(0, qcolor(T.green, 0.55))
            g.setColorAt(0.25, qcolor(T.green, 0.0))
            g.setColorAt(1, qcolor(T.green, 0.0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(g)
            p.drawEllipse(c, r, r)
        elif self.kind == "ring":
            k = (t % 1.4) / 1.4
            c, r = QPointF(w / 2, h / 2), min(w, h) / 2 - 3
            p.setPen(QPen(qcolor(T.green, 1 - k), 2))
            p.drawEllipse(c, r * (0.3 + 0.7 * k), r * (0.3 + 0.7 * k))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(qcolor(T.green))
            p.drawEllipse(c, 3, 3)
        elif self.kind == "scan":
            p.setPen(QPen(qcolor(T.border_active), 1))
            p.drawRoundedRect(QRectF(1, 1, w - 2, h - 2), 4, 4)
            x = ((t * 0.9) % 1.0) * (w - 6) + 3
            g = QLinearGradient(x - 18, 0, x + 2, 0)
            g.setColorAt(0, qcolor(T.green, 0))
            g.setColorAt(1, qcolor(T.green, 0.9))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(g)
            p.drawRect(QRectF(x - 18, 3, 20, h - 6))
        else:  # nodes
            n = 5
            active = int(t * 4) % (n + 1)
            for i in range(n):
                x = 8 + i * (w - 16) / (n - 1)
                on = i < active
                p.setPen(QPen(qcolor(T.green if on else T.border_active, 0.8), 1.5))
                if i:
                    p.drawLine(QPointF(8 + (i - 1) * (w - 16) / (n - 1), h / 2), QPointF(x, h / 2))
                p.setBrush(qcolor(T.green if on else T.panel))
                p.drawEllipse(QPointF(x, h / 2), 4, 4)


# ---------------------------------------------------------------- gauge
class GaugeWidget(QWidget):
    """Animated arc gauge for a real 0..100 metric."""

    def __init__(self, label: str, color: str = T.green, parent=None) -> None:
        super().__init__(parent)
        self.label, self.color = label, color
        self._shown, self._target, self._text = 0.0, 0.0, "—"
        self.setMinimumSize(110, 110)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_value(self, percent: float | None, text: str | None = None, color: str | None = None) -> None:
        if color:
            self.color = color
        if percent is None:
            self._target, self._shown = 0.0, 0.0
            self._text = text or "n/a"
            self.update()
            return
        target = max(0.0, min(100.0, percent))
        self._text = text if text is not None else f"{target:.0f}%"
        start = self._shown
        self._target = target
        animate_value(self, start, target, 450, self._set_shown)

    def _set_shown(self, v: float) -> None:
        self._shown = v
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height() - 18)
        rect = QRectF((self.width() - side) / 2 + 8, 8, side - 16, side - 16)
        pen = QPen(qcolor(T.border), 8)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 225 * 16, -270 * 16)
        col = self.color
        if self._shown >= 90:
            col = T.danger
        elif self._shown >= 75 and self.color == T.green:
            col = T.warning
        pen.setColor(qcolor(col))
        p.setPen(pen)
        p.drawArc(rect, 225 * 16, int(-270 * 16 * self._shown / 100))
        f = QFont(self.font())
        f.setPixelSize(max(12, int(side * 0.2)))
        f.setBold(True)
        p.setFont(f)
        p.setPen(qcolor(T.text))
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, self._text)
        f.setPixelSize(11)
        f.setBold(False)
        p.setFont(f)
        p.setPen(qcolor(T.text_secondary))
        p.drawText(QRectF(0, self.height() - 18, self.width(), 16), Qt.AlignmentFlag.AlignCenter, self.label)
