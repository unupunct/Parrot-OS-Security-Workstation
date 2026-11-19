"""Vector illustrations of wireless hardware, drawn with QPainter (no image files). They show the KIND of hardware that was
detected (USB dongle, PCIe card, internal M.2/mini-PCIe module, or generic) and are labelled as illustrations: they are not a
picture of the exact device."""
from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient
from PySide6.QtWidgets import QSizePolicy, QWidget

from .tokens import T

KINDS = ("usb", "pcie", "m2", "generic")
CAPTIONS = {"usb": "USB Wi-Fi adapter", "pcie": "PCIe expansion card", "m2": "Internal module (mini-PCIe / M.2)",
            "generic": "Wireless adapter"}


def kind_for(bus: str | None, form_factor: str) -> str:
    if bus == "usb":
        return "usb"
    if form_factor == "pcie":
        return "pcie"
    if form_factor == "m2":
        return "m2"
    return "generic"


class HardwareArt(QWidget):
    def __init__(self, kind: str = "generic", parent=None) -> None:
        super().__init__(parent)
        self.kind = kind if kind in KINDS else "generic"
        self.setMinimumSize(300, 220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_kind(self, kind: str) -> None:
        self.kind = kind if kind in KINDS else "generic"
        self.update()

    # ---- helpers
    @staticmethod
    def _pcb(p: QPainter, r: QRectF, radius: float = 8) -> None:
        g = QLinearGradient(r.topLeft(), r.bottomRight())
        g.setColorAt(0.0, QColor("#14683A"))
        g.setColorAt(1.0, QColor("#0B3D22"))
        p.setPen(QPen(QColor("#1FA45B"), 1.5))
        p.setBrush(QBrush(g))
        p.drawRoundedRect(r, radius, radius)

    @staticmethod
    def _chip(p: QPainter, r: QRectF, label: str = "") -> None:
        g = QLinearGradient(r.topLeft(), r.bottomLeft())
        g.setColorAt(0.0, QColor("#2B2F2C"))
        g.setColorAt(1.0, QColor("#111412"))
        p.setPen(QPen(QColor("#4A524D"), 1))
        p.setBrush(QBrush(g))
        p.drawRoundedRect(r, 2, 2)
        pin = QPen(QColor("#B7A16A"), 1)
        p.setPen(pin)
        n = max(int(r.width() // 7), 2)
        for i in range(n):
            x = r.left() + 4 + i * (r.width() - 8) / max(n - 1, 1)
            p.drawLine(QPointF(x, r.top() - 3), QPointF(x, r.top()))
            p.drawLine(QPointF(x, r.bottom()), QPointF(x, r.bottom() + 3))
        if label:
            f = QFont(p.font())
            f.setPixelSize(7)
            p.setFont(f)
            p.setPen(QColor("#7C867F"))
            p.drawText(r, Qt.AlignmentFlag.AlignCenter, label)

    @staticmethod
    def _shield(p: QPainter, r: QRectF) -> None:
        g = QLinearGradient(r.topLeft(), r.bottomRight())
        g.setColorAt(0.0, QColor("#D5D9D6"))
        g.setColorAt(0.5, QColor("#9FA6A2"))
        g.setColorAt(1.0, QColor("#C4C9C6"))
        p.setPen(QPen(QColor("#6F7773"), 1.2))
        p.setBrush(QBrush(g))
        p.drawRoundedRect(r, 3, 3)
        p.setPen(QPen(QColor(255, 255, 255, 70), 1))
        p.drawLine(QPointF(r.left() + 4, r.top() + 4), QPointF(r.right() - 4, r.top() + 4))

    @staticmethod
    def _smd(p: QPainter, r: QRectF, n: int = 14, seed: int = 3) -> None:
        p.setPen(Qt.PenStyle.NoPen)
        for i in range(n):
            x = r.left() + ((i * 37 + seed * 11) % 100) / 100 * (r.width() - 6)
            y = r.top() + ((i * 53 + seed * 7) % 100) / 100 * (r.height() - 4)
            p.setBrush(QColor("#C9B77A" if i % 3 else "#2A2E2B"))
            p.drawRect(QRectF(x, y, 5, 3))

    @staticmethod
    def _antenna(p: QPainter, base: QPointF, angle_deg: float, length: float = 46) -> None:
        a = math.radians(angle_deg)
        tip = QPointF(base.x() + length * math.cos(a), base.y() + length * math.sin(a))
        p.setPen(QPen(QColor("#B8962E"), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(base, tip)
        p.setPen(QPen(QColor("#E6C95C"), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(base, tip)
        p.setBrush(QColor("#8E7424"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(base, 6, 6)

    @staticmethod
    def _fingers(p: QPainter, x: float, y: float, w: float, count: int, horizontal: bool = True, pitch: float = 6.0) -> None:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#D6B656"))
        for i in range(count):
            if horizontal:
                p.drawRect(QRectF(x + i * pitch, y, w, 14))
            else:
                p.drawRect(QRectF(x, y + i * pitch, 14, w))

    # ---- drawings
    def _draw_usb(self, p: QPainter, c: QPointF, s: float) -> None:
        body = QRectF(c.x() - 130 * s, c.y() - 34 * s, 230 * s, 68 * s)
        g = QLinearGradient(body.topLeft(), body.bottomLeft())
        g.setColorAt(0.0, QColor("#2E3431"))
        g.setColorAt(1.0, QColor("#121513"))
        p.setPen(QPen(QColor("#58625C"), 1.5))
        p.setBrush(QBrush(g))
        p.drawRoundedRect(body, 10, 10)
        plug = QRectF(body.right() - 2, c.y() - 20 * s, 54 * s, 40 * s)
        sg = QLinearGradient(plug.topLeft(), plug.bottomLeft())
        sg.setColorAt(0.0, QColor("#E3E6E4"))
        sg.setColorAt(1.0, QColor("#8E9591"))
        p.setBrush(QBrush(sg))
        p.setPen(QPen(QColor("#6F7773"), 1.2))
        p.drawRect(plug)
        p.setBrush(QColor("#0B0D0C"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRect(QRectF(plug.left() + 10, plug.center().y() - 6 * s, plug.width() - 18, 12 * s))
        p.setBrush(QColor("#2FD27A"))
        p.drawEllipse(QPointF(body.left() + 26 * s, c.y()), 5, 5)       # status LED
        halo = QRadialGradient(QPointF(body.left() + 26 * s, c.y()), 16)
        halo.setColorAt(0.0, QColor(47, 210, 122, 120))
        halo.setColorAt(1.0, QColor(47, 210, 122, 0))
        p.setBrush(QBrush(halo))
        p.drawEllipse(QPointF(body.left() + 26 * s, c.y()), 16, 16)
        # wifi emblem on the shell
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(QColor("#3AC77C"), 2.2))
        ex = body.left() + 90 * s
        for r in (10, 18, 26):
            p.drawArc(QRectF(ex - r, c.y() + 8 - r, 2 * r, 2 * r), 50 * 16, 80 * 16)
        p.setBrush(QColor("#3AC77C"))
        p.drawEllipse(QPointF(ex, c.y() + 8), 2.6, 2.6)
        # ribs
        p.setPen(QPen(QColor("#3C443F"), 1))
        for i in range(7):
            x = body.left() + 130 * s + i * 11 * s
            p.drawLine(QPointF(x, body.top() + 10), QPointF(x, body.bottom() - 10))

    def _draw_pcie(self, p: QPainter, c: QPointF, s: float) -> None:
        board = QRectF(c.x() - 150 * s, c.y() - 55 * s, 270 * s, 100 * s)
        self._pcb(p, board, 4)
        bracket = QRectF(board.left() - 14 * s, board.top() - 8 * s, 14 * s, board.height() + 16 * s)
        p.setPen(QPen(QColor("#6F7773"), 1.2))
        p.setBrush(QColor("#B9BEBB"))
        p.drawRect(bracket)
        self._fingers(p, board.left() + 40 * s, board.bottom() - 2, 10, 18, True, 8.5 * s)       # PCIe edge connector
        p.setBrush(QColor("#0B3D22"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRect(QRectF(board.left() + 40 * s + 6 * 8.5 * s - 3, board.bottom() - 2, 5, 14))   # key notch
        self._shield(p, QRectF(board.left() + 80 * s, board.top() + 18 * s, 100 * s, 56 * s))
        self._chip(p, QRectF(board.left() + 24 * s, board.top() + 22 * s, 36 * s, 26 * s), "WLAN")
        self._smd(p, QRectF(board.left() + 24 * s, board.top() + 56 * s, 150 * s, 28 * s), 18, 5)
        self._smd(p, QRectF(board.left() + 190 * s, board.top() + 14 * s, 70 * s, 60 * s), 12, 9)
        self._antenna(p, QPointF(bracket.left() + 4, board.top() + 14 * s), 215, 46 * s)
        self._antenna(p, QPointF(bracket.left() + 4, board.bottom() - 22 * s), 150, 46 * s)

    def _draw_m2(self, p: QPainter, c: QPointF, s: float) -> None:
        board = QRectF(c.x() - 140 * s, c.y() - 40 * s, 250 * s, 80 * s)
        path = QPainterPath()
        path.addRoundedRect(board, 5, 5)
        g = QLinearGradient(board.topLeft(), board.bottomRight())
        g.setColorAt(0.0, QColor("#14683A"))
        g.setColorAt(1.0, QColor("#0B3D22"))
        p.setPen(QPen(QColor("#1FA45B"), 1.5))
        p.setBrush(QBrush(g))
        p.drawPath(path)
        self._fingers(p, board.left() - 3, board.top() + 6, 8, 8, False, 8.5 * s)      # gold fingers on the left edge
        p.setBrush(QColor("#0B3D22"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRect(QRectF(board.left(), board.top() + 6 + 4 * 8.5 * s - 2, 8, 5))
        self._shield(p, QRectF(board.left() + 56 * s, board.top() + 12 * s, 110 * s, 56 * s))
        self._chip(p, QRectF(board.left() + 20 * s, board.top() + 18 * s, 26 * s, 22 * s))
        self._smd(p, QRectF(board.left() + 20 * s, board.top() + 46 * s, 36 * s, 26 * s), 7, 2)
        self._smd(p, QRectF(board.left() + 176 * s, board.top() + 10 * s, 62 * s, 60 * s), 12, 6)
        for y in (board.top() + 18 * s, board.bottom() - 18 * s):
            p.setBrush(QColor("#E6C95C"))
            p.setPen(QPen(QColor("#8E7424"), 1))
            p.drawEllipse(QPointF(board.right() - 12 * s, y), 7, 7)                         # u.FL antenna connectors
            p.setBrush(QColor("#7A5F18"))
            p.drawEllipse(QPointF(board.right() - 12 * s, y), 3, 3)
        self._antenna(p, QPointF(board.right() + 18 * s, board.top() - 2), 300, 40 * s)
        self._antenna(p, QPointF(board.right() + 18 * s, board.bottom() + 2), 60, 40 * s)
        p.setPen(QPen(QColor("#C9B77A"), 1.2))
        p.drawLine(QPointF(board.right() - 12 * s, board.top() + 18 * s), QPointF(board.right() + 18 * s, board.top() - 2))
        p.drawLine(QPointF(board.right() - 12 * s, board.bottom() - 18 * s), QPointF(board.right() + 18 * s, board.bottom() + 2))

    def _draw_generic(self, p: QPainter, c: QPointF, s: float) -> None:
        board = QRectF(c.x() - 90 * s, c.y() - 60 * s, 180 * s, 120 * s)
        self._pcb(p, board, 14)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(QColor("#3AC77C"), 4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        for r in (14, 28, 42):
            p.drawArc(QRectF(c.x() - r * s, c.y() + 22 * s - r * s, 2 * r * s, 2 * r * s), 40 * 16, 100 * 16)
        p.setBrush(QColor("#3AC77C"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(c.x(), c.y() + 22 * s), 5 * s, 5 * s)

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        # soft green glow under the part, like a product shot on a dark surface
        glow = QRadialGradient(QPointF(w / 2, h * 0.52), min(w, h) * 0.55)
        glow.setColorAt(0.0, QColor(0, 255, 102, 38))
        glow.setColorAt(1.0, QColor(0, 255, 102, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(glow))
        p.drawRect(self.rect())
        s = max(0.5, min(w / 360.0, (h - 40) / 200.0))
        c = QPointF(w / 2, (h - 22) / 2)
        {"usb": self._draw_usb, "pcie": self._draw_pcie, "m2": self._draw_m2}.get(self.kind, self._draw_generic)(p, c, s)
        f = QFont(self.font())
        f.setPixelSize(11)
        f.setItalic(True)
        p.setFont(f)
        p.setPen(QColor(T.text_muted))
        p.drawText(QRectF(0, h - 20, w, 18), Qt.AlignmentFlag.AlignCenter, "Illustrative image (not a photo of your hardware)")
        p.end()
