"""Interactive network topology view (rendering only; discovery lives in `network_inventory`).

Strategy for responsiveness with many nodes: a single QPainter widget, pre-rendered glow sprites,
viewport culling, labels/particles disabled for very large or zoomed-out graphs, and the layout
computed once per data change (NumPy) then eased on screen. Frames are only produced while the
widget is visible, animations are enabled and the view is not paused.
"""
from __future__ import annotations

import math

import numpy as np
from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPixmap, QRadialGradient
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QToolButton, QVBoxLayout, QWidget

from ..services.network_inventory import NetNode, Topology
from .design.components import qcolor
from .design.graph_layout import bounds, force_layout
from .design.icons import icon
from .design.motion import Animated, Motion
from .design.tokens import T

KIND_COLOR = {"self": T.green, "gateway": T.cyan, "internet": "#B07CFF", "segment": T.text_secondary}
ALL_KINDS = {"self", "gateway", "host", "internet", "segment"}
DEVICE_COLORS = (("printer", T.warning), ("phone", "#3B9BFF"), ("tv", "#FF8AD8"), ("camera", T.danger), ("network", T.cyan),
                 ("nas", "#E0B060"), ("storage", "#E0B060"), ("computer", T.green), ("iot", "#7CE0C8"), ("private", "#3B9BFF"))
STATE_COLOR = {"reachable": T.emerald, "stale": T.warning, "unknown": T.text_secondary}
RADIUS = {"self": 13.0, "gateway": 15.0, "host": 9.0, "internet": 14.0, "segment": 12.0}
MAX_PARTICLE_EDGES = 250


def node_color(n: NetNode) -> str:
    if n.kind in KIND_COLOR:
        return KIND_COLOR[n.kind]
    t = (n.device_type or "").lower()
    for word, col in DEVICE_COLORS:
        if word in t:
            return col
    return STATE_COLOR.get(n.state, T.text_secondary)


class TopologyView(Animated, QWidget):
    fps_profile = {"low": 6, "normal": 12, "high": 20}
    node_selected = Signal(object)        # NetNode | None
    discover_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumSize(420, 300)
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)   # we fill every pixel: no parent repaint
        self._grid_tile: tuple[float, QPixmap] | None = None
        self._legend_pix: QPixmap | None = None
        self._nodes: list[NetNode] = []
        self._index: dict[str, int] = {}
        self._edges: list[tuple[int, int]] = []
        self._target = np.zeros((0, 2))
        self._cur = np.zeros((0, 2))
        self._scale, self._off = 1.0, QPointF(0, 0)
        self._t = 0.0
        self._selected: str | None = None
        self._hover: str | None = None
        self._press: QPointF | None = None
        self._dragged = False
        self._filter_text, self._filter_kinds = "", set(ALL_KINDS)
        self.animation_paused = False
        self._sprites: dict[str, QPixmap] = {}
        self._fit_pending = True
        self._build_controls()

    # ---------------- controls ----------------
    def _build_controls(self) -> None:
        bar = QWidget(self)
        bar.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        self.btn_fit = self._tool("fit", "Fit network to screen", self.fit)
        self.btn_reset = self._tool("reset", "Reset camera", self.reset_camera)
        self.btn_pause = self._tool("pause", "Pause / resume animation", self.toggle_pause)
        for b in (self.btn_fit, self.btn_reset, self.btn_pause):
            lay.addWidget(b)
        self._bar = bar
        self.empty_btn = QPushButton("Refresh from neighbor cache", self)
        self.empty_btn.setObjectName("primary")
        self.empty_btn.clicked.connect(self.discover_requested)
        self.empty_btn.hide()

    def _tool(self, name: str, tip: str, slot) -> QToolButton:
        b = QToolButton()
        b.setIcon(icon(name, T.text_secondary, 16))
        b.setToolTip(tip)
        b.setFixedSize(30, 28)
        b.clicked.connect(slot)
        return b

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self._bar.adjustSize()
        self._bar.move(self.width() - self._bar.width() - 12, 12)
        self.empty_btn.adjustSize()
        self.empty_btn.move((self.width() - self.empty_btn.width()) // 2, int(self.height() * 0.66))
        if self._fit_pending:
            self.fit(animate=False)

    # ---------------- data ----------------
    def set_topology(self, topo: Topology) -> None:
        old = {n.id: self._cur[i].copy() for i, n in enumerate(self._nodes)} if len(self._cur) else {}
        self._nodes = list(topo.nodes)
        self._index = {n.id: i for i, n in enumerate(self._nodes)}
        self._edges = [(self._index[a], self._index[b]) for a, b in topo.edges if a in self._index and b in self._index]
        n = len(self._nodes)
        hub = self._index.get(topo.hub) if topo.hub in self._index else self._index.get("gateway", self._index.get("self"))
        fixed = {}
        if "gateway" in self._index and "self" in self._index:
            fixed[self._index["self"]] = (0.0, 125.0)
        self._target = force_layout(n, self._edges, fixed, hub, iterations=140 if n <= 150 else 40)
        start = np.zeros((n, 2))
        hub_pos = self._target[hub] if hub is not None else np.zeros(2)
        for i, node in enumerate(self._nodes):
            start[i] = old.get(node.id, hub_pos)
        self._cur = start if Motion.instance().enabled else self._target.copy()
        if self._selected and self._selected not in self._index:
            self._selected = None
            self.node_selected.emit(None)
        has_hosts = any(x.kind == "host" for x in self._nodes)
        self.empty_btn.setVisible(not has_hosts)
        self._fit_pending = True
        self.fit(animate=False)
        self.update()

    def set_filter(self, text: str = "", kinds: set[str] | None = None) -> None:
        self._filter_text = text.strip().lower()
        self._filter_kinds = kinds if kinds is not None else set(ALL_KINDS)
        self.update()

    def matches(self, n: NetNode) -> bool:
        if n.kind not in self._filter_kinds:
            return False
        q = self._filter_text
        if not q:
            return True
        hay = " ".join(filter(None, [n.label, n.ip, n.mac, n.vendor, n.device_type])).lower()
        return q in hay

    def selected_node(self) -> NetNode | None:
        return self._nodes[self._index[self._selected]] if self._selected in self._index else None

    def select(self, node_id: str | None) -> None:
        self._selected = node_id if node_id in self._index else None
        self.node_selected.emit(self.selected_node())
        self.update()

    def node_count(self) -> int:
        return len(self._nodes)

    # ---------------- camera ----------------
    def _w2s(self, x: float, y: float) -> QPointF:
        return QPointF(x * self._scale + self._off.x(), y * self._scale + self._off.y())

    def fit(self, animate: bool = True) -> None:
        if self.width() < 50:
            return
        x0, y0, x1, y1 = bounds(self._target)
        w, h = max(x1 - x0, 160.0), max(y1 - y0, 160.0)
        pad = 90
        self._scale = max(0.15, min((self.width() - 2 * pad) / w, (self.height() - 2 * pad) / h, 1.6))
        cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
        self._off = QPointF(self.width() / 2 - cx * self._scale, self.height() / 2 - cy * self._scale)
        self._fit_pending = False
        self.update()

    def reset_camera(self) -> None:
        self._scale = 1.0
        hub = self._index.get("gateway", self._index.get("self"))
        c = self._target[hub] if hub is not None and len(self._target) else np.zeros(2)
        self._off = QPointF(self.width() / 2 - c[0], self.height() / 2 - c[1])
        self.update()

    def toggle_pause(self) -> None:
        self.set_paused(not self.animation_paused)

    def set_paused(self, paused: bool) -> None:
        self.animation_paused = paused
        self.btn_pause.setIcon(icon("play" if paused else "pause", T.text_secondary, 16))
        self.update()

    # ---------------- animation ----------------
    def tick(self, dt: float) -> None:
        self._t += dt
        if len(self._cur):
            diff = self._target - self._cur
            if np.abs(diff).max() > 0.2:
                self._cur += diff * min(1.0, dt * 6.0)
        self.update()

    def motion_changed(self) -> None:
        if not Motion.instance().enabled and len(self._cur):
            self._cur = self._target.copy()
        self.update()

    # ---------------- interaction ----------------
    def wheelEvent(self, e) -> None:  # noqa: N802
        factor = 1.0015 ** e.angleDelta().y()
        new = max(0.15, min(4.0, self._scale * factor))
        pos = e.position()
        k = new / self._scale
        self._off = QPointF(pos.x() - (pos.x() - self._off.x()) * k, pos.y() - (pos.y() - self._off.y()) * k)
        self._scale = new
        self.update()

    def _node_at(self, pos: QPointF) -> str | None:
        best, best_d = None, 1e9
        for i, n in enumerate(self._nodes):
            if not self.matches(n):
                continue
            p = self._w2s(*self._cur[i])
            r = RADIUS[n.kind] * max(self._scale, 0.7) + 5
            d = math.hypot(p.x() - pos.x(), p.y() - pos.y())
            if d <= r and d < best_d:
                best, best_d = n.id, d
        return best

    def mousePressEvent(self, e) -> None:  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            self._press, self._dragged = e.position(), False
            self.setFocus()

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        if self._press is not None and e.buttons() & Qt.MouseButton.LeftButton:
            d = e.position() - self._press
            if self._dragged or abs(d.x()) + abs(d.y()) > 4:
                self._dragged = True
                self._off += d
                self._press = e.position()
                self.setCursor(Qt.CursorShape.ClosedHandCursor)
                self.update()
                return
        h = self._node_at(e.position())
        if h != self._hover:
            self._hover = h
            self._hover_pos = e.position()
            self.setCursor(Qt.CursorShape.PointingHandCursor if h else Qt.CursorShape.ArrowCursor)
        self._hover_pos = e.position()
        if self._hover or self.animation_paused or not Motion.instance().enabled:
            self.update()

    def mouseReleaseEvent(self, e) -> None:  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton and self._press is not None:
            if not self._dragged:
                self.select(self._node_at(e.position()))
            self._press, self._dragged = None, False
            self.setCursor(Qt.CursorShape.ArrowCursor)

    def mouseDoubleClickEvent(self, e) -> None:  # noqa: N802
        self.fit()

    def leaveEvent(self, e) -> None:  # noqa: N802
        self._hover = None
        self.update()
        super().leaveEvent(e)

    # ---------------- painting ----------------
    def _sprite(self, color: str) -> QPixmap:
        s = self._sprites.get(color)
        if s is None:
            size = 96
            s = QPixmap(size, size)
            s.fill(Qt.GlobalColor.transparent)
            p = QPainter(s)
            g = QRadialGradient(size / 2, size / 2, size / 2)
            g.setColorAt(0.0, qcolor(color, 0.55))
            g.setColorAt(0.35, qcolor(color, 0.16))
            g.setColorAt(1.0, qcolor(color, 0.0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(g)
            p.drawEllipse(0, 0, size, size)
            p.end()
            self._sprites[color] = s
        return s

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(T.background_secondary))
        self._paint_grid(p)
        animate = Motion.instance().enabled and not self.animation_paused
        n_nodes = len(self._nodes)
        view = QRectF(-60, -60, self.width() + 120, self.height() + 120)
        pts = [self._w2s(*self._cur[i]) for i in range(n_nodes)]

        # edges (+ particles)
        sel_idx = self._index.get(self._selected) if self._selected else None
        show_particles = animate and len(self._edges) <= MAX_PARTICLE_EDGES and self._scale > 0.3
        for k, (a, b) in enumerate(self._edges):
            na, nb = self._nodes[a], self._nodes[b]
            if not view.contains(pts[a]) and not view.contains(pts[b]):
                continue
            dim = not (self.matches(na) and self.matches(nb))
            hot = sel_idx is not None and sel_idx in (a, b)
            col = node_color(nb if na.kind in ("gateway", "self") else na)
            alpha = 0.10 if dim else (0.85 if hot else 0.35)
            p.setPen(QPen(qcolor(col, alpha), 2.0 if hot else 1.2))
            p.drawLine(pts[a], pts[b])
            if show_particles and not dim:
                for j in range(2 if hot else 1):
                    f = ((self._t * (0.28 + 0.07 * (k % 4))) + j * 0.5 + k * 0.137) % 1.0
                    q = QPointF(pts[a].x() + (pts[b].x() - pts[a].x()) * f, pts[a].y() + (pts[b].y() - pts[a].y()) * f)
                    p.setPen(Qt.PenStyle.NoPen)
                    p.setBrush(qcolor(T.soft_green if hot else col, 0.9))
                    p.drawEllipse(q, 2.2, 2.2)

        # nodes
        show_labels = self._scale > 0.55 and n_nodes <= 400
        font = QFont(self.font())
        font.setPixelSize(11)
        p.setFont(font)
        for i, n in enumerate(self._nodes):
            pt = pts[i]
            if not view.contains(pt):
                continue
            dim = not self.matches(n)
            col = node_color(n)
            r = RADIUS[n.kind] * max(0.7, min(self._scale, 1.8))
            if n.id == self._hover:
                r *= 1.15
            op = 0.25 if dim else 1.0
            p.setOpacity(op)
            gs = r * 5.2
            p.drawPixmap(QRectF(pt.x() - gs / 2, pt.y() - gs / 2, gs, gs).toRect(), self._sprite(col))
            if animate and not dim and n.state in ("self", "reachable") or n.kind == "gateway" and animate:
                ph = ((self._t * 0.6) + (i * 0.23)) % 1.0
                p.setPen(QPen(qcolor(col, 0.5 * (1 - ph)), 1.5))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(pt, r + ph * 16, r + ph * 16)
            p.setPen(QPen(qcolor(col), 2))
            p.setBrush(qcolor(T.background, 0.95))
            p.drawEllipse(pt, r, r)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(qcolor(col))
            p.drawEllipse(pt, r * 0.42, r * 0.42)
            if n.id == self._selected:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(qcolor(T.soft_green), 2, Qt.PenStyle.DashLine))
                p.drawEllipse(pt, r + 7, r + 7)
            if (show_labels or n.id in (self._selected, self._hover)) and not dim:
                p.setPen(qcolor(T.text if n.kind != "host" else T.text_secondary))
                label = n.ip if n.kind == "host" else n.label
                p.drawText(QRectF(pt.x() - 80, pt.y() + r + 6, 160, 16), Qt.AlignmentFlag.AlignHCenter, label or "")
            p.setOpacity(1.0)

        self._paint_legend(p)
        if self._hover and self._hover in self._index:
            self._paint_hover(p, self._nodes[self._index[self._hover]])
        if not any(n.kind == "host" for n in self._nodes):
            self._paint_empty(p)

    def _paint_grid(self, p: QPainter) -> None:
        step = max(24, int(48 * min(max(self._scale, 0.5), 2.0)))
        if self._grid_tile is None or self._grid_tile[0] != step:
            tile = QPixmap(step, step)
            tile.fill(Qt.GlobalColor.transparent)
            tp = QPainter(tile)
            tp.setPen(QPen(qcolor(T.green, 0.06), 1))
            tp.drawLine(0, 0, 0, step)
            tp.drawLine(0, 0, step, 0)
            tp.end()
            self._grid_tile = (step, tile)
        p.drawTiledPixmap(self.rect(), self._grid_tile[1], QPointF(self._off.x() % step, self._off.y() % step).toPoint())

    def _paint_legend(self, p: QPainter) -> None:
        if self._legend_pix is None:
            items = [("This computer", T.green), ("Gateway", T.cyan), ("Host – reachable", T.emerald),
                     ("Host – stale", T.warning), ("Host – unknown", T.text_secondary), ("Internet (default route)", KIND_COLOR["internet"]),
                     ("Network segment (hub)", KIND_COLOR["segment"])]
            h = 17 * (len(items) + 1) + 12
            pix = QPixmap(166, h)
            pix.fill(Qt.GlobalColor.transparent)
            q = QPainter(pix)
            q.setRenderHint(QPainter.RenderHint.Antialiasing)
            q.setPen(QPen(qcolor(T.border), 1))
            q.setBrush(qcolor(T.panel, 0.9))
            q.drawRoundedRect(QRectF(1, 1, 158, h - 2), 8, 8)
            f = QFont(self.font())
            f.setPixelSize(11)
            q.setFont(f)
            y = 8
            for label, col in items:
                q.setPen(Qt.PenStyle.NoPen)
                q.setBrush(qcolor(col))
                q.drawEllipse(QPointF(15, y + 8), 4, 4)
                q.setPen(qcolor(T.text_secondary))
                q.drawText(QPointF(28, y + 12), label)
                y += 17
            q.setPen(QPen(qcolor(T.emerald, 0.6), 1.5))
            q.drawLine(QPointF(10, y + 8), QPointF(20, y + 8))
            q.setPen(qcolor(T.text_secondary))
            q.drawText(QPointF(28, y + 12), "L2 neighbor link")
            q.end()
            self._legend_pix = pix
        p.drawPixmap(6, self.height() - self._legend_pix.height() - 6, self._legend_pix)

    def _paint_hover(self, p: QPainter, n: NetNode) -> None:
        lines = [n.label if n.kind != "host" else (n.ip or n.label)]
        if n.kind == "host" and n.label != n.ip:
            lines.append(n.label)
        for k, v in (("IP", n.ip if n.kind != "host" else None), ("MAC", n.mac), ("Vendor", n.vendor),
                     ("Type", n.device_type), ("State", n.state), ("Source", n.source)):
            if v:
                lines.append(f"{k}: {v}")
        f = QFont(self.font())
        f.setPixelSize(12)
        p.setFont(f)
        fm = p.fontMetrics()
        w = max(fm.horizontalAdvance(l) for l in lines) + 22
        h = len(lines) * 17 + 14
        pos = getattr(self, "_hover_pos", QPointF(20, 20))
        x = min(pos.x() + 16, self.width() - w - 6)
        y = min(pos.y() + 16, self.height() - h - 6)
        p.setPen(QPen(qcolor(T.border_active), 1))
        p.setBrush(qcolor(T.panel_elevated, 0.97))
        p.drawRoundedRect(QRectF(x, y, w, h), 8, 8)
        for i, l in enumerate(lines):
            p.setPen(qcolor(T.green if i == 0 else T.text_secondary))
            p.drawText(QPointF(x + 11, y + 20 + i * 17), l)

    def _paint_empty(self, p: QPainter) -> None:
        f = QFont(self.font())
        f.setPixelSize(15)
        f.setBold(True)
        p.setFont(f)
        p.setPen(qcolor(T.text))
        y = int(self.height() * 0.66) - 54
        p.drawText(QRectF(0, y, self.width(), 24), Qt.AlignmentFlag.AlignHCenter, "No other devices discovered yet")
        f.setBold(False)
        f.setPixelSize(12)
        p.setFont(f)
        p.setPen(qcolor(T.text_secondary))
        p.drawText(QRectF(self.width() * 0.2, y + 28, self.width() * 0.6, 40),
                   Qt.AlignmentFlag.AlignHCenter | Qt.TextFlag.TextWordWrap,
                   "Devices appear here once they show up in this computer's neighbor (ARP) cache or in imported "
                   "scan results. Authorized Nmap discovery arrives in Phase 4.")
