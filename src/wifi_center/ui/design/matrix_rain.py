"""Matrix-style falling characters, rendered cheaply and used only where requested.

Technique: keep one persistent pixmap; every frame paint a translucent black rect over it (the fade
creates the trails) and draw just one glyph per active column at its head. Cost scales with the number
of columns, not with trail length. Painted at low opacity so the interface stays readable.
"""
from __future__ import annotations

import random

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPixmap
from PySide6.QtWidgets import QWidget

from .motion import Animated, Motion
from .tokens import T

GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789:.=*+-<>"
CELL = 16


class RainField:
    """Pure state of the rain columns (testable without a display)."""

    def __init__(self, columns: int, rows: int, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self.columns, self.rows = columns, rows
        self.heads = [self.rng.uniform(-rows, 0) for _ in range(columns)]
        self.speeds = [self.rng.uniform(5.0, 18.0) for _ in range(columns)]      # rows / second
        self.active = [self.rng.random() < 0.55 for _ in range(columns)]

    def step(self, dt: float) -> list[tuple[int, int]]:
        """Advance; return (column, row) cells where a new head glyph should be drawn."""
        out = []
        for c in range(self.columns):
            if not self.active[c]:
                if self.rng.random() < dt * 0.35:
                    self.active[c] = True
                    self.heads[c] = self.rng.uniform(-6, 0)
                    self.speeds[c] = self.rng.uniform(5.0, 18.0)
                continue
            prev = int(self.heads[c])
            self.heads[c] += self.speeds[c] * dt
            for r in range(prev + 1, int(self.heads[c]) + 1):
                if 0 <= r < self.rows:
                    out.append((c, r))
            if self.heads[c] > self.rows + self.rng.randint(4, 20):
                self.active[c] = self.rng.random() < 0.6
                self.heads[c] = self.rng.uniform(-8, 0)
                self.speeds[c] = self.rng.uniform(5.0, 18.0)
        return out


class MatrixRain(Animated, QWidget):
    """Background widget. `opacity` is the final blend (0..1); keep it low behind content."""

    fps_profile = {"low": 4, "normal": 8, "high": 12}  # every frame repaints whatever overlaps it

    def __init__(self, opacity: float = 0.22, parent=None, fade_bottom: bool = False) -> None:
        super().__init__(parent)
        self.opacity = opacity
        self.fade_bottom = fade_bottom      # band mode: dissolve into the background at the bottom edge
        self._pix: QPixmap | None = None
        self._field: RainField | None = None
        self._font = QFont("monospace")
        self._font.setPixelSize(CELL - 2)
        self._font.setStyleHint(QFont.StyleHint.Monospace)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, False)

    def _ensure(self) -> None:
        w, h = max(self.width(), 1), max(self.height(), 1)
        if self._pix is None or self._pix.width() != w or self._pix.height() != h:
            self._pix = QPixmap(w, h)
            self._pix.fill(QColor(T.background))
            self._field = RainField(w // CELL + 1, h // CELL + 1)

    def tick(self, dt: float) -> None:
        if not Motion.instance().enabled:
            return
        self._ensure()
        assert self._pix is not None and self._field is not None
        p = QPainter(self._pix)
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        p.fillRect(self._pix.rect(), QColor(8, 12, 9, 34))   # fade -> trails
        p.setFont(self._font)
        rng = self._field.rng
        for c, r in self._field.step(dt):
            ch = GLYPHS[rng.randrange(len(GLYPHS))]
            p.setPen(QColor(T.soft_green))
            p.drawText(QRectF(c * CELL, r * CELL, CELL, CELL), Qt.AlignmentFlag.AlignCenter, ch)
            if r > 0:  # previous head dims to the main green
                p.setPen(QColor(0, 255, 102, 150))
                p.drawText(QRectF(c * CELL, (r - 1) * CELL, CELL, CELL), Qt.AlignmentFlag.AlignCenter,
                           GLYPHS[rng.randrange(len(GLYPHS))])
        p.end()
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(T.background))
        if self._pix is not None and Motion.instance().enabled:
            p.setOpacity(self.opacity)
            p.drawPixmap(0, 0, self._pix)
            p.setOpacity(1.0)
        if self.fade_bottom:
            g = QLinearGradient(0, 0, 0, self.height())
            g.setColorAt(0.0, QColor(8, 12, 9, 0))
            g.setColorAt(1.0, QColor(8, 12, 9, 255))
            p.fillRect(self.rect(), g)
