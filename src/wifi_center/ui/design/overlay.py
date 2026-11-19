"""Startup transition: Matrix rain + logo that fades away; click or key skips it."""
from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QTimer, Qt
from PySide6.QtWidgets import QGraphicsOpacityEffect, QVBoxLayout, QWidget

from .components import LogoWidget
from .matrix_rain import MatrixRain
from .motion import Motion
from .tokens import T


class StartupOverlay(QWidget):
    def __init__(self, parent: QWidget, accent: str = T.green, hold_ms: int = 1100) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(f"background: {T.background};")
        self.rain = MatrixRain(0.85, self)
        lay = QVBoxLayout(self)
        lay.addStretch(1)
        logo = LogoWidget(accent)
        logo.setFixedWidth(360)
        lay.addWidget(logo, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addStretch(1)
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._done = False
        self.setGeometry(parent.rect())
        self.raise_()
        self.show()
        QTimer.singleShot(hold_ms, self.dismiss)

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self.rain.setGeometry(self.rect())

    def mousePressEvent(self, _e) -> None:  # noqa: N802
        self.dismiss()

    def dismiss(self) -> None:
        if self._done:
            return
        self._done = True
        dur = Motion.instance().duration(450)
        if dur == 0:
            self.deleteLater()
            return
        anim = QPropertyAnimation(self._effect, b"opacity", self)
        anim.setDuration(dur)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        anim.finished.connect(self.deleteLater)
        anim.start()
        self._anim = anim
