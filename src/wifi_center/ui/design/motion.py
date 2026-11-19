"""Central animation system: one shared frame clock, intensity levels and reduced motion.

Widgets that animate continuously subclass `Animated` and implement `tick(dt)`. They only receive
frames while visible, and the clock stops completely when nobody is subscribed, the app is
inactive, or reduced motion is on. One-shot transitions use `fade_in` / `animate_value`, whose
durations scale with the intensity (and drop to zero in reduced-motion mode).
"""
from __future__ import annotations

import logging
import time
import weakref
from typing import Callable

from PySide6.QtCore import QEasingCurve, QObject, QPropertyAnimation, QTimer, QVariantAnimation, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QGraphicsOpacityEffect, QWidget

log = logging.getLogger(__name__)

INTENSITIES = ("low", "normal", "high")
FRAME_MS = {"low": 100, "normal": 50, "high": 33}      # 10 / 20 / 30 fps for continuous effects
DURATION_SCALE = {"low": 0.6, "normal": 1.0, "high": 1.0}


class Motion(QObject):
    """Process-wide motion settings and frame clock."""

    _instance: "Motion | None" = None

    def __init__(self) -> None:
        super().__init__()
        self.intensity = "high"
        self._reduced = False
        self._subs: "weakref.WeakSet[Animated]" = weakref.WeakSet()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        self._last = time.monotonic()
        self._acc: "weakref.WeakKeyDictionary[Animated, float]" = weakref.WeakKeyDictionary()
        app = QApplication.instance()
        if app is not None:
            app.applicationStateChanged.connect(lambda _s: self._sync())

    @classmethod
    def instance(cls) -> "Motion":
        if cls._instance is None:
            cls._instance = Motion()
        return cls._instance

    # ---- settings ----
    @property
    def reduced(self) -> bool:
        # Headless platforms (tests, CI) never animate continuously.
        return self._reduced or QGuiApplication.platformName() in ("offscreen", "minimal")

    def configure(self, intensity: str, reduced_motion: bool) -> None:
        self.intensity = intensity if intensity in INTENSITIES else "high"
        self._reduced = bool(reduced_motion)
        self._timer.setInterval(FRAME_MS[self.intensity])
        self._sync()
        for a in list(self._subs):
            a.motion_changed()

    @property
    def enabled(self) -> bool:
        return not self.reduced

    def duration(self, ms: int) -> int:
        return 0 if self.reduced else int(ms * DURATION_SCALE[self.intensity])

    # ---- frame clock ----
    def subscribe(self, w: "Animated") -> None:
        self._subs.add(w)
        self._sync()

    def unsubscribe(self, w: "Animated") -> None:
        self._subs.discard(w)
        self._sync()

    def subscriber_count(self) -> int:
        return len(self._subs)

    def _sync(self) -> None:
        app = QApplication.instance()
        active = app is None or app.applicationState() == Qt.ApplicationState.ApplicationActive \
            or QGuiApplication.platformName() == "offscreen"
        should_run = bool(self._subs) and self.enabled and active
        if should_run and not self._timer.isActive():
            self._timer.setInterval(FRAME_MS[self.intensity])
            self._last = time.monotonic()
            self._timer.start()
        elif not should_run and self._timer.isActive():
            self._timer.stop()

    @property
    def running(self) -> bool:
        return self._timer.isActive()

    def _on_tick(self) -> None:
        now = time.monotonic()
        dt = min(now - self._last, 0.25)  # clamp after stalls so animations never jump
        self._last = now
        for w in list(self._subs):
            try:
                if not w.isVisible() or w.animation_paused:
                    continue
                prof = w.fps_profile
                if prof:  # per-effect frame-rate cap by intensity (heavy effects tick less often)
                    acc = self._acc.get(w, 0.0) + dt
                    if acc < 1.0 / prof[self.intensity]:
                        self._acc[w] = acc
                        continue
                    dt, self._acc[w] = acc, 0.0
                w.tick(dt)
            except RuntimeError:  # widget already destroyed
                self._subs.discard(w)
            except Exception:
                log.exception("animation tick failed; unsubscribing %s", type(w).__name__)
                self._subs.discard(w)


class Animated:
    """Mixin for QWidgets that need per-frame updates. Subscribes only while shown."""

    animation_paused = False
    fps_profile: dict[str, int] | None = None   # e.g. {"low": 6, "normal": 12, "high": 20}

    def tick(self, dt: float) -> None:  # pragma: no cover - overridden
        pass

    def motion_changed(self) -> None:
        pass

    # Qt event hooks (mixin must come before QWidget in the MRO)
    def showEvent(self, e) -> None:  # noqa: N802
        Motion.instance().subscribe(self)
        super().showEvent(e)  # type: ignore[misc]

    def hideEvent(self, e) -> None:  # noqa: N802
        Motion.instance().unsubscribe(self)
        super().hideEvent(e)  # type: ignore[misc]


# ---------------- one-shot helpers ----------------
def fade_in(widget: QWidget, ms: int = 180, slide: int = 0, on_done: Callable[[], None] | None = None) -> None:
    """Fade (and optionally slide up by `slide` px) a widget in. No-op in reduced motion."""
    m = Motion.instance()
    dur = m.duration(ms)
    if dur <= 0:
        if on_done:
            on_done()
        return
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(0.0)
    widget.setGraphicsEffect(effect)
    anim = QPropertyAnimation(effect, b"opacity", widget)
    anim.setDuration(dur)
    anim.setStartValue(0.0)
    anim.setEndValue(1.0)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def finished() -> None:
        try:
            widget.setGraphicsEffect(None)  # effects slow down child rendering; remove when done
        except RuntimeError:
            return
        if on_done:
            on_done()

    anim.finished.connect(finished)
    widget._fade_anim = anim  # keep a reference
    anim.start()


def animate_value(parent: QObject, start: float, end: float, ms: int, setter: Callable[[float], None],
                  curve: QEasingCurve.Type = QEasingCurve.Type.OutCubic) -> QVariantAnimation | None:
    """Animate a number into `setter`; applies the end value immediately in reduced motion."""
    dur = Motion.instance().duration(ms)
    if dur <= 0:
        setter(end)
        return None
    anim = QVariantAnimation(parent)
    anim.setStartValue(float(start))
    anim.setEndValue(float(end))
    anim.setDuration(dur)
    anim.setEasingCurve(curve)
    anim.valueChanged.connect(lambda v: setter(float(v)))
    anim.start(QVariantAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim
