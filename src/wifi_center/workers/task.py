"""Run a callable on the Qt thread pool and deliver the result on the GUI thread."""
from __future__ import annotations

import logging
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

log = logging.getLogger(__name__)
_live: set["_Task"] = set()  # keep tasks (and their signal objects) alive until delivery


class _Signals(QObject):  # created on the GUI thread, so slots run there
    finished = Signal(object)
    failed = Signal(str)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], Any]) -> None:
        super().__init__()
        self.setAutoDelete(False)
        self.fn = fn
        self.signals = _Signals()

    def run(self) -> None:
        try:
            result = self.fn()
            self._emit(self.signals.finished, result)
        except Exception as e:
            log.exception("background task failed")
            self._emit(self.signals.failed, str(e))

    @staticmethod
    def _emit(signal, value) -> None:
        try:
            signal.emit(value)
        except RuntimeError:  # receiver side already torn down (window closed / app exiting)
            pass


def _guard(callback):
    """A failing completion callback (e.g. UI already closed) is logged, never fatal."""
    def wrapper(value=None):
        try:
            callback(value)
        except Exception:
            log.exception("background completion callback failed")
    return wrapper


def run_in_background(
    fn: Callable[[], Any],
    on_done: Callable[[Any], None],
    on_error: Callable[[str], None] | None = None,
) -> None:
    """Call from the GUI thread. `on_done` / `on_error` run on the GUI thread."""
    task = _Task(fn)
    task.signals.finished.connect(_guard(on_done))
    if on_error:
        task.signals.failed.connect(_guard(on_error))
    task.signals.finished.connect(lambda _=None: _live.discard(task))
    task.signals.failed.connect(lambda _=None: _live.discard(task))
    _live.add(task)
    QThreadPool.globalInstance().start(task)
