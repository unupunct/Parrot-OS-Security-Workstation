"""Application entry point."""
from __future__ import annotations

import sys


def _pyqtgraph_compat() -> None:
    """pyqtgraph 0.13.x expects QOpenGLWidget in QtWidgets; PySide6 >= 6.4 moved it to QtOpenGLWidgets."""
    try:
        from pyqtgraph.Qt import QtWidgets
        if not hasattr(QtWidgets, "QOpenGLWidget"):
            try:
                from PySide6.QtOpenGLWidgets import QOpenGLWidget
            except ImportError:                       # not shipped on every distribution: a stand-in the isinstance check rejects
                class QOpenGLWidget:  # type: ignore[no-redef]
                    pass
            QtWidgets.QOpenGLWidget = QOpenGLWidget
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    from PySide6.QtWidgets import QApplication

    from . import APP_NAME, __version__
    from .application.app_controller import AppController
    from .ui.main_window import MainWindow
    from .ui.theme import build_stylesheet

    argv = list(sys.argv if argv is None else argv)
    if "--version" in argv:
        print(f"{APP_NAME} {__version__}")
        return 0

    _pyqtgraph_compat()
    qapp = QApplication(argv)
    qapp.setApplicationName("wifi-center")
    qapp.setApplicationDisplayName(APP_NAME)
    from pathlib import Path

    from PySide6.QtGui import QIcon
    qapp.setWindowIcon(QIcon(str(Path(__file__).parent / "resources" / "icons" / "wifi-center.svg")))
    qapp.setDesktopFileName("wifi-center")
    controller = AppController()
    qapp.setStyleSheet(build_stylesheet(controller.settings.get("appearance.accent")))
    qapp.aboutToQuit.connect(controller.shutdown)
    win = MainWindow(controller)
    win.show()
    return qapp.exec()


if __name__ == "__main__":
    sys.exit(main())
