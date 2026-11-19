"""Application entry point."""
from __future__ import annotations

import sys


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

    qapp = QApplication(argv)
    qapp.setApplicationName("wifi-center")
    qapp.setApplicationDisplayName(APP_NAME)
    controller = AppController()
    qapp.setStyleSheet(build_stylesheet(controller.settings.get("appearance.accent")))
    qapp.aboutToQuit.connect(controller.shutdown)
    win = MainWindow(controller)
    win.show()
    return qapp.exec()


if __name__ == "__main__":
    sys.exit(main())
