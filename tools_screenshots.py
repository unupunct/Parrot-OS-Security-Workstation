"""Render demo screenshots of selected pages (offscreen, own temporary profile, demo project: no personal or network data).

    QT_QPA_PLATFORM=offscreen python tools_screenshots.py docs/screenshots
"""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from PySide6.QtWidgets import QApplication                               # noqa: E402  (PySide6 first: pyqtgraph binds to the first Qt it sees)

import wifi_center.__main__ as entry                                    # noqa: E402
entry._pyqtgraph_compat()

from wifi_center.application.app_controller import AppController         # noqa: E402
from wifi_center.application.paths import AppPaths                       # noqa: E402
from wifi_center.ui.main_window import MainWindow                        # noqa: E402
from wifi_center.ui.theme import build_stylesheet                        # noqa: E402

# The Overview is deliberately not captured: it lists the devices found on the machine's real network.
PAGES = ("tools_all", "assessment", "reports", "project_history", "docs")


def pump(app, n=40, seconds=0.0):
    import time
    end = time.time() + seconds
    for _ in range(n):
        app.processEvents()
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    paths = AppPaths(config_dir=tmp / "c", data_dir=tmp / "d", log_dir=tmp / "d/logs", backup_dir=tmp / "d/b", db_path=tmp / "d/w.db", default_resources_dir=tmp / "r")
    app = QApplication([])
    ctl = AppController(paths=paths, console_log=False)
    app.setStyleSheet(build_stylesheet(ctl.settings.get("appearance.accent")))
    pid = ctl.projects.create("Demo: small office")
    ctl.projects.add_scope(pid, "192.0.2.0/24", "documentation range (demo)")
    ctl.projects.add_finding(pid, "Guest Wi-Fi without encryption", "high", "The guest SSID accepts connections without a passphrase.", "Enable WPA3 or WPA2-PSK.", "demo", "Guest-AP")
    ctl.projects.add_finding(pid, "Router firmware is outdated", "medium", "Firmware is several releases behind.", "Update and enable automatic updates.", "demo")
    win = MainWindow(ctl)
    win.resize(1440, 860)
    win.show()
    pump(app)
    for page in PAGES:
        win.sidebar.select_page(page)
        pump(app, 80, 8.0 if page in ("tools_all", "docs") else 1.0)           # these pages fill in from background scans
        if page == "reports":
            win.stack.currentWidget().preview()
            pump(app, 120)
        win.grab().save(str(out / f"{page}.png"))
        print("saved", page)
    ctl.shutdown()


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots"))
