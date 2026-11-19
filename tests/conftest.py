import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from wifi_center.application.app_controller import AppController
from wifi_center.application.paths import AppPaths


@pytest.fixture
def paths(tmp_path):
    return AppPaths(
        config_dir=tmp_path / "config",
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "data" / "logs",
        backup_dir=tmp_path / "data" / "backups",
        db_path=tmp_path / "data" / "wifi-center.db",
        default_resources_dir=tmp_path / "res",
    )


@pytest.fixture
def controller(paths):
    c = AppController(paths=paths, console_log=False)
    yield c
    c.shutdown()
