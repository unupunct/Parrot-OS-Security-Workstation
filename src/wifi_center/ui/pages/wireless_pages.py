"""Wi-Fi Center (adapter manager) and Wireless Discovery."""
from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QPlainTextEdit, QPushButton, QSplitter, QTableWidgetItem,
                               QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services.adapter_service import AdapterService, WirelessAdapter
from ...services.wireless_service import ScanError
from ...workers.task import run_in_background
import pyqtgraph as pg
from PySide6.QtWidgets import QTabWidget

from ..charts import NumItem, color, fmt_ts, make_plot, make_table, signal_bars
from ..design.components import LoadingIndicator, StatusChip
from ..design.terminal_view import TerminalView
from ..design.tokens import T
from ..radar import RadarWidget
from .netsec_common import confirm_dialog

esc = html.escape


from .adapter_page import AdapterPage  # noqa: E402,F401  (moved to its own module)
from .discovery_page import COLS, DiscoveryPage  # noqa: E402,F401  (moved to its own module)


