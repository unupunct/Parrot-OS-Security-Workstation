"""Matrix-dark theme. One palette, one stylesheet generator."""
from __future__ import annotations

PALETTE = {
    "bg": "#090D0B",
    "sidebar": "#0D1410",
    "card": "#111B15",
    "elevated": "#17231B",
    "border": "#1F2E25",
    "green": "#00FF66",
    "emerald": "#20C979",
    "cyan": "#00D5C8",
    "text": "#E7F1E9",
    "text2": "#8D9C91",
    "warn": "#F2B84B",
    "error": "#F05D5E",
    "info": "#4DA3FF",
}

ACCENT_PRESETS = {
    "Matrix green": "#00FF66",
    "Emerald": "#20C979",
    "Cyan": "#00D5C8",
    "Amber": "#F2B84B",
}


def _darken(hex_color: str, f: float) -> str:
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return "#%02X%02X%02X" % (int(r * f), int(g * f), int(b * f))


def build_stylesheet(accent: str = "#00FF66") -> str:
    p = dict(PALETTE, green=accent)
    p["accent_dim"] = _darken(accent, 0.55)
    return """
* { font-family: "Inter", "Noto Sans", "Segoe UI", sans-serif; font-size: 13px; }
QMainWindow, QWidget#root { background: %(bg)s; color: %(text)s; }
QWidget { color: %(text)s; }
QToolTip { background: %(elevated)s; color: %(text)s; border: 1px solid %(border)s; padding: 4px; }

QFrame#topbar { background: %(sidebar)s; border-bottom: 1px solid %(border)s; }
QLabel#logo { color: %(green)s; font-size: 16px; font-weight: 700; letter-spacing: 1px; }
QLabel#workspace { color: %(text2)s; font-size: 13px; }
QLabel#statusPill, QLabel#privPill {
    background: %(card)s; border: 1px solid %(border)s; border-radius: 10px; padding: 3px 10px; color: %(text2)s; }
QLabel#privPill[active="true"] { color: %(warn)s; border-color: %(warn)s; }

QTreeWidget#sidebar { background: %(sidebar)s; border: none; border-right: 1px solid %(border)s;
    outline: 0; padding: 6px 4px; }
QTreeWidget#sidebar::item { padding: 5px 6px; border-radius: 4px; color: %(text)s; }
QTreeWidget#sidebar::item:hover { background: %(elevated)s; }
QTreeWidget#sidebar::item:selected { background: %(elevated)s; color: %(green)s; border-left: 2px solid %(green)s; }

QFrame#card { background: %(card)s; border: 1px solid %(border)s; border-radius: 8px; }
QLabel#cardTitle { color: %(text2)s; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
QLabel#bigValue { font-size: 22px; font-weight: 600; color: %(text)s; }
QLabel#muted { color: %(text2)s; }
QLabel#pageTitle { font-size: 20px; font-weight: 600; }
QLabel#ok { color: %(green)s; } QLabel#warn { color: %(warn)s; } QLabel#err { color: %(error)s; }

QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; }
QStackedWidget { background: transparent; }
QToolButton { background: %(elevated)s; border: 1px solid %(border)s; border-radius: 5px; padding: 6px 14px; }
QToolButton:hover { border-color: %(green)s; }
QToolButton::menu-indicator { image: none; }
QPushButton { background: %(elevated)s; border: 1px solid %(border)s; border-radius: 5px; padding: 6px 14px; }
QPushButton:hover { border-color: %(green)s; }
QPushButton:disabled { color: %(text2)s; }
QPushButton#primary { background: %(accent_dim)s; color: #000; border: 1px solid %(green)s; font-weight: 600; }
QPushButton#primary:hover { background: %(green)s; }

QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QListWidget, QTableView {
    background: %(card)s; border: 1px solid %(border)s; border-radius: 5px; padding: 4px 6px;
    selection-background-color: %(accent_dim)s; selection-color: #000; }
QLineEdit:focus, QComboBox:focus { border-color: %(green)s; }
QTabWidget::pane { border: 1px solid %(border)s; border-radius: 6px; top: -1px; }
QTabBar::tab { background: %(sidebar)s; padding: 6px 14px; border: 1px solid %(border)s; border-bottom: none; }
QTabBar::tab:selected { color: %(green)s; background: %(card)s; }
QHeaderView::section { background: %(sidebar)s; color: %(text2)s; border: none; border-bottom: 1px solid %(border)s;
    padding: 6px; font-weight: 600; }
QTableWidget { gridline-color: %(border)s; alternate-background-color: %(card)s; }
QTableWidget::item { padding: 4px; border: none; }
QTableWidget::item:selected { background: %(elevated)s; color: %(green)s; }
QTableCornerButton::section { background: %(sidebar)s; border: none; }
QProgressBar { background: %(sidebar)s; border: 1px solid %(border)s; border-radius: 4px; height: 8px; text-align: center; }
QProgressBar::chunk { background: %(green)s; border-radius: 3px; }
QSplitter::handle { background: %(border)s; width: 2px; }
QScrollBar:vertical { background: %(bg)s; width: 10px; }
QScrollBar::handle:vertical { background: %(border)s; border-radius: 4px; min-height: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QMenu { background: %(card)s; border: 1px solid %(border)s; }
QMenu::item:selected { background: %(elevated)s; color: %(green)s; }
""" % p
