"""MATRIX PRO stylesheet. All colours come from `design.tokens`; accent can be customised."""
from __future__ import annotations

from .design.tokens import T, mix, with_alpha

PALETTE = {  # kept for compatibility with older callers
    "bg": T.background, "sidebar": T.sidebar, "card": T.panel, "elevated": T.panel_elevated,
    "border": T.border, "green": T.green, "emerald": T.emerald, "cyan": T.cyan, "text": T.text,
    "text2": T.text_secondary, "warn": T.warning, "error": T.danger, "info": T.info,
}

ACCENT_PRESETS = {
    "Matrix green": "#00FF66",
    "Emerald": "#20D979",
    "Cyan": "#00D9CE",
    "Amber": "#F2B84B",
}


def build_stylesheet(accent: str = T.green) -> str:
    p = {k: v for k, v in vars(T).items() if isinstance(v, (str, int)) and not k.startswith("_")}
    p["green"] = accent
    p["accent_dim"] = mix(T.background, accent, 0.42)
    p["accent_tint"] = with_alpha(accent, 0.10)
    p["accent_tint2"] = with_alpha(accent, 0.18)
    p["accent_line"] = with_alpha(accent, 0.55)
    return """
* { font-family: %(font_stack)s; font-size: 13px; outline: 0; }
QMainWindow, QWidget#root { background: %(background)s; color: %(text)s; }
QWidget { color: %(text)s; }
QToolTip { background: %(panel_elevated)s; color: %(text)s; border: 1px solid %(border_active)s; padding: 5px 8px; }

/* ---------- shell ---------- */
QFrame#topbar { background: %(background_secondary)s; border-bottom: 1px solid %(border)s; }
QLabel#crumbs { color: %(text_muted)s; font-size: 12px; }
QLabel#pageHeading { font-size: 20px; font-weight: 700; color: %(text)s; }
QLabel#pageSub { color: %(text_secondary)s; font-size: 12px; }
QFrame#sidebarPane { background: %(sidebar)s; border-right: 1px solid %(border)s; }
QScrollArea#sidebarScroll, QScrollArea#sidebarScroll > QWidget > QWidget { background: transparent; border: none; }
QScrollArea#sidebarScroll QScrollBar:vertical { width: 6px; margin: 2px 1px; }
QLabel#navCategory { color: %(text_muted)s; font-size: 11px; font-weight: 700; letter-spacing: 1.5px; }
QFrame#navSeparator { background: %(border)s; max-height: 1px; border: none; }

QPushButton#searchField { background: %(panel)s; border: 1px solid %(border)s; border-radius: 8px; color: %(text_secondary)s;
    text-align: left; padding: 8px 14px; }
QPushButton#searchField:hover { border-color: %(border_active)s; color: %(text)s; }
QPushButton#searchField:focus { border-color: %(green)s; }

QFrame#statusChip { background: %(panel)s; border: 1px solid %(border)s; border-radius: 15px; }
QFrame#statusChip:hover { border-color: %(border_active)s; background: %(panel_hover)s; }
QLabel#chipText { color: %(text_secondary)s; font-size: 12px; }

QFrame#palette { background: %(background_secondary)s; border: 1px solid %(border_active)s; border-radius: 12px; }
QLineEdit#paletteInput { background: transparent; border: none; border-bottom: 1px solid %(border)s; border-radius: 0;
    padding: 14px 16px; font-size: 15px; }
QListWidget#paletteList { background: transparent; border: none; padding: 6px; }
QListWidget#paletteList::item { padding: 8px 10px; border-radius: 6px; color: %(text)s; }
QListWidget#paletteList::item:selected { background: %(accent_tint2)s; color: %(green)s; }

/* ---------- surfaces ---------- */
QFrame#card, QFrame#panel { background: %(panel)s; border: 1px solid %(border)s; border-radius: %(radius)spx; }
QFrame#panel:hover { border-color: %(border_active)s; }
QFrame#metricTile { background: %(panel)s; border: 1px solid %(border)s; border-radius: %(radius)spx; }
QFrame#metricTile:hover { border-color: %(border_active)s; background: %(panel_elevated)s; }
QFrame#toolCard { background: %(panel)s; border: 1px solid %(border)s; border-radius: %(radius)spx; }
QFrame#toolCard:hover { background: %(panel_hover)s; border-color: %(accent_line)s; }
QFrame#toolCard[selected="true"] { border-color: %(green)s; background: %(panel_elevated)s; }
QLabel#cardTitle, QLabel#panelTitle { color: %(text_secondary)s; font-size: 11px; font-weight: 700; letter-spacing: 1.2px; }
QLabel#bigValue { font-size: 22px; font-weight: 700; color: %(text)s; }
QLabel#metricValue { font-size: 20px; font-weight: 700; }
QLabel#muted { color: %(text_secondary)s; }
QLabel#faint { color: %(text_muted)s; font-size: 11px; }
QLabel#pageTitle { font-size: 20px; font-weight: 700; }
QLabel#ok { color: %(success)s; } QLabel#warn { color: %(warning)s; } QLabel#err { color: %(danger)s; }
QLabel#badge { background: %(accent_tint2)s; color: %(green)s; border-radius: 8px; padding: 0 6px; font-size: 10px; font-weight: 700; }
QLabel#badgeWarn { background: rgba(242,184,75,0.18); color: %(warning)s; border-radius: 8px; padding: 0 6px; font-size: 10px; font-weight: 700; }
QLabel#badgeErr { background: rgba(241,91,100,0.18); color: %(danger)s; border-radius: 8px; padding: 0 6px; font-size: 10px; font-weight: 700; }

/* ---------- controls ---------- */
QPushButton, QToolButton { background: %(panel_elevated)s; border: 1px solid %(border)s; border-radius: 7px; padding: 7px 14px; }
QToolButton { padding: 4px 6px; }
QPushButton:hover, QToolButton:hover { border-color: %(accent_line)s; background: %(panel_hover)s; }
QPushButton:pressed { background: %(accent_tint)s; }
QPushButton:focus, QToolButton:focus { border-color: %(green)s; }
QPushButton:disabled, QToolButton:disabled { color: %(text_muted)s; border-color: %(border)s; background: %(background_secondary)s; }
QPushButton#primary { background: %(accent_dim)s; color: #031208; border: 1px solid %(green)s; font-weight: 700; }
QPushButton#primary:hover { background: %(green)s; }
QPushButton#primary:disabled { background: %(background_secondary)s; color: %(text_muted)s; border-color: %(border)s; }
QPushButton#danger { border-color: %(danger)s; color: %(danger)s; }
QToolButton::menu-indicator { image: none; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid %(border_active)s; border-radius: 4px; background: %(panel)s; }
QCheckBox::indicator:checked { background: %(green)s; border-color: %(green)s; }

QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QTextBrowser, QListWidget, QSpinBox {
    background: %(panel)s; border: 1px solid %(border)s; border-radius: 7px; padding: 5px 8px;
    selection-background-color: %(accent_dim)s; selection-color: #031208; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus { border-color: %(green)s; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background: %(panel_elevated)s; border: 1px solid %(border_active)s; selection-background-color: %(accent_tint2)s; selection-color: %(green)s; }
QListWidget::item { padding: 6px 8px; border-radius: 5px; }
QListWidget::item:selected { background: %(accent_tint2)s; color: %(green)s; }
QListWidget::item:hover:!selected { background: %(panel_hover)s; }

QTableWidget, QTableView { background: %(panel)s; border: 1px solid %(border)s; border-radius: 8px; gridline-color: %(border)s;
    alternate-background-color: %(background_secondary)s; selection-background-color: %(accent_tint2)s; }
QTableWidget::item { padding: 4px 6px; border: none; }
QTableWidget::item:selected { background: %(accent_tint2)s; color: %(green)s; }
QHeaderView::section { background: %(background_secondary)s; color: %(text_secondary)s; border: none; border-bottom: 1px solid %(border)s;
    padding: 7px 6px; font-weight: 700; font-size: 12px; }
QTableCornerButton::section { background: %(background_secondary)s; border: none; }

QTreeWidget, QTreeView { background: %(panel)s; border: 1px solid %(border)s; border-radius: 8px;
    alternate-background-color: %(background_secondary)s; show-decoration-selected: 1; }
QTreeView::item { padding: 4px 2px; }
QTreeView::item:selected { background: %(accent_tint2)s; color: %(green)s; }
QTreeView::item:hover:!selected { background: %(panel_hover)s; }
QTreeView::indicator, QTableView::indicator, QListView::indicator { width: 16px; height: 16px; border: 1px solid %(border_active)s;
    border-radius: 4px; background: %(panel)s; }
QTreeView::indicator:checked, QTableView::indicator:checked, QListView::indicator:checked { background: %(green)s; border-color: %(green)s; }
QTreeView::indicator:disabled { border-color: %(border)s; }
QTabWidget::pane { border: 1px solid %(border)s; border-radius: 8px; top: -1px; background: %(background_secondary)s; }
QTabBar::tab { background: transparent; padding: 8px 16px; color: %(text_secondary)s; border: none; border-bottom: 2px solid transparent; }
QTabBar::tab:hover { color: %(text)s; }
QTabBar::tab:selected { color: %(green)s; border-bottom: 2px solid %(green)s; }
QProgressBar { background: %(background_secondary)s; border: 1px solid %(border)s; border-radius: 4px; height: 8px; text-align: center; }
QProgressBar::chunk { background: %(green)s; border-radius: 3px; }
QSplitter::handle { background: %(border)s; }
QSplitter::handle:hover { background: %(border_active)s; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: %(border_active)s; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: %(accent_line)s; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: %(border_active)s; border-radius: 4px; min-width: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QMenu { background: %(panel_elevated)s; border: 1px solid %(border_active)s; border-radius: 8px; padding: 4px; }
QMenu::item { padding: 7px 18px; border-radius: 5px; }
QMenu::item:selected { background: %(accent_tint2)s; color: %(green)s; }
QMenu::separator { height: 1px; background: %(border)s; margin: 4px 8px; }
QDialog, QMessageBox { background: %(background_secondary)s; }
QStackedWidget { background: transparent; }
""" % p
