"""Unified line-icon set drawn with QPainter (24x24 grid, 1.8px rounded strokes).

Icons are vector, recoloured on demand (e.g. green on hover/active) and cached.
Ops: ("l", [(x,y),...]) polyline · ("g", [(x,y),...]) closed polygon · ("c", cx, cy, r) circle ·
("r", x, y, w, h, radius) rounded rect · ("a", cx, cy, r, start_deg, span_deg) arc · ("d", cx, cy) dot.
"""
from __future__ import annotations

from functools import lru_cache

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap, QPolygonF

ICONS: dict[str, list[tuple]] = {
    "dashboard": [("r", 3, 3, 7, 8, 1.5), ("r", 14, 3, 7, 5, 1.5), ("r", 14, 11, 7, 10, 1.5), ("r", 3, 14, 7, 7, 1.5)],
    "activity": [("l", [(2, 12), (6, 12), (9, 4), (13, 20), (16, 12), (22, 12)])],
    "hardware": [("r", 6, 6, 12, 12, 2), ("l", [(9, 2), (9, 6)]), ("l", [(15, 2), (15, 6)]), ("l", [(9, 18), (9, 22)]),
                 ("l", [(15, 18), (15, 22)]), ("l", [(2, 9), (6, 9)]), ("l", [(2, 15), (6, 15)]),
                 ("l", [(18, 9), (22, 9)]), ("l", [(18, 15), (22, 15)])],
    "wifi": [("a", 12, 19, 3, 0, 360), ("a", 12, 19, 9, 40, 100), ("a", 12, 19, 15, 45, 90)],
    "discovery": [("c", 12, 12, 9), ("c", 12, 12, 4.5), ("l", [(12, 12), (19, 7)])],
    "kismet": [("a", 12, 12, 10, 200, 140), ("a", 12, 12, 10, 20, 140), ("c", 12, 12, 3), ("l", [(3, 12), (6, 12)]),
               ("l", [(18, 12), (21, 12)])],
    "spectrum": [("l", [(4, 20), (4, 12)]), ("l", [(9, 20), (9, 5)]), ("l", [(14, 20), (14, 9)]),
                 ("l", [(19, 20), (19, 14)])],
    "bluetooth": [("l", [(7, 7), (17, 17), (12, 22), (12, 2), (17, 7), (7, 17)])],
    "packets": [("g", [(12, 3), (21, 8), (21, 16), (12, 21), (3, 16), (3, 8)]), ("l", [(3, 8), (12, 13), (21, 8)]),
                ("l", [(12, 13), (12, 21)])],
    "network": [("c", 12, 5, 2.5), ("c", 5, 19, 2.5), ("c", 19, 19, 2.5), ("l", [(12, 7.5), (5, 16.5)]),
                ("l", [(12, 7.5), (19, 16.5)]), ("l", [(7.5, 19), (16.5, 19)])],
    "map": [("g", [(3, 6), (9, 4), (15, 6), (21, 4), (21, 18), (15, 20), (9, 18), (3, 20)]), ("l", [(9, 4), (9, 18)]),
            ("l", [(15, 6), (15, 20)])],
    "shield": [("g", [(12, 2.5), (20, 5.5), (20, 12), (12, 21.5), (4, 12), (4, 5.5)])],
    "web": [("c", 12, 12, 9), ("l", [(3, 12), (21, 12)]), ("a", 12, 12, 9, 90, 180), ("a", 12, 12, 4.5, 90, 180),
            ("a", 12, 12, 4.5, -90, 180)],
    "key": [("c", 8, 15, 4.5), ("l", [(11.5, 11.5), (20, 3)]), ("l", [(17, 6), (20, 9)]), ("l", [(14, 9), (16, 11)])],
    "osint": [("c", 10.5, 10.5, 7), ("l", [(15.5, 15.5), (21, 21)])],
    "user": [("c", 12, 8, 4), ("a", 12, 21, 8, 20, 140)],
    "mail": [("r", 3, 5, 18, 14, 2), ("l", [(3.5, 6.5), (12, 13), (20.5, 6.5)])],
    "globe": [("c", 12, 12, 9), ("a", 12, 12, 9, 90, 180), ("a", 12, 12, 4, 90, 180), ("a", 12, 12, 4, -90, 180),
              ("l", [(3, 12), (21, 12)])],
    "pin": [("a", 12, 9.5, 6.5, 0, 180), ("l", [(5.5, 9.5), (12, 21), (18.5, 9.5)]), ("c", 12, 9.5, 2.3)],
    "update": [("a", 12, 12, 8, 30, 280), ("l", [(19, 3.5), (19.5, 8.5), (14.5, 8.5)])],
    "software": [("r", 3, 3, 8, 8, 1.5), ("r", 13, 3, 8, 8, 1.5), ("r", 3, 13, 8, 8, 1.5), ("l", [(17, 13), (17, 21)]),
                 ("l", [(13, 17), (21, 17)])],
    "cleanup": [("l", [(5, 7), (19, 7)]), ("l", [(9, 7), (9, 4), (15, 4), (15, 7)]), ("g", [(6.5, 7), (17.5, 7), (16.5, 21), (7.5, 21)]),
                ("l", [(10, 11), (10, 17)]), ("l", [(14, 11), (14, 17)])],
    "package": [("g", [(12, 2.5), (21, 7), (21, 17), (12, 21.5), (3, 17), (3, 7)]), ("l", [(3, 7), (12, 11.5), (21, 7)]),
                ("l", [(12, 11.5), (12, 21.5)])],
    "root": [("g", [(12, 2.5), (20, 5.5), (20, 12), (12, 21.5), (4, 12), (4, 5.5)]), ("r", 9, 10.5, 6, 5, 1),
             ("a", 12, 10.5, 2.2, 0, 180)],
    "info": [("c", 12, 12, 9), ("l", [(12, 11), (12, 17)]), ("d", 12, 7.5)],
    "history": [("a", 12, 12, 9, 40, 300), ("l", [(12, 7), (12, 12), (16, 14)]), ("l", [(3, 4), (3.5, 9), (8.5, 8.5)])],
    "tools": [("g", [(14, 3), (21, 10), (18, 13), (11, 6)]), ("l", [(15.5, 11.5), (6, 21)]), ("l", [(4, 19), (6, 21)])],
    "installed": [("c", 12, 12, 9), ("l", [(7.5, 12.5), (10.5, 15.5), (16.5, 9)])],
    "missing": [("g", [(12, 3), (22, 20), (2, 20)]), ("l", [(12, 10), (12, 15)]), ("d", 12, 17.8)],
    "config": [("c", 12, 12, 3), ("a", 12, 12, 8, 20, 50), ("a", 12, 12, 8, 110, 50), ("a", 12, 12, 8, 200, 50),
               ("a", 12, 12, 8, 290, 50)],
    "terminal": [("r", 2.5, 4, 19, 16, 2), ("l", [(6.5, 9), (10, 12), (6.5, 15)]), ("l", [(12, 15.5), (17, 15.5)])],
    "wordlist": [("g", [(5, 3), (19, 3), (19, 21), (5, 21)]), ("l", [(9, 8), (15, 8)]), ("l", [(9, 12), (15, 12)]),
                 ("l", [(9, 16), (13, 16)])],
    "docs": [("g", [(4, 3), (17, 3), (20, 6), (20, 21), (4, 21)]), ("l", [(8, 10), (16, 10)]), ("l", [(8, 14), (16, 14)])],
    "folder": [("l", [(3, 7), (3, 19), (21, 19), (21, 9), (11, 9), (9, 6), (3, 6), (3, 7)])],
    "reports": [("l", [(4, 20), (4, 4)]), ("l", [(4, 20), (20, 20)]), ("g", [(8, 16), (8, 11), (11, 11), (11, 16)]),
                ("g", [(13, 16), (13, 7), (16, 7), (16, 16)])],
    "evidence": [("r", 3, 8, 18, 12, 2), ("l", [(8, 8), (8, 5), (16, 5), (16, 8)]), ("c", 12, 14, 2.5)],
    "project": [("l", [(3, 7), (3, 19), (21, 19), (21, 9), (11, 9), (9, 6), (3, 6)]), ("l", [(8, 14), (16, 14)])],
    "settings": [("l", [(4, 7), (20, 7)]), ("l", [(4, 12), (20, 12)]), ("l", [(4, 17), (20, 17)]), ("c", 9, 7, 2.2),
                 ("c", 15, 12, 2.2), ("c", 8, 17, 2.2)],
    "bell": [("a", 12, 11, 6, 0, 180), ("l", [(6, 11), (6, 15), (4, 17.5), (20, 17.5), (18, 15), (18, 11)]),
             ("a", 12, 19.5, 2, 180, 180)],
    "search": [("c", 10.5, 10.5, 7), ("l", [(15.5, 15.5), (21, 21)])],
    "play": [("g", [(7, 4), (19, 12), (7, 20)])],
    "pause": [("l", [(8, 5), (8, 19)]), ("l", [(16, 5), (16, 19)])],
    "fit": [("l", [(4, 9), (4, 4), (9, 4)]), ("l", [(15, 4), (20, 4), (20, 9)]), ("l", [(20, 15), (20, 20), (15, 20)]),
            ("l", [(9, 20), (4, 20), (4, 15)])],
    "reset": [("a", 12, 12, 8, 20, 300), ("l", [(4, 4), (4.5, 9.5), (10, 9)])],
    "chevron": [("l", [(9, 6), (15, 12), (9, 18)])],
    "launch": [("l", [(9, 5), (19, 5), (19, 15)]), ("l", [(19, 5), (5, 19)])],
    "cpu": [("r", 6, 6, 12, 12, 2), ("l", [(10, 6), (10, 2)]), ("l", [(14, 6), (14, 2)]), ("l", [(10, 22), (10, 18)]),
            ("l", [(14, 22), (14, 18)])],
    "ram": [("r", 2, 7, 20, 9, 1.5), ("l", [(6, 16), (6, 19)]), ("l", [(10, 16), (10, 19)]), ("l", [(14, 16), (14, 19)]),
            ("l", [(18, 16), (18, 19)]), ("r", 5, 10, 3, 3, 0.5), ("r", 10.5, 10, 3, 3, 0.5), ("r", 16, 10, 3, 3, 0.5)],
    "gpu": [("r", 2, 6, 20, 11, 2), ("c", 12, 11.5, 3.5), ("l", [(5, 20), (19, 20)]), ("l", [(5, 9), (8, 9)])],
    "disk": [("r", 3, 4, 18, 16, 2), ("c", 12, 11, 4), ("d", 12, 11), ("d", 6.5, 17)],
    "disc": [("c", 12, 12, 9), ("c", 12, 12, 2.5), ("a", 12, 12, 6, 200, 60)],
    "speaker": [("g", [(4, 9), (8, 9), (13, 5), (13, 19), (8, 15), (4, 15)]), ("a", 13, 12, 5, 315, 90), ("a", 13, 12, 8, 320, 80)],
    "usb": [("l", [(12, 3), (12, 18)]), ("c", 12, 20, 2), ("l", [(12, 9), (7, 12), (7, 14)]), ("l", [(12, 12), (17, 9), (17, 7)]),
            ("d", 7, 15), ("r", 15.5, 5, 3, 2.5, 0.5)],
    "board": [("r", 3, 3, 18, 18, 2), ("r", 7, 7, 5, 5, 1), ("l", [(15, 8), (18, 8)]), ("l", [(15, 12), (18, 12)]),
              ("l", [(7, 17), (18, 17)])],
}

ALIASES = {"packages": "package", "wifi_center": "wifi", "wireless_discovery": "discovery", "net_discovery": "discovery",
           "net_mapping": "map", "lan_scanner": "discovery", "assessment": "shield", "web_security": "web", "password_audit": "key",
           "osint_user": "user", "osint_email": "mail", "osint_domain": "globe", "osint_ip": "pin",
           "overview": "dashboard", "system_hw": "hardware", "sys_updates": "update", "sw_updates": "software",
           "root_access": "root", "sys_info": "info", "maintenance": "history", "tools_all": "tools",
           "tools_installed": "installed", "tools_missing": "missing", "tools_config": "config",
           "wordlists": "wordlist", "local_resources": "folder", "project_history": "history",
           "settings_general": "settings", "settings_appearance": "settings", "settings_integrations": "package",
           "settings_permissions": "shield", "settings_backup": "history"}


def _path_for(op: tuple) -> QPainterPath:
    p = QPainterPath()
    kind = op[0]
    if kind in ("l", "g"):
        pts = op[1]
        p.moveTo(*pts[0])
        for pt in pts[1:]:
            p.lineTo(*pt)
        if kind == "g":
            p.closeSubpath()
    elif kind == "c":
        p.addEllipse(QPointF(op[1], op[2]), op[3], op[3])
    elif kind == "r":
        p.addRoundedRect(QRectF(op[1], op[2], op[3], op[4]), op[5], op[5])
    elif kind == "a":
        cx, cy, r, start, span = op[1:]
        p.arcMoveTo(QRectF(cx - r, cy - r, 2 * r, 2 * r), start)
        p.arcTo(QRectF(cx - r, cy - r, 2 * r, 2 * r), start, span)
    return p


@lru_cache(maxsize=512)
def icon_pixmap(name: str, color: str, size: int, dpr: float = 1.0) -> QPixmap:
    name = ALIASES.get(name, name)
    ops = ICONS.get(name) or ICONS["info"]
    pm = QPixmap(int(size * dpr), int(size * dpr))
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size / 24, size / 24)
    pen = QPen(QColor(color), 1.8)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    for op in ops:
        if op[0] == "d":
            p.setBrush(QColor(color))
            p.drawEllipse(QPointF(op[1], op[2]), 1.3, 1.3)
            p.setBrush(Qt.BrushStyle.NoBrush)
        else:
            p.drawPath(_path_for(op))
    p.end()
    return pm


def icon(name: str, color: str = "#91A397", size: int = 20) -> QIcon:
    return QIcon(icon_pixmap(name, color, size, 2.0))


def has_icon(name: str) -> bool:
    return ALIASES.get(name, name) in ICONS
