"""MATRIX PRO design tokens: the single source of truth for colours, spacing and type."""
from __future__ import annotations


class T:
    # surfaces
    background = "#080C09"
    background_secondary = "#0B120D"
    sidebar = "#0A100C"
    panel = "#101912"
    panel_elevated = "#142019"
    panel_hover = "#19291F"
    # accents
    green = "#00FF66"
    emerald = "#20D979"
    soft_green = "#75F5A4"
    cyan = "#00D9CE"
    # text
    text = "#E7F2E9"
    text_secondary = "#91A397"
    text_muted = "#5D7164"
    # lines
    border = "#203328"
    border_active = "#176A3A"
    # status
    success = "#2AE887"
    warning = "#F2B84B"
    danger = "#F15B64"
    info = "#42C7F5"

    # spacing / shape
    gutter = 16
    gap = 12
    radius = 10
    radius_small = 6
    sidebar_width = 262
    topbar_height = 76
    # type
    font_stack = '"Inter", "Segoe UI", "Noto Sans", "DejaVu Sans", sans-serif'
    mono_stack = '"JetBrains Mono", "DejaVu Sans Mono", "Cascadia Mono", "Consolas", monospace'

    STATUS = {"ok": success, "warning": warning, "error": danger, "missing": text_muted, "info": info,
              "running": info, "succeeded": success, "failed": danger, "cancelled": warning,
              "timeout": warning, "launched": success, "interrupted": warning}


def with_alpha(hex_color: str, alpha: float) -> str:
    """'#RRGGBB' + 0..1 alpha -> 'rgba(r,g,b,a)' for stylesheets."""
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return f"rgba({r},{g},{b},{alpha:.2f})"


def mix(a: str, b: str, t: float) -> str:
    """Linear blend of two '#RRGGBB' colours (t=0 -> a, t=1 -> b)."""
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02X%02X%02X" % tuple(round(x + (y - x) * t) for x, y in zip(ca, cb))
