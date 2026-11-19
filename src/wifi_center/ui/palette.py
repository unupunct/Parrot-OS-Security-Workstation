"""Command palette (Ctrl+K): pages, tools, documentation, projects, settings and supported actions.

Only supported, non-restricted operations are offered: tool launches come from the integration
profile's declared operations, never from free-form input.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QDialog, QFrame, QLabel, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout,
                               QWidget)

from ..application.app_controller import AppController
from ..integrations.base import LaunchMethod
from .design.motion import fade_in
from .design.tokens import T
from .navigation import NAVIGATION


@dataclass
class Command:
    group: str
    title: str
    subtitle: str
    run: Callable[[], None]
    shortcut: str = ""
    keywords: str = ""


def fuzzy_score(query: str, text: str) -> int | None:
    """Subsequence match score (higher is better); None if `query` is not a subsequence of `text`."""
    q, t = query.lower().strip(), text.lower()
    if not q:
        return 0
    if q in t:
        return 1000 - t.index(q) * 5 - len(t)
    pos, score = 0, 0
    for ch in q:
        i = t.find(ch, pos)
        if i < 0:
            return None
        score += 10 - min(i - pos, 9)
        pos = i + 1
    return score


GROUP_ORDER = ["Pages", "Tools", "OSINT", "Actions", "Documentation", "Projects", "Settings"]
SHORTCUTS = {"overview": "Ctrl+1", "wireless_discovery": "Ctrl+2", "tools_all": "Ctrl+3", "terminal": "Ctrl+4",
             "settings_general": "Ctrl+,"}


def build_commands(app: AppController, navigate: Callable[[str], None], open_tool: Callable[[str], None],
                   run_op: Callable[[str, str], None], open_url: Callable[[str], None],
                   actions: dict[str, tuple[str, Callable[[], None], str]]) -> list[Command]:
    cmds: list[Command] = []
    for cat in NAVIGATION:
        for it in cat.items:
            group = "Settings" if cat.title == "SETTINGS" else "Pages"
            cmds.append(Command(group, it.title, f"{cat.title.title()} · {it.summary}",
                                lambda pid=it.id: navigate(pid), SHORTCUTS.get(it.id, ""), cat.title))
    for s in app.tools.statuses():
        p = s.profile
        cmds.append(Command("Tools", p.name, f"{p.category} · {'installed' if s.installed else 'not installed'}"
                            + (f" {s.version}" if s.version else ""), lambda tid=p.id: open_tool(tid), "", p.description))
        cmds.append(Command("Documentation", f"{p.name} documentation", p.docs_url,
                            lambda u=p.docs_url: open_url(u), "", "docs help manual"))
        if s.installed and not p.restricted:
            for op in p.operations:
                if op.method == LaunchMethod.DESKTOP and not op.dynamic:
                    cmds.append(Command("Actions", f"Launch {p.name}", op.description,
                                        lambda tid=p.id, oid=op.id: run_op(tid, oid), "", "start open"))
    for key, (title, fn, sub) in actions.items():
        cmds.append(Command("Actions", title, sub, fn, "", key))
    for r in app.osint.resources():
        cmds.append(Command("OSINT", r["name"], " · ".join(r["categories"]) + " · " + (r["description"] or ""),
                            lambda: navigate("osint"), "", " ".join(r["categories"]) + " osint research"))
    for r in app.db.query("SELECT id, name, kind FROM projects ORDER BY updated_at DESC LIMIT 50"):
        cmds.append(Command("Projects", r["name"], f"{r['kind']} project", lambda: navigate("project_history")))
    return cmds


class CommandPalette(QDialog):
    def __init__(self, parent: QWidget, provider: Callable[[], list[Command]]) -> None:
        super().__init__(parent, Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setModal(True)
        self._provider = provider
        self._commands: list[Command] = []
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        frame = QFrame()
        frame.setObjectName("palette")
        outer.addWidget(frame)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 6)
        lay.setSpacing(0)
        self.input = QLineEdit()
        self.input.setObjectName("paletteInput")
        self.input.setPlaceholderText("Type a page, tool, setting or action…")
        self.input.textChanged.connect(self._refilter)
        self.input.installEventFilter(self)
        lay.addWidget(self.input)
        self.list = QListWidget()
        self.list.setObjectName("paletteList")
        self.list.setMinimumHeight(340)
        self.list.itemActivated.connect(self._activate)
        self.list.itemClicked.connect(self._activate)
        lay.addWidget(self.list)
        hint = QLabel("↑↓ navigate   ·   Enter run   ·   Esc close")
        hint.setObjectName("faint")
        hint.setContentsMargins(16, 6, 16, 0)
        lay.addWidget(hint)
        self.resize(640, 480)

    def open(self) -> None:  # noqa: A003
        self._commands = self._provider()
        self.input.clear()
        self._refilter("")
        p = self.parentWidget()
        if p:
            g = p.geometry()
            self.move(p.mapToGlobal(g.topLeft()).x() + (g.width() - self.width()) // 2,
                      p.mapToGlobal(g.topLeft()).y() + 90)
        self.show()
        fade_in(self, 140)
        self.input.setFocus()

    # ---- filtering ----
    def _matches(self, query: str) -> list[Command]:
        if not query.strip():
            fav = [c for c in self._commands if c.group == "Pages"][:8]
            return fav + [c for c in self._commands if c.group == "Actions"][:6]
        scored = []
        for c in self._commands:
            s = max((x for x in (fuzzy_score(query, c.title), fuzzy_score(query, c.keywords),
                                 fuzzy_score(query, c.subtitle)) if x is not None), default=None)
            if s is not None:
                scored.append((s + (50 if fuzzy_score(query, c.title) is not None else 0), c))
        scored.sort(key=lambda x: -x[0])
        return [c for _, c in scored[:40]]

    def _refilter(self, query: str) -> None:
        self.list.clear()
        by_group: dict[str, list[Command]] = {}
        for c in self._matches(query):
            by_group.setdefault(c.group, []).append(c)
        first_selectable = None
        for g in GROUP_ORDER:
            if g not in by_group:
                continue
            head = QListWidgetItem(g.upper())
            head.setFlags(Qt.ItemFlag.NoItemFlags)
            f = QFont(head.font())
            f.setPixelSize(10)
            f.setBold(True)
            head.setFont(f)
            head.setForeground(QColor(T.text_muted))
            self.list.addItem(head)
            for c in by_group[g]:
                text = c.title + (f"      {c.shortcut}" if c.shortcut else "")
                it = QListWidgetItem(text)
                it.setToolTip(c.subtitle)
                it.setData(Qt.ItemDataRole.UserRole, c)
                self.list.addItem(it)
                if first_selectable is None:
                    first_selectable = it
        if first_selectable:
            self.list.setCurrentItem(first_selectable)
        elif query.strip():
            none = QListWidgetItem("No matching commands")
            none.setFlags(Qt.ItemFlag.NoItemFlags)
            self.list.addItem(none)

    def _activate(self, item: QListWidgetItem) -> None:
        cmd = item.data(Qt.ItemDataRole.UserRole)
        if cmd is None:
            return
        self.accept()
        cmd.run()

    def _step(self, delta: int) -> None:
        row = self.list.currentRow()
        n = self.list.count()
        i = row + delta
        while 0 <= i < n:
            if self.list.item(i).data(Qt.ItemDataRole.UserRole) is not None:
                self.list.setCurrentRow(i)
                return
            i += delta

    def eventFilter(self, obj, ev) -> bool:  # noqa: N802
        if obj is self.input and ev.type() == QEvent.Type.KeyPress:
            k = ev.key()
            if k == Qt.Key.Key_Down:
                self._step(1)
                return True
            if k == Qt.Key.Key_Up:
                self._step(-1)
                return True
            if k in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                it = self.list.currentItem()
                if it:
                    self._activate(it)
                return True
        return super().eventFilter(obj, ev)
