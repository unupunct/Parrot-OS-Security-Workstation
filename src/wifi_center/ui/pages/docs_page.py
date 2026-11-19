"""Documentation reader: browse and read guides, offline manual pages and package docs inside the app; website links open in
your browser only when you press the button."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QFont, QPalette, QTextCursor, QTextDocument
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit, QSplitter,
                               QStackedWidget, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services import docs_service as ds
from ...workers.task import run_in_background
from ..design.components import LoadingIndicator, MatrixButton
from ..design.tokens import T
from .netsec_common import confirm_dialog

esc = html.escape
GROUP_ORDER = (ds.GUIDES, ds.MANPAGES, ds.PACKAGE_DOCS, ds.WEBSITES)
GROUP_HELP = {ds.GUIDES: "How WIFI Center works", ds.MANPAGES: "Installed on this computer, readable offline",
              ds.PACKAGE_DOCS: "README and release notes from /usr/share/doc", ds.WEBSITES: "Opens your browser when you press the button"}


class DocumentationPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.svc: ds.DocsService = app.docs
        self.entries: list[ds.DocEntry] = []
        self._current: ds.DocEntry | None = None
        self._history: list[str] = []
        self._pos = -1
        self._fmt = "text"
        self._font_pt = 11

        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Documentation")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("scan", 20)
        head.addWidget(self.loader)
        head.addStretch(1)
        self.count = QLabel("")
        self.count.setObjectName("muted")
        head.addWidget(self.count)
        lay.addLayout(head)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search guides, tools, commands…")
        self.search.textChanged.connect(self._fill)
        ll.addWidget(self.search)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(14)
        self.tree.setUniformRowHeights(True)
        self.tree.currentItemChanged.connect(self._select)
        ll.addWidget(self.tree, 1)
        left.setMinimumWidth(240)
        left.setMaximumWidth(380)
        split.addWidget(left)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        self.b_back = MatrixButton("◂ Back")
        self.b_fwd = MatrixButton("Forward ▸")
        self.b_back.clicked.connect(lambda: self._go(-1))
        self.b_fwd.clicked.connect(lambda: self._go(1))
        self.title = QLabel("Select a document")
        self.title.setStyleSheet("font-size: 16px; font-weight: 700;")
        self.title.setWordWrap(True)
        self.find = QLineEdit()
        self.find.setPlaceholderText("Find in page…")
        self.find.setMaximumWidth(220)
        self.find.returnPressed.connect(lambda: self._find(True))
        self.b_prev = MatrixButton("▲")
        self.b_next = MatrixButton("▼")
        self.b_prev.clicked.connect(lambda: self._find(False))
        self.b_next.clicked.connect(lambda: self._find(True))
        self.b_smaller = MatrixButton("A−")
        self.b_bigger = MatrixButton("A+")
        self.b_smaller.clicked.connect(lambda: self._zoom(-1))
        self.b_bigger.clicked.connect(lambda: self._zoom(1))
        for w in (self.b_back, self.b_fwd):
            bar.addWidget(w)
        bar.addWidget(self.title, 1)
        for w in (self.find, self.b_prev, self.b_next, self.b_smaller, self.b_bigger):
            bar.addWidget(w)
        rl.addLayout(bar)

        body = QSplitter(Qt.Orientation.Horizontal)
        body.setChildrenCollapsible(False)
        self.stack = QStackedWidget()
        self.welcome = QLabel("Choose a guide, manual page or tool on the left.\n\nGuides and manual pages are read here, "
                              "offline. Tool websites open in your browser only when you press the button.")
        self.welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.welcome.setWordWrap(True)
        self.welcome.setObjectName("muted")
        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)
        self.browser.anchorClicked.connect(self._link)
        pal = self.browser.palette()
        pal.setColor(QPalette.ColorRole.Link, QColor(T.cyan))
        self.browser.setPalette(pal)
        self.browser.setStyleSheet(f"QTextBrowser {{ background: #07100A; border: 1px solid {T.border}; border-radius: 8px; padding: 14px; }}")
        self.plain = QPlainTextEdit()
        self.plain.setReadOnly(True)
        self.plain.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.plain.setStyleSheet(f"QPlainTextEdit {{ background: #050805; border: 1px solid {T.border}; border-radius: 8px; padding: 12px; }}")
        self.link_card = self._link_card()
        for w in (self.welcome, self.browser, self.plain, self.link_card):
            self.stack.addWidget(w)
        body.addWidget(self.stack)
        side = QWidget()
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 0)
        cap = QLabel("ON THIS PAGE")
        cap.setObjectName("panelTitle")
        sl.addWidget(cap)
        self.outline = QListWidget()
        self.outline.itemClicked.connect(self._jump)
        sl.addWidget(self.outline, 1)
        side.setMinimumWidth(170)
        side.setMaximumWidth(280)
        body.addWidget(side)
        body.setStretchFactor(0, 1)
        rl.addWidget(body, 1)
        split.addWidget(right)
        split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setObjectName("muted")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self._sync_buttons()
        self._apply_font()
        self._load()

    # ------------------------------------------------------------------ catalogue
    def _link_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("panel")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(24, 20, 24, 20)
        self.l_title = QLabel("")
        self.l_title.setStyleSheet("font-size: 18px; font-weight: 700;")
        self.l_title.setWordWrap(True)
        self.l_desc = QLabel("")
        self.l_desc.setWordWrap(True)
        self.l_desc.setObjectName("muted")
        self.l_url = QLabel("")
        self.l_url.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.l_url.setStyleSheet(f"color: {T.cyan};")
        self.l_url.setWordWrap(True)
        self.l_open = MatrixButton("Open in browser", "primary", "launch")
        self.l_open.clicked.connect(self._open_link_entry)
        note = QLabel("WIFI Center does not fetch this page. Pressing the button hands the address to your default browser.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        for w in (self.l_title, self.l_desc, self.l_url):
            cl.addWidget(w)
        cl.addSpacing(8)
        cl.addWidget(self.l_open, 0, Qt.AlignmentFlag.AlignLeft)
        cl.addWidget(note)
        cl.addStretch(1)
        return card

    def _load(self) -> None:
        self.loader.start()
        self.msg.setText("Looking for guides and installed manual pages…")
        run_in_background(self.svc.catalogue, self._loaded, lambda e: (self.loader.stop(), self.msg.setText(f"Could not list the documentation: {e}")))

    def _loaded(self, entries: list[ds.DocEntry]) -> None:
        self.loader.stop()
        self.entries = entries
        self.msg.setText("")
        self._fill()
        first = self.tree.topLevelItem(0)
        if first is not None and first.childCount():
            self.tree.setCurrentItem(first.child(0))

    def _fill(self) -> None:
        q = self.search.text().strip().lower()
        keep = self._current.id if self._current else None
        self.tree.blockSignals(True)
        self.tree.clear()
        shown = 0
        for group in GROUP_ORDER:
            rows = [e for e in self.entries if e.group == group and (not q or q in (e.title + " " + e.summary + " " + e.source).lower())]
            if not rows:
                continue
            top = QTreeWidgetItem([f"{group}  ({len(rows)})"])
            top.setFlags(top.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            top.setToolTip(0, GROUP_HELP[group])
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            top.setForeground(0, QColor(T.green))
            self.tree.addTopLevelItem(top)
            for e in rows:
                it = QTreeWidgetItem([e.title])
                it.setData(0, Qt.ItemDataRole.UserRole, e.id)
                it.setToolTip(0, e.summary or e.source)
                top.addChild(it)
                shown += 1
                if e.id == keep:
                    self.tree.setCurrentItem(it)
            top.setExpanded(bool(q) or group in (ds.GUIDES, ds.MANPAGES))
        self.tree.blockSignals(False)
        self.count.setText(f"{shown} of {len(self.entries)} documents")

    # ------------------------------------------------------------------ opening
    def _entry(self, entry_id: str) -> ds.DocEntry | None:
        return next((e for e in self.entries if e.id == entry_id), None)

    def _select(self, item: QTreeWidgetItem | None, _prev=None) -> None:
        if item is None or item.parent() is None:
            return
        e = self._entry(item.data(0, Qt.ItemDataRole.UserRole))
        if e:
            self.show_entry(e)

    def show_entry(self, e: ds.DocEntry, record: bool = True) -> None:
        self._current = e
        self.title.setText(e.title)
        self.find.clear()
        if record:
            self._history = self._history[: self._pos + 1] + [e.id]
            self._pos = len(self._history) - 1
        self._sync_buttons()
        if e.kind == "link":
            self.l_title.setText(e.title)
            self.l_desc.setText(e.summary)
            self.l_url.setText(e.source)
            self.outline.clear()
            self.stack.setCurrentWidget(self.link_card)
            return
        try:
            fmt, text = self.svc.render(e)
        except (OSError, ValueError) as err:
            self.outline.clear()
            self.stack.setCurrentWidget(self.welcome)
            self.welcome.setText(f"Could not open this document:\n{err}")
            return
        self._fmt = fmt
        if fmt == "markdown":
            self.browser.setMarkdown(text)
            self.stack.setCurrentWidget(self.browser)
            outline = ds.markdown_outline(text)
        else:
            f = QFont("monospace")
            f.setStyleHint(QFont.StyleHint.Monospace)
            f.setPointSize(self._font_pt - 1)
            self.plain.setFont(f)
            self.plain.setPlainText(text)
            self.stack.setCurrentWidget(self.plain)
            outline = ds.man_outline(text) if e.kind == "man" else []
        self._apply_font()
        self.outline.clear()
        for level, heading in outline:
            it = QListWidgetItem(("    " * (level - 1)) + heading)
            it.setData(Qt.ItemDataRole.UserRole, heading)
            self.outline.addItem(it)

    def _open_link_entry(self) -> None:
        e = self._current
        if e and e.kind == "link":
            QDesktopServices.openUrl(QUrl(e.source))
            self.msg.setText(f"Opened {e.source} in your browser.")

    def _link(self, url: QUrl) -> None:
        href = url.toString()
        if self._current and (target := ds.resolve_link(self._current.source, href)):
            e = next((x for x in self.entries if x.source == target), None)
            if e:
                self.show_entry(e)
                return
        if url.scheme() in ("http", "https"):
            if confirm_dialog(self, "Open link", f"<p>Open this address in your browser?</p><p><code>{esc(href)}</code></p>", "Open"):
                QDesktopServices.openUrl(url)
            return
        if href.startswith("#"):
            self.browser.scrollToAnchor(href[1:])

    # ------------------------------------------------------------------ reader controls
    def _go(self, step: int) -> None:
        n = self._pos + step
        if 0 <= n < len(self._history):
            self._pos = n
            e = self._entry(self._history[n])
            if e:
                self.show_entry(e, record=False)

    def _sync_buttons(self) -> None:
        self.b_back.setEnabled(self._pos > 0)
        self.b_fwd.setEnabled(0 <= self._pos < len(self._history) - 1)

    def _view(self):
        return self.browser if self.stack.currentWidget() is self.browser else self.plain

    def _jump(self, item: QListWidgetItem) -> None:
        heading = item.data(Qt.ItemDataRole.UserRole)
        view = self._view()
        view.moveCursor(QTextCursor.MoveOperation.Start)
        if view.find(heading, QTextDocument.FindFlag.FindCaseSensitively):
            view.ensureCursorVisible()
            cur = view.textCursor()
            cur.clearSelection()
            view.setTextCursor(cur)

    def _find(self, forward: bool) -> None:
        text = self.find.text()
        if not text or self.stack.currentWidget() in (self.welcome, self.link_card):
            return
        view = self._view()
        flags = QTextDocument.FindFlag(0) if forward else QTextDocument.FindFlag.FindBackward
        if not view.find(text, flags):                              # wrap around
            view.moveCursor(QTextCursor.MoveOperation.Start if forward else QTextCursor.MoveOperation.End)
            if not view.find(text, flags):
                self.msg.setText(f"“{text}” was not found on this page.")
                return
        self.msg.setText("")

    def _zoom(self, step: int) -> None:
        self._font_pt = max(8, min(22, self._font_pt + step))
        self._apply_font()

    def _apply_font(self) -> None:
        f = self.browser.font()
        f.setPointSize(self._font_pt)
        self.browser.setFont(f)
        self.browser.document().setDefaultFont(f)
        p = self.plain.font()
        p.setPointSize(self._font_pt - 1)
        self.plain.setFont(p)
