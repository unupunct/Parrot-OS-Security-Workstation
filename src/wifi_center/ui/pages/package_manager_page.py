"""Package Manager: browse, inspect and manage APT packages.

Every change goes through the confirmed workflow (apt-get -s simulation, the full list of installs / upgrades / removals, an explicit
approval, the privileged helper) and is recorded in the permanent transaction history. Nothing here runs autoremove, purge or
cache cleaning on its own, `remove` keeps configuration files, and history is only cleared when the user asks."""
from __future__ import annotations

import html

import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QMenu, QPlainTextEdit, QSplitter, QStackedWidget,
                               QTableWidgetItem, QTabWidget, QTextBrowser, QToolButton, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...privileged.protocol import PrivilegedOp
from ...security.input_validation import ValidationError
from ...services.maintenance_service import PACKAGE_OPS
from ...services.package_service import PackageDetails, PackageRow
from ...services.privileged_service import run_privileged
from ...workers.task import run_in_background
from ..charts import NumItem, fmt_ts, make_plot, make_table
from ..design.components import LoadingIndicator, MatrixButton, Panel
from ..design.icons import icon_pixmap
from ..design.tokens import T
from .netsec_common import confirm_dialog
from .parrot_common import apply_transaction, proposal_html

esc = html.escape
VIEWS = (("installed", "Installed"), ("available", "Available"), ("upgradable", "Upgradable"), ("removed", "Config left"))
STATUS_STYLE = {"installed": ("Installed", T.green), "upgradable": ("Upgradable", T.warning), "config-files": ("Config left", T.text_muted),
                "not-installed": ("Not installed", T.text_secondary)}
COLS = ["", "Package", "Version", "Status", "Size", "Summary"]


def _say(label: QLabel, text: str, error: bool = False) -> None:
    label.setText(f"<span style='color:{T.danger if error else T.text_secondary}'>{esc(text)}</span>")


def badge(text: str, color: str) -> str:
    return f"<span style='color:{color}'>● {esc(text)}</span>"


class PackageManagerPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._rows: list[PackageRow] = []
        self._details: PackageDetails | None = None
        self._view = "installed"
        self._upgradable: set[str] = set()
        self._tool: str | None = None
        lay = QVBoxLayout(self)

        # ---- header: title + search
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon_pixmap("package", T.green, 38, 2.0))
        head.addWidget(ic)
        tl = QVBoxLayout()
        tl.setSpacing(0)
        t = QLabel("Package Manager")
        t.setObjectName("pageTitle")
        sub = QLabel("Install, update and manage packages · every change is simulated, listed and confirmed first")
        sub.setObjectName("muted")
        tl.addWidget(t)
        tl.addWidget(sub)
        head.addLayout(tl)
        self.loader = LoadingIndicator("scan", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        self.query = QLineEdit()
        self.query.setPlaceholderText("Search packages (letters, digits, + . _ : -)")
        self.query.setMinimumWidth(320)
        self.query.returnPressed.connect(self.search)
        go = MatrixButton("Search", "primary", "search")
        go.clicked.connect(self.search)
        head.addWidget(self.query)
        head.addWidget(go)
        lay.addLayout(head)

        # ---- view chips + tools
        bar = QHBoxLayout()
        self.chips: dict[str, MatrixButton] = {}
        for key, label in VIEWS:
            b = MatrixButton(label)
            b.setCheckable(True)
            b.clicked.connect(lambda _=False, k=key: self.set_view(k))
            self.chips[key] = b
            bar.addWidget(b)
        bar.addStretch(1)
        self.b_refresh = MatrixButton("Refresh", icon_name="reset")
        self.b_refresh.clicked.connect(self.refresh)
        self.b_upgrade_all = MatrixButton("Upgrade all…", "primary", "update")
        self.b_upgrade_all.clicked.connect(self._upgrade_all)
        more = QToolButton()
        more.setText("More ▾")
        more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(more)
        for key, label in (("broken", "Broken packages"), ("orphans", "Orphaned packages"), ("cache", "Cache manager"),
                           ("repos", "Repositories")):
            menu.addAction(label, lambda k=key: self.open_tool(k))
        more.setMenu(menu)
        self.more_btn = more
        for w in (self.b_refresh, self.b_upgrade_all, more):
            bar.addWidget(w)
        lay.addLayout(bar)
        self.banner = QLabel("")
        self.banner.setWordWrap(True)
        self.banner.setTextFormat(Qt.TextFormat.RichText)
        self.banner.hide()
        lay.addWidget(self.banner)

        # ---- main: list (or tool page) | details
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        self.stack = QStackedWidget()
        self.table = make_table(COLS, stretch_col=5)
        self.table.setSortingEnabled(True)
        self.table.setColumnWidth(0, 30)
        self.table.itemSelectionChanged.connect(self._select)
        self.stack.addWidget(self.table)
        self.stack.addWidget(self._tool_page())
        split.addWidget(self.stack)
        split.addWidget(self._details_panel())
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([760, 520])

        # ---- bottom: history | activity
        bottom = QSplitter(Qt.Orientation.Horizontal)
        bottom.setChildrenCollapsible(False)
        hist = Panel("Transaction history")
        self.history = make_table(["Date and time", "Operation", "Packages", "Result", "Details"], stretch_col=4)
        self.history.setMinimumHeight(120)
        hist.add(self.history, 1)
        hrow = QHBoxLayout()
        self.b_clear = MatrixButton("Clear history…", "danger")
        self.b_clear.clicked.connect(self._clear_history)
        hrow.addStretch(1)
        hrow.addWidget(self.b_clear)
        hw = QWidget()
        hw.setLayout(hrow)
        hist.add(hw)
        act = Panel("Package activity")
        self.activity = make_plot("", "", "operations")
        self.activity.getPlotItem().setAxisItems({"bottom": pg.DateAxisItem(orientation="bottom")})
        self.act_empty = QLabel("No package operations recorded yet.\nEvery installation, update and removal you confirm is counted here.")
        self.act_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.act_empty.setObjectName("muted")
        self.act_stack = QStackedWidget()
        self.act_stack.addWidget(self.activity)
        self.act_stack.addWidget(self.act_empty)
        act.add(self.act_stack, 1)
        self.act_legend = QLabel("")
        self.act_legend.setTextFormat(Qt.TextFormat.RichText)
        act.add(self.act_legend)
        bottom.addWidget(hist)
        bottom.addWidget(act)
        bottom.setSizes([760, 520])
        vsplit = QSplitter(Qt.Orientation.Vertical)
        vsplit.addWidget(split)
        vsplit.addWidget(bottom)
        vsplit.setStretchFactor(0, 3)
        vsplit.setSizes([520, 230])
        lay.addWidget(vsplit, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)

        self._sync_actions()
        self.set_view("installed", load=False)
        self.reload_history()
        self.refresh()

    # ================================================================== panels
    def _details_panel(self) -> QWidget:
        panel = Panel("")
        head = QHBoxLayout()
        self.d_icon = QLabel()
        self.d_icon.setPixmap(icon_pixmap("package", T.green, 44, 2.0))
        head.addWidget(self.d_icon)
        col = QVBoxLayout()
        col.setSpacing(0)
        self.d_name = QLabel("Select a package")
        self.d_name.setStyleSheet("font-size: 20px; font-weight: 800;")
        self.d_ver = QLabel("")
        self.d_ver.setTextFormat(Qt.TextFormat.RichText)
        self.d_sum = QLabel("")
        self.d_sum.setObjectName("muted")
        self.d_sum.setWordWrap(True)
        for w in (self.d_name, self.d_ver, self.d_sum):
            col.addWidget(w)
        head.addLayout(col, 1)
        hw = QWidget()
        hw.setLayout(head)
        panel.add(hw)

        self.tabs = QTabWidget()
        self.detail = QTextBrowser()                                 # Details
        self.detail.setFrameShape(QFrame.Shape.NoFrame)
        self.deps = QTextBrowser()                                   # Dependencies
        self.deps.setFrameShape(QFrame.Shape.NoFrame)
        self.files = QPlainTextEdit()                                # Files
        self.files.setReadOnly(True)
        self.change = QPlainTextEdit()                               # Changelog
        self.change.setReadOnly(True)
        chw = QWidget()
        chl = QVBoxLayout(chw)
        chl.setContentsMargins(0, 0, 0, 0)
        chl.addWidget(self.change, 1)
        self.b_remote = MatrixButton("Fetch changelog from the repository (network)")
        self.b_remote.clicked.connect(self._fetch_changelog)
        chl.addWidget(self.b_remote)
        self.verify = QTextBrowser()                                 # Verify
        self.verify.setFrameShape(QFrame.Shape.NoFrame)
        vw = QWidget()
        vl = QVBoxLayout(vw)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.addWidget(self.verify, 1)
        self.b_verify = MatrixButton("Verify installed files")
        self.b_verify.clicked.connect(self._verify)
        vl.addWidget(self.b_verify)
        for w, name in ((self.detail, "Details"), (self.deps, "Dependencies"), (self.files, "Files"), (chw, "Changelog"), (vw, "Verify")):
            self.tabs.addTab(w, name)
        self.tabs.currentChanged.connect(self._tab_changed)
        panel.add(self.tabs, 1)

        grid1, grid2 = QHBoxLayout(), QHBoxLayout()
        self.b_install = MatrixButton("Install…", "primary", "update")
        self.b_install.clicked.connect(lambda: self._propose("install"))
        self.b_reinstall = MatrixButton("Reinstall…", icon_name="reset")
        self.b_reinstall.clicked.connect(lambda: self._propose("reinstall"))
        self.b_remove = MatrixButton("Remove…", "danger", "cleanup")
        self.b_remove.clicked.connect(lambda: self._propose("remove"))
        self.b_files = MatrixButton("View files", icon_name="folder")
        self.b_files.clicked.connect(lambda: self.tabs.setCurrentIndex(2))
        self.b_log = MatrixButton("View changelog", icon_name="docs")
        self.b_log.clicked.connect(lambda: self.tabs.setCurrentIndex(3))
        self.b_props = MatrixButton("Properties", icon_name="info")
        self.b_props.clicked.connect(self._properties)
        for b in (self.b_install, self.b_reinstall, self.b_remove):
            grid1.addWidget(b)
        for b in (self.b_files, self.b_log, self.b_props):
            grid2.addWidget(b)
        for g in (grid1, grid2):
            w = QWidget()
            w.setLayout(g)
            panel.add(w)
        grid3 = QHBoxLayout()
        self.b_download = MatrixButton("Download only…")
        self.b_download.setToolTip("Fetch the package files into the APT cache without installing")
        self.b_download.clicked.connect(lambda: self._propose("download"))
        self.b_preview = MatrixButton("Preview changes")
        self.b_preview.setToolTip("Show what installing this package would change, without applying anything")
        self.b_preview.clicked.connect(lambda: self._propose("install", apply=False))
        grid3.addWidget(self.b_download)
        grid3.addWidget(self.b_preview)
        w3 = QWidget()
        w3.setLayout(grid3)
        panel.add(w3)
        return panel

    def _tool_page(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self.tool_title = QLabel("")
        self.tool_title.setStyleSheet("font-size: 16px; font-weight: 700;")
        back = MatrixButton("◂ Packages")
        back.clicked.connect(lambda: self.set_view(self._view))
        head.addWidget(back)
        head.addWidget(self.tool_title, 1)
        lay.addLayout(head)
        self.tool_view = QTextBrowser()
        lay.addWidget(self.tool_view, 1)
        self.tool_row = QHBoxLayout()
        self.tool_btn = MatrixButton("", "primary")
        self.tool_btn2 = MatrixButton("")
        self._tool_actions: dict[int, object] = {}          # what the two tool buttons do for the open tool
        self.tool_btn.clicked.connect(lambda: self._tool_actions.get(1, lambda: None)())
        self.tool_btn2.clicked.connect(lambda: self._tool_actions.get(2, lambda: None)())
        self.tool_row.addWidget(self.tool_btn)
        self.tool_row.addWidget(self.tool_btn2)
        self.tool_row.addStretch(1)
        lay.addLayout(self.tool_row)
        return w

    # ================================================================== views and loading
    def set_view(self, view: str, load: bool = True) -> None:
        self._view = view
        for k, b in self.chips.items():
            b.setChecked(k == view)
        self.stack.setCurrentWidget(self.table)
        self._tool = None
        if view == "available" and not self.query.text().strip():
            self.table.setRowCount(0)
            _say(self.msg, "Type a package name or keyword and press Search to look through the repositories.")
            return
        if load:
            self.search()

    def refresh(self) -> None:
        self.search()
        self.reload_history()
        self._load_counts()

    def search(self) -> None:
        q = self.query.text()
        view = self._view
        if view == "available":
            try:
                self.app.packages.validate_query(q)
            except ValidationError as e:
                _say(self.msg, str(e), True)
                return
        if self._tool:
            self.stack.setCurrentWidget(self.table)
            self._tool = None
        self.loader.start()
        fn = {"installed": lambda: self.app.packages.installed(q), "available": lambda: self.app.packages.search_available(q),
              "removed": lambda: [r for r in self.app.pkgtools.removed() if q.strip().lower() in r.name.lower()],
              "upgradable": self._upgradable_rows}[view]
        run_in_background(fn, self._loaded, lambda e: (self.loader.stop(), _say(self.msg, f"Failed: {e}", True)))

    def _upgradable_rows(self) -> list[PackageRow]:
        tx = self.app.pkgtools.upgradable()
        if not tx.ok:
            raise RuntimeError(tx.error)
        q = self.query.text().strip().lower()
        return [PackageRow(c.name, f"{c.old} → {c.new}" if c.old else c.new, "installed", 0, c.origin, True) for c in tx.upgrades if q in c.name.lower()]

    def _loaded(self, rows: list[PackageRow]) -> None:
        self.loader.stop()
        self._rows = rows
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, p in enumerate(rows):
            key = "upgradable" if (p.upgradable or p.name in self._upgradable) and p.status == "installed" else p.status or "not-installed"
            text, col = STATUS_STYLE.get(key, STATUS_STYLE["not-installed"])
            icon_item = QTableWidgetItem()
            icon_item.setIcon(QIcon(icon_pixmap("package", col, 18, 2.0)))
            self.table.setItem(r, 0, icon_item)
            name = QTableWidgetItem(p.name)
            name.setData(Qt.ItemDataRole.UserRole, key)
            self.table.setItem(r, 1, name)
            self.table.setItem(r, 2, QTableWidgetItem(p.version))
            st = QTableWidgetItem("● " + text)
            st.setForeground(QColor(col))
            self.table.setItem(r, 3, st)
            self.table.setItem(r, 4, NumItem(f"{p.size_kb:,} KiB" if p.size_kb else "", p.size_kb))
            self.table.setItem(r, 5, QTableWidgetItem(p.summary))
        self.table.setSortingEnabled(True)
        shown = {"installed": "installed", "available": "matching", "removed": "with configuration left", "upgradable": "upgradable"}[self._view]
        _say(self.msg, f"{len(rows)} {shown} package(s)." if rows else "No matching packages." + ("" if self.app.apt.available() else " APT is not available on this system."))
        self._select()

    def _load_counts(self) -> None:
        def work():
            tx = self.app.pkgtools.upgradable()
            audit, _fix = self.app.pkgtools.broken()
            return tx, audit

        def done(res) -> None:
            tx, audit = res
            self._upgradable = {c.name for c in tx.upgrades} if tx.ok else set()
            n = len(self._upgradable)
            self.chips["upgradable"].setText(f"Upgradable ({n})" if n else "Upgradable")
            self.b_upgrade_all.setEnabled(n > 0)
            if audit:
                self.banner.setText(f"<span style='color:{T.warning}'><b>⚠ dpkg reports {len(audit)} package(s) in an inconsistent state</b> "
                                    f"({esc(', '.join(audit[:5]))}{'…' if len(audit) > 5 else ''}): an installation was probably interrupted. "
                                    "Open <i>More → Broken packages</i> to review and repair it.</span>")
                self.banner.show()
            else:
                self.banner.hide()
        run_in_background(work, done, lambda e: None)

    # ================================================================== selection and details
    def _current_name(self) -> str | None:
        r = self.table.currentRow()
        it = self.table.item(r, 1) if r >= 0 and self.stack.currentWidget() is self.table else None
        return it.text() if it else None

    def _current_state(self) -> str:
        r = self.table.currentRow()
        it = self.table.item(r, 1) if r >= 0 else None
        return it.data(Qt.ItemDataRole.UserRole) if it else ""

    def _sync_actions(self) -> None:
        name, state = self._current_name(), self._current_state()
        installed = state in ("installed", "upgradable")
        self.b_install.setText("Update…" if state == "upgradable" else "Install…")
        self.b_install.setEnabled(bool(name) and state != "installed")
        self.b_reinstall.setEnabled(bool(name) and installed)
        self.b_remove.setEnabled(bool(name) and installed)
        self.b_download.setEnabled(bool(name) and state in ("upgradable", "not-installed", "config-files"))
        self.b_preview.setEnabled(bool(name))
        for b in (self.b_files, self.b_log, self.b_props):
            b.setEnabled(bool(name))
        self.b_verify.setEnabled(bool(name) and installed)
        self.b_remote.setEnabled(bool(name))
        tips = {"installed": "already installed: use Reinstall or Remove", "": "select a package"}
        self.b_install.setToolTip(tips.get(state, "") if not self.b_install.isEnabled() else "")

    def _select(self) -> None:
        name = self._current_name()
        self._sync_actions()
        for w in (self.deps, self.verify):
            w.clear()
        self.files.clear()
        self.change.clear()
        if not name:
            self.d_name.setText("Select a package")
            self.d_ver.setText("")
            self.d_sum.setText("")
            self.detail.setHtml(f"<p style='color:{T.text_secondary}'>Select a package to see its details, dependencies, files and changelog.</p>")
            return
        state = self._current_state()
        text, col = STATUS_STYLE.get(state, STATUS_STYLE["not-installed"])
        self.d_name.setText(name)
        self.d_icon.setPixmap(icon_pixmap("package", col, 44, 2.0))
        self.d_ver.setText(badge(text, col))
        self.detail.setHtml("<p>Loading…</p>")
        run_in_background(lambda: self.app.packages.details(name), self._show_details,
                          lambda e: self.detail.setHtml(f"<p>{esc(str(e))}</p>"))
        self._tab_changed(self.tabs.currentIndex())

    def _show_details(self, d: PackageDetails) -> None:
        if d.name != self._current_name():
            return
        self._details = d
        f = d.fields
        state = self._current_state()
        text, col = STATUS_STYLE.get(state, STATUS_STYLE["not-installed"])
        self.d_ver.setText(f"{esc(d.installed or d.candidate or '')} &nbsp; " + badge(text, col))
        self.d_sum.setText((f.get("Description", "").splitlines() or [""])[0])
        size = f.get("Installed-Size", "")
        rows = [("Version", d.installed or d.candidate or "—"), ("Candidate", d.candidate or "—"), ("Architecture", f.get("Architecture", "")),
                ("Installed size", f"{int(size):,} KiB" if size.isdigit() else ""), ("Download size", f"{int(f['Size']) // 1024:,} KiB" if f.get("Size", "").isdigit() else ""),
                ("Section", f.get("Section", "")), ("Priority", f.get("Priority", "")), ("Maintainer", f.get("Maintainer", "")),
                ("Homepage", f.get("Homepage", ""))]
        body = "".join(f"<tr><td style='color:{T.text_secondary}'>{esc(k)}&nbsp;&nbsp;</td><td>{esc(v)}</td></tr>" for k, v in rows if v)
        origins = "".join(f"<li>{esc(o)}</li>" for o in d.origins) or "<li>none (not in any configured repository)</li>"
        long_desc = esc("\n".join(f.get("Description", "").splitlines()[1:])).replace("\n", "<br>")
        self.detail.setHtml(f"<table cellpadding='3'>{body}</table><h4>Description</h4><p>{long_desc or esc(self.d_sum.text())}</p>"
                            f"<h4>Repositories</h4><ul>{origins}</ul>")

    def _tab_changed(self, idx: int) -> None:
        name = self._current_name()
        if not name:
            return
        if idx == 1 and not self.deps.toPlainText():
            self.deps.setHtml("<p>Loading…</p>")
            run_in_background(lambda: (self.app.pkgtools.dependencies(name), self.app.pkgtools.reverse_dependencies(name), self.app.pkgtools.dependency_tree(name)),
                              lambda r: self._show_deps(name, *r), lambda e: self.deps.setHtml(f"<p>{esc(str(e))}</p>"))
        elif idx == 2 and not self.files.toPlainText():
            self.files.setPlainText("Loading…")
            run_in_background(lambda: self.app.pkgtools.files(name), lambda fl: self._show_files(name, fl),
                              lambda e: self.files.setPlainText(str(e)))
        elif idx == 3 and not self.change.toPlainText():
            run_in_background(lambda: self.app.pkgtools.changelog_local(name), lambda t: self._show_changelog(name, t),
                              lambda e: self.change.setPlainText(str(e)))

    def _show_deps(self, name: str, deps, rdeps, tree) -> None:
        if name != self._current_name():
            return
        groups: dict[str, list[str]] = {}
        for d in deps:
            groups.setdefault(d.kind, []).append(("(one of) " if d.alternative else "") + d.name + (" (virtual)" if d.virtual else ""))
        body = "".join(f"<h4>{esc(k)}</h4><ul>" + "".join(f"<li>{esc(x)}</li>" for x in v) + "</ul>" for k, v in groups.items()) or "<p>No dependencies listed.</p>"

        def render(n, depth=0) -> str:
            mark = {True: "✔", False: "✖", None: "·"}[n.installed]
            line = f"{'&nbsp;' * 4 * depth}{mark} {esc(n.name)}" + (" <span style='color:%s'>(shown above)</span>" % T.text_secondary if n.repeated else "") + "<br>"
            return line + "".join(render(c, depth + 1) for c in n.children)
        rev = ", ".join(esc(x) for x in rdeps[:40]) + (" …" if len(rdeps) > 40 else "") or "none installed"
        self.deps.setHtml(body + f"<h4>Needed by (installed)</h4><p>{rev}</p><h4>Dependency tree (Depends, 2 levels)</h4><p>{render(tree)}</p>")

    def _show_files(self, name: str, files: list[str]) -> None:
        if name == self._current_name():
            self.files.setPlainText(f"{len(files)} file(s)\n\n" + "\n".join(files) if files else
                                    "No file list: the package is not installed (files are only known for installed packages).")

    def _show_changelog(self, name: str, text: str | None) -> None:
        if name == self._current_name():
            self.change.setPlainText(text or "This package ships no changelog on this computer. Use the button below to fetch it from the repository.")

    def _fetch_changelog(self) -> None:
        name = self._current_name()
        if not name:
            return
        if not confirm_dialog(self, "Fetch changelog", f"<p>Download the changelog of <b>{esc(name)}</b> from your APT repository?</p>"
                              "<p>This contacts the repository server. Nothing is installed.</p>", "Fetch"):
            return
        self.change.setPlainText("Fetching…")
        run_in_background(lambda: self.app.pkgtools.changelog_remote(name), lambda t: self.change.setPlainText(t),
                          lambda e: self.change.setPlainText(f"Could not fetch the changelog: {e}"))

    def _verify(self) -> None:
        name = self._current_name()
        if not name:
            return
        self.verify.setHtml("<p>Comparing installed files with the package's recorded checksums…</p>")

        def done(issues) -> None:
            if name != self._current_name():
                return
            if not issues:
                self.verify.setHtml(f"<p style='color:{T.green}'>✔ No differences found for the files dpkg could read.</p>"
                                    f"<p style='color:{T.text_secondary}'>Files only root can read are skipped. Edited configuration files are normal.</p>")
                return
            rows = "".join(f"<tr><td style='color:{T.warning if i.config else T.danger}'>{'config' if i.config else 'file'}</td><td>{esc(i.path)}</td><td>{esc(i.meaning)}</td></tr>" for i in issues)
            self.verify.setHtml(f"<p>{len(issues)} difference(s):</p><table cellpadding='3'>{rows}</table>"
                                f"<p style='color:{T.text_secondary}'>Modified configuration files are usually intentional. A changed program file is worth a look; reinstall the package to restore it.</p>")
        run_in_background(lambda: self.app.pkgtools.verify(name), done, lambda e: self.verify.setHtml(f"<p>{esc(str(e))}</p>"))
        self.tabs.setCurrentIndex(4)

    def _properties(self) -> None:
        d = self._details
        if not d or d.name != self._current_name():
            return
        raw = "\n".join(f"{k}: {v}" for k, v in d.fields.items())
        self.tabs.setCurrentIndex(0)
        self.detail.setHtml(f"<pre>{esc(raw)}</pre>")

    # ================================================================== transactions (always simulated, listed, confirmed)
    def _propose(self, kind: str, apply: bool = True) -> None:
        name = self._current_name()
        if not name:
            return
        self.loader.start()

        def done(tx) -> None:
            self.loader.stop()
            if not apply:
                if not tx.ok:
                    _say(self.msg, f"Cannot preview: {tx.error}", True)
                    return
                confirm_dialog(self, "Preview: nothing will be changed",
                               "<p>This is what APT would do. Nothing has been changed.</p>" + (proposal_html(tx) or "<p>No changes.</p>"), "Close")
                _say(self.msg, "Preview shown; nothing was applied.")
                return

            def finished(msg: str) -> None:
                _say(self.msg, msg, msg.startswith(("Failed", "Cannot")))
                self.refresh()
            first = apply_transaction(self, self.app, tx, kind, [name], on_done=finished)
            _say(self.msg, first, first.startswith(("Failed", "Cannot")))
            self.reload_history()
        run_in_background(lambda: self.app.apt.plan(kind, [name]), done, lambda e: (self.loader.stop(), _say(self.msg, f"Failed: {e}", True)))

    def _upgrade_all(self) -> None:
        self.loader.start()

        def done(tx) -> None:
            self.loader.stop()
            first = apply_transaction(self, self.app, tx, "upgrade", None, on_done=lambda m: (_say(self.msg, m, m.startswith(("Failed", "Cannot"))), self.refresh()))
            _say(self.msg, first, first.startswith(("Failed", "Cannot")))
            self.reload_history()
        run_in_background(lambda: self.app.apt.plan("upgrade"), done, lambda e: (self.loader.stop(), _say(self.msg, f"Failed: {e}", True)))

    # ================================================================== maintenance tools
    def open_tool(self, tool: str) -> None:
        self._tool = tool
        self.stack.setCurrentIndex(1)
        self._tool_actions = {}
        for b in (self.tool_btn, self.tool_btn2):
            b.hide()
        self.tool_view.setHtml("<p>Loading…</p>")
        titles = {"broken": "Broken packages", "orphans": "Orphaned packages", "cache": "Cache manager", "repos": "Repositories"}
        self.tool_title.setText(titles[tool])
        loader = {"broken": self.app.pkgtools.broken, "orphans": self.app.pkgtools.orphans, "cache": self.app.pkgtools.cache_info,
                  "repos": self.app.apt.repositories}[tool]
        run_in_background(loader, lambda res: self._tool_loaded(tool, res), lambda e: self.tool_view.setHtml(f"<p style='color:{T.danger}'>{esc(str(e))}</p>"))

    def _tool_loaded(self, tool: str, res) -> None:
        if tool != self._tool:
            return
        if tool == "broken":
            audit, fix = res
            parts = []
            if audit:
                parts.append(f"<p style='color:{T.warning}'><b>{len(audit)} package(s) are half-installed or unconfigured</b> (dpkg --audit):</p><ul>"
                             + "".join(f"<li>{esc(a)}</li>" for a in audit) + "</ul><p>Finishing the interrupted installation configures them; it does not remove anything.</p>")
            else:
                parts.append(f"<p style='color:{T.green}'>✔ dpkg reports no half-installed or unconfigured packages.</p>")
            if fix is not None and fix.ok and not fix.is_empty:
                parts.append(f"<p style='color:{T.warning}'><b>APT proposes this repair for broken dependencies:</b></p>{proposal_html(fix)}")
            elif fix is not None and fix.ok:
                parts.append(f"<p style='color:{T.green}'>✔ APT finds no broken dependencies.</p>")
            self.tool_view.setHtml("".join(parts))
            self.tool_btn.setText("Finish interrupted installation…")
            self.tool_btn.setEnabled(bool(audit))
            self._tool_actions[1] = self._configure_pending
            self.tool_btn2.setText("Fix dependencies…")
            self.tool_btn2.setEnabled(bool(fix is not None and fix.ok and not fix.is_empty))
            self._tool_actions[2] = lambda: self._apply_global("fix-broken")
            self.tool_btn.show()
            self.tool_btn2.show()
        elif tool == "orphans":
            tx = res
            if not tx.ok:
                self.tool_view.setHtml(f"<p style='color:{T.danger}'>{esc(tx.error)}</p>")
                return
            names = [c.name for c in tx.removes]
            self.tool_view.setHtml((f"<p><b>{len(names)} package(s) were installed automatically and nothing needs them any more.</b></p>{proposal_html(tx)}"
                                    "<p style='color:%s'>Nothing is removed unless you confirm. Their configuration files are kept.</p>" % T.text_secondary)
                                   if names else f"<p style='color:{T.green}'>✔ No unused dependencies.</p>")
            self.tool_btn.setText("Remove unused packages…")
            self.tool_btn.setEnabled(bool(names))
            self._tool_actions[1] = lambda: self._apply_global("autoremove")
            self.tool_btn.show()
        elif tool == "cache":
            ci = res
            big = "".join(f"<li>{esc(n)} <span style='color:{T.text_secondary}'>{s / 1024 / 1024:.1f} MiB</span></li>" for n, s in ci.largest[:10])
            self.tool_view.setHtml(f"<p><b>{ci.files}</b> downloaded package file(s) in <code>{esc(ci.path)}</code>, "
                                   f"<b>{ci.total_bytes / 1024 / 1024:.1f} MiB</b>.</p><ul>{big}</ul>"
                                   f"<p style='color:{T.text_secondary}'>These can be downloaded again. Cleaning is never automatic: it runs only when you confirm below.</p>")
            self.tool_btn.setText("Clean package cache…")
            self.tool_btn.setEnabled(ci.files > 0)
            self._tool_actions[1] = self._clean_cache
            self.tool_btn.show()
        elif tool == "repos":
            rows = "".join(f"<tr><td>{esc(r.kind)}</td><td>{esc(r.uri)}</td><td>{esc(r.suite)}</td><td>{esc(' '.join(r.components))}</td>"
                           f"<td style='color:{T.green if r.enabled else T.text_muted}'>{'enabled' if r.enabled else 'disabled'}</td><td>{esc(str(r.source_file))}</td></tr>" for r in res)
            self.tool_view.setHtml(f"<table cellpadding='4'><tr><th>Type</th><th>URI</th><th>Suite</th><th>Components</th><th>State</th><th>Source file</th></tr>{rows}</table>"
                                   f"<p style='color:{T.text_secondary}'>WIFI Center only reads your APT sources; it never edits them. Change "
                                   "<code>/etc/apt/sources.list</code> or <code>/etc/apt/sources.list.d/</code> yourself.</p>")

    def _apply_global(self, kind: str) -> None:
        self.loader.start()

        def done(tx) -> None:
            self.loader.stop()
            first = apply_transaction(self, self.app, tx, kind, None, on_done=lambda m: (_say(self.msg, m, m.startswith(("Failed", "Cannot"))), self.refresh(),
                                                                                       self.open_tool(self._tool or "broken") if self._tool else None))
            _say(self.msg, first, first.startswith(("Failed", "Cannot")))
            self.reload_history()
        run_in_background(lambda: self.app.apt.plan(kind), done, lambda e: (self.loader.stop(), _say(self.msg, f"Failed: {e}", True)))

    def _run_helper(self, op: PrivilegedOp, title: str, op_type: str, text: str, ok_text: str) -> None:
        backend = self.app.privileged
        if not backend.available():
            self.app.maintenance.record(title, op_type, "not executed", errors="privileged helper unavailable; nothing was changed")
            _say(self.msg, backend.explain_unavailable(), True)
            self.reload_history()
            return
        if not confirm_dialog(self, title, text, ok_text):
            self.app.maintenance.record(title, op_type, "cancelled")
            _say(self.msg, "Cancelled. Nothing was changed.")
            self.reload_history()
            return
        if self.app.apt.lock_holders():
            _say(self.msg, "Another package manager is running; WIFI Center never overrides its lock. Try again when it has finished.", True)
            return
        self.app.audit.record("apt.apply", kind=op.kind)

        def done(res) -> None:
            self.app.maintenance.record(title, op_type, "success" if res.ok else ("failed" if res.executed else "cancelled"),
                                        errors="" if res.ok else res.message)
            _say(self.msg, ("Done: " if res.ok else "Failed: ") + res.message, not res.ok)
            self.refresh()
        run_privileged(backend, op, lambda line: None, done)

    def _configure_pending(self) -> None:
        self._run_helper(PrivilegedOp("dpkg_configure"), "Finish interrupted installation", "configure",
                         "<p>Run <code>dpkg --configure -a</code> to finish configuring packages that were unpacked but not set up?</p>"
                         "<p>This continues an interrupted installation. It removes nothing. You will be asked to authenticate.</p>", "Finish installation")

    def _clean_cache(self) -> None:
        self._run_helper(PrivilegedOp("apt_clean"), "Clean package cache", "autoremove",
                         "<p>Delete the downloaded package files in the APT cache (<code>apt-get clean</code>)?</p>"
                         "<p>Installed software and configuration are not touched; packages are simply downloaded again if needed.</p>", "Clean cache")

    # ================================================================== history and activity
    def reload_history(self) -> None:
        rows = self.app.maintenance.entries(limit=500)
        rows = [e for e in rows if e["op_type"] in PACKAGE_OPS]
        self.history.setRowCount(len(rows))
        for r, e in enumerate(rows):
            ok = e["result"] == "success"
            mark, col = ("✔ success", T.green) if ok else ("✖ failed", T.danger) if e["result"] == "failed" else (f"– {e['result']}", T.text_muted)
            pk = (e["packages_changed"] or "").replace("\n", ", ")
            vals = [fmt_ts(e["finished_at"]), e["name"], pk[:90] + ("…" if len(pk) > 90 else ""), mark, (e["errors"] or "")[:120]]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 3:
                    it.setForeground(QColor(col))
                self.history.setItem(r, c, it)
        self.b_clear.setEnabled(bool(rows))
        self._draw_activity()

    def _draw_activity(self) -> None:
        from datetime import datetime
        act = self.app.maintenance.activity()
        self.activity.clear()
        if not act:
            self.act_stack.setCurrentWidget(self.act_empty)
            self.act_legend.setText("")
            return
        self.act_stack.setCurrentWidget(self.activity)
        xs = [datetime.fromisoformat(a["bucket"]).timestamp() for a in act]
        base = [0.0] * len(xs)
        for key, color in (("installs", T.green), ("upgrades", "#3B9BFF"), ("removals", T.warning), ("other", T.text_secondary), ("failed", T.danger)):
            hs = [float(a[key]) for a in act]
            if any(hs):
                self.activity.addItem(pg.BarGraphItem(x=xs, y0=base, height=hs, width=60 * 60 * 16, brush=pg.mkColor(color), pen=None))
                base = [b + h for b, h in zip(base, hs)]
        self.activity.setYRange(0, max(base) * 1.2)
        self.act_legend.setText(f"<span style='color:{T.green}'>■</span> installs &nbsp; <span style='color:#3B9BFF'>■</span> updates &nbsp; "
                                f"<span style='color:{T.warning}'>■</span> removals &nbsp; <span style='color:{T.danger}'>■</span> failed "
                                f"<span style='color:{T.text_secondary}'>· operations per day</span>")

    def _clear_history(self) -> None:
        n = len([e for e in self.app.maintenance.entries(limit=100000) if e["op_type"] in PACKAGE_OPS])
        if not confirm_dialog(self, "Clear transaction history",
                              f"<p>Permanently delete {n} package transaction record(s)?</p><p>This only removes the history shown here; it does not change "
                              "any installed software. It cannot be undone, and history is never cleared automatically.</p>", "Clear history", danger=True):
            return
        count = self.app.maintenance.clear(PACKAGE_OPS)
        self.app.audit.record("packages.clear_history", records=count)
        self.reload_history()
        _say(self.msg, f"Cleared {count} history record(s).")
