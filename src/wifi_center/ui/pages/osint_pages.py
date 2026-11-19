"""OSINT Explorer and the Username / Email / Domain / IP research workspaces (one class, different presets)."""
from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
                               QLineEdit, QListWidget, QListWidgetItem, QMenu, QPlainTextEdit, QPushButton,
                               QSplitter, QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...security.input_validation import ValidationError
from ...services import osint_service as osv
from ...services.osint_catalog import CATEGORIES, INPUT_TYPES
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.components import LoadingIndicator, MatrixButton, Panel
from ..design.tokens import T
from .netsec_common import ProjectBar, confirm_dialog

esc = html.escape
TYPE_LABELS = ["Auto-detect", "Username", "Email", "Domain", "IP address", "URL", "Text"]
TYPE_KEYS = [None, "username", "email", "domain", "ip", "url", "text"]
MODES = {
    "explorer": (None, "Username, e-mail, domain, IP address, URL or free text", "OSINT Explorer"),
    "username": ("username", "Username to research (letters, digits, . _ -)", "Username Search"),
    "email": ("email", "E-mail address", "Email Research"),
    "domain": ("domain", "Domain name, e.g. example.com", "Domain Research"),
    "ip": ("ip", "IPv4 or IPv6 address", "IP Research"),
}
RESULT_COLOR = {"confirmed": T.success, "possible": T.info, "none": T.text_secondary, "inconclusive": T.warning,
                "unavailable": T.danger}
AVAIL_TEXT = {"reachable": ("● reachable", T.success), "unavailable": ("● unreachable", T.danger),
              None: ("not checked", T.text_muted)}


class CustomResourceDialog(QDialog):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add a custom resource")
        self.setMinimumWidth(520)
        form = QFormLayout(self)
        self.name = QLineEdit()
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://site.example/search?q={term}")
        self.category = QComboBox()
        self.category.addItems(CATEGORIES)
        self.kind = QComboBox()
        self.kind.addItems(INPUT_TYPES)
        self.kind.setCurrentText("text")
        self.desc = QPlainTextEdit()
        self.desc.setMaximumHeight(70)
        form.addRow("Name", self.name)
        form.addRow("URL template", self.url)
        form.addRow("Category", self.category)
        form.addRow("Works with", self.kind)
        form.addRow("Description", self.desc)
        note = QLabel("Only public https sites. The URL must contain {term} once, after the host name.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        form.addRow(note)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        form.addRow(box)


class OsintWorkspacePage(QWidget):
    COLS = ["★", "Resource", "Category", "Availability", "Result", ""]

    def __init__(self, app: AppController, mode: str = "explorer") -> None:
        super().__init__()
        self.app, self.mode = app, mode
        self.forced_type, placeholder, title = MODES[mode]
        self._rows: list[dict] = []
        self._term = ""
        self._kind: str | None = None
        self._selected: dict | None = None
        self._category: str | None = None
        self._favorites_only = False

        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel(title)
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("ring", 24)
        head.addWidget(self.loader)
        head.addStretch(1)
        lay.addLayout(head)
        note = QLabel("A transparent, source-based workflow: resources open in your own browser, nothing is scraped or "
                      "automated, and a page that loads is never proof that an account or person exists. Record what "
                      "you actually find as confirmed, possible, no result, inconclusive or unavailable.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)

        top = QHBoxLayout()
        self.bar = ProjectBar(app, kind="investigation", new_kind="investigation", label="Investigation")
        self.bar.project_changed.connect(self._project_changed)
        top.addWidget(self.bar, 1)
        exp = MatrixButton("Export…", icon_name="docs")
        exp.clicked.connect(self._export_menu)
        top.addWidget(exp)
        lay.addLayout(top)

        search = QHBoxLayout()
        self.term = QLineEdit()
        self.term.setPlaceholderText(placeholder)
        self.term.returnPressed.connect(self.search)
        self.kind = QComboBox()
        self.kind.addItems(TYPE_LABELS)
        if self.forced_type:
            self.kind.setCurrentIndex(TYPE_KEYS.index(self.forced_type))
            self.kind.setEnabled(False)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter resources…")
        self.filter.setMaximumWidth(200)
        self.filter.textChanged.connect(self._populate)
        go = MatrixButton("Search", "primary", "search")
        go.clicked.connect(self.search)
        search.addWidget(self.term, 3)
        search.addWidget(self.kind)
        search.addWidget(go)
        search.addWidget(self.filter)
        lay.addLayout(search)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        split.addWidget(self._left())
        split.addWidget(self._center())
        split.addWidget(self._right())
        split.setStretchFactor(1, 4)
        split.setStretchFactor(2, 2)
        split.setSizes([220, 760, 360])
        lay.addWidget(split, 1)
        self._reload_left()
        self._populate()

    # ================================================================ left
    def _left(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        p = Panel("Categories")
        self.cats = QListWidget()
        self.cats.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.cats.currentRowChanged.connect(self._category_changed)
        p.add(self.cats, 1)
        lay.addWidget(p, 3)
        q = Panel("Investigations")
        self.invs = QListWidget()
        self.invs.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.invs.setWordWrap(True)
        self.invs.itemClicked.connect(lambda it: self.bar.reload(select=it.data(Qt.ItemDataRole.UserRole)))
        q.add(self.invs, 1)
        lay.addWidget(q, 2)
        return w

    def _reload_left(self) -> None:
        keep = self.cats.currentRow()
        self.cats.blockSignals(True)
        self.cats.clear()
        counts = {c: len(self.app.osint.resources(category=c)) for c in CATEGORIES}
        self.cats.addItem(f"All resources ({len(self.app.osint.resources())})")
        self.cats.addItem(f"★ Saved ({len(self.app.osint.resources(favorites=True))})")
        for c in CATEGORIES:
            self.cats.addItem(f"{c} ({counts[c]})")
        self.cats.setCurrentRow(max(keep, 0))
        self.cats.blockSignals(False)
        self.invs.clear()
        for p in self.app.projects.list("investigation")[:15]:
            it = QListWidgetItem(f"{p['name']}\n{fmt_ts(p['updated_at'].replace(' ', 'T') + '+00:00')}")
            it.setData(Qt.ItemDataRole.UserRole, p["id"])
            self.invs.addItem(it)

    def _category_changed(self, row: int) -> None:
        self._favorites_only = row == 1
        self._category = CATEGORIES[row - 2] if row >= 2 else None
        self._populate()

    # ================================================================ center
    def _center(self) -> QWidget:
        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        hh = self.table.horizontalHeader()
        for i in range(len(self.COLS)):
            hh.setSectionResizeMode(i, hh.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, hh.ResizeMode.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table.itemSelectionChanged.connect(self._select_row)
        self.table.cellClicked.connect(self._cell_clicked)
        return self.table

    def _effective_kind(self) -> str | None:
        if self.forced_type:
            return self.forced_type
        return TYPE_KEYS[self.kind.currentIndex()]

    def search(self) -> None:
        text = self.term.text()
        try:
            kind = self._effective_kind() or osv.detect_type(text)
            clean = osv.validate_term(text, kind)
        except ValidationError as e:
            self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>")
            return
        self._term, self._kind = clean, kind
        self.msg.setText(f"<span style='color:{T.text_secondary}'>Researching <b>{esc(clean)}</b> as {esc(kind)}. "
                         "Open a resource, then record what you find.</span>")
        self._populate()

    def _populate(self) -> None:
        kind = self._kind if self._term else self._effective_kind()
        self._rows = self.app.osint.resources(self._category, kind, self.filter.text(), self._favorites_only)
        recorded = self.app.osint.results_for(self.bar.project_id(), self._term) if self._term and self.bar.project_id() else {}
        self.table.setRowCount(len(self._rows))
        for r, d in enumerate(self._rows):
            star = QTableWidgetItem("★" if d["favorite"] else "☆")
            star.setForeground(QColor(T.warning if d["favorite"] else T.text_muted))
            star.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            star.setToolTip("Click to save or unsave this resource")
            self.table.setItem(r, 0, star)
            name = QTableWidgetItem(d["name"] + ("  🔒" if d["needs_account"] else ""))
            name.setToolTip((d["description"] or "") + ("\nNeeds an account for full results." if d["needs_account"] else ""))
            self.table.setItem(r, 1, name)
            self.table.setItem(r, 2, QTableWidgetItem(d["categories"][0]))
            text, color = AVAIL_TEXT.get(d["availability"], AVAIL_TEXT[None])
            av = QTableWidgetItem(text)
            av.setForeground(QColor(color))
            if d["checked_at"]:
                av.setToolTip(f"Checked {fmt_ts(d['checked_at'])}")
            self.table.setItem(r, 3, av)
            combo = QComboBox()
            combo.addItem("— not recorded —", None)
            for key in osv.RESULTS:
                combo.addItem(osv.RESULT_LABELS[key], key)
            if d["slug"] in recorded:
                combo.setCurrentIndex(combo.findData(recorded[d["slug"]]))
            combo.setMinimumWidth(150)
            combo.setEnabled(bool(self._term and self.bar.project_id()))
            combo.setToolTip("Record what you found. Select an investigation first." if not self.bar.project_id()
                             else "Record what you found")
            combo.currentIndexChanged.connect(lambda _i, row=r: self._result_changed(row))
            self.table.setCellWidget(r, 4, combo)
            btn = QPushButton("Open")
            btn.setMinimumWidth(72)
            btn.setEnabled(bool(self._term) or not d["supports_term"])
            btn.clicked.connect(lambda _=False, row=r: self._open(row))
            self.table.setCellWidget(r, 5, btn)
        self._select_row()

    def _row_dict(self, row: int) -> dict | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def _cell_clicked(self, row: int, col: int) -> None:
        d = self._row_dict(row)
        if d and col == 0:
            self.app.osint.set_favorite(d["slug"], not d["favorite"])
            self._reload_left()
            self._populate()

    def _result_changed(self, row: int) -> None:
        d = self._row_dict(row)
        pid = self.bar.project_id()
        combo = self.table.cellWidget(row, 4)
        value = combo.currentData() if combo else None
        if not d or not pid or not self._term or value is None:
            return
        try:
            url = osv.build_url(d, self._term, self._kind) if d["supports_term"] else d["url_template"]
            self.app.osint.set_result(pid, self._term, d["slug"], value, url)
        except ValidationError as e:
            self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>")
            return
        self.app.projects.touch(pid)
        self.app.audit.record("osint.record", project=pid, resource=d["slug"], result=value)
        self._reload_left()
        self._show_details(d)

    def _open(self, row: int) -> None:
        d = self._row_dict(row)
        if not d:
            return
        try:
            url = osv.build_url(d, self._term, self._kind) if d["supports_term"] else d["url_template"]
        except ValidationError as e:
            self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>")
            return
        note = ""
        if not d["supports_term"] and self._term:
            QGuiApplication.clipboard().setText(self._term)
            note = " The search term was copied to your clipboard."
        QDesktopServices.openUrl(QUrl(url))                       # explicit user action, in the user's browser
        pid = self.bar.project_id()
        if pid and self._term and not self.app.osint.results_for(pid, self._term).get(d["slug"]):
            self.app.osint.set_result(pid, self._term, d["slug"], "inconclusive", url)   # opened, nothing concluded yet
            self._populate()
        self.app.audit.record("osint.open", resource=d["slug"], kind=self._kind or "")
        self.msg.setText(f"<span style='color:{T.text_secondary}'>Opened <b>{esc(d['name'])}</b>.{note} "
                         "Loading a page does not confirm anything: record what you find.</span>")

    # ================================================================ right
    def _right(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        p = Panel("Selected resource")
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        p.add(self.details, 2)
        row = QHBoxLayout()
        self.save_url = MatrixButton("Save URL to investigation")
        self.save_url.clicked.connect(self._save_url)
        self.remove_btn = MatrixButton("Remove")
        self.remove_btn.clicked.connect(self._remove_custom)
        row.addWidget(self.save_url)
        row.addWidget(self.remove_btn)
        holder = QWidget()
        holder.setLayout(row)
        p.add(holder)
        lay.addWidget(p, 3)
        q = Panel("Observations and notes")
        self.note = QPlainTextEdit()
        self.note.setPlaceholderText("Observation about the selected term/resource (timestamped when saved)")
        self.note.setMaximumHeight(90)
        q.add(self.note)
        add = MatrixButton("Save observation", "primary")
        add.clicked.connect(self._save_note)
        q.add(add)
        self.notes_view = QTextBrowser()
        q.add(self.notes_view, 1)
        lay.addWidget(q, 3)
        tools = QHBoxLayout()
        check = MatrixButton("Check availability…", icon_name="reset")
        check.clicked.connect(self._check_availability)
        custom = MatrixButton("Add custom resource…")
        custom.clicked.connect(self._add_custom)
        tools.addWidget(check)
        tools.addWidget(custom)
        holder2 = QWidget()
        holder2.setLayout(tools)
        lay.addWidget(holder2)
        return w

    def _select_row(self) -> None:
        d = self._row_dict(self.table.currentRow())
        self._selected = d
        self._show_details(d)

    def _show_details(self, d: dict | None) -> None:
        self.save_url.setEnabled(bool(d and self._term and self.bar.project_id()))
        self.remove_btn.setVisible(bool(d and not d["builtin"]))
        if not d:
            self.details.setHtml(f"<p style='color:{T.text_secondary}'>Select a resource.</p>")
            return
        res = self.app.osint.results_for(self.bar.project_id(), self._term).get(d["slug"]) if self._term else None
        rows = [("Categories", ", ".join(d["categories"])), ("Works with", ", ".join(d["input_types"])),
                ("URL pattern", d["url_template"]), ("Source", d["source"] or "—"),
                ("Account needed", "yes, for full results" if d["needs_account"] else "no"),
                ("Availability", AVAIL_TEXT.get(d["availability"], AVAIL_TEXT[None])[0] +
                 (f" ({fmt_ts(d['checked_at'])})" if d["checked_at"] else "")),
                ("Your result", osv.RESULT_LABELS.get(res, "not recorded") if self._term else "—")]
        self.details.setHtml(f"<h3>{esc(d['name'])}</h3><p style='color:{T.text_secondary}'>{esc(d['description'] or '')}</p>"
                             "<table cellpadding='3'>" + "".join(
            f"<tr><td style='color:{T.text_secondary}'>{k}&nbsp;</td><td>{esc(v)}</td></tr>" for k, v in rows)
            + "</table>")

    def _save_url(self) -> None:
        d, pid = self._selected, self.bar.project_id()
        if not (d and pid and self._term):
            return
        try:
            url = osv.build_url(d, self._term, self._kind) if d["supports_term"] else d["url_template"]
            self.app.projects.add_reference(pid, url, f"{d['name']}: {self._term}")
        except ValidationError as e:
            self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>")
            return
        self.msg.setText("Saved the public URL to the investigation.")

    def _save_note(self) -> None:
        pid = self.bar.project_id()
        if not pid:
            self.msg.setText("Select or create an investigation first.")
            return
        d = self._selected
        prefix = f"[{self._term}{' · ' + d['name'] if d else ''}] " if self._term else ""
        self.app.projects.add_note(pid, prefix + self.note.toPlainText())
        self.note.clear()
        self._reload_notes()

    def _reload_notes(self) -> None:
        pid = self.bar.project_id()
        notes = self.app.projects.notes(pid) if pid else []
        self.notes_view.setHtml("".join(
            f"<p><span style='color:{T.text_secondary}'>{esc(n['created_at'])} UTC</span><br>{esc(n['body'])}</p>"
            for n in notes) or f"<p style='color:{T.text_secondary}'>No observations yet.</p>")

    def _project_changed(self, _pid: int) -> None:
        self._reload_notes()
        self._reload_left()
        self._populate()

    # ================================================================ tools
    def _check_availability(self) -> None:
        rows = list(self._rows)
        if not rows:
            return
        hosts = self.app.osint.hosts_for(rows)
        text = (f"This sends one request per site to the home page of {len(hosts)} public sites "
                "(your IP address is visible to them). The search term is never sent.<br><br>"
                + esc(", ".join(hosts[:12])) + (" …" if len(hosts) > 12 else ""))
        if not confirm_dialog(self, "Check availability", text, "Check sites"):
            return
        self.loader.start()
        self.msg.setText("Checking availability…")
        slugs = [r["slug"] for r in rows]
        self.app.audit.record("osint.availability_check", sites=len(hosts))

        def done(res: dict) -> None:
            self.loader.stop()
            up = sum(1 for v in res.values() if v == "reachable")
            self.msg.setText(f"Checked {len(res)} resources: {up} reachable, {len(res) - up} unreachable.")
            self._populate()
        run_in_background(lambda: self.app.osint.check_availability(slugs), done,
                          lambda e: (self.loader.stop(), self.msg.setText(f"Check failed: {e}")))

    def _add_custom(self) -> None:
        dlg = CustomResourceDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            slug = self.app.osint.add_custom(dlg.name.text(), dlg.url.text(), [dlg.category.currentText()],
                                             [dlg.kind.currentText()], dlg.desc.toPlainText())
        except ValidationError as e:
            self.msg.setText(f"<span style='color:{T.danger}'>Not added: {esc(str(e))}</span>")
            return
        self.app.audit.record("osint.custom_added", slug=slug)
        self.msg.setText(f"Added custom resource “{esc(dlg.name.text())}”.")
        self._reload_left()
        self._populate()

    def _remove_custom(self) -> None:
        d = self._selected
        if d and not d["builtin"] and confirm_dialog(self, "Remove resource", f"Remove “{esc(d['name'])}”?",
                                                     "Remove", danger=True):
            self.app.osint.remove_custom(d["slug"])
            self._reload_left()
            self._populate()

    def _export_menu(self) -> None:
        pid = self.bar.project_id()
        if not pid:
            self.msg.setText("Select or create an investigation first.")
            return
        menu = QMenu(self)
        for label, fmt in (("JSON", "json"), ("CSV", "csv"), ("Markdown", "md"), ("HTML", "html")):
            menu.addAction(label, lambda f=fmt: self._export(f))
        menu.exec(self.mapToGlobal(self.rect().topRight()))

    def _export(self, fmt: str) -> None:
        pid = self.bar.project_id()
        name, _ = QFileDialog.getSaveFileName(self, "Export investigation", str(Path.home() / f"investigation.{fmt}"),
                                              f"{fmt.upper()} (*.{fmt})")
        if name:
            Path(name).write_text(self.app.osint.export_investigation(pid, fmt, self.app.projects), encoding="utf-8")
            self.app.audit.record("osint.export", project=pid, path=name)
            self.msg.setText(f"Exported to {name}")
