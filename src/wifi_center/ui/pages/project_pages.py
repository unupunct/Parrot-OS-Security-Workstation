"""Phase 9 pages: Reports (assessment reports), Evidence (files referenced by projects) and Project History."""
from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QSplitter, QTableWidgetItem,
                               QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...security.input_validation import ValidationError
from ...services.project_reports import FORMATS, ReportOptions
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.components import MatrixButton, Panel
from ..design.tokens import T
from .netsec_common import ProjectBar, confirm_dialog

esc = html.escape
STATE_TEXT = {"ok": ("✔ unchanged", T.success), "changed": ("✖ CHANGED", T.danger), "missing": ("✖ missing", T.danger)}


def utc_ts(sql_time: str) -> str:
    """SQLite 'YYYY-MM-DD HH:MM:SS' (UTC) -> local time text."""
    return fmt_ts(sql_time.replace(" ", "T") + "+00:00") if sql_time and "T" not in sql_time else fmt_ts(sql_time)


def title_label(text: str, sub: str) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(0)
    t = QLabel(text)
    t.setObjectName("pageTitle")
    s = QLabel(sub)
    s.setObjectName("muted")
    s.setWordWrap(True)
    lay.addWidget(t)
    lay.addWidget(s)
    return w


# ====================================================================== Reports
class ReportsPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app, self.svc = app, app.projreports
        lay = QVBoxLayout(self)
        lay.addWidget(title_label("Reports", "Assessment reports from a project: scope, findings with remediation status, evidence integrity, notes and references. "
                                             "Nothing is added that is not stored in the project."))
        self.bar = ProjectBar(app)
        self.bar.project_changed.connect(self._reload)
        lay.addWidget(self.bar)
        split = QSplitter(Qt.Orientation.Horizontal)
        side = Panel("Report options")
        self.title = QLineEdit()
        self.title.setPlaceholderText("Report title (default: project name)")
        self.client = QLineEdit()
        self.client.setPlaceholderText("Client (optional)")
        self.by = QLineEdit()
        self.by.setPlaceholderText("Prepared by (optional)")
        self.resolved = QCheckBox("Include resolved findings")
        self.resolved.setChecked(True)
        self.notes = QCheckBox("Include my project notes")
        self.paths = QCheckBox("Show local file paths of evidence")
        self.verify = QCheckBox("Re-check evidence SHA-256 now")
        self.verify.setChecked(True)
        self.fmt = QComboBox()
        self.fmt.addItems([f.upper() for f in FORMATS])
        for w in (self.title, self.client, self.by, self.resolved, self.notes, self.paths, self.verify, QLabel("Format"), self.fmt):
            side.add(w)
        row = QHBoxLayout()
        b_prev = MatrixButton("Preview")
        b_prev.clicked.connect(self.preview)
        self.b_gen = MatrixButton("Generate…", "primary")
        self.b_gen.clicked.connect(self.generate)
        row.addWidget(b_prev)
        row.addWidget(self.b_gen)
        rw = QWidget()
        rw.setLayout(row)
        side.add(rw)
        split.addWidget(side)
        self.view = QTextBrowser()
        split.addWidget(self.view)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 3)
        lay.addWidget(split, 3)
        hist = Panel("Reports generated for this project")
        self.table = make_table(["Generated", "Format", "Title", "File", "Size", "File check"], stretch_col=3)
        hist.add(self.table, 1)
        hrow = QHBoxLayout()
        b_chk = MatrixButton("Check file")
        b_chk.clicked.connect(self.check)
        b_forget = MatrixButton("Remove from list…")
        b_forget.clicked.connect(self.forget)
        hrow.addWidget(b_chk)
        hrow.addWidget(b_forget)
        hrow.addStretch(1)
        hw = QWidget()
        hw.setLayout(hrow)
        hist.add(hw)
        lay.addWidget(hist, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.rows: list[dict] = []
        self._reload()

    def showEvent(self, e) -> None:                                  # noqa: N802
        super().showEvent(e)
        self.bar.reload()
        self._reload()

    def say(self, text: str, error: bool = False) -> None:
        self.msg.setText(f"<span style='color:{T.danger if error else T.green}'>{esc(text)}</span>")

    def _options(self) -> ReportOptions:
        return ReportOptions(self.title.text(), self.by.text().strip(), self.client.text().strip(), self.notes.isChecked(), self.resolved.isChecked(),
                             self.paths.isChecked(), self.verify.isChecked())

    def _reload(self, *_a) -> None:
        pid = self.bar.project_id()
        self.b_gen.setEnabled(bool(pid))
        self.rows = self.svc.generated(pid) if pid else []
        self.table.setRowCount(len(self.rows))
        for r, g in enumerate(self.rows):
            for c, v in enumerate((utc_ts(g["generated_at"]), g["fmt"].upper(), g["title"], g["path"], f"{g['size'] // 1024 or 1} KiB", "not checked")):
                self.table.setItem(r, c, QTableWidgetItem(v))

    def preview(self) -> None:
        pid = self.bar.project_id()
        if not pid:
            self.say("Create or pick a project first.", True)
            return
        opts = self._options()
        self.say("Building the preview…")
        run_in_background(lambda: self.svc.build(pid, opts), lambda r: (self.view.setHtml(self.svc.to_html(r)), self.say(
            f"{len(r.findings)} finding(s), {len(r.evidence)} evidence file(s)" + (f"; {len(r.integrity_problems)} evidence file(s) changed or missing" if r.integrity_problems else "") + ".")),
            lambda e: self.say(str(e), True))

    def generate(self) -> None:
        pid = self.bar.project_id()
        if not pid:
            return
        fmt = self.fmt.currentText().lower()
        name, _ = QFileDialog.getSaveFileName(self, "Save report", str(Path.home() / f"assessment-report.{fmt}"), f"{fmt.upper()} (*.{fmt})")
        if not name:
            return
        opts = self._options()

        def done(p: Path) -> None:
            self.app.audit.record("report.generate", project=pid, fmt=fmt, path=str(p))
            self.say(f"Report saved to {p}")
            self._reload()
        if fmt == "pdf":                                              # Qt text rendering belongs on the UI thread
            try:
                done(self.svc.write(self.svc.build(pid, opts), name, fmt))
            except (OSError, RuntimeError, ValueError) as e:
                self.say(str(e), True)
            return
        run_in_background(lambda: self.svc.write(self.svc.build(pid, opts), name, fmt), done, lambda e: self.say(str(e), True))

    def _selected(self) -> dict | None:
        r = self.table.currentRow()
        return self.rows[r] if 0 <= r < len(self.rows) else None

    def check(self) -> None:
        g = self._selected()
        if not g:
            return
        state = self.svc.verify_generated(g["id"])
        text, color = STATE_TEXT[state]
        it = QTableWidgetItem(text)
        it.setForeground(QColor(color))
        self.table.setItem(self.table.currentRow(), 5, it)
        self.say({"ok": "The file is exactly as it was generated.", "changed": "The file was modified after it was generated.", "missing": "The file no longer exists."}[state], state != "ok")

    def forget(self) -> None:
        g = self._selected()
        if g and confirm_dialog(self, "Remove from list", f"<p>Remove <b>{esc(g['title'])}</b> from this list?</p><p>The report file itself is <b>not</b> deleted.</p>", "Remove"):
            self.svc.forget_generated(g["id"])
            self._reload()


# ====================================================================== Evidence
class EvidencePage(QWidget):
    COLS = ["Project", "File", "Description", "Finding", "SHA-256 (recorded)", "Added", "Integrity"]

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.rows: list[dict] = []
        lay = QVBoxLayout(self)
        lay.addWidget(title_label("Evidence", "Files your projects refer to. They stay where they are: WIFI Center stores the path and a SHA-256 so any change is detected."))
        self.bar = ProjectBar(app, allow_none=True)
        self.bar.project_changed.connect(self.reload)
        top = QHBoxLayout()
        top.addWidget(self.bar, 1)
        self.b_add = MatrixButton("Add file…", "primary")
        self.b_add.clicked.connect(self.add)
        self.b_link = MatrixButton("Link to finding…")
        self.b_link.clicked.connect(self.link)
        self.b_verify = MatrixButton("Verify all")
        self.b_verify.clicked.connect(self.verify_all)
        self.b_remove = MatrixButton("Remove reference…", "danger")
        self.b_remove.clicked.connect(self.remove)
        for b in (self.b_add, self.b_link, self.b_verify, self.b_remove):
            top.addWidget(b)
        lay.addLayout(top)
        self.table = make_table(self.COLS, stretch_col=1)
        self.table.itemSelectionChanged.connect(self._sel)
        lay.addWidget(self.table, 1)
        self.path = QLabel("")
        self.path.setObjectName("muted")
        self.path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.path.setWordWrap(True)
        lay.addWidget(self.path)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.reload()

    def showEvent(self, e) -> None:                                  # noqa: N802
        super().showEvent(e)
        self.bar.reload()
        self.reload()

    def say(self, text: str, error: bool = False) -> None:
        self.msg.setText(f"<span style='color:{T.danger if error else T.green}'>{esc(text)}</span>")

    def reload(self, *_a) -> None:
        pid = self.bar.project_id()
        self.rows = self.app.projects.evidence_all(pid)
        self.table.setRowCount(len(self.rows))
        for r, e in enumerate(self.rows):
            vals = (e["project"], Path(e["path"]).name, e["description"] or "", e["finding"] or "—", (e["sha256"] or "")[:16] + "…", utc_ts(e["added_at"]), "not checked")
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))
        self.b_add.setEnabled(bool(pid))
        self.b_verify.setEnabled(bool(self.rows))
        self._sel()

    def _selected(self) -> dict | None:
        r = self.table.currentRow()
        return self.rows[r] if 0 <= r < len(self.rows) else None

    def _sel(self) -> None:
        e = self._selected()
        self.path.setText(e["path"] if e else "")
        self.b_link.setEnabled(bool(e))
        self.b_remove.setEnabled(bool(e))

    def add(self) -> None:
        pid = self.bar.project_id()
        name, _ = QFileDialog.getOpenFileName(self, "Evidence file")
        if not pid or not name:
            return
        try:
            self.app.projects.add_evidence(pid, name)
        except (ValidationError, OSError) as e:
            self.say(f"Not added: {e}", True)
            return
        self.app.audit.record("evidence.add", project=pid, path=name)
        self.say(f"Added {Path(name).name} with its SHA-256.")
        self.reload()

    def link(self) -> None:
        e = self._selected()
        if not e:
            return
        findings = self.app.projects.findings(e["project_id"])
        names = ["(no finding)"] + [f"#{f['id']} [{f['severity']}] {f['title']}" for f in findings]
        choice, ok = QInputDialog.getItem(self, "Link evidence", "Finding this evidence supports:", names, 0, False)
        if not ok:
            return
        fid = None if choice == names[0] else findings[names.index(choice) - 1]["id"]
        try:
            self.app.projects.link_evidence(e["id"], fid)
        except ValidationError as ex:
            self.say(str(ex), True)
            return
        self.reload()

    def verify_all(self) -> None:
        rows = list(self.rows)
        self.say(f"Checking {len(rows)} file(s)…")

        def work() -> list[str]:
            return [self.app.projects.verify_evidence(e["id"]) for e in rows]

        def done(states: list[str]) -> None:
            for r, s in enumerate(states):
                if r < self.table.rowCount():
                    text, color = STATE_TEXT[s]
                    it = QTableWidgetItem(text)
                    it.setForeground(QColor(color))
                    self.table.setItem(r, 6, it)
            bad = sum(1 for s in states if s != "ok")
            self.say("All files match their recorded SHA-256." if not bad else f"{bad} file(s) changed or missing.", bool(bad))
        run_in_background(work, done, lambda ex: self.say(str(ex), True))

    def remove(self) -> None:
        e = self._selected()
        if e and confirm_dialog(self, "Remove evidence reference", f"<p>Remove the reference to <b>{esc(Path(e['path']).name)}</b> from <b>{esc(e['project'])}</b>?</p>"
                                "<p>The file on disk is <b>not</b> deleted.</p>", "Remove", danger=True):
            self.app.projects.remove_evidence(e["id"])
            self.app.audit.record("evidence.remove", project=e["project_id"], path=e["path"])
            self.reload()


# ====================================================================== Project History
class ProjectHistoryPage(QWidget):
    COLS = ["Project", "Kind", "Created", "Last activity", "Findings", "Open", "Evidence", "Scope", "Notes", "Reports"]

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app, self.svc = app, app.projreports
        self.rows: list[dict] = []
        lay = QVBoxLayout(self)
        lay.addWidget(title_label("Project History", "Every project and what happened in it. The timeline is built from the timestamps stored with each finding, "
                                                     "note, evidence file, scope entry, import and report, so it cannot drift from the data."))
        bar = QHBoxLayout()
        self.b_export = MatrixButton("Export project (JSON)…")
        self.b_export.clicked.connect(self.export)
        self.b_delete = MatrixButton("Delete project…", "danger")
        self.b_delete.clicked.connect(self.delete)
        bar.addStretch(1)
        bar.addWidget(self.b_export)
        bar.addWidget(self.b_delete)
        lay.addLayout(bar)
        split = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table(self.COLS, stretch_col=0)
        self.table.itemSelectionChanged.connect(self._sel)
        split.addWidget(self.table)
        self.timeline = QTextBrowser()
        split.addWidget(self.timeline)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.reload()

    def showEvent(self, e) -> None:                                  # noqa: N802
        super().showEvent(e)
        self.reload()

    def say(self, text: str, error: bool = False) -> None:
        self.msg.setText(f"<span style='color:{T.danger if error else T.green}'>{esc(text)}</span>")

    def reload(self) -> None:
        keep = (self._selected() or {}).get("id")
        self.rows = self.svc.overview()
        self.table.setRowCount(len(self.rows))
        for r, p in enumerate(self.rows):
            vals = (p["name"], p["kind"], utc_ts(p["created_at"]), utc_ts(p["updated_at"]), p["findings"], p["open"], p["evidence"], p["scope"], p["notes"], p["reports"])
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(str(v)))
            if p["id"] == keep:
                self.table.selectRow(r)
        self._sel()

    def _selected(self) -> dict | None:
        r = self.table.currentRow()
        return self.rows[r] if 0 <= r < len(self.rows) else None

    def _sel(self) -> None:
        p = self._selected()
        self.b_export.setEnabled(bool(p))
        self.b_delete.setEnabled(bool(p))
        if not p:
            self.timeline.setHtml("<p>Select a project to see its timeline.</p>" if self.rows else "<p>No projects yet. Create one in Security Assessment.</p>")
            return
        items = self.svc.activity(p["id"], 300)
        icons = {"project": "●", "finding": "▲", "note": "✎", "evidence": "▣", "scope": "◎", "import": "⇩", "report": "▤"}
        self.timeline.setHtml(f"<h3>{esc(p['name'])}</h3>" + "".join(
            f"<p><span style='color:{T.text_muted}'>{esc(utc_ts(a['time']))}</span> &nbsp;{icons.get(a['kind'], '•')} {esc(a['text'])}</p>" for a in items))

    def export(self) -> None:
        p = self._selected()
        if not p:
            return
        name, _ = QFileDialog.getSaveFileName(self, "Export project", str(Path.home() / f"project-{p['id']}.json"), "JSON (*.json)")
        if name:
            Path(name).write_text(self.svc.export_bundle(p["id"]), encoding="utf-8", newline="")
            self.app.audit.record("project.export", project=p["id"], path=name)
            self.say(f"Exported to {name}. It contains full evidence paths and your notes: keep it private.")

    def delete(self) -> None:
        p = self._selected()
        if p and confirm_dialog(self, "Delete project", f"<p>Delete <b>{esc(p['name'])}</b> with its {p['findings']} finding(s), {p['evidence']} evidence reference(s), notes, scope and "
                                "report history from the database?</p><p>Evidence files and generated report files on disk are <b>not</b> touched. This cannot be undone.</p>", "Delete", danger=True):
            self.app.projects.delete(p["id"])
            self.app.audit.record("project.delete", project=p["id"], name=p["name"])
            self.reload()
