"""Security Assessment (projects, findings, evidence, imports, integrations), Web Security, Password Auditing."""
from __future__ import annotations

import html
import re
from datetime import date
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit,
                               QSpinBox, QTabWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...integrations.base import Health, LaunchMethod
from ...security.input_validation import ValidationError
from ...security.operation_policy import PolicyViolation
from ...services import password_policy as pp
from ...services.bloodhound_service import DEFAULT_URL as BH_URL
from ...services.nmap_parsers import ParseError
from ...services.project_service import SEVERITIES, STATUSES
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.components import Badge, MatrixButton, Panel
from ..design.tokens import T
from .netsec_common import SEV_COLOR, ProjectBar, confirm_dialog

esc = html.escape


# ======================================================================== findings dialog
class FindingDialog(QDialog):
    def __init__(self, parent: QWidget, finding: dict | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit finding" if finding else "New finding")
        self.setMinimumWidth(560)
        f = finding or {}
        form = QFormLayout(self)
        self.title = QLineEdit(f.get("title", ""))
        self.severity = QComboBox()
        self.severity.addItems(SEVERITIES)
        self.severity.setCurrentText(f.get("severity", "medium"))
        self.status = QComboBox()
        self.status.addItems(STATUSES)
        self.status.setCurrentText(f.get("status", "open"))
        self.location = QLineEdit(f.get("location") or "")
        self.description = QPlainTextEdit(f.get("description") or "")
        self.recommendation = QPlainTextEdit(f.get("recommendation") or "")
        self.remediation = QPlainTextEdit(f.get("remediation_notes") or "")
        self.due = QLineEdit(f.get("due_date") or "")
        self.due.setPlaceholderText("YYYY-MM-DD (optional)")
        for plain in (self.description, self.recommendation, self.remediation):
            plain.setMaximumHeight(80)
        form.addRow("Title", self.title)
        form.addRow("Severity", self.severity)
        form.addRow("Status", self.status)
        form.addRow("Location", self.location)
        form.addRow("Description", self.description)
        form.addRow("Recommendation", self.recommendation)
        form.addRow("Remediation notes", self.remediation)
        form.addRow("Due date", self.due)
        self.err = QLabel("")
        self.err.setObjectName("err")
        form.addRow(self.err)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _accept(self) -> None:
        if not self.title.text().strip():
            self.err.setText("A title is required.")
            return
        due = self.due.text().strip()
        if due:
            try:
                date.fromisoformat(due)
            except ValueError:
                self.err.setText("Due date must look like 2026-12-31.")
                return
        self.accept()

    def values(self) -> dict:
        return {"title": self.title.text().strip(), "severity": self.severity.currentText(),
                "status": self.status.currentText(), "location": self.location.text().strip(),
                "description": self.description.toPlainText(), "recommendation": self.recommendation.toPlainText(),
                "remediation_notes": self.remediation.toPlainText(), "due_date": self.due.text().strip()}


# ======================================================================== assessment
class AssessmentPage(QWidget):
    COLS = ["Severity", "Title", "Status", "Location", "Source", "Due"]

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._findings: list[dict] = []
        lay = QVBoxLayout(self)
        t = QLabel("Security Assessment")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        top = QHBoxLayout()
        self.bar = ProjectBar(app)
        self.bar.project_changed.connect(self._reload)
        dele = MatrixButton("Delete project…")
        dele.clicked.connect(self._delete_project)
        top.addWidget(self.bar, 1)
        top.addWidget(dele)
        lay.addLayout(top)
        self.summary = QLabel("")
        self.summary.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(self.summary)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._findings_tab(), "Findings")
        self.tabs.addTab(self._evidence_tab(), "Evidence")
        self.tabs.addTab(self._notes_tab(), "Notes")
        self.tabs.addTab(self._import_tab(), "Import results")
        self.tabs.addTab(self._integrations_tab(), "Integrations")
        lay.addWidget(self.tabs, 1)
        self.msg = QLabel("")
        self.msg.setObjectName("muted")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self._reload()

    def _pid(self) -> int | None:
        return self.bar.project_id()

    def showEvent(self, e) -> None:  # noqa: N802
        super().showEvent(e)
        self._reload()   # pick up findings imported elsewhere

    def _reload(self, *_a) -> None:
        self._reload_findings()
        self._reload_evidence()
        self._reload_notes()

    # ---------------- findings ----------------
    def _findings_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All statuses", *STATUSES])
        self.status_filter.currentIndexChanged.connect(self._reload_findings)
        add = MatrixButton("Add finding…", "primary")
        add.clicked.connect(self._add_finding)
        edit = MatrixButton("Edit / track remediation…")
        edit.clicked.connect(self._edit_finding)
        dele = MatrixButton("Delete…")
        dele.clicked.connect(self._delete_finding)
        for x in (self.status_filter, add, edit, dele):
            row.addWidget(x)
        row.addStretch(1)
        lay.addLayout(row)
        self.ftable = make_table(self.COLS, stretch_col=1)
        self.ftable.doubleClicked.connect(lambda *_: self._edit_finding())
        self.ftable.itemSelectionChanged.connect(self._show_finding)
        lay.addWidget(self.ftable, 3)
        self.fdetail = QTextBrowser()
        self.fdetail.setMaximumHeight(170)
        lay.addWidget(self.fdetail, 1)
        return w

    def _reload_findings(self) -> None:
        pid = self._pid()
        status = None if self.status_filter.currentIndex() == 0 else self.status_filter.currentText()
        self._findings = self.app.projects.findings(pid, status) if pid else []
        self.ftable.setRowCount(len(self._findings))
        for r, f in enumerate(self._findings):
            vals = [f["severity"], f["title"], f["status"], f["location"] or "", f["source_tool"] or "manual",
                    f["due_date"] or ""]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 0:
                    item.setForeground(QColor(SEV_COLOR[f["severity"]]))
                self.ftable.setItem(r, c, item)
        summ = self.app.projects.severity_summary(pid) if pid else {}
        self.summary.setText("  ".join(f"<span style='color:{SEV_COLOR[s]}'><b>{summ[s]}</b> {s}</span>"
                                       for s in reversed(SEVERITIES) if s in summ)
                             or f"<span style='color:{T.text_secondary}'>No unresolved findings.</span>")
        self.fdetail.clear()

    def _current_finding(self) -> dict | None:
        r = self.ftable.currentRow()
        return self._findings[r] if 0 <= r < len(self._findings) else None

    def _show_finding(self) -> None:
        f = self._current_finding()
        if not f:
            return
        rows = [("Description", f["description"]), ("Recommendation", f["recommendation"]),
                ("Remediation notes", f["remediation_notes"]), ("Imported from", f["source_ref"])]
        self.fdetail.setHtml("".join(f"<p><b style='color:{T.text_secondary}'>{k}</b><br>{esc(v)}</p>"
                                     for k, v in rows if v) or "<p>No further details.</p>")

    def _add_finding(self) -> None:
        pid = self._pid()
        if not pid:
            self.msg.setText("Create a project first.")
            return
        dlg = FindingDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            v = dlg.values()
            fid = self.app.projects.add_finding(pid, v["title"], v["severity"], v["description"], v["recommendation"],
                                                "", v["location"])
            extra = {k: v[k] for k in ("status", "remediation_notes", "due_date")}
            self.app.projects.update_finding(fid, **extra)
            self.app.audit.record("finding.add", project=pid, id=fid)
            self._reload_findings()

    def _edit_finding(self) -> None:
        f = self._current_finding()
        if not f:
            return
        dlg = FindingDialog(self, f)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.app.projects.update_finding(f["id"], **dlg.values())
            self.app.audit.record("finding.update", id=f["id"])
            self._reload_findings()

    def _delete_finding(self) -> None:
        f = self._current_finding()
        if f and confirm_dialog(self, "Delete finding", f"Delete “{esc(f['title'])}”?", "Delete", danger=True):
            self.app.projects.delete_finding(f["id"])
            self.app.audit.record("finding.delete", id=f["id"])
            self._reload_findings()

    def _delete_project(self) -> None:
        pid = self._pid()
        if pid and confirm_dialog(self, "Delete project",
                                  "Delete this project and its findings, scope, notes and imported scan results from "
                                  "the database?<br>Evidence files on disk are not touched.", "Delete project", danger=True):
            self.app.projects.delete(pid)
            self.app.audit.record("project.delete", id=pid)
            self.bar.reload()

    # ---------------- evidence ----------------
    def _evidence_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        add = MatrixButton("Add evidence file…", "primary")
        add.clicked.connect(self._add_evidence)
        ver = MatrixButton("Verify integrity")
        ver.clicked.connect(self._verify_evidence)
        row.addWidget(add)
        row.addWidget(ver)
        row.addStretch(1)
        lay.addLayout(row)
        self.etable = make_table(["File", "SHA-256", "Description", "Added", "Integrity"])
        lay.addWidget(self.etable, 1)
        info = QLabel("Files stay where they are; WIFI Center stores the path and SHA-256 so changes are detected.")
        info.setObjectName("muted")
        lay.addWidget(info)
        return w

    def _reload_evidence(self) -> None:
        rows = self.app.projects.evidence(self._pid()) if self._pid() else []
        self._evidence = rows
        self.etable.setRowCount(len(rows))
        for r, e in enumerate(rows):
            for c, v in enumerate([e["path"], (e["sha256"] or "")[:16] + "…", e["description"] or "",
                                   fmt_ts(e["added_at"].replace(" ", "T") + "+00:00"), "not checked"]):
                self.etable.setItem(r, c, QTableWidgetItem(v))

    def _add_evidence(self) -> None:
        if not self._pid():
            return
        name, _ = QFileDialog.getOpenFileName(self, "Evidence file")
        if not name:
            return
        try:
            self.app.projects.add_evidence(self._pid(), name)
        except (ValidationError, OSError) as e:
            self.msg.setText(f"Not added: {e}")
            return
        self.app.audit.record("evidence.add", project=self._pid(), path=name)
        self._reload_evidence()

    def _verify_evidence(self) -> None:
        for r, e in enumerate(self._evidence):
            state = self.app.projects.verify_evidence(e["id"])
            item = QTableWidgetItem({"ok": "✔ unchanged", "changed": "✖ CHANGED", "missing": "✖ missing"}[state])
            item.setForeground(QColor(T.success if state == "ok" else T.danger))
            self.etable.setItem(r, 4, item)

    # ---------------- notes ----------------
    def _notes_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.note_input = QPlainTextEdit()
        self.note_input.setPlaceholderText("Assessment note (timestamped when saved)")
        self.note_input.setMaximumHeight(100)
        add = MatrixButton("Save note", "primary")
        add.clicked.connect(self._add_note)
        lay.addWidget(self.note_input)
        lay.addWidget(add)
        self.notes_view = QTextBrowser()
        lay.addWidget(self.notes_view, 1)
        return w

    def _reload_notes(self) -> None:
        notes = self.app.projects.notes(self._pid()) if self._pid() else []
        self.notes_view.setHtml("".join(
            f"<p><span style='color:{T.text_secondary}'>{esc(n['created_at'])}</span><br>{esc(n['body'])}</p>"
            for n in notes) or f"<p style='color:{T.text_secondary}'>No notes yet.</p>")

    def _add_note(self) -> None:
        if self._pid():
            self.app.projects.add_note(self._pid(), self.note_input.toPlainText())
            self.note_input.clear()
            self._reload_notes()

    # ---------------- import ----------------
    def _import_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(QLabel("Import existing results into the selected project. Files are only read."))
        for label, fmt in (("Nmap results (XML / normal / grepable)…", "nmap"), ("Nikto report…", "nikto"),
                           ("Burp Suite issues export (XML)…", "burp"), ("Metasploit workspace export (XML)…", "metasploit"),
                           ("Generic findings (CSV / JSON)…", "generic")):
            b = MatrixButton(label, icon_name="folder")
            b.clicked.connect(lambda _=False, f=fmt: self._import(f))
            lay.addWidget(b)
        hint = QLabel("Generic format columns: title, severity, description, location, recommendation. "
                      "Re-importing an identical file is ignored.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        lay.addStretch(1)
        return w

    def _import(self, fmt: str) -> None:
        pid = self._pid()
        if not pid:
            self.msg.setText("Create a project first.")
            return
        name, _ = QFileDialog.getOpenFileName(self, "Import results", "", "Reports (*.xml *.csv *.json *.txt *.nmap "
                                              "*.gnmap);;All files (*)")
        if not name:
            return
        try:
            if fmt == "nmap":
                sid = self.app.nmap.import_file(name, pid)
                self.msg.setText(f"Imported Nmap results as scan #{sid} (see Network Discovery).")
            else:
                r = self.app.report_import.import_file(pid, name, fmt, nmap=self.app.nmap)
                self.msg.setText("This file was already imported." if r["duplicate"] else
                                 f"Imported {r['findings']} findings" + (f" and {r['hosts']} hosts" if r["hosts"] else "")
                                 + f" from the {r['tool']} report.")
            self.app.audit.record("report.import", project=pid, tool=fmt, path=name)
        except (ParseError, ValidationError, OSError, ValueError) as e:
            self.msg.setText(f"<span style='color:{T.danger}'>Import failed: {esc(str(e))}</span>")
        self._reload()

    # ---------------- integrations ----------------
    def _integrations_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.msf = Panel("Metasploit Framework")
        self.msf_lbl = self.msf.add_text()
        lay.addWidget(self.msf)
        self.bh = Panel("BloodHound Community Edition")
        self.bh_lbl = self.bh.add_text()
        row = QHBoxLayout()
        refresh = MatrixButton("Check Docker / containers", icon_name="reset")
        refresh.clicked.connect(self._refresh_bh)
        check = MatrixButton("Check service (loopback)")
        check.clicked.connect(self._check_bh)
        row.addWidget(refresh)
        row.addWidget(check)
        row.addStretch(1)
        holder = QWidget()
        holder.setLayout(row)
        self.bh.add(holder)
        self.bh_url = QLineEdit(self.app.settings.get("integrations.bloodhound_url"))
        self.bh_url.setPlaceholderText(BH_URL)
        self.bh.add(self.bh_url)
        lay.addWidget(self.bh)
        lay.addStretch(1)
        self._refresh_msf()
        self._bh_note("Press “Check Docker / containers” to look (read-only). WIFI Center never deploys, starts or "
                      "exposes BloodHound for you.")
        return w

    def _tool_status_html(self, tool_id: str) -> str:
        s = self.app.tools.cached(tool_id) or self.app.tools.scan_tool(tool_id)
        col = {Health.OK: T.success, Health.WARNING: T.warning, Health.ERROR: T.danger}.get(s.health.level, T.text_muted)
        return (f"<span style='color:{col}'><b>{s.health.level.value.title()}</b></span> — {esc(s.health.detail)}<br>"
                f"Version: {esc(s.version or 'unknown')}<br><a href='{esc(s.profile.docs_url)}'>Documentation</a>")

    def _refresh_msf(self) -> None:
        self.msf_lbl.setText(self._tool_status_html("metasploit") +
                             f"<br><span style='color:{T.text_secondary}'>Restricted integration: detection, version, "
                             "dependency checks and docs only. Use “Import results” to organise a workspace export "
                             "(hosts, services, vulnerability records).</span>")
        self.msf_lbl.setOpenExternalLinks(True)

    def _bh_note(self, text: str) -> None:
        self.bh_lbl.setText(self._tool_status_html("bloodhound-ce") + f"<br><br>{esc(text)}")
        self.bh_lbl.setOpenExternalLinks(True)

    def _refresh_bh(self) -> None:
        self._bh_note("Checking Docker…")

        def done(st) -> None:
            parts = [f"Docker installed: {st.docker_installed} · daemon reachable: {st.daemon_reachable} · "
                     f"compose plugin: {st.compose_available}"]
            for c in st.containers:
                parts.append(f"• {c.name} ({c.image}) — {c.status}" + (f" · CPU {c.cpu} · memory {c.memory}" if c.cpu else ""))
            if st.message:
                parts.append(st.message)
            self._bh_note("\n".join(parts))
        run_in_background(self.app.bloodhound.status, done, lambda e: self._bh_note(f"Check failed: {e}"))

    def _check_bh(self) -> None:
        url = self.bh_url.text().strip() or BH_URL
        try:
            from ...services.kismet_service import validate_loopback_url
            validate_loopback_url(url)
        except ValidationError as e:
            self._bh_note(f"Not checked: {e}")
            return
        self.app.settings.set("integrations.bloodhound_url", url)
        self._bh_note("Contacting the loopback service…")
        run_in_background(lambda: self.app.bloodhound.check_service(url), self._bh_note,
                          lambda e: self._bh_note(f"Check failed: {e}"))


# ======================================================================== web security
class WebSecurityPage(QWidget):
    TOOLS = ("burpsuite", "nikto", "sqlmap")

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        t = QLabel("Web Security")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        note = QLabel("Status and launching for supported web-testing tools, plus project references, report import and "
                      "remediation tracking. No unattended exploitation or data extraction is offered.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        cards = QHBoxLayout()
        self._cards: dict[str, tuple[QLabel, MatrixButton | None]] = {}
        for tid in self.TOOLS:
            panel = Panel(self.app.tools.profile(tid).name)
            lbl = panel.add_text()
            lbl.setOpenExternalLinks(True)
            btn = None
            prof = self.app.tools.profile(tid)
            if any(o.method == LaunchMethod.DESKTOP and not o.dynamic for o in prof.operations):
                btn = MatrixButton("Launch", "primary", "launch")
                btn.clicked.connect(lambda _=False, x=tid: self._launch(x))
                panel.add(btn)
            self._cards[tid] = (lbl, btn)
            cards.addWidget(panel)
        lay.addLayout(cards)
        top = QHBoxLayout()
        self.bar = ProjectBar(app)
        self.bar.project_changed.connect(self._reload_refs)
        top.addWidget(self.bar, 1)
        lay.addLayout(top)
        split = QHBoxLayout()
        refs = Panel("Project references (in-scope applications and URLs)")
        self.refs = QListWidget()
        self.refs.itemDoubleClicked.connect(self._open_ref)
        refs.add(self.refs, 1)
        row = QHBoxLayout()
        self.ref_input = QLineEdit()
        self.ref_input.setPlaceholderText("https://app.example.com/")
        add = MatrixButton("Add", "primary")
        add.clicked.connect(self._add_ref)
        rm = MatrixButton("Remove")
        rm.clicked.connect(self._remove_ref)
        for x in (self.ref_input, add, rm):
            row.addWidget(x)
        holder = QWidget()
        holder.setLayout(row)
        refs.add(holder)
        split.addWidget(refs, 2)
        imp = Panel("Import and track")
        for label, fmt in (("Import Nikto report…", "nikto"), ("Import Burp issues export…", "burp"),
                           ("Import generic findings (CSV/JSON)…", "generic")):
            b = MatrixButton(label, icon_name="folder")
            b.clicked.connect(lambda _=False, f=fmt: self._import(f))
            imp.add(b)
        self.unresolved = imp.add_text()
        go = MatrixButton("Open findings in Security Assessment")
        go.clicked.connect(lambda: self.navigate("assessment"))
        imp.add(go)
        split.addWidget(imp, 1)
        lay.addLayout(split, 1)
        self.msg = QLabel("")
        self.msg.setObjectName("muted")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.navigate = lambda _p: None
        self.operation_started = lambda _id: None
        self.refresh_status()
        self._reload_refs()

    def refresh_status(self) -> None:
        for tid, (lbl, btn) in self._cards.items():
            s = self.app.tools.cached(tid) or self.app.tools.scan_tool(tid)
            col = {Health.OK: T.success, Health.WARNING: T.warning, Health.ERROR: T.danger}.get(s.health.level, T.text_muted)
            lbl.setText(f"<span style='color:{col}'><b>{s.health.level.value.title()}</b></span> — {esc(s.health.detail)}"
                        f"<br>Version: {esc(s.version or 'unknown')}"
                        + (f"<br><span style='color:{T.warning}'>Restricted: detection, version and docs only.</span>"
                           if s.profile.restricted else "")
                        + f"<br><a href='{esc(s.profile.docs_url)}'>Documentation</a>")
            if btn:
                btn.setEnabled(s.installed)

    def _launch(self, tool_id: str) -> None:
        s = self.app.tools.cached(tool_id)
        try:
            req = self.app.tools.integration(tool_id).launch_supported_operation("launch", None)
            oid = self.app.operations.start(s.profile, req)
        except (ValueError, PolicyViolation) as e:
            self.msg.setText(f"Cannot launch: {e}")
            return
        self.operation_started(oid)

    def _pid(self) -> int | None:
        return self.bar.project_id()

    def _reload_refs(self, *_a) -> None:
        self.refs.clear()
        pid = self._pid()
        for r in self.app.projects.references(pid) if pid else []:
            it = QListWidgetItem(r["url"] + (f"  —  {r['label']}" if r["label"] else ""))
            it.setData(Qt.ItemDataRole.UserRole, r["url"])
            self.refs.addItem(it)
        summ = self.app.projects.severity_summary(pid) if pid else {}
        self.unresolved.setText("Unresolved findings: " + (", ".join(f"{n} {s}" for s, n in summ.items()) or "none"))

    def _add_ref(self) -> None:
        if not self._pid():
            self.msg.setText("Create a project first.")
            return
        try:
            self.app.projects.add_reference(self._pid(), self.ref_input.text())
        except ValidationError as e:
            self.msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>")
            return
        self.ref_input.clear()
        self._reload_refs()

    def _remove_ref(self) -> None:
        it = self.refs.currentItem()
        if it and self._pid():
            self.app.projects.remove_reference(self._pid(), it.data(Qt.ItemDataRole.UserRole))
            self._reload_refs()

    def _open_ref(self, item: QListWidgetItem) -> None:
        QDesktopServices.openUrl(QUrl(item.data(Qt.ItemDataRole.UserRole)))   # explicit user action

    def _import(self, fmt: str) -> None:
        pid = self._pid()
        if not pid:
            self.msg.setText("Create a project first.")
            return
        name, _ = QFileDialog.getOpenFileName(self, "Import report", "", "Reports (*.xml *.csv *.json);;All files (*)")
        if not name:
            return
        try:
            r = self.app.report_import.import_file(pid, name, fmt)
            self.msg.setText("This file was already imported." if r["duplicate"] else
                             f"Imported {r['findings']} findings from the {r['tool']} report.")
            self.app.audit.record("report.import", project=pid, tool=fmt, path=name)
        except (ParseError, ValidationError, OSError, ValueError) as e:
            self.msg.setText(f"<span style='color:{T.danger}'>Import failed: {esc(str(e))}</span>")
        self._reload_refs()


# ======================================================================== password auditing
class PasswordAuditPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._report: pp.AuditReport | None = None
        self._blocklist: set[str] = set()
        lay = QVBoxLayout(self)
        t = QLabel("Password Auditing")
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        banner = QLabel("Offline password-policy evaluation. Nothing is cracked, guessed or sent anywhere, and "
                        "password text is never saved or logged: results identify entries by line or user name only. "
                        "Use synthetic test data or data you are authorized to evaluate.")
        banner.setWordWrap(True)
        banner.setObjectName("warn")
        lay.addWidget(banner)
        self.john = QLabel("")
        self.john.setTextFormat(Qt.TextFormat.RichText)
        self.john.setOpenExternalLinks(True)
        lay.addWidget(self.john)
        form = QHBoxLayout()
        self.min_len = QSpinBox()
        self.min_len.setRange(1, 128)
        self.min_len.setValue(12)
        self.classes = QSpinBox()
        self.classes.setRange(1, 4)
        self.classes.setValue(3)
        self.repeat = QSpinBox()
        self.repeat.setRange(1, 10)
        self.repeat.setValue(3)
        self.seq = QCheckBox("Forbid sequences")
        self.seq.setChecked(True)
        self.userpass = QCheckBox("Lines are username:password")
        for label, w in (("Min length", self.min_len), ("Classes", self.classes), ("Max repeat", self.repeat)):
            form.addWidget(QLabel(label))
            form.addWidget(w)
        form.addWidget(self.seq)
        form.addWidget(self.userpass)
        form.addStretch(1)
        lay.addLayout(form)
        row = QHBoxLayout()
        load = MatrixButton("Load candidates from file…", icon_name="folder")
        load.clicked.connect(self._load_file)
        bl = MatrixButton("Choose blocklist…")
        bl.clicked.connect(self._load_blocklist)
        self.bl_lbl = QLabel("No blocklist")
        self.bl_lbl.setObjectName("muted")
        run = MatrixButton("Evaluate", "primary", "installed")
        run.clicked.connect(self._evaluate)
        clear = MatrixButton("Clear input")
        clear.clicked.connect(lambda: self.input.clear())
        for x in (load, bl, self.bl_lbl, run, clear):
            row.addWidget(x)
        row.addStretch(1)
        lay.addLayout(row)
        self.input = QPlainTextEdit()
        self.input.setPlaceholderText("One candidate per line (synthetic test passwords recommended)")
        self.input.setMaximumHeight(150)
        lay.addWidget(self.input)
        self.summary = QTextBrowser()
        self.summary.setMaximumHeight(130)
        lay.addWidget(self.summary)
        self.table = make_table(["Entry", "Result", "Violations"])
        lay.addWidget(self.table, 1)
        bottom = QHBoxLayout()
        self.bar = ProjectBar(app)
        save = MatrixButton("Save summary as a finding")
        save.clicked.connect(self._save_finding)
        bottom.addWidget(self.bar, 1)
        bottom.addWidget(save)
        lay.addLayout(bottom)
        self.msg = QLabel("")
        self.msg.setObjectName("muted")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self._john_status()

    def _john_status(self) -> None:
        s = self.app.tools.cached("john") or self.app.tools.scan_tool("john")
        self.john.setText(f"John the Ripper: <b>{'installed ' + esc(s.version or '') if s.installed else 'not installed'}</b>"
                          f" — WIFI Center does not run it; evaluation is done by the built-in policy engine. "
                          f"<a href='{esc(s.profile.docs_url)}'>Documentation</a>")

    def _policy(self) -> pp.Policy:
        return pp.Policy(min_length=self.min_len.value(), min_classes=self.classes.value(),
                         max_repeat=self.repeat.value(), forbid_sequences=self.seq.isChecked())

    def _load_file(self) -> None:
        name, _ = QFileDialog.getOpenFileName(self, "Candidate passwords", "", "Text (*.txt *.lst *.csv);;All files (*)")
        if name:
            p = Path(name)
            if p.stat().st_size > 20 * 1024 * 1024:
                self.msg.setText("File too large (limit 20 MiB).")
                return
            self.input.setPlainText(p.read_text(encoding="utf-8", errors="replace"))

    def _load_blocklist(self) -> None:
        name, _ = QFileDialog.getOpenFileName(self, "Blocklist (approved dataset)", "", "Text (*.txt *.lst);;All files (*)")
        if name:
            self._blocklist = pp.load_blocklist(Path(name))
            self.bl_lbl.setText(f"{len(self._blocklist):,} entries from {Path(name).name}")

    def _evaluate(self) -> None:
        entries = pp.parse_entries(self.input.toPlainText(), self.userpass.isChecked())
        if not entries:
            self.msg.setText("Enter or load at least one candidate.")
            return
        rep = pp.audit(entries, self._policy(), self._blocklist)
        self._report = rep
        self.summary.setPlainText(pp.summary_text(rep) + ("\n(Stopped at the entry limit.)" if rep.truncated else ""))
        shown = [r for r in rep.results if not r.passed][:2000] or rep.results[:200]
        self.table.setRowCount(len(shown))
        for i, r in enumerate(shown):
            vals = [r.label, "meets policy" if r.passed else "fails", ", ".join(pp.RULES[v] for v in r.violations)]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 1:
                    item.setForeground(QColor(T.success if r.passed else T.danger))
                self.table.setItem(i, c, item)
        self.app.audit.record("password.audit", entries=rep.total, failed=rep.failed)   # counts only
        self.msg.setText("Evaluated. The candidate text is still in the box above; use “Clear input” when done.")

    def _save_finding(self) -> None:
        pid = self.bar.project_id()
        if not self._report or not pid:
            self.msg.setText("Evaluate first and choose a project.")
            return
        rep = self._report
        sev = "high" if rep.total and rep.failed / rep.total > 0.5 else "medium" if rep.failed else "info"
        self.app.projects.add_finding(pid, "Password policy evaluation", sev, pp.summary_text(rep),
                                      "Enforce the policy at password creation; consider a blocklist.", "policy-audit")
        self.app.audit.record("finding.add", project=pid, source="policy-audit")
        self.msg.setText("Saved the aggregate summary as a finding (no password text included).")
