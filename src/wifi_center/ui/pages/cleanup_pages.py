"""System Cleanup (scan, explain, preview, dry-run, confirm) and Maintenance History."""
from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QSplitter, QTableWidgetItem,
                               QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services.cleanup_service import CategoryScan, CleanResult
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.components import LoadingIndicator, MatrixButton
from ..design.tokens import T
from ..widgets import human_bytes
from .netsec_common import confirm_dialog

esc = html.escape
PREVIEW_LIMIT = 200


class CleanupPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._scans: list[CategoryScan] = []
        self._summary_html = ""
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("System Cleanup")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("scan", 24)
        head.addWidget(self.loader)
        head.addStretch(1)
        lay.addLayout(head)
        note = QLabel("Scan first, read why each category is considered safe, preview the exact candidates, then choose. "
                      "Documents, settings, projects and active application data are never scanned. Dry run is on by default.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        top = QHBoxLayout()
        self.b_scan = MatrixButton("Scan system", "primary", "discovery")
        self.b_scan.clicked.connect(self.scan)
        self.dry = QCheckBox("Dry run (show what would be removed, remove nothing)")
        self.dry.setChecked(True)
        self.b_clean = MatrixButton("Clean selected…", "danger")
        self.b_clean.clicked.connect(self.clean)
        self.total = QLabel("")
        top.addWidget(self.b_scan)
        top.addWidget(self.dry)
        top.addStretch(1)
        top.addWidget(self.total)
        top.addWidget(self.b_clean)
        lay.addLayout(top)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Category / candidate", "Items", "Size", "Needs root"])
        self.tree.setColumnWidth(0, 360)
        self.tree.itemChanged.connect(self._totals)
        self.tree.currentItemChanged.connect(self._select)
        split.addWidget(self.tree)
        self.detail = QTextBrowser()
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 1)
        self.msg = QLabel("Press “Scan system” to look for candidates. Nothing is removed by scanning.")
        self.msg.setWordWrap(True)
        self.msg.setObjectName("muted")
        lay.addWidget(self.msg)
        self.b_clean.setEnabled(False)

    # ---------------------------------------------------------------- scan
    def scan(self) -> None:
        self.b_scan.setEnabled(False)
        self.loader.start()
        self.msg.setText("Scanning…")
        run_in_background(self.app.cleanup.scan, self._scanned, lambda e: (self.loader.stop(), self.b_scan.setEnabled(True),
                                                                           self.msg.setText(f"Scan failed: {e}")))

    def _scanned(self, scans: list[CategoryScan]) -> None:
        self.loader.stop()
        self.b_scan.setEnabled(True)
        self._scans = scans
        self.tree.blockSignals(True)
        self.tree.clear()
        for s in scans:
            c = s.category
            top = QTreeWidgetItem([c.title, f"{s.count}{'+' if s.truncated else ''}", human_bytes(s.total_size) if s.total_size else "—",
                                   "yes" if c.needs_root else "no"])
            top.setData(0, Qt.ItemDataRole.UserRole, c.id)
            usable = s.available and s.count > 0
            top.setFlags(top.flags() | Qt.ItemFlag.ItemIsUserCheckable if usable else top.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
            if usable:
                top.setCheckState(0, Qt.CheckState.Checked if c.default_selected else Qt.CheckState.Unchecked)
            else:
                top.setForeground(0, QColor(T.text_muted))
            for cand in s.items[:PREVIEW_LIMIT]:
                child = QTreeWidgetItem([cand.path, "", human_bytes(cand.size) if cand.size else "", ""])
                child.setFlags(child.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
                top.addChild(child)
            if s.count > PREVIEW_LIMIT:
                more = QTreeWidgetItem([f"… and {s.count - PREVIEW_LIMIT} more (all are included when the category is selected)"])
                more.setForeground(0, QColor(T.text_muted))
                top.addChild(more)
            self.tree.addTopLevelItem(top)
        self.tree.blockSignals(False)
        self._totals()
        found = sum(s.count for s in scans)
        scan_text = (f"Scan finished: {found} candidate(s) in {sum(1 for s in scans if s.count)} categories." if found
                     else "Nothing to clean up (or the locations were not found on this system).")
        # keep the result of the cleanup that triggered this rescan visible above the fresh scan summary
        self.msg.setText((self._summary_html + "<br>" if self._summary_html else "") + esc(scan_text))
        self._summary_html = ""
        if self.tree.topLevelItemCount():
            self.tree.setCurrentItem(self.tree.topLevelItem(0))

    def _selected_ids(self) -> list[str]:
        out = []
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            if it.flags() & Qt.ItemFlag.ItemIsUserCheckable and it.checkState(0) == Qt.CheckState.Checked:
                out.append(it.data(0, Qt.ItemDataRole.UserRole))
        return out

    def _totals(self) -> None:
        ids = set(self._selected_ids())
        size = sum(s.total_size for s in self._scans if s.category.id in ids)
        count = sum(s.count for s in self._scans if s.category.id in ids)
        self.total.setText(f"Selected: {count} item(s), about {human_bytes(size)} recoverable" if ids else "Nothing selected")
        self.b_clean.setEnabled(bool(ids))

    def _select(self, cur, _prev=None) -> None:
        if cur is None:
            return
        top = cur.parent() or cur
        cid = top.data(0, Qt.ItemDataRole.UserRole)
        s = next((x for x in self._scans if x.category.id == cid), None)
        if not s:
            return
        c = s.category
        extra = (f"<p style='color:{T.warning}'>Needs root: this application cannot remove these itself. They are handed "
                 "to the privileged helper (Phase 8) after your confirmation.</p>" if c.needs_root else
                 f"<p style='color:{T.success}'>Owned by you: removed by WIFI Center after confirmation.</p>")
        status = ("" if s.available else f"<p style='color:{T.text_secondary}'>Not available on this system"
                  + (f": {esc(s.note)}" if s.note else ".") + "</p>")
        self.detail.setHtml(f"<h3>{esc(c.title)}</h3><p><b>Why this is considered safe:</b> {esc(c.why_safe)}</p>{extra}{status}"
                            f"<p>{s.count} candidate(s), {human_bytes(s.total_size)}{' ' + esc(s.note) if s.note and s.available else ''}</p>")

    # ---------------------------------------------------------------- clean
    def clean(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        dry = self.dry.isChecked()
        chosen = [s for s in self._scans if s.category.id in ids]
        lines = "".join(f"<li>{esc(s.category.title)}: {s.count} item(s), {human_bytes(s.total_size)}"
                        f"{' (needs the privileged helper)' if s.category.needs_root else ''}</li>" for s in chosen)
        text = (f"<p><b>{'Dry run: nothing will be removed.' if dry else 'This permanently removes the files below.'}</b></p>"
                f"<ul>{lines}</ul><p style='color:{T.text_secondary}'>Total about "
                f"{human_bytes(sum(s.total_size for s in chosen))}.</p>")
        if not confirm_dialog(self, "Dry run" if dry else "Confirm cleanup", text, "Run dry run" if dry else "Remove files",
                              None if dry else "I reviewed the categories and understand the files are deleted.", danger=not dry):
            return
        self.loader.start()
        self.b_clean.setEnabled(False)
        self.app.audit.record("cleanup.run", categories=ids, dry_run=dry)

        def done(results: list[CleanResult]) -> None:
            self.loader.stop()
            self._summary(results, dry)
            self.scan()
        run_in_background(lambda: self.app.cleanup.clean(self._scans, ids, dry_run=dry), done,
                          lambda e: (self.loader.stop(), self.msg.setText(f"Cleanup failed: {e}")))

    def _summary(self, results: list[CleanResult], dry: bool) -> None:
        removed = sum(r.removed for r in results)
        freed = sum(r.freed for r in results)
        problems = [e for r in results for e in r.errors]
        blocked = [r for r in results if not r.executed]
        lines = [f"{'Would remove' if dry else 'Removed'} {removed} item(s), about {human_bytes(freed)}."]
        if blocked:
            lines.append(f"{len(blocked)} categor{'y' if len(blocked) == 1 else 'ies'} need the privileged helper and were "
                         "not changed.")
        if problems:
            lines.append(f"{len(problems)} problem(s), e.g. {problems[0]}")
        self._summary_html = f"<span style='color:{T.warning if problems or blocked else T.success}'>{esc(' '.join(lines))}</span>"
        self.msg.setText(self._summary_html)


class MaintenancePage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Maintenance History")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        self.kind = QComboBox()
        self.kind.addItems(["All operations", "upgrade", "update", "install", "remove", "cleanup"])
        self.kind.currentIndexChanged.connect(self.reload)
        self.result = QComboBox()
        self.result.addItems(["All results", "success", "failed", "cancelled", "not executed", "dry run"])
        self.result.currentIndexChanged.connect(self.reload)
        exp = MatrixButton("Export…", icon_name="docs")
        exp.clicked.connect(self._export)
        for w in (self.kind, self.result, exp):
            head.addWidget(w)
        lay.addLayout(head)
        self.table = make_table(["Operation", "Type", "Started", "Finished", "Result", "Packages / files", "Errors"],
                                stretch_col=6)
        self.table.itemSelectionChanged.connect(self._select)
        lay.addWidget(self.table, 2)
        self.detail = QTextBrowser()
        self.detail.setMaximumHeight(160)
        lay.addWidget(self.detail, 1)
        self.msg = QLabel("Only maintenance performed or proposed through WIFI Center is recorded here.")
        self.msg.setObjectName("muted")
        lay.addWidget(self.msg)
        self._rows: list[dict] = []
        self.reload()

    def showEvent(self, e) -> None:  # noqa: N802
        super().showEvent(e)
        self.reload()

    def reload(self) -> None:
        op = None if self.kind.currentIndex() == 0 else self.kind.currentText()
        res = None if self.result.currentIndex() == 0 else self.result.currentText()
        self._rows = self.app.maintenance.entries(op, res)
        self.table.setRowCount(len(self._rows))
        colors = {"success": T.success, "failed": T.danger, "cancelled": T.warning, "not executed": T.warning,
                  "dry run": T.info}
        for r, e in enumerate(self._rows):
            pk = (e["packages_changed"] or "").replace("\n", ", ")
            vals = [e["name"], e["op_type"], fmt_ts(e["started_at"]), fmt_ts(e["finished_at"]), e["result"] or "",
                    pk[:100] or (f"{e['files_removed']} files" if e["files_removed"] is not None else ""),
                    (e["errors"] or "").replace("\n", " ")[:120]]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 4:
                    item.setForeground(QColor(colors.get(e["result"], T.text)))
                self.table.setItem(r, c, item)
        self._select()

    def _select(self) -> None:
        r = self.table.currentRow()
        if not (0 <= r < len(self._rows)):
            self.detail.setHtml(f"<p style='color:{T.text_secondary}'>Select an entry.</p>")
            return
        e = self._rows[r]
        self.detail.setHtml(f"<h3>{esc(e['name'])}</h3><p>Result: <b>{esc(e['result'] or '')}</b></p>"
                            f"<p><b>Packages changed</b><br>{esc(e['packages_changed'] or 'none').replace(chr(10), '<br>')}</p>"
                            f"<p><b>Files removed:</b> {e['files_removed'] if e['files_removed'] is not None else 'n/a'}</p>"
                            f"<p><b>Errors</b><br>{esc(e['errors'] or 'none').replace(chr(10), '<br>')}</p>")

    def _export(self) -> None:
        name, _ = QFileDialog.getSaveFileName(self, "Export maintenance history", str(Path.home() / "maintenance-history.csv"),
                                              "CSV (*.csv);;JSON (*.json)")
        if name:
            fmt = "json" if name.lower().endswith(".json") else "csv"
            Path(name).write_text(self.app.maintenance.export(fmt), encoding="utf-8")
            self.app.audit.record("maintenance.export", path=name)
            self.msg.setText(f"Exported to {name}")
