"""Network Discovery (scoped Nmap workflow, imports, history, comparison) and Network Mapping."""
from __future__ import annotations

import html
import re
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
                               QPlainTextEdit, QSplitter, QTabWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout,
                               QWidget)

from ...application.app_controller import AppController
from ...integrations.nmap_args import SCAN_PROFILES
from ...security.input_validation import ValidationError
from ...security.operation_policy import PolicyViolation
from ...services.network_inventory import NetNode, Topology
from ...services.nmap_parsers import ParseError
from ...services.nmap_service import PlannedScan
from ...services.project_service import ScopeError
from ..charts import fmt_ts, make_table
from ..design.components import LoadingIndicator, MatrixButton
from ..design.tokens import T
from ..topology import TopologyView
from .netsec_common import ProjectBar, confirm_dialog

esc = html.escape


class NetworkDiscoveryPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._planned: PlannedScan | None = None
        self._op_id: int | None = None
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Network Discovery")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("scan", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        lay.addLayout(head)
        self.bar = ProjectBar(app)
        self.bar.project_changed.connect(self._project_changed)
        lay.addWidget(self.bar)
        note = QLabel("Scans run only against targets inside the project's authorized scope, after you confirm. "
                      "Approved profiles only: no scripts, no OS fingerprinting, no spoofing.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._scan_tab(), "Scan")
        self.tabs.addTab(self._scope_tab(), "Authorized scope")
        self.tabs.addTab(self._results_tab(), "Results")
        self.tabs.addTab(self._history_tab(), "History and comparison")
        lay.addWidget(self.tabs, 1)
        self._project_changed(self.bar.project_id() or 0)

    # ---------------- helpers ----------------
    def _pid(self) -> int | None:
        return self.bar.project_id()

    def _project_changed(self, _pid: int) -> None:
        self._reload_scope()
        self._reload_scans()
        self._update_scan_state()

    def _nmap_installed(self) -> bool:
        st = self.app.tools.cached("nmap") or self.app.tools.scan_tool("nmap")
        return st.installed

    def _update_scan_state(self) -> None:
        installed = self._nmap_installed()
        has_scope = bool(self._pid() and self.app.projects.scope(self._pid()))
        self.start_btn.setEnabled(installed and has_scope and self._op_id is None)
        if not installed:
            self.scan_msg.setText("Nmap is not installed (sudo apt install nmap). You can still import existing results.")
        elif not self._pid():
            self.scan_msg.setText("Create or select a project first.")
        elif not has_scope:
            self.scan_msg.setText("Add the targets you are authorized to scan on the “Authorized scope” tab first.")
        elif self._op_id is None:
            self.scan_msg.setText("")

    # ---------------- scan tab ----------------
    def _scan_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        self.targets = QLineEdit()
        self.targets.setPlaceholderText("Targets inside the scope: 10.0.0.0/24 10.0.1.5 host.example.com")
        self.profile = QComboBox()
        for key, (title, desc, _flags) in SCAN_PROFILES.items():
            self.profile.addItem(title, key)
            self.profile.setItemData(self.profile.count() - 1, desc, Qt.ItemDataRole.ToolTipRole)
        self.start_btn = MatrixButton("Review and start scan…", "primary", "discovery")
        self.start_btn.clicked.connect(self._review_scan)
        self.cancel_btn = MatrixButton("Cancel scan", "danger")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel)
        row.addWidget(self.targets, 3)
        row.addWidget(self.profile, 1)
        row.addWidget(self.start_btn)
        row.addWidget(self.cancel_btn)
        lay.addLayout(row)
        self.profile_desc = QLabel(SCAN_PROFILES["discovery"][1])
        self.profile_desc.setObjectName("muted")
        self.profile.currentIndexChanged.connect(
            lambda: self.profile_desc.setText(SCAN_PROFILES[self.profile.currentData()][1]))
        lay.addWidget(self.profile_desc)
        self.scan_msg = QLabel("")
        self.scan_msg.setWordWrap(True)
        lay.addWidget(self.scan_msg)
        self.live = QPlainTextEdit()
        self.live.setReadOnly(True)
        self.live.setPlaceholderText("Live scan output appears here.")
        self.live.setStyleSheet(f"font-family: {T.mono_stack};")
        lay.addWidget(self.live, 1)
        imp = QHBoxLayout()
        b = MatrixButton("Import existing results…", icon_name="folder")
        b.setToolTip("Nmap XML (-oX), normal (-oN) or grepable (-oG) output")
        b.clicked.connect(self._import)
        imp.addWidget(b)
        imp.addStretch(1)
        lay.addLayout(imp)
        return w

    def _review_scan(self) -> None:
        pid = self._pid()
        targets = [t for t in re.split(r"[\s,;]+", self.targets.text().strip()) if t]
        integ = self.app.tools.integration("nmap")
        try:  # dry plan first: scope + syntax errors are shown before any confirmation is requested
            planned = self.app.nmap.plan_scan(integ, pid or 0, targets, self.profile.currentData(), confirmed=True)
        except (ScopeError, ValidationError, ValueError, PolicyViolation) as e:
            self.scan_msg.setText(f"<span style='color:{T.danger}'>Cannot start: {esc(str(e))}</span>")
            return
        proj = self.app.projects.get(pid)
        title, desc, _ = SCAN_PROFILES[planned.profile]
        text = (f"<b>Scan project “{esc(proj['name'])}”</b><br><br>Targets: <b>{esc(', '.join(planned.targets))}</b><br>"
                f"Profile: {esc(title)} — {esc(desc)}<br><br>All targets are inside the project's authorized scope.<br>"
                "Scanning generates network traffic that may be logged or alarm monitoring systems.")
        if not confirm_dialog(self, "Confirm scan", text, "Start scan",
                              "I am authorized to scan these targets and accept the traffic this generates."):
            self.scan_msg.setText("Scan cancelled.")
            return
        self.app.audit.record("scan.confirmed", project=pid, targets=planned.targets, profile=planned.profile)
        self._run(planned)

    def _run(self, planned: PlannedScan) -> None:
        st = self.app.tools.cached("nmap")
        try:
            op_id = self.app.operations.start(st.profile, planned.request, f"Nmap {planned.profile}: "
                                              + " ".join(planned.targets))
        except PolicyViolation as e:
            self.scan_msg.setText(f"Refused by policy: {e}")
            return
        self._planned, self._op_id = planned, op_id
        self.live.clear()
        self.loader.start()
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.scan_msg.setText("Scanning…")
        ops = self.app.operations
        ops.output.connect(self._on_output)
        ops.finished.connect(self._on_finished)

    def _on_output(self, op_id: int, stream: str, line: str) -> None:
        if op_id == self._op_id:
            self.live.appendPlainText(line)

    def _cancel(self) -> None:
        if self._op_id is not None:
            self.app.operations.cancel(self._op_id)

    def _on_finished(self, op_id: int, status: str) -> None:
        if op_id != self._op_id:
            return
        ops = self.app.operations
        ops.output.disconnect(self._on_output)
        ops.finished.disconnect(self._on_finished)
        planned, self._op_id, self._planned = self._planned, None, None
        self.loader.stop()
        self.cancel_btn.setEnabled(False)
        msg = f"Scan {status}."
        if status == "succeeded" and planned:
            try:
                sid = self.app.nmap.finish_planned(planned)
                msg = f"Scan complete: results saved as scan #{sid}."
                self._reload_scans()
                self.tabs.setCurrentIndex(2)
            except (ParseError, OSError) as e:
                msg = f"Scan finished but its results could not be imported: {e}"
        self._update_scan_state()
        self.scan_msg.setText(msg)   # after the refresh, which may clear its own hints

    def _import(self) -> None:
        name, _ = QFileDialog.getOpenFileName(self, "Import Nmap results", "",
                                              "Nmap results (*.xml *.nmap *.gnmap *.txt);;All files (*)")
        if not name:
            return
        try:
            sid = self.app.nmap.import_file(name, self._pid())
        except (ParseError, ValidationError, OSError) as e:
            self.scan_msg.setText(f"<span style='color:{T.danger}'>Import failed: {esc(str(e))}</span>")
            return
        self.app.audit.record("scan.import", path=name, scan=sid)
        self.scan_msg.setText(f"Imported as scan #{sid}.")
        self._reload_scans()

    # ---------------- scope tab ----------------
    def _scope_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        info = QLabel("Only hosts and networks listed here can be scanned. Names are matched exactly (no DNS lookups).")
        info.setObjectName("muted")
        info.setWordWrap(True)
        lay.addWidget(info)
        self.scope_table = make_table(["Target", "Type", "Note", "Added"])
        lay.addWidget(self.scope_table, 1)
        row = QHBoxLayout()
        self.scope_input = QLineEdit()
        self.scope_input.setPlaceholderText("IP, CIDR network or hostname you are authorized to test")
        add = MatrixButton("Add to scope", "primary")
        add.clicked.connect(self._add_scope)
        rm = MatrixButton("Remove selected")
        rm.clicked.connect(self._remove_scope)
        for x in (self.scope_input, add, rm):
            row.addWidget(x)
        lay.addLayout(row)
        self.scope_msg = QLabel("")
        self.scope_msg.setWordWrap(True)
        lay.addWidget(self.scope_msg)
        return w

    def _reload_scope(self) -> None:
        rows = self.app.projects.scope(self._pid()) if self._pid() else []
        self.scope_table.setRowCount(len(rows))
        for r, e in enumerate(rows):
            for c, v in enumerate([e["target"], e["kind"], e["note"] or "", fmt_ts(e["added_at"].replace(" ", "T") + "+00:00")]):
                self.scope_table.setItem(r, c, QTableWidgetItem(v))

    def _add_scope(self) -> None:
        if not self._pid():
            self.scope_msg.setText("Create a project first.")
            return
        try:
            v = self.app.projects.add_scope(self._pid(), self.scope_input.text())
        except ValidationError as e:
            self.scope_msg.setText(f"<span style='color:{T.danger}'>{esc(str(e))}</span>")
            return
        self.app.audit.record("scope.add", project=self._pid(), target=v)
        self.scope_input.clear()
        self.scope_msg.setText(f"Added {v}.")
        self._reload_scope()
        self._update_scan_state()

    def _remove_scope(self) -> None:
        r = self.scope_table.currentRow()
        item = self.scope_table.item(r, 0) if r >= 0 else None
        if item and self._pid():
            self.app.projects.remove_scope(self._pid(), item.text())
            self.app.audit.record("scope.remove", project=self._pid(), target=item.text())
            self._reload_scope()
            self._update_scan_state()

    # ---------------- results tab ----------------
    def _results_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        top = QHBoxLayout()
        self.scan_pick = QComboBox()
        self.scan_pick.currentIndexChanged.connect(self._show_scan)
        exp = MatrixButton("Export…", icon_name="docs")
        exp.clicked.connect(self._export)
        top.addWidget(QLabel("Scan"))
        top.addWidget(self.scan_pick, 1)
        top.addWidget(exp)
        lay.addLayout(top)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.host_table = make_table(["Address", "Hostname", "MAC", "Vendor", "Status", "Open ports"])
        self.host_table.setSortingEnabled(True)
        self.host_table.itemSelectionChanged.connect(self._show_host)
        self.host_detail = QTextBrowser()
        split.addWidget(self.host_table)
        split.addWidget(self.host_detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 1)
        self.result_msg = QLabel("")
        self.result_msg.setObjectName("muted")
        lay.addWidget(self.result_msg)
        self._hosts: list[dict] = []
        return w

    def _reload_scans(self) -> None:
        scans = self.app.nmap.scans(self._pid())
        self.scan_pick.blockSignals(True)
        self.scan_pick.clear()
        for s in scans:
            self.scan_pick.addItem(f"#{s['id']} · {s['kind']} · {s['target'] or s['source_file'] or ''} · "
                                   f"{s['host_count']} hosts · {fmt_ts(s['imported_at'].replace(' ', 'T') + '+00:00')}",
                                   s["id"])
        self.scan_pick.blockSignals(False)
        self._reload_history(scans)
        self._show_scan()

    def _scan_id(self) -> int | None:
        return self.scan_pick.currentData()

    def _show_scan(self) -> None:
        sid = self._scan_id()
        self._hosts = self.app.nmap.hosts(sid) if sid else []
        self.host_table.setSortingEnabled(False)
        self.host_table.setRowCount(len(self._hosts))
        for r, h in enumerate(self._hosts):
            opens = [p for p in h["ports"] if p["state"] == "open"]
            vals = [h["address"], h["hostname"] or "", h["mac"] or "", h["vendor"] or "", h["status"], str(len(opens))]
            for c, v in enumerate(vals):
                self.host_table.setItem(r, c, QTableWidgetItem(v))
        self.host_table.setSortingEnabled(True)
        self.host_detail.setHtml("" if self._hosts else f"<p style='color:{T.text_secondary}'>No results yet. Run a "
                                 "scan or import existing results.</p>")

    def _show_host(self) -> None:
        r = self.host_table.currentRow()
        item = self.host_table.item(r, 0) if r >= 0 else None
        h = next((x for x in self._hosts if item and x["address"] == item.text()), None)
        if not h:
            return
        rows = "".join(
            f"<tr><td>{p['port']}/{p['proto']}</td><td>{esc(p['state'])}</td><td>{esc(p['service'] or '')}</td>"
            f"<td>{esc(' '.join(x for x in (p['product'], p['version']) if x))}</td></tr>" for p in h["ports"])
        self.host_detail.setHtml(
            f"<h3>{esc(h['address'])}</h3><p style='color:{T.text_secondary}'>{esc(h['hostname'] or '')} "
            f"{esc(h['os_guess'] or '')}</p><table cellpadding='4'><tr><th>Port</th><th>State</th><th>Service</th>"
            f"<th>Version</th></tr>{rows}</table>" if h["ports"] else f"<h3>{esc(h['address'])}</h3><p>No port data "
            "(host discovery only).</p>")

    def _export(self) -> None:
        sid = self._scan_id()
        if not sid:
            return
        name, _ = QFileDialog.getSaveFileName(self, "Export scan", str(Path.home() / f"scan-{sid}.csv"),
                                              "CSV (*.csv);;JSON (*.json)")
        if name:
            fmt = "json" if name.lower().endswith(".json") else "csv"
            Path(name).write_text(self.app.nmap.export(sid, fmt), encoding="utf-8")
            self.app.audit.record("scan.export", scan=sid, path=name)
            self.result_msg.setText(f"Exported to {name}")

    # ---------------- history tab ----------------
    def _history_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.history = make_table(["#", "Kind", "Target / file", "Hosts", "Imported"])
        lay.addWidget(self.history, 1)
        row = QHBoxLayout()
        self.cmp_a, self.cmp_b = QComboBox(), QComboBox()
        cmp_btn = MatrixButton("Compare", "primary")
        cmp_btn.clicked.connect(self._compare)
        dele = MatrixButton("Delete selected scan…")
        dele.clicked.connect(self._delete_scan)
        for x in (QLabel("Older"), self.cmp_a, QLabel("Newer"), self.cmp_b, cmp_btn, dele):
            row.addWidget(x)
        lay.addLayout(row)
        self.diff_view = QTextBrowser()
        lay.addWidget(self.diff_view, 1)
        return w

    def _reload_history(self, scans: list[dict]) -> None:
        self.history.setRowCount(len(scans))
        for r, s in enumerate(scans):
            for c, v in enumerate([str(s["id"]), s["kind"], s["target"] or s["source_file"] or "", str(s["host_count"]),
                                   fmt_ts(s["imported_at"].replace(" ", "T") + "+00:00")]):
                self.history.setItem(r, c, QTableWidgetItem(v))
        for box in (self.cmp_a, self.cmp_b):
            box.clear()
            for s in scans:
                box.addItem(f"#{s['id']} ({s['host_count']} hosts)", s["id"])
        if len(scans) >= 2:
            self.cmp_a.setCurrentIndex(1)
            self.cmp_b.setCurrentIndex(0)

    def _compare(self) -> None:
        a, b = self.cmp_a.currentData(), self.cmp_b.currentData()
        if not a or not b or a == b:
            self.diff_view.setHtml("<p>Choose two different scans.</p>")
            return
        d = self.app.nmap.compare(a, b)
        if d.is_empty:
            self.diff_view.setHtml(f"<p style='color:{T.success}'>No differences in live hosts or open ports.</p>")
            return
        h = [f"<h3>Scan #{a} → #{b}</h3>"]
        if d.new_hosts:
            h.append(f"<p style='color:{T.success}'><b>New hosts:</b> {esc(', '.join(d.new_hosts))}</p>")
        if d.gone_hosts:
            h.append(f"<p style='color:{T.warning}'><b>Hosts no longer seen:</b> {esc(', '.join(d.gone_hosts))}</p>")
        for c in d.changes:
            parts = [f"+ {x}" for x in c["opened"]] + [f"− {x}" for x in c["closed"]] + \
                    [f"~ {k}: {o} → {n}" for k, o, n in c["changed"]]
            h.append(f"<p><b>{esc(c['address'])}</b><br>{'<br>'.join(esc(p) for p in parts)}</p>")
        self.diff_view.setHtml("".join(h))

    def _delete_scan(self) -> None:
        r = self.history.currentRow()
        item = self.history.item(r, 0) if r >= 0 else None
        if not item:
            return
        if confirm_dialog(self, "Delete scan", f"Delete scan #{item.text()} from the database?<br>"
                          "Inventory entries and files on disk are not removed.", "Delete", danger=True):
            self.app.nmap.delete_scan(int(item.text()))
            self.app.audit.record("scan.delete", scan=int(item.text()))
            self._reload_scans()


class NetworkMappingPage(QWidget):
    """Topology of the hosts from a chosen scan, centred on this computer."""

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Network Mapping")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        head.addStretch(1)
        lay.addLayout(head)
        top = QHBoxLayout()
        self.bar = ProjectBar(app)
        self.bar.project_changed.connect(self._reload_scans)
        self.scan_pick = QComboBox()
        self.scan_pick.setMinimumWidth(300)
        self.scan_pick.currentIndexChanged.connect(self._draw)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search hosts…")
        self.search.textChanged.connect(lambda t: self.view.set_filter(t))
        export = MatrixButton("Export nodes…", icon_name="docs")
        export.clicked.connect(self._export)
        top.addWidget(self.bar)
        top.addWidget(self.scan_pick)
        top.addWidget(self.search)
        top.addWidget(export)
        lay.addLayout(top)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.view = TopologyView()
        self.view.node_selected.connect(self._selected)
        self.view.discover_requested.connect(self._reload_scans)
        self.view.empty_btn.setText("Reload scans")
        self.detail = QTextBrowser()
        split.addWidget(self.view)
        split.addWidget(self.detail)
        self.detail.setMinimumWidth(260)
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 1)
        split.setSizes([1100, 320])
        lay.addWidget(split, 1)
        self.msg = QLabel("Map of hosts from stored scan results. Import or run a scan under Network Discovery.")
        self.msg.setObjectName("muted")
        lay.addWidget(self.msg)
        self._topo: Topology | None = None
        self._reload_scans()

    def showEvent(self, e) -> None:  # noqa: N802
        super().showEvent(e)
        self._reload_scans()   # pick up scans imported elsewhere

    def _reload_scans(self, *_a) -> None:
        pid = self.bar.project_id()
        scans = self.app.nmap.scans(pid)
        self.scan_pick.blockSignals(True)
        self.scan_pick.clear()
        for s in scans:
            self.scan_pick.addItem(f"#{s['id']} · {s['target'] or s['source_file'] or s['kind']} · {s['host_count']} hosts", s["id"])
        self.scan_pick.blockSignals(False)
        self._draw()

    def _draw(self) -> None:
        sid = self.scan_pick.currentData()
        me = NetNode("self", "This computer", None, "self", "self", source="local")
        nodes, edges = [me], []
        for h in self.app.nmap.hosts(sid) if sid else []:
            if h["status"] != "up":
                continue
            services = [f"{p['port']}/{p['proto']} {p['service'] or ''}".strip() for p in h["ports"] if p["state"] == "open"]
            nodes.append(NetNode(h["address"], h["hostname"] or h["address"], h["address"], "host", "reachable",
                                 h["mac"] or None, h["vendor"] or None, h["os_guess"] or None, "nmap", None, services))
            edges.append(("self", h["address"]))
        self._topo = Topology(nodes, edges)
        self.view.set_topology(self._topo)
        self.detail.setHtml(f"<p style='color:{T.text_secondary}'>Select a host.</p>")

    def _selected(self, node: NetNode | None) -> None:
        if not node or node.kind != "host":
            return
        rows = [("Address", node.ip), ("Hostname", node.label if node.label != node.ip else None), ("MAC", node.mac),
                ("Vendor", node.vendor), ("OS guess", node.device_type)]
        body = "".join(f"<tr><td style='color:{T.text_secondary}'>{k}&nbsp;</td><td>{esc(str(v))}</td></tr>"
                       for k, v in rows if v)
        svc = "".join(f"<li>{esc(s)}</li>" for s in node.services) or "<li>none recorded</li>"
        self.detail.setHtml(f"<table>{body}</table><h4>Open services</h4><ul>{svc}</ul>")

    def _export(self) -> None:
        if not self._topo:
            return
        import json
        name, _ = QFileDialog.getSaveFileName(self, "Export map", str(Path.home() / "network-map.json"), "JSON (*.json)")
        if name:
            data = {"nodes": [n.__dict__ for n in self._topo.nodes], "edges": self._topo.edges}
            Path(name).write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.app.audit.record("map.export", path=name)
            self.msg.setText(f"Exported to {name}")
