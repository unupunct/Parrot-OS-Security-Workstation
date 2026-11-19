"""Network Discovery dashboard: identify the connected network, scan an authorized range, identify devices, see an
evidence-based topology and compare scans. It is the first tab of Network Discovery; the existing Nmap workflow tabs are unchanged.

All work goes through NetworkDiscoveryEngine, which enforces the project scope, the attached-network rule and the size limit."""
from __future__ import annotations

import html
import ipaddress
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
                               QProgressBar, QSpinBox, QSplitter, QTableWidgetItem, QTabWidget, QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services import network_discovery as nd
from ...services.network_inventory import NetNode, Topology
from ...services.net_identity import NetworkIdentity
from ...services.project_service import ScopeError
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.components import MatrixButton, Panel
from ..design.tokens import T
from ..topology import TopologyView
from .netsec_common import confirm_dialog

esc = html.escape
COLS = ["IP", "MAC", "Hostname", "Manufacturer", "Device type", "Response", "Latency", "Status", "First seen", "Last seen", "Notes"]
BASIS_MARK = {"confirmed": "✔ ", "inferred": "~ ", "unknown": "? "}
STATUS_COLOR = {"responded": T.green, "cached": T.warning}


class _Bridge(QObject):
    progress = Signal(int, int, int)
    done = Signal(object)
    failed = Signal(str)


def card(title: str, value: str, sub: str = "", color: str = T.green) -> QFrame:
    f = QFrame()
    f.setObjectName("panel")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(16, 10, 16, 10)
    lay.setSpacing(2)
    t = QLabel(title.upper())
    t.setObjectName("panelTitle")
    v = QLabel(value)
    v.setStyleSheet(f"font-size: 24px; font-weight: 800; color: {color};")
    s = QLabel(sub)
    s.setObjectName("muted")
    s.setWordWrap(True)
    for w in (t, v, s):
        lay.addWidget(w)
    f.value, f.sub = v, s                      # type: ignore[attr-defined]
    return f


class DiscoveryDashboard(QWidget):
    def __init__(self, app: AppController, project_id) -> None:
        super().__init__()
        self.app = app
        self._project_id = project_id                      # callable -> int | None (the page's project bar)
        self.engine: nd.NetworkDiscoveryEngine = app.netdisc
        self.identities: list[NetworkIdentity] = []
        self.hosts: list[nd.HostResult] = []
        self.last_scan: dict | None = None
        self._control: nd.ScanControl | None = None
        self._plan: nd.DiscoveryPlan | None = None
        self._graph: nd.TopologyGraph | None = None
        self._bridge = _Bridge()
        self._bridge.progress.connect(self._on_progress)
        self._bridge.done.connect(self._finished)
        self._bridge.failed.connect(self._scan_failed)

        lay = QVBoxLayout(self)
        cards = QHBoxLayout()
        self.c_gw = card("Gateway", "—", "not identified yet", T.cyan)
        self.c_pot = card("Potential hosts", "—", "usable addresses in the range")
        self.c_found = card("Discovered", "0", "hosts in the shown scan")
        self.c_last = card("Last scan", "never", "", T.text)
        for c in (self.c_gw, self.c_pot, self.c_found, self.c_last):
            cards.addWidget(c, 1)
        lay.addLayout(cards)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        split.addWidget(self._left())
        split.addWidget(self._right())
        split.setStretchFactor(1, 1)
        split.setSizes([400, 900])
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setObjectName("muted")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self.identify()
        self.reload_history()

    # ================================================================== left column
    def _left(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        ident = Panel("Network identification")
        row = QHBoxLayout()
        self.nets = QComboBox()
        self.nets.currentIndexChanged.connect(self._net_changed)
        self.b_ident = MatrixButton("Identify my network", "primary", "discovery")
        self.b_ident.clicked.connect(self.identify)
        row.addWidget(self.nets, 1)
        row.addWidget(self.b_ident)
        rw = QWidget()
        rw.setLayout(row)
        ident.add(rw)
        self.info = QTextBrowser()
        self.info.setFrameShape(QFrame.Shape.NoFrame)
        self.info.setMinimumHeight(190)
        ident.add(self.info, 1)
        lay.addWidget(ident, 3)

        conf = Panel("Scan configuration")
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        self.mode = QComboBox()
        for key, (title, desc) in nd.MODES.items():
            self.mode.addItem(title, key)
            self.mode.setItemData(self.mode.count() - 1, desc, Qt.ItemDataRole.ToolTipRole)
        self.mode.setCurrentIndex(1)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self.cidr = QLineEdit()
        self.cidr.setPlaceholderText("192.168.1.0/24")
        self.cidr.textChanged.connect(self._cidr_changed)
        self.conc = QSpinBox()
        self.conc.setRange(1, 256)
        self.conc.setValue(64)
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(0.2, 10.0)
        self.timeout.setSingleStep(0.2)
        self.timeout.setValue(1.0)
        self.timeout.setSuffix(" s")
        self.v6 = QCheckBox("Include IPv6 neighbour discovery")
        self.v6.setToolTip("Sends an all-nodes link-local echo and reads the IPv6 neighbour table (no addresses are guessed)")
        for r, (lab, wd) in enumerate((("Mode", self.mode), ("Range (CIDR)", self.cidr), ("Concurrency", self.conc), ("Timeout", self.timeout))):
            grid.addWidget(QLabel(lab), r, 0)
            grid.addWidget(wd, r, 1)
        gw = QWidget()
        gw.setLayout(grid)
        conf.add(gw)
        conf.add(self.v6)
        self.mode_desc = QLabel(nd.MODES["full"][1])
        self.mode_desc.setObjectName("muted")
        self.mode_desc.setWordWrap(True)
        conf.add(self.mode_desc)
        self.scope_lbl = QLabel("")
        self.scope_lbl.setWordWrap(True)
        self.scope_lbl.setTextFormat(Qt.TextFormat.RichText)
        conf.add(self.scope_lbl)
        self.b_scope = MatrixButton("Add this range to the authorized scope…")
        self.b_scope.clicked.connect(self._add_scope)
        conf.add(self.b_scope)
        btns = QHBoxLayout()
        self.b_go = MatrixButton("Discover Network…", "primary", "play")
        self.b_go.clicked.connect(self._review)
        self.b_pause = MatrixButton("Pause")
        self.b_pause.clicked.connect(self._pause)
        self.b_cancel = MatrixButton("Cancel", "danger")
        self.b_cancel.clicked.connect(self._cancel)
        for b in (self.b_go, self.b_pause, self.b_cancel):
            btns.addWidget(b)
        bw = QWidget()
        bw.setLayout(btns)
        conf.add(bw)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        conf.add(self.progress)
        self.progress_lbl = QLabel("")
        self.progress_lbl.setObjectName("muted")
        self.progress_lbl.setWordWrap(True)
        conf.add(self.progress_lbl)
        lay.addWidget(conf, 4)
        self._set_running(False)
        return w

    # ================================================================== right column
    def _right(self) -> QWidget:
        self.tabs = QTabWidget()
        # ---- hosts
        hosts = QWidget()
        hl = QVBoxLayout(hosts)
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search IP, MAC, name, manufacturer, type…")
        self.search.textChanged.connect(self._fill_hosts)
        self.f_status = QComboBox()
        self.f_status.addItems(["All statuses", "responded", "cached"])
        self.f_status.currentIndexChanged.connect(self._fill_hosts)
        self.f_type = QComboBox()
        self.f_type.addItem("All device types")
        self.f_type.currentIndexChanged.connect(self._fill_hosts)
        self.b_csv = MatrixButton("CSV")
        self.b_json = MatrixButton("JSON")
        self.b_html = MatrixButton("HTML")
        for b, fmt in ((self.b_csv, "csv"), (self.b_json, "json"), (self.b_html, "html")):
            b.clicked.connect(lambda _=False, f=fmt: self._export(f))
        for wd in (self.search, self.f_status, self.f_type, self.b_csv, self.b_json, self.b_html):
            bar.addWidget(wd)
        bar.setStretch(0, 1)
        hl.addLayout(bar)
        self.table = make_table(COLS)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._select_host)
        hl.addWidget(self.table, 3)
        self.detail = QTextBrowser()
        self.detail.setMinimumHeight(120)
        self.detail.setPlainText("Select a host to see its details and how its type was determined.")
        hl.addWidget(self.detail, 1)
        row = QHBoxLayout()
        self.label = QLineEdit()
        self.label.setPlaceholderText("Your name for this device (saved by MAC address)")
        self.b_label = MatrixButton("Save name")
        self.b_label.clicked.connect(self._save_label)
        self.b_copy = MatrixButton("Copy IP")
        self.b_copy.clicked.connect(self._copy_ip)
        for wd in (self.label, self.b_label, self.b_copy):
            row.addWidget(wd)
        row.setStretch(0, 1)
        hl.addLayout(row)
        self.tabs.addTab(hosts, "Hosts")
        # ---- topology
        topo = QWidget()
        tl = QVBoxLayout(topo)
        self.topo = TopologyView()
        self.topo.node_selected.connect(self._node_selected)
        tl.addWidget(self.topo, 3)
        self.topo_note = QLabel("")
        self.topo_note.setObjectName("muted")
        self.topo_note.setWordWrap(True)
        tl.addWidget(self.topo_note)
        self.topo_detail = QTextBrowser()
        self.topo_detail.setMaximumHeight(140)
        self.topo_detail.setPlainText("Click a node to see its details and the evidence behind its connections.")
        tl.addWidget(self.topo_detail)
        self.tabs.addTab(topo, "Topology")
        # ---- history
        hist = QWidget()
        hy = QVBoxLayout(hist)
        self.hist = make_table(["#", "Started (UTC)", "Interface", "Range", "Mode", "Targets", "Hosts", "Duration", "Status"])
        self.hist.setSelectionMode(self.hist.SelectionMode.ExtendedSelection)
        hy.addWidget(self.hist, 2)
        hrow = QHBoxLayout()
        self.b_view = MatrixButton("Show selected scan")
        self.b_view.clicked.connect(self._show_scan)
        self.b_cmp = MatrixButton("Compare two selected scans")
        self.b_cmp.clicked.connect(self._compare)
        self.b_del = MatrixButton("Delete selected scan…", "danger")
        self.b_del.clicked.connect(self._delete_scan)
        for b in (self.b_view, self.b_cmp, self.b_del):
            hrow.addWidget(b)
        hrow.addStretch(1)
        hy.addLayout(hrow)
        self.cmp_out = QTextBrowser()
        self.cmp_out.setPlainText("Select two scans and press Compare. History is kept until you delete a scan yourself.")
        hy.addWidget(self.cmp_out, 2)
        self.tabs.addTab(hist, "Scan history")
        return self.tabs

    # ================================================================== identification
    def identify(self) -> None:
        self.b_ident.setEnabled(False)
        self.info.setPlainText("Reading interfaces, routes and neighbours…")

        def done(ids: list[NetworkIdentity]) -> None:
            self.b_ident.setEnabled(True)
            self.identities = ids
            keep = self.nets.currentData()
            self.nets.blockSignals(True)
            self.nets.clear()
            for i in ids:
                self.nets.addItem(i.title, i.interface.name)
            self.nets.blockSignals(False)
            idx = self.nets.findData(keep)
            self.nets.setCurrentIndex(idx if idx >= 0 else (next((n for n, i in enumerate(ids) if i.default_route), 0)))
            if not ids:
                self.info.setPlainText("No active IPv4 network was found (no interface is up with a usable address).")
            self._net_changed()
        run_in_background(self.engine.identifier.identify, done, lambda e: (self.b_ident.setEnabled(True), self.info.setPlainText(f"Failed: {e}")))

    def _ident(self) -> NetworkIdentity | None:
        name = self.nets.currentData()
        return next((i for i in self.identities if i.interface.name == name), None)

    def _net_changed(self) -> None:
        i = self._ident()
        if not i:
            self._update_cards()
            return
        itf = i.interface
        mask = str(ipaddress.ip_network(i.cidr).netmask) if i.v4 else "—"
        v6 = ", ".join(a.address for a in itf.v6) or "none"
        rows = [("Interface", f"{itf.name} ({itf.kind})"), ("State", itf.state.upper()), ("MAC address", itf.mac or "—"),
                ("IPv4 address", f"{i.v4.address}/{i.v4.prefixlen}" if i.v4 else "—"), ("Subnet", f"{i.cidr} (mask {mask})"),
                ("Gateway", (i.gateway or "none") + (f" · {i.gateway_mac}" if i.gateway_mac else "")),
                ("DNS", ", ".join(i.dns) or "unknown"), ("IPv6", v6), ("MTU", str(itf.mtu or "—"))]
        self.info.setHtml("<table cellpadding='3'>" + "".join(
            f"<tr><td style='color:{T.text_secondary}'>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in rows) + "</table>"
            f"<p style='color:{T.text_secondary}'>The subnet is calculated from this interface's real prefix length "
            f"(/{i.v4.prefixlen if i.v4 else '?'}), not guessed from the address.</p>")
        self.cidr.setText(i.cidr)                             # auto-populated; editable
        self._update_cards()

    # ================================================================== configuration state
    def _mode_changed(self) -> None:
        self.mode_desc.setText(nd.MODES[self.mode.currentData()][1])
        neighbor = self.mode.currentData() == "neighbor"
        for wd in (self.conc, self.timeout):
            wd.setEnabled(not neighbor)

    def _cidr_changed(self) -> None:
        self._update_scope_state()
        self._update_cards()

    def _target(self) -> ipaddress.IPv4Network | None:
        try:
            n = ipaddress.ip_network(self.cidr.text().strip(), strict=False)
            return n if isinstance(n, ipaddress.IPv4Network) else None
        except ValueError:
            return None

    def _update_cards(self) -> None:
        i = self._ident()
        self.c_gw.value.setText(i.gateway if i and i.gateway else "—")
        self.c_gw.sub.setText((f"{i.gateway_mac} · via {i.interface.name}" if i and i.gateway_mac else "no default route" if i else "not identified yet"))
        t = self._target()
        usable = (max(t.num_addresses - 2, 0) if t.prefixlen < 31 else t.num_addresses) if t else 0
        self.c_pot.value.setText(f"{usable:,}" if t else "—")
        self.c_pot.sub.setText(f"usable addresses in {t}" if t else "enter a valid range")
        self.c_found.value.setText(str(len(self.hosts)))
        if self.last_scan:
            self.c_last.value.setText(fmt_ts(self.last_scan["started_at"])[11:16] if self.last_scan.get("started_at") else "—")
            self.c_last.sub.setText(f"{self.last_scan['mode']} · {self.last_scan['duration_s']:.1f} s · {self.last_scan['status']}")
        self._update_scope_state()

    def _update_scope_state(self) -> None:
        pid, t = self._project_id(), self._target()
        running = self._control is not None
        in_scope = False
        if not pid:
            msg, col = "Select or create a project above: scans only run inside a project's authorized scope.", T.warning
        elif t is None:
            msg, col = "Enter a valid IPv4 range.", T.danger
        else:
            chk = self.app.projects.check_scope(pid, [str(t)])[0]
            in_scope = chk.in_scope
            msg, col = (f"{t} is inside the project's authorized scope.", T.green) if in_scope else \
                       (f"{t} is NOT inside the authorized scope. Nothing will be scanned until you add it (it is never added automatically).", T.warning)
        self.scope_lbl.setText(f"<span style='color:{col}'>{esc(msg)}</span>")
        self.b_scope.setVisible(bool(pid and t is not None and not in_scope))
        self.b_go.setEnabled(bool(pid and t is not None and in_scope and self._ident() is not None) and not running)

    def project_changed(self) -> None:
        self.reload_history()
        self._update_scope_state()

    def _add_scope(self) -> None:
        pid, t = self._project_id(), self._target()
        if not pid or t is None:
            return
        proj = self.app.projects.get(pid)
        if not confirm_dialog(self, "Add to authorized scope",
                              f"<p>Add <b>{esc(str(t))}</b> to the authorized scope of project <b>{esc(proj['name'] if proj else '')}</b>?</p>"
                              "<p>Only add networks you own or are explicitly authorized to scan. The scope is changed only by you, never automatically.</p>",
                              "Add to scope", "I am authorized to scan this network."):
            return
        self.app.projects.add_scope(pid, str(t), "added from Network Discovery")
        self.app.audit.record("netdisc.scope_add", project=pid, target=str(t))
        self._update_scope_state()

    # ================================================================== scanning
    def _config(self) -> nd.DiscoveryConfig:
        i = self._ident()
        return nd.DiscoveryConfig(self.cidr.text().strip(), self.mode.currentData(), i.interface.name if i else "", int(self.conc.value()),
                                  float(self.timeout.value()), self.v6.isChecked(), self._project_id())

    def _review(self) -> None:
        try:
            plan = self.engine.plan(self._config(), self.identities)
        except (nd.DiscoveryError, ScopeError) as e:
            self.progress_lbl.setText(f"<span style='color:{T.danger}'>Cannot start: {esc(str(e))}</span>")
            return
        proj = self.app.projects.get(plan.config.project_id)
        title, desc = nd.MODES[plan.config.mode]
        sends = ("<li>No packets are sent: the ARP and IPv6 neighbour tables are only read.</li>" if plan.config.mode == "neighbor" else
                 "<li>One ICMP echo (ping) to every address, which also triggers ARP resolution.</li>"
                 + ("<li>A second pass to addresses that stayed silent.</li>" if plan.config.mode == "full" else "")
                 + ("<li>An IPv6 all-nodes echo, then the IPv6 neighbour table.</li>" if plan.config.ipv6 else ""))
        text = (f"<p><b>{esc(title)}</b>: {esc(desc)}</p>"
                f"<table cellpadding='3'><tr><td>Exact range</td><td><b>{esc(str(plan.network))}</b></td></tr>"
                f"<tr><td>Addresses</td><td>{self.engine.target_count(plan):,}</td></tr>"
                f"<tr><td>Interface</td><td>{esc(plan.identity.interface.name)} ({esc(plan.identity.interface.kind)})</td></tr>"
                f"<tr><td>Project</td><td>{esc(proj['name'] if proj else '')}</td></tr>"
                f"<tr><td>Authorized scope</td><td>{esc(', '.join(plan.scope))}</td></tr>"
                f"<tr><td>Concurrency / timeout</td><td>{plan.config.concurrency} / {plan.config.timeout:.1f} s</td></tr></table>"
                f"<p>What will be sent:</p><ul>{sends}</ul>"
                "<p>No port scans, spoofing or configuration changes are performed. A missing answer does not prove a host is offline.</p>")
        if not confirm_dialog(self, "Confirm network discovery", text, "Start discovery",
                              "I am authorized to scan exactly this range."):
            return
        self._start(plan)

    def _start(self, plan: nd.DiscoveryPlan) -> None:
        self._plan = plan
        self._control = nd.ScanControl()
        self._set_running(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress_lbl.setText(f"Scanning {plan.network}…")
        self.app.audit.record("netdisc.scan", project=plan.config.project_id, range=str(plan.network), mode=plan.config.mode,
                              interface=plan.identity.interface.name, addresses=self.engine.target_count(plan))
        start_ident = plan.identity.v4
        last = [0.0]

        def change_check() -> str | None:
            if time.monotonic() - last[0] < 3.0:
                return None
            last[0] = time.monotonic()
            now = next((i for i in self.engine.identifier.identify() if i.interface.name == plan.identity.interface.name), None)
            if now is None or not now.v4 or (start_ident and (now.v4.address, now.v4.prefixlen) != (start_ident.address, start_ident.prefixlen)):
                return "the network configuration changed during the scan (address, prefix or link state)"
            return None

        control, bridge = self._control, self._bridge

        def work() -> None:
            try:
                out = self.engine.run(plan, control, lambda d, t, f: bridge.progress.emit(d, t, f), change_check)
                bridge.done.emit(out)
            except Exception as e:                                   # reported, never silent
                bridge.failed.emit(str(e))

        threading.Thread(target=work, name="netdisc", daemon=True).start()

    def _on_progress(self, done: int, total: int, found: int) -> None:
        self.progress.setValue(int(done * 100 / max(total, 1)))
        self.progress_lbl.setText(f"{done:,} of {total:,} addresses probed · {found} answered" + (" · PAUSED" if self._control and self._control.paused else ""))

    def _pause(self) -> None:
        c = self._control
        if not c:
            return
        if c.paused:
            c.resume()
            self.b_pause.setText("Pause")
        else:
            c.pause()
            self.b_pause.setText("Resume")

    def _cancel(self) -> None:
        if self._control:
            self._control.cancel()
            self.progress_lbl.setText("Cancelling… partial results will be kept.")

    def _set_running(self, running: bool) -> None:
        self.b_pause.setEnabled(running)
        self.b_cancel.setEnabled(running)
        self.b_ident.setEnabled(not running)
        self.b_pause.setText("Pause")
        if not running:
            self._update_scope_state()
        else:
            self.b_go.setEnabled(False)

    def _scan_failed(self, err: str) -> None:
        self._control = None
        self._set_running(False)
        self.progress_lbl.setText(f"<span style='color:{T.danger}'>Scan failed: {esc(err)}</span>")

    def _finished(self, out: nd.ScanOutcome) -> None:
        self._control = None
        self._set_running(False)
        self.progress.setValue(100 if out.status == "completed" else self.progress.value())
        text = {"completed": f"Done: {len(out.hosts)} host(s) in {out.duration_s:.1f} s.",
                "cancelled": f"Cancelled: {len(out.hosts)} host(s) found before stopping (saved).",
                "aborted": f"Stopped: {out.note}. {len(out.hosts)} host(s) found (saved)."}[out.status]
        self.progress_lbl.setText(text + " A missing response does not prove a host is offline.")
        self.reload_history()
        self._show_hosts(out.hosts, self.engine.scans(limit=1)[0] if out.scan_id else None)

    # ================================================================== results
    def _show_hosts(self, hosts: list[nd.HostResult], scan: dict | None) -> None:
        self.hosts, self.last_scan = hosts, scan
        types = sorted({h.device_type for h in hosts})
        cur = self.f_type.currentText()
        self.f_type.blockSignals(True)
        self.f_type.clear()
        self.f_type.addItem("All device types")
        self.f_type.addItems(types)
        idx = self.f_type.findText(cur)
        self.f_type.setCurrentIndex(max(idx, 0))
        self.f_type.blockSignals(False)
        self._fill_hosts()
        ident = self._ident()
        if ident:
            self._graph = nd.build_topology(ident, hosts)
            self._draw_topology()
        self._update_cards()

    def _visible(self) -> list[nd.HostResult]:
        q = self.search.text().strip().lower()
        out = self.hosts
        if self.f_status.currentIndex() > 0:
            out = [h for h in out if h.status == self.f_status.currentText()]
        if self.f_type.currentIndex() > 0:
            out = [h for h in out if h.device_type == self.f_type.currentText()]
        if q:
            out = [h for h in out if q in " ".join((h.ip, h.mac, h.hostname, h.vendor, h.device_type, *h.tags)).lower()]
        return out

    def _fill_hosts(self) -> None:
        rows = self._visible()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, h in enumerate(rows):
            vals = [h.ip, h.mac or "—", h.hostname or "—", h.vendor or "—", BASIS_MARK[h.type_basis] + h.device_type, h.response_method,
                    "—" if h.latency_ms is None else f"{h.latency_ms:.1f} ms", h.status, fmt_ts(h.first_seen), fmt_ts(h.last_seen), ", ".join(h.tags)]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, h.ip)
                if c == 7:
                    it.setForeground(QColor(STATUS_COLOR.get(h.status, T.text)))
                if c == 4:
                    it.setToolTip(f"{h.type_basis}: {h.type_reason}")
                    it.setForeground(QColor(T.green if h.type_basis == "confirmed" else T.text if h.type_basis == "inferred" else T.text_muted))
                it.setData(Qt.ItemDataRole.UserRole + 1, h.sort_key if c == 0 else None)
                self.table.setItem(r, c, it)
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()

    def _current_host(self) -> nd.HostResult | None:
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        ip = it.data(Qt.ItemDataRole.UserRole) if it else None
        return next((h for h in self.hosts if h.ip == ip), None)

    def _select_host(self) -> None:
        h = self._current_host()
        if h:
            self.detail.setHtml(self._host_html(h))
            known = next((d for d in self.engine.devices() if d["mac"] == h.mac), None) if h.mac else None
            self.label.setText(known["label"] if known else "")

    @staticmethod
    def _host_html(h: nd.HostResult) -> str:
        basis = {"confirmed": f"<span style='color:{T.green}'>Confirmed</span>", "inferred": f"<span style='color:{T.warning}'>Inferred (a hint, not a fact)</span>",
                 "unknown": "<span>Unknown</span>"}[h.type_basis]
        rows = [("IP address", h.ip), ("MAC address", h.mac or "not learned (no ARP/NDP entry)"), ("Host name", h.hostname or "no reverse-DNS name"),
                ("Manufacturer", h.vendor or "unknown (from the MAC address prefix)"), ("Response", f"{h.response_method} · {h.status}"
                 + ("" if h.latency_ms is None else f" · {h.latency_ms:.1f} ms")), ("First / last seen", f"{fmt_ts(h.first_seen)} / {fmt_ts(h.last_seen)}"),
                ("Notes", ", ".join(h.tags) or "—")]
        tbl = "".join(f"<tr><td style='color:{T.text_secondary}'>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in rows)
        return (f"<p style='font-size:15px'><b>{esc(h.device_type)}</b> &nbsp; {basis}</p><p style='color:{T.text_secondary}'>Why: {esc(h.type_reason)}</p>"
                f"<table cellpadding='2'>{tbl}</table>")

    def _save_label(self) -> None:
        h = self._current_host()
        if h and h.mac:
            self.engine.set_label(h.mac, self.label.text())
            self.msg.setText("Name saved.")

    def _copy_ip(self) -> None:
        h = self._current_host()
        if h:
            QGuiApplication.clipboard().setText(h.ip)
            self.msg.setText(f"Copied {h.ip}")

    def _export(self, fmt: str) -> None:
        hosts = self._visible()
        if not hosts:
            self.msg.setText("Nothing to export: run a scan or clear the filters.")
            return
        name, _ = QFileDialog.getSaveFileName(self, "Export hosts", str(Path.home() / f"network-discovery.{fmt}"), f"{fmt.upper()} (*.{fmt})")
        if not name:
            return
        text = {"csv": lambda: nd.to_csv(hosts), "json": lambda: nd.to_json(self.last_scan, hosts), "html": lambda: nd.to_html(self.last_scan, hosts)}[fmt]()
        Path(name).write_text(text, encoding="utf-8")
        self.app.audit.record("netdisc.export", path=name, rows=len(hosts), format=fmt)
        self.msg.setText(f"Exported {len(hosts)} host(s) to {name}")

    # ================================================================== topology
    def _draw_topology(self) -> None:
        g = self._graph
        if not g:
            return
        nodes = []
        for n in g.nodes:
            state = "self" if n.kind == "self" else "reachable" if "responded" in n.detail else "stale" if n.kind == "host" else "unknown"
            nodes.append(NetNode(n.id, n.label, n.ip or None, n.kind, state, n.mac or None, None, n.device_type or None, "evidence", None, []))
        self.topo.set_topology(Topology(nodes, [(e.a, e.b) for e in g.edges], note=g.note, hub=next((n.id for n in g.nodes if n.kind == "segment"), None)))
        self.topo_note.setText(g.note)

    def _node_selected(self, node) -> None:
        g = self._graph
        if node is None or not g:
            return
        gn = next((n for n in g.nodes if n.id == node.id), None)
        ev = [e for e in g.edges if node.id in (e.a, e.b)]
        host = next((h for h in self.hosts if f"host:{h.ip}" == node.id), None)
        head = self._host_html(host) if host else f"<p><b>{esc(gn.label if gn else node.label)}</b></p><p>{esc(gn.detail if gn else '')}</p>"
        lines = "".join(f"<li>{esc(e.evidence)}</li>" for e in ev)
        self.topo_detail.setHtml(head + f"<p style='color:{T.text_secondary}'>Evidence for its connections:</p><ul>{lines or '<li>none</li>'}</ul>")

    # ================================================================== history
    def reload_history(self) -> None:
        scans = self.engine.scans(self._project_id())
        self.hist.setRowCount(len(scans))
        for r, s in enumerate(scans):
            for c, v in enumerate([str(s["id"]), fmt_ts(s["started_at"]), s["interface"] or "", s["cidr"], s["mode"], str(s["targets_total"]),
                                   str(s["hosts_found"]), f"{s['duration_s'] or 0:.1f} s", s["status"]]):
                self.hist.setItem(r, c, QTableWidgetItem(v))
        if scans and not self.hosts:
            self._show_hosts(self.engine.hosts(scans[0]["id"]), scans[0])

    def _selected_ids(self) -> list[int]:
        rows = sorted({i.row() for i in self.hist.selectedIndexes()})
        return [int(self.hist.item(r, 0).text()) for r in rows]

    def _show_scan(self) -> None:
        ids = self._selected_ids()
        if ids:
            scan = next((s for s in self.engine.scans(limit=500) if s["id"] == ids[0]), None)
            self._show_hosts(self.engine.hosts(ids[0]), scan)
            self.tabs.setCurrentIndex(0)

    def _compare(self) -> None:
        ids = sorted(self._selected_ids())
        if len(ids) != 2:
            self.cmp_out.setPlainText("Select exactly two scans.")
            return
        res = self.engine.compare(ids[0], ids[1])

        def block(title: str, items: list[str]) -> str:
            return f"<h4>{esc(title)} ({len(items)})</h4>" + ("<ul>" + "".join(f"<li>{esc(i)}</li>" for i in items) + "</ul>" if items else "<p>—</p>")
        self.cmp_out.setHtml(
            f"<p>Scan {ids[0]} → scan {ids[1]}</p>"
            + block("New in the later scan", [f"{h.ip}  {h.mac}  {h.vendor}  {h.device_type}" for h in res["new"]])
            + block("Not seen in the later scan (this does NOT prove they are offline)", [f"{h.ip}  {h.mac}  {h.vendor}" for h in res["not_seen"]])
            + block("Changed", [f"{h.ip}: {d}" for h, d in res["changed"]]))

    def _delete_scan(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        if not confirm_dialog(self, "Delete scan", f"<p>Permanently delete {len(ids)} scan record(s) and their results from the history?</p>"
                              "<p>Devices remembered from them (names, first seen) are kept. This cannot be undone.</p>", "Delete", danger=True):
            return
        for i in ids:
            self.engine.delete_scan(i)
        self.app.audit.record("netdisc.delete_scan", ids=ids)
        self.reload_history()
