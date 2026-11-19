"""Network Command Center dashboard. Every value is read from the system or the application database."""
from __future__ import annotations

import html
import time
from collections import deque
from typing import Callable

import pyqtgraph as pg
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (QComboBox, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QScrollArea, QSplitter, QVBoxLayout, QWidget)

from ..application.app_controller import AppController
from ..services.adapter_service import AdapterService, WirelessAdapter
from ..services.network_inventory import NetNode, Topology
from ..services.system_service import SystemService
from ..workers.task import run_in_background
from .board import WidgetBoard
from .charts import make_plot
from .design.components import GaugeWidget, LoadingIndicator, MatrixButton, MetricTile, Panel
from .design.tokens import T
from .topology import TopologyView
from .widgets import human_bytes, human_duration

esc = html.escape
HISTORY = 60


def _muted(text: str) -> str:
    return f'<span style="color:{T.text_secondary}">{text}</span>'


def rate(nbytes: float) -> str:
    return human_bytes(nbytes) + "/s"


class Dashboard(QWidget):
    def __init__(self, app: AppController, on_connectivity: Callable[[bool], None] | None = None,
                 navigate: Callable[[str], None] | None = None) -> None:
        super().__init__()
        self.app = app
        self.sys = app.services.get(SystemService)
        self.adapters = app.services.get(AdapterService)
        self._on_connectivity = on_connectivity
        self._navigate = navigate or (lambda _p: None)
        self._cpu, self._ram = deque(maxlen=HISTORY), deque(maxlen=HISTORY)
        self._down, self._up = deque(maxlen=HISTORY), deque(maxlen=HISTORY)
        self._last_net: tuple[float, int, int] | None = None
        self._updates_tile = ("…", "checking cached package lists", T.text_secondary)
        self._adapter_list: list[WirelessAdapter] = []
        self._topology: Topology | None = None
        self._online = False
        self._build()
        self._sample = QTimer(self)
        self._sample.setInterval(1000)  # cheap psutil reads; runs only while the page is visible
        self._sample.timeout.connect(self.refresh_fast)
        self._topo_timer = QTimer(self)
        self._topo_timer.setInterval(30000)
        self._topo_timer.timeout.connect(self.refresh_topology)
        self.refresh_fast()
        self.refresh_db()
        self.refresh_slow()
        self.refresh_topology()

    # ================= visibility-gated timers =================
    def showEvent(self, e) -> None:  # noqa: N802
        super().showEvent(e)
        self._sample.start()
        self._topo_timer.start()

    def hideEvent(self, e) -> None:  # noqa: N802
        self._sample.stop()
        self._topo_timer.stop()
        super().hideEvent(e)

    # ================= layout =================
    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.viewport().setAutoFillBackground(False)
        body = QWidget()
        scroll.setWidget(body)
        body.setAutoFillBackground(False)   # QScrollArea.setWidget re-enables the grey system fill
        outer.addWidget(scroll)
        col = QVBoxLayout(body)
        col.setContentsMargins(T.gutter, 4, T.gutter, T.gutter)
        col.setSpacing(T.gap)

        head = QHBoxLayout()
        title = QLabel("Network Command Center")
        title.setObjectName("pageTitle")
        head.addWidget(title)
        head.addStretch(1)
        self.rearrange = MatrixButton("Rearrange", icon_name="settings")
        self.rearrange.setCheckable(True)
        self.rearrange.setToolTip("Move and resize the lower panels; your layout is remembered")
        self.rearrange.toggled.connect(lambda on: self.board.set_edit_mode(on))
        refresh = MatrixButton("Refresh", icon_name="reset")
        refresh.clicked.connect(self.refresh_all)
        head.addWidget(self.rearrange)
        head.addWidget(refresh)
        col.addLayout(head)

        tiles = QGridLayout()
        tiles.setSpacing(T.gap)
        self.t_health = MetricTile("System health", "hardware")
        self.t_net = MetricTile("Network", "network")
        self.t_wifi = MetricTile("Wireless adapter", "wifi")
        self.t_tools = MetricTile("Tool status", "tools")
        self.t_updates = MetricTile("Pending updates", "update")
        for i, (t, page) in enumerate(((self.t_health, "system_hw"), (self.t_net, "wifi_center"),
                                       (self.t_wifi, "wifi_center"), (self.t_tools, "tools_all"),
                                       (self.t_updates, "sys_updates"))):
            t.clicked.connect(lambda p=page: self._navigate(p))
            tiles.addWidget(t, 0, i)
            tiles.setColumnStretch(i, 1)
        col.addLayout(tiles)

        self.split = QSplitter(Qt.Orientation.Horizontal)
        self.split.setChildrenCollapsible(False)
        self.split.addWidget(self._topology_panel())
        self.split.addWidget(self._activity_column())
        self.split.setStretchFactor(0, 4)
        self.split.setStretchFactor(1, 1)
        self.split.setMinimumHeight(430)
        saved = self.app.settings.get("ui.dashboard_splitter")
        self.split.setSizes(saved if len(saved) == 2 and all(s > 0 for s in saved) else [900, 340])
        self.split.splitterMoved.connect(lambda *_: self.app.settings.set(
            "ui.dashboard_splitter", [int(s) for s in self.split.sizes()]))
        col.addWidget(self.split)

        self.board = WidgetBoard()
        self.board.add("resources", "System resources", self._resources_panel(), 2)
        self.board.add("activity", "Recent activity", self._simple_panel("Recent activity", "audit_lbl"), 1)
        self.board.add("findings", "Security findings", self._simple_panel("Security findings", "find_lbl"), 1)
        self.board.add("projects", "Recent projects", self._simple_panel("Recent projects", "proj_lbl"), 1)
        self.board.add("tools", "Tool inventory", self._simple_panel("Tool inventory", "tools_lbl"), 1)
        self.board.apply_state(self.app.settings.get("ui.dashboard_layout"))
        self.board.layout_changed.connect(lambda: self.app.settings.set(
            "ui.dashboard_layout", self.board.layout_state()))
        col.addWidget(self.board)
        col.addStretch(1)

    def _simple_panel(self, title: str, attr: str) -> Panel:
        p = Panel(title)
        setattr(self, attr, p.add_text())
        return p

    def _topology_panel(self) -> Panel:
        p = Panel("Network topology")
        self.topo_loader = LoadingIndicator("scan", 22)
        p.add_header_widget(self.topo_loader)
        self.topo_search = QLineEdit()
        self.topo_search.setPlaceholderText("Search devices…")
        self.topo_search.setClearButtonEnabled(True)
        self.topo_search.setMaximumWidth(200)
        self.topo_filter = QComboBox()
        self.topo_filter.addItems(["All nodes", "Hosts only", "Infrastructure"])
        for w in (self.topo_search, self.topo_filter):
            p.add_header_widget(w)
        self.topo = TopologyView()
        self.topo.discover_requested.connect(self.refresh_topology)
        self.topo.node_selected.connect(self._node_selected)
        self.topo_search.textChanged.connect(self._apply_topo_filter)
        self.topo_filter.currentIndexChanged.connect(self._apply_topo_filter)
        p.add(self.topo, 1)
        self.topo_note = QLabel("")
        self.topo_note.setObjectName("faint")
        self.topo_note.setWordWrap(True)
        p.add(self.topo_note)
        return p

    def _activity_column(self) -> QWidget:
        w = QWidget()
        w.setAutoFillBackground(False)
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(T.gap)
        net = Panel("Network activity")
        self.speed_lbl = net.add_text()
        self.net_plot = make_plot()
        self.net_plot.setMinimumHeight(110)
        self.net_plot.setMaximumHeight(140)
        self.net_plot.getAxis("left").setWidth(48)
        self.net_plot.getPlotItem().setLabel("left", "KiB/s", color=T.text_secondary)
        self.net_plot.hideAxis("bottom")
        net.add(self.net_plot)
        self.down_curve = self.net_plot.plot(pen=pg.mkPen(T.green, width=2), fillLevel=0,
                                             brush=pg.mkBrush(0, 255, 102, 35))
        self.up_curve = self.net_plot.plot(pen=pg.mkPen(T.cyan, width=2))
        lay.addWidget(net)
        dev = Panel("Discovered devices")
        self.dev_list = QListWidget()
        self.dev_list.setMinimumHeight(100)
        self.dev_list.itemClicked.connect(lambda it: self.topo.select(it.data(Qt.ItemDataRole.UserRole)))
        dev.add(self.dev_list, 1)
        self.sel_lbl = dev.add_text()
        self.sel_lbl.setText(_muted("Select a node on the map for details."))
        lay.addWidget(dev, 1)
        ops = Panel("Running operations")
        self.live_lbl = ops.add_text()
        lay.addWidget(ops)
        return w

    def _resources_panel(self) -> Panel:
        p = Panel("System resources")
        row = QHBoxLayout()
        self.g_cpu = GaugeWidget("CPU", T.green)
        self.g_ram = GaugeWidget("Memory", T.cyan)
        self.g_disk = GaugeWidget("Storage", T.emerald)
        for g in (self.g_cpu, self.g_ram, self.g_disk):
            g.setMinimumHeight(120)
            row.addWidget(g)
        holder = QWidget()
        holder.setLayout(row)
        p.add(holder)
        self.res_plot = make_plot()
        self.res_plot.setYRange(0, 100)
        self.res_plot.setMinimumHeight(100)
        self.res_plot.setMaximumHeight(150)
        self.cpu_curve = self.res_plot.plot(pen=pg.mkPen(T.green, width=2), name="CPU")
        self.ram_curve = self.res_plot.plot(pen=pg.mkPen(T.cyan, width=2), name="RAM")
        self.res_plot.hideAxis("bottom")
        self.res_plot.getPlotItem().setLabel("left", "% (last 60 s)", color=T.text_secondary)
        p.add(self.res_plot)
        self.sys_lbl = p.add_text()
        self.os_lbl = p.add_text()
        return p

    # ================= refresh =================
    def refresh_all(self) -> None:
        self.refresh_fast()
        self.refresh_db()
        self.refresh_slow()
        self.refresh_topology()

    def refresh_fast(self) -> None:
        cpu = self.sys.cpu_percent()
        used, total, pct = self.sys.memory()
        d = self.sys.disk()
        self._cpu.append(cpu)
        self._ram.append(pct)
        self.g_cpu.set_value(cpu)
        self.g_ram.set_value(pct)
        self.g_disk.set_value(d.percent)
        xs = list(range(len(self._cpu)))
        self.cpu_curve.setData(xs, list(self._cpu))
        self.ram_curve.setData(xs, list(self._ram))

        sent, recv = self.sys.net_counters()
        now = time.monotonic()
        if self._last_net:
            dt = max(now - self._last_net[0], 0.001)
            self._down.append(max(0, (recv - self._last_net[2]) / dt))
            self._up.append(max(0, (sent - self._last_net[1]) / dt))
        self._last_net = (now, sent, recv)
        if self._down:
            ys = list(range(len(self._down)))
            self.down_curve.setData(ys, [v / 1024 for v in self._down])
            self.up_curve.setData(ys, [v / 1024 for v in self._up])
            self.speed_lbl.setText(f'<span style="color:{T.green}">▼ {rate(self._down[-1])}</span> &nbsp; '
                                   f'<span style="color:{T.cyan}">▲ {rate(self._up[-1])}</span>')
        else:
            self.speed_lbl.setText(_muted("measuring…"))

        os_ = self.sys.os_info()
        self._online = self.sys.has_connectivity()
        if self._on_connectivity:
            self._on_connectivity(self._online)
        self.os_lbl.setText(
            f"<b>{esc(os_.pretty_name)}</b> {_muted('· kernel ' + esc(os_.kernel) + ' · host ' + esc(os_.hostname))}"
            + ("" if os_.is_parrot else "<br>" + _muted("Not running on Parrot OS — OS-specific features are limited.")))
        self.sys_lbl.setText(f"Uptime {human_duration(self.sys.uptime_seconds())} · memory {human_bytes(used)} / "
                             f"{human_bytes(total)} · storage {human_bytes(d.used)} / {human_bytes(d.total)}")

        worst = max(cpu, pct, d.percent)
        level, color = (("Healthy", T.success) if worst < 75 else ("Busy", T.warning) if worst < 90
                        else ("Critical", T.danger))
        self.t_health.set(level, f"CPU {cpu:.0f}% · RAM {pct:.0f}% · Disk {d.percent:.0f}%", color)
        gw = next((n.ip for n in self._topology.nodes if n.kind == "gateway"), None) if self._topology else None
        ifaces = [i.name for i in self.sys.interfaces() if i.is_up and i.name != "lo"]
        self.t_net.set("Online" if self._online else "Offline",
                       (f"Gateway {gw} · " if gw else "") + (", ".join(ifaces[:2]) or "no active interface"),
                       T.success if self._online else T.warning)
        self.t_updates.set(*self._updates_tile)

    def refresh_slow(self) -> None:
        run_in_background(self.adapters.detect, self._show_adapters,
                          lambda e: self.t_wifi.set("Error", esc(e), T.danger))
        run_in_background(self.sys.pending_updates, self._show_updates,
                          lambda e: self._set_updates("Error", e, T.danger))

    def _set_updates(self, value: str, detail: str, color: str) -> None:
        self._updates_tile = (value, detail, color)
        self.t_updates.set(value, detail, color)

    def _show_updates(self, res: dict | None) -> None:
        if res is None:
            self._set_updates("Unknown", "apt not available on this system", T.text_secondary)
        elif res["upgrade"] == 0 and res["remove"] == 0:
            self._set_updates("Up to date", "from cached package lists", T.success)
        else:
            self._set_updates(f"{res['upgrade']} upgradable", f"{res['remove']} to remove · cached lists", T.warning)

    def _show_adapters(self, adapters: list[WirelessAdapter]) -> None:
        self._adapter_list = adapters
        if not self.adapters.supported():
            self.t_wifi.set("n/a", "Wireless detection needs Linux", T.text_secondary)
        elif not adapters:
            self.t_wifi.set("None", "No wireless adapter detected", T.text_secondary)
        else:
            a = adapters[0]
            mon = {True: "monitor ✓", False: "no monitor mode", None: "monitor ?"}[a.monitor_capable]
            self.t_wifi.set(f"{a.interface} {a.state}",
                            f"{a.driver or 'driver ?'} · {', '.join(a.bands) or 'bands ?'} · {mon}",
                            T.success if a.state == "up" else T.warning)

    # ---- topology
    def refresh_topology(self) -> None:
        if self.topo_loader.active:
            return
        self.topo_loader.start()
        run_in_background(self.app.inventory.snapshot, self._topology_ready, self._topology_failed)

    def _topology_failed(self, err: str) -> None:
        self.topo_loader.stop()
        self.topo_note.setText(f"Topology refresh failed: {esc(err)}")

    def _topology_ready(self, topo: Topology) -> None:
        self.topo_loader.stop()
        self._topology = topo
        self.topo.set_topology(topo)
        self.topo_note.setText(topo.note or "")
        self.dev_list.clear()
        for n in topo.nodes:
            if n.kind != "host":
                continue
            it = QListWidgetItem(f"{n.ip}   {n.vendor or ''}".rstrip())
            it.setData(Qt.ItemDataRole.UserRole, n.id)
            self.dev_list.addItem(it)
        if self.dev_list.count() == 0:
            empty = QListWidgetItem("No devices discovered")
            empty.setFlags(Qt.ItemFlag.NoItemFlags)
            self.dev_list.addItem(empty)
        self._apply_topo_filter()

    def _apply_topo_filter(self) -> None:
        kinds = {0: {"self", "gateway", "host"}, 1: {"host"}, 2: {"self", "gateway"}}[self.topo_filter.currentIndex()]
        self.topo.set_filter(self.topo_search.text(), kinds)

    def _node_selected(self, node: NetNode | None) -> None:
        if node is None:
            self.sel_lbl.setText(_muted("Select a node on the map for details."))
            return
        rows = [("Name", node.label), ("Role", node.kind), ("IP", node.ip), ("MAC", node.mac), ("Vendor", node.vendor),
                ("Type", node.device_type), ("State", node.state), ("Source", node.source),
                ("Interface", node.interface), ("Services", ", ".join(node.services) or None)]
        self.sel_lbl.setText("<table cellpadding='1'>" + "".join(
            f"<tr><td>{_muted(esc(k))}&nbsp;</td><td>{esc(str(v))}</td></tr>" for k, v in rows if v) + "</table>")

    # ---- database-driven panels
    def refresh_db(self) -> None:
        db = self.app.db
        ts = self.app.tools.summary()
        if ts["scanned"] == 0:
            self.tools_lbl.setText(_muted("Scanning for installed tools…"))
            self.t_tools.set("Scanning…", "detecting installed tools", T.text_secondary)
        else:
            color = T.danger if ts["errors"] else T.warning if ts["warnings"] else T.success
            self.t_tools.set(f"{ts['installed']}/{ts['total']} installed",
                             f"{ts['errors']} dependency problems · {ts['warnings']} warnings", color)
            self.tools_lbl.setText(
                f"<b>{ts['installed']}</b> installed · {ts['total'] - ts['installed']} not installed<br>"
                f"Healthy {ts['healthy']} · Warnings {ts['warnings']} · Dependency problems {ts['errors']}<br>"
                + _muted("Update detection arrives with the software update manager (Phase 7)."))

        running = db.query("SELECT name, tool_id, started_at FROM operations WHERE status='running' "
                           "ORDER BY id DESC LIMIT 5")
        self.live_lbl.setText("<br>".join(
            f"{esc(r['name'])} {_muted('(' + esc(r['tool_id'] or 'app') + ')')}" for r in running)
            or _muted("No running operations."))

        sev = db.query("SELECT severity, COUNT(*) n FROM findings WHERE status != 'resolved' GROUP BY severity")
        self.find_lbl.setText(
            ("<br>".join(f"{esc(r['severity']).title()}: <b>{r['n']}</b>" for r in sev) + "<br>"
             + _muted("unresolved findings")) if sev else _muted("No findings recorded."))
        projs = db.query("SELECT name, updated_at FROM projects ORDER BY updated_at DESC LIMIT 5")
        self.proj_lbl.setText("<br>".join(f"{esc(r['name'])} {_muted(r['updated_at'])}" for r in projs)
                              or _muted("No projects yet."))
        try:
            entries = self.app.audit.tail(6)
        except OSError:
            entries = []
        self.audit_lbl.setText("<br>".join(
            f"{_muted(esc(e['ts'][11:19]))} {esc(e['event'])}"
            + (f" {_muted(esc(str(e.get('tool') or e.get('operation'))))}" if e.get("tool") or e.get("operation") else "")
            for e in reversed(entries)) or _muted("Nothing yet."))
