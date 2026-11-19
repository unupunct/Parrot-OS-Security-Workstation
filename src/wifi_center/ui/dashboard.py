"""Overview dashboard. Every value is read from the system or the application database."""
from __future__ import annotations

import html
from typing import Callable

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QProgressBar, QPushButton,
                               QScrollArea, QVBoxLayout, QWidget)

from ..application.app_controller import AppController
from ..services.adapter_service import AdapterService, WirelessAdapter
from ..services.system_service import SystemService
from ..workers.task import run_in_background
from .widgets import Card, human_bytes, human_duration

esc = html.escape


def _muted(text: str) -> str:
    return f'<span style="color:#8D9C91">{text}</span>'


class Dashboard(QWidget):
    def __init__(self, app: AppController, on_connectivity: Callable[[bool], None] | None = None) -> None:
        super().__init__()
        self.app = app
        self.sys = app.services.get(SystemService)
        self.adapters = app.services.get(AdapterService)
        self._on_connectivity = on_connectivity
        self._build()
        self.refresh_fast()
        self.refresh_db()
        self.refresh_slow()
        self._fast = QTimer(self)
        self._fast.timeout.connect(self.refresh_fast)
        self._fast.start(2000)  # cheap psutil reads only

    # ---------------- layout ----------------
    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        title = QLabel("Overview")
        title.setObjectName("pageTitle")
        head.addWidget(title)
        head.addStretch(1)
        btn = QPushButton("Refresh")
        btn.setToolTip("Re-read adapters, updates and database summaries")
        btn.clicked.connect(self.refresh_all)
        head.addWidget(btn)
        outer.addLayout(head)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        self.grid = QGridLayout(body)
        self.grid.setSpacing(14)
        scroll.setWidget(body)
        outer.addWidget(scroll)

        # System status
        self.c_sys = Card("System Status")
        self.os_lbl = self.c_sys.add_text()
        self.cpu_bar = self._bar("CPU", self.c_sys)
        self.ram_bar = self._bar("RAM", self.c_sys)
        self.disk_bar = self._bar("Storage", self.c_sys)
        self.sys_lbl = self.c_sys.add_text()
        self.c_sys.finish()

        self.c_wifi = Card("Wireless Adapter")
        self.wifi_lbl = self.c_wifi.add_text()
        self.c_wifi.finish()

        self.c_tools = Card("Tool Inventory")
        self.tools_lbl = self.c_tools.add_text()
        self.c_tools.finish()

        self.c_live = Card("Live Activity")
        self.live_lbl = self.c_live.add_text()
        self.c_live.finish()

        self.c_net = Card("Network Overview")
        self.net_lbl = self.c_net.add_text()
        self.c_net.finish()

        self.c_find = Card("Security Findings")
        self.find_lbl = self.c_find.add_text()
        self.c_find.finish()

        self.c_proj = Card("Recent Projects")
        self.proj_lbl = self.c_proj.add_text()
        self.c_proj.finish()

        cards = [self.c_sys, self.c_wifi, self.c_tools, self.c_live, self.c_net, self.c_find, self.c_proj]
        for i, c in enumerate(cards):
            self.grid.addWidget(c, i // 2, i % 2)
        self.grid.setColumnStretch(0, 1)
        self.grid.setColumnStretch(1, 1)

    def _bar(self, label: str, card: Card) -> tuple[QLabel, QProgressBar]:
        row = QWidget()
        lay = QHBoxLayout(row)
        lay.setContentsMargins(0, 0, 0, 0)
        name = QLabel(label)
        name.setFixedWidth(64)
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setTextVisible(False)
        val = QLabel("—")
        val.setObjectName("muted")
        val.setMinimumWidth(170)
        lay.addWidget(name)
        lay.addWidget(bar, 1)
        lay.addWidget(val)
        card.add(row)
        return val, bar

    # ---------------- refresh ----------------
    def refresh_all(self) -> None:
        self.refresh_fast()
        self.refresh_db()
        self.refresh_slow()

    def refresh_fast(self) -> None:
        cpu = self.sys.cpu_percent()
        self.cpu_bar[1].setValue(int(cpu))
        self.cpu_bar[0].setText(f"{cpu:.0f}%")
        used, total, pct = self.sys.memory()
        self.ram_bar[1].setValue(int(pct))
        self.ram_bar[0].setText(f"{human_bytes(used)} / {human_bytes(total)}")
        d = self.sys.disk()
        self.disk_bar[1].setValue(int(d.percent))
        self.disk_bar[0].setText(f"{human_bytes(d.used)} / {human_bytes(d.total)}")
        os_ = self.sys.os_info()
        online = self.sys.has_connectivity()
        if self._on_connectivity:
            self._on_connectivity(online)
        self.os_lbl.setText(
            f"<b>{esc(os_.pretty_name)}</b><br>{_muted('Kernel ' + esc(os_.kernel) + ' · host ' + esc(os_.hostname))}"
            + ("" if os_.is_parrot else "<br>" + _muted("Not running on Parrot OS — OS-specific features are limited."))
        )
        self._sys_extra = (human_duration(self.sys.uptime_seconds()), online)
        self._render_sys_extra()

    def _render_sys_extra(self, updates_text: str | None = None) -> None:
        if updates_text is not None:
            self._updates_text = updates_text
        up, online = self._sys_extra
        self.sys_lbl.setText(
            f"Uptime {up} · Network: {'connected' if online else 'not connected'}<br>"
            f"Pending updates: {getattr(self, '_updates_text', _muted('checking…'))}"
        )

    def refresh_slow(self) -> None:
        self.wifi_lbl.setText(_muted("Detecting adapters…"))
        run_in_background(self.adapters.detect, self._show_adapters,
                          lambda e: self.wifi_lbl.setText(f'<span style="color:#F05D5E">Detection failed: {esc(e)}</span>'))
        run_in_background(self.sys.pending_updates, self._show_updates, lambda e: self._render_sys_extra(esc(e)))

    def _show_updates(self, res: dict | None) -> None:
        if res is None:
            self._render_sys_extra(_muted("unavailable (apt not found or query failed)"))
        else:
            self._render_sys_extra(f"{res['upgrade']} upgradable · {res['remove']} to remove "
                                   + _muted("(from cached package lists)"))

    def _show_adapters(self, adapters: list[WirelessAdapter]) -> None:
        if not self.adapters.supported():
            self.wifi_lbl.setText(_muted("Wireless detection needs Linux (/sys/class/net)."))
            return
        if not adapters:
            self.wifi_lbl.setText(_muted("No wireless adapters detected."))
            return
        parts = []
        for a in adapters:
            mon = {True: "supported", False: "not supported", None: "unknown (install <i>iw</i>)"}[a.monitor_capable]
            parts.append(
                f"<b>{esc(a.interface)}</b> — {esc(a.state)}"
                + (f", connected to {esc(a.connected_ssid)}" if a.connected_ssid else "")
                + f"<br>{_muted('Driver')} {esc(a.driver or 'unknown')} · "
                f"{_muted('Maker')} {esc(a.manufacturer or 'unknown')}<br>"
                f"{_muted('Bands')} {esc(', '.join(a.bands) or 'unknown')} · {_muted('Monitor mode')} {mon}"
            )
        self.wifi_lbl.setText("<br><br>".join(parts))

    def refresh_db(self) -> None:
        db = self.app.db
        ts = self.app.tools.summary()
        if ts["scanned"] == 0:
            self.tools_lbl.setText(_muted("Scanning for installed tools…"))
        else:
            self.tools_lbl.setText(
                f"<b>{ts['installed']}</b> installed · {ts['total'] - ts['installed']} not installed<br>"
                f"Healthy: {ts['healthy']} · Warnings: {ts['warnings']} · "
                f"Dependency problems: {ts['errors']}<br>"
                + _muted("Update detection for tools arrives with the software update manager (Phase 7)."))

        running = db.query("SELECT name, tool_id, started_at FROM operations WHERE status='running' "
                           "ORDER BY id DESC LIMIT 5")
        self.live_lbl.setText(
            "<br>".join(f"{esc(r['name'])} {_muted('(' + esc(r['tool_id'] or 'app') + ', since ' + r['started_at'] + ')')}"
                        for r in running) or _muted("No running operations."))

        n_dev = db.query_one("SELECT COUNT(*) n FROM network_devices")["n"]
        n_obs = db.query_one("SELECT COUNT(*) n FROM wireless_observations")["n"]
        ifaces = [i for i in self.sys.interfaces() if i.is_up and i.name != "lo"]
        self.net_lbl.setText(
            f"{n_dev} hosts in inventory · {n_obs} wireless observations<br>"
            f"{_muted('Active interfaces')} " + (esc(", ".join(i.name for i in ifaces)) or "none"))

        sev = db.query("SELECT severity, COUNT(*) n FROM findings WHERE status != 'resolved' GROUP BY severity")
        if sev:
            self.find_lbl.setText("<br>".join(f"{esc(r['severity']).title()}: <b>{r['n']}</b>" for r in sev)
                                  + "<br>" + _muted("unresolved findings"))
        else:
            self.find_lbl.setText(_muted("No findings recorded."))

        projs = db.query("SELECT name, updated_at FROM projects ORDER BY updated_at DESC LIMIT 5")
        self.proj_lbl.setText("<br>".join(f"{esc(r['name'])} {_muted(r['updated_at'])}" for r in projs)
                              or _muted("No projects yet."))
