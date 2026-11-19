"""Parrot OS manager: overview, system information, updates, software sources, packages."""
from __future__ import annotations

import html
import threading
from datetime import datetime, timezone

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPlainTextEdit, QSplitter, QTabWidget, QTableWidgetItem, QTextBrowser,
                               QToolButton, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...security.input_validation import ValidationError
from ...services import software_sources as ss
from ...services.apt_service import Transaction, risk_flags
from ...services.package_service import PackageDetails
from ...services.privileged_service import PrivilegedOp, run_privileged
from ...services.system_service import SystemService
from ...services.update_runner import UpdateError, plan_update, run_streaming
from ...workers.task import run_in_background
from ..charts import fmt_ts, make_table
from ..design.components import GaugeWidget, LoadingIndicator, MatrixButton, MetricTile, Panel
from ..design.terminal_view import TerminalView
from ..design.tokens import T
from ..widgets import human_bytes, human_duration
from .netsec_common import confirm_dialog
from .parrot_common import apply_transaction, equivalent_command, proposal_html

esc = html.escape


def _utc(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "unknown"


def _say(label: QLabel, text: str, error: bool = False) -> None:
    label.setText(f"<span style='color:{T.danger if error else T.text_secondary}'>{esc(text)}</span>")


# ====================================================================== overview (System & Hardware)
class ParrotOverviewPage(QWidget):
    def __init__(self, app: AppController, navigate=None) -> None:
        super().__init__()
        self.app = app
        self._navigate = navigate or (lambda _p: None)
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("System & Hardware")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("ring", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        refresh = MatrixButton("Refresh", icon_name="reset")
        refresh.clicked.connect(self.refresh)
        head.addWidget(refresh)
        lay.addLayout(head)
        grid = QGridLayout()
        grid.setSpacing(T.gap)
        names = [("os", "Parrot OS", "hardware", "system_hw"), ("kernel", "Kernel", "cpu", "sys_info"),
                 ("cpu", "CPU", "cpu", "sys_info"), ("mem", "Memory", "hardware", "sys_info"),
                 ("disk", "Storage", "folder", "sys_info"), ("repo", "Repository health", "package", "sys_info"),
                 ("updates", "Available updates", "update", "sys_updates"), ("last_up", "Last update", "history", "maintenance"),
                 ("last_clean", "Last cleanup", "cleanup", "cleanup")]
        self.tiles: dict[str, MetricTile] = {}
        for i, (key, title, icon_name, page) in enumerate(names):
            tile = MetricTile(title, icon_name)
            tile.clicked.connect(lambda p=page: self._navigate(p))
            self.tiles[key] = tile
            grid.addWidget(tile, i // 3, i % 3)
        for c in range(3):
            grid.setColumnStretch(c, 1)
        lay.addLayout(grid)
        gauges = Panel("Live resources")
        row = QHBoxLayout()
        self.g_cpu, self.g_mem, self.g_disk = GaugeWidget("CPU", T.green), GaugeWidget("Memory", T.cyan), GaugeWidget("Storage", T.emerald)
        for g in (self.g_cpu, self.g_mem, self.g_disk):
            row.addWidget(g)
        holder = QWidget()
        holder.setLayout(row)
        gauges.add(holder)
        lay.addWidget(gauges)
        self.note = QLabel("")
        self.note.setWordWrap(True)
        self.note.setObjectName("muted")
        lay.addWidget(self.note)
        lay.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        self.loader.start()
        run_in_background(self._gather, self._show, lambda e: (self.loader.stop(), _say(self.note, f"Failed: {e}", True)))

    def _gather(self) -> dict:
        rep = self.app.sysinfo.collect()
        sysv = self.app.services.get(SystemService)
        ups = self.app.apt.upgradable() if self.app.apt.available() else None
        return {"rep": rep, "cpu": sysv.cpu_percent(), "ups": ups, "refresh": self.app.apt.last_refresh()}

    def _show(self, d: dict) -> None:
        self.loader.stop()
        r = d["rep"]
        T_ = self.tiles
        T_["os"].set(r.os_pretty, "Parrot OS detected" if r.is_parrot else "Not running on Parrot OS",
                     T.success if r.is_parrot else T.warning)
        T_["kernel"].set(r.kernel, f"{r.arch} · up {human_duration(r.uptime_seconds)}", T.cyan)
        T_["cpu"].set(f"{r.cpu_logical} threads", r.cpu_model[:60], T.green)
        pct = r.mem_used / r.mem_total * 100 if r.mem_total else 0
        T_["mem"].set(f"{pct:.0f}% used", f"{human_bytes(r.mem_used)} of {human_bytes(r.mem_total)}",
                      T.danger if pct > 90 else T.warning if pct > 75 else T.success)
        root = next((x for x in r.disks if x.mount in ("/", "C:\\")), r.disks[0] if r.disks else None)
        T_["disk"].set(f"{root.percent:.0f}% used" if root else "unknown",
                       f"{human_bytes(root.used)} of {human_bytes(root.total)} on {root.mount}" if root else "",
                       T.danger if root and root.percent > 90 else T.success)
        active = sum(1 for x in r.repositories if x.enabled and x.kind == "deb")
        T_["repo"].set(f"{active} active" if r.repositories else "none found",
                       "; ".join(r.repo_notes[:1]) or "configuration looks normal",
                       T.warning if r.repo_notes or not active else T.success)
        ups = d["ups"]
        T_["updates"].set("unknown" if ups is None else f"{len(ups)} available",
                          f"lists refreshed {_utc(d['refresh'])}" if d["refresh"] else "package lists never refreshed",
                          T.text_secondary if ups is None else T.warning if ups else T.success)
        lu, lc = self.app.maintenance.last("upgrade"), self.app.maintenance.last("cleanup")
        T_["last_up"].set(fmt_ts(lu["finished_at"]) if lu else "never", "recorded by WIFI Center" if lu else "no upgrade recorded here",
                          T.text_secondary)
        T_["last_clean"].set(fmt_ts(lc["finished_at"]) if lc else "never", f"{lc['files_removed'] or 0} files removed" if lc else "no cleanup recorded here",
                             T.text_secondary)
        self.g_cpu.set_value(d["cpu"])
        self.g_mem.set_value(pct)
        self.g_disk.set_value(root.percent if root else None)
        self.note.setText("Update and cleanup history only includes operations performed through WIFI Center.")


# ====================================================================== system information
class SystemInfoPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("System Information")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("ring", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        b = MatrixButton("Refresh", icon_name="reset")
        b.clicked.connect(self.refresh)
        head.addWidget(b)
        lay.addLayout(head)
        self.tabs = QTabWidget()
        self.t_overview = make_table(["Property", "Value"], stretch_col=1)
        self.t_disks = make_table(["Mount point", "Device", "Type", "Used", "Total", "Use %"], stretch_col=1)
        self.t_net = make_table(["Interface", "State", "Addresses"], stretch_col=2)
        self.t_running = make_table(["Service", "State", "Description"], stretch_col=2)
        self.t_failed = make_table(["Service", "State", "Description"], stretch_col=2)
        svc = QWidget()
        sl = QVBoxLayout(svc)
        self.svc_note = QLabel("")
        self.svc_note.setObjectName("warn")
        sl.addWidget(self.svc_note)
        sl.addWidget(QLabel("Failed services"))
        sl.addWidget(self.t_failed, 1)
        sl.addWidget(QLabel("Running services"))
        sl.addWidget(self.t_running, 2)
        self.t_repo = make_table(["Type", "URI", "Suite", "Components", "State", "Source file"], stretch_col=1)
        repo = QWidget()
        rl = QVBoxLayout(repo)
        self.repo_notes = QLabel("")
        self.repo_notes.setWordWrap(True)
        rl.addWidget(self.repo_notes)
        rl.addWidget(self.t_repo, 1)
        for w, name in ((self.t_overview, "Overview"), (self.t_disks, "Storage and filesystems"),
                        (self.t_net, "Network interfaces"), (svc, "Services"), (repo, "Package repositories")):
            self.tabs.addTab(w, name)
        lay.addWidget(self.tabs, 1)
        self.msg = QLabel("")
        lay.addWidget(self.msg)
        self.refresh()

    def refresh(self) -> None:
        self.loader.start()
        run_in_background(self.app.sysinfo.collect, self._show, lambda e: (self.loader.stop(), _say(self.msg, f"Failed: {e}", True)))

    @staticmethod
    def _fill(table, rows) -> None:
        table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, v in enumerate(row):
                table.setItem(r, c, QTableWidgetItem(str(v)))

    def _show(self, r) -> None:
        self.loader.stop()
        self._fill(self.t_overview, [
            ("Operating system", r.os_pretty), ("Release codename", r.codename or "unknown"), ("Kernel", r.kernel),
            ("Architecture", r.arch), ("Host name", r.hostname), ("CPU", f"{r.cpu_model} ({r.cpu_physical} cores, {r.cpu_logical} threads)"),
            ("Memory", f"{human_bytes(r.mem_used)} used of {human_bytes(r.mem_total)}"),
            ("Swap", f"{human_bytes(r.swap_used)} of {human_bytes(r.swap_total)}" if r.swap_total else "none"),
            ("Boot time", _utc(r.boot_time)), ("Uptime", human_duration(r.uptime_seconds)),
            ("Boot analysis", r.boot_analysis or "not available (systemd-analyze)"), ("Desktop environment", r.desktop)])
        self._fill(self.t_disks, [(d.mount, d.device, d.fstype, human_bytes(d.used), human_bytes(d.total), f"{d.percent:.0f}%")
                                  for d in r.disks])
        self._fill(self.t_net, [(n, "up" if up else "down", ", ".join(a) or "—") for n, up, a in r.interfaces])
        self._fill(self.t_running, [(u.name, u.sub, u.description) for u in r.running])
        self._fill(self.t_failed, [(u.name, u.sub, u.description) for u in r.failed])
        self.svc_note.setText(r.services_note or ("" if r.failed else "No failed services."))
        self.svc_note.setObjectName("warn" if r.services_note else "ok")
        self._fill(self.t_repo, [(x.kind, x.uri, x.suite, " ".join(x.components), "enabled" if x.enabled else "disabled",
                                  x.source_file) for x in r.repositories])
        self.repo_notes.setText("<br>".join(esc(n) for n in r.repo_notes) or
                                f"<span style='color:{T.text_secondary}'>No problems found in the repository configuration.</span>")


# ====================================================================== system updates
STEPS = ["Check network connectivity", "Check repository configuration", "Refresh package metadata",
         "Retrieve the package transaction proposal", "Display the changes", "Request your confirmation",
         "Execute the approved transaction", "Show live output", "Record the transaction", "Report the result"]


class SystemUpdatesPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._tx: Transaction | None = None
        self._kind = "upgrade"
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("System Updates")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("radar", 26)
        head.addWidget(self.loader)
        head.addStretch(1)
        lay.addLayout(head)

        tiles = QHBoxLayout()
        self.t_refresh = MetricTile("Last package-list refresh", "history")
        self.t_avail = MetricTile("Available updates", "update")
        self.t_changes = MetricTile("Install / remove", "package")
        self.t_size = MetricTile("Estimated download", "folder")
        for x in (self.t_refresh, self.t_avail, self.t_changes, self.t_size):
            tiles.addWidget(x)
        lay.addLayout(tiles)
        self.banner = QLabel("")
        self.banner.setWordWrap(True)
        lay.addWidget(self.banner)

        panel = Panel("Update workflow")
        row = QHBoxLayout()
        self.b_check = MatrixButton("Check for Updates", "primary", "reset")
        self.b_check.clicked.connect(self.check)
        self.b_lists = MatrixButton("Update Package Lists")
        self.b_lists.clicked.connect(self.update_lists)
        self.b_upgrade = MatrixButton("Upgrade Installed Packages")
        self.b_upgrade.clicked.connect(lambda: self.propose("upgrade"))
        self.b_full = MatrixButton("Full System Upgrade")
        self.b_full.clicked.connect(lambda: self.propose("dist-upgrade"))
        self.b_view = MatrixButton("View Package Changes")
        self.b_view.clicked.connect(lambda: self.propose("upgrade", apply=False))
        for b in (self.b_check, self.b_lists, self.b_upgrade, self.b_full, self.b_view):
            row.addWidget(b)
        holder = QWidget()
        holder.setLayout(row)
        panel.add(holder)
        self.steps_lbl = QLabel()
        self.steps_lbl.setTextFormat(Qt.TextFormat.RichText)
        panel.add(self.steps_lbl)
        self._mark(0)
        lay.addWidget(panel)

        split = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table(["Package", "Action", "Current", "New", "Source"], stretch_col=0)
        self.table.setSortingEnabled(True)
        split.addWidget(self.table)
        out = QWidget()
        ol = QVBoxLayout(out)
        ol.setContentsMargins(0, 0, 0, 0)
        self.toggle = QToolButton()
        self.toggle.setText("▾ Live output")
        self.toggle.setCheckable(True)
        self.toggle.setChecked(True)
        self.toggle.toggled.connect(lambda on: (self.output.setVisible(on), self.toggle.setText(("▾" if on else "▸") + " Live output")))
        self.output = TerminalView()
        self.output.setMinimumHeight(150)
        ol.addWidget(self.toggle)
        ol.addWidget(self.output)
        split.addWidget(out)
        split.setStretchFactor(0, 3)
        split.setSizes([260, 160])
        self.table.setMinimumHeight(150)
        lay.addWidget(split, 1)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self._banner()
        self._refresh_tiles()

    # ---- helpers
    def _banner(self) -> None:
        parts = []
        if not self.app.apt.available():
            parts.append("APT is not available on this system, so updates cannot be checked here.")
        if not self.app.privileged.available():
            parts.append(self.app.privileged.explain_unavailable())
        holders = self.app.apt.lock_holders() if self.app.apt.available() else []
        if holders:
            parts.append("Another package manager is running: " + ", ".join(holders) + ".")
        self.banner.setText(f"<span style='color:{T.warning}'>{esc(' '.join(parts))}</span>" if parts else "")
        for b in (self.b_check, self.b_upgrade, self.b_full, self.b_view):
            b.setEnabled(self.app.apt.available())
        self.b_lists.setEnabled(self.app.apt.available())

    def _refresh_tiles(self, tx: Transaction | None = None) -> None:
        last = self.app.apt.last_refresh()
        age = (datetime.now(timezone.utc) - last).days if last else None
        self.t_refresh.set(_utc(last)[:16] if last else "never", f"{age} day(s) ago" if age is not None else "no timestamp found",
                           T.warning if age is None or age > 7 else T.success)
        if tx and tx.ok:
            n = len(tx.upgrades)
            self.t_avail.set(str(n), f"{tx.counts[3]} not upgraded" if tx.counts[3] else "from cached package lists",
                             T.warning if n else T.success)
            self.t_changes.set(f"{len(tx.installs)} / {len(tx.removes)}", "new packages / removals",
                               T.danger if tx.removes else T.text_secondary)
            self.t_size.set(tx.download or "0 B", tx.disk_change and f"disk {tx.disk_change}" or "", T.cyan)
        else:
            for tile in (self.t_avail, self.t_changes, self.t_size):
                tile.set("—", "press Check for Updates", T.text_secondary)

    def _mark(self, upto: int, current: int | None = None) -> None:
        cells = []
        for i, name in enumerate(STEPS):
            mark, col = ("✔", T.success) if i < upto else (("▶", T.info) if i == current else ("○", T.text_muted))
            cells.append(f"<span style='color:{col}'>{mark}</span> {i + 1}. {esc(name)}")
        half = (len(cells) + 1) // 2
        rows = "".join(f"<tr><td style='padding-right:36px'>{cells[r]}</td><td>{cells[r + half] if r + half < len(cells) else ''}</td></tr>"
                       for r in range(half))
        self.steps_lbl.setText(f"<table cellpadding='2'>{rows}</table>")

    def _fill_table(self, tx: Transaction) -> None:
        rows = [(c.name, "remove", c.old, "", "") for c in tx.removes] + \
               [(c.name, "install", "", c.new, c.origin) for c in tx.installs] + \
               [(c.name, "upgrade", c.old, c.new, c.origin) for c in tx.upgrades]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, v in enumerate(row):
                item = QTableWidgetItem(v)
                if c == 1:
                    item.setForeground(QColor({"remove": T.danger, "install": T.info, "upgrade": T.success}[v]))
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)

    # ---- actions
    def check(self) -> None:
        self._banner()
        self.output.clear()
        self.loader.start()
        self._mark(0, 0)
        self.msg.setText("")

        def work():
            online = self.app.services.get(SystemService).has_connectivity()
            repos = self.app.apt.repositories()
            tx = self.app.apt.plan("upgrade")
            return online, repos, tx

        def done(res) -> None:
            online, repos, tx = res
            self.loader.stop()
            self._tx, self._kind = tx, "upgrade"
            self._mark(5)
            self._refresh_tiles(tx)
            self._fill_table(tx)
            self.output.setPlainText(tx.raw or tx.error)
            notes = [] if online else ["No network connection detected: update lists cannot be refreshed."]
            notes.append("Metadata step skipped: refreshing needs root (use Update Package Lists); the lists shown are "
                         "the cached ones.")
            if not any(r.enabled for r in repos):
                notes.append("No enabled repositories are configured.")
            notes += risk_flags(tx)
            if not tx.ok:
                _say(self.msg, f"Check failed: {tx.error}", True)
            else:
                _say(self.msg, f"{len(tx.upgrades)} package(s) can be upgraded." + (" " + " ".join(notes) if notes else ""),
                     bool(risk_flags(tx)))
        run_in_background(work, done, lambda e: (self.loader.stop(), _say(self.msg, f"Check failed: {e}", True)))

    def update_lists(self) -> None:
        online = self.app.services.get(SystemService).has_connectivity()
        text = ("<p>Refresh the package lists from the configured repositories (<code>apt-get update</code>)?</p>"
                "<p>This contacts your repository servers and changes only the package lists, not installed software.</p>"
                + ("" if online else f"<p style='color:{T.warning}'>No network connection was detected.</p>")
                + f"<p style='color:{T.text_secondary}'>Equivalent command: <code>{esc(equivalent_command('update'))}</code></p>")
        if not self.app.privileged.available():
            text = f"<p style='color:{T.warning}'>{esc(self.app.privileged.explain_unavailable())}</p>" + text
        ok = confirm_dialog(self, "Update package lists", text, "Update lists" if self.app.privileged.available() else "Close")
        if not self.app.privileged.available():
            self.app.maintenance.record("Update package lists", "update", "not executed",
                                        errors="privileged helper unavailable; nothing was changed")
            _say(self.msg, self.app.privileged.explain_unavailable())
            return
        if not ok:
            return
        if self.app.apt.lock_holders():
            _say(self.msg, "Another package manager is running; try again when it finishes.", True)
            return
        self.output.clear()
        self.output.command("apt-get update", "run by the privileged helper after you authenticate")

        def finished(res) -> None:
            (self.output.ok if res.ok else self.output.error)(res.message)
            status = "success" if res.ok else ("failed" if res.executed else "cancelled")
            self.app.maintenance.record("Update package lists", "update", status, errors="" if res.ok else res.message)
            _say(self.msg, res.message, not res.ok)
            self._refresh_tiles(self._tx)
        _say(self.msg, "Waiting for authorization and the helper…")
        run_privileged(self.app.privileged, PrivilegedOp("apt_update"), self.output.appendPlainText, finished)

    def propose(self, kind: str, apply: bool = True) -> None:
        self._banner()
        self.loader.start()
        self._mark(3, 3)

        def done(tx: Transaction) -> None:
            self.loader.stop()
            self._tx, self._kind = tx, kind
            self._fill_table(tx)
            self._refresh_tiles(tx)
            self.output.setPlainText(tx.raw or tx.error)
            self._mark(5, 5)
            if not apply:
                _say(self.msg, "Proposed changes shown above; nothing was applied." if tx.ok else f"Failed: {tx.error}", not tx.ok)
                return
            self.output.clear()
            self.output.command(equivalent_command(kind, None), "run by the privileged helper after you authenticate")
            self._mark(6, 6)

            def finished(msg: str) -> None:
                _say(self.msg, msg, msg.startswith(("Failed", "Cannot")))
                self._mark(10)
                self._refresh_tiles(None)
            first = apply_transaction(self, self.app, tx, kind, on_output=self.output.appendPlainText, on_done=finished)
            _say(self.msg, first, first.startswith(("Failed", "Cannot")))
        run_in_background(lambda: self.app.apt.plan(kind), done, lambda e: (self.loader.stop(), _say(self.msg, f"Failed: {e}", True)))


# ====================================================================== software updates
class _UpdateBridge(QObject):
    """Worker-thread output reaches the GUI thread through queued signals."""
    line = Signal(str)
    done = Signal(object, str)


class SoftwareUpdatesPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._reports: list[ss.SourceReport] = []
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Software Updates")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("nodes", 18)
        head.addWidget(self.loader)
        head.addStretch(1)
        lay.addLayout(head)
        note = QLabel("Detection across APT, Flatpak, Snap, pipx, git checkouts and AppImages. Checking Flatpak, Snap and "
                      "git for updates contacts their servers, so it only runs when you ask. Updates other than APT are "
                      "never applied here: the exact command is shown for you to run.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        self.sources = make_table(["Source", "Items", "Updates", "Update method", "Last check", "Status"], stretch_col=3)
        self.sources.itemSelectionChanged.connect(self._select)
        lay.addWidget(self.sources, 1)
        row = QHBoxLayout()
        self.b_scan = MatrixButton("Detect sources", "primary", "reset")
        self.b_scan.clicked.connect(self.scan)
        self.b_check = MatrixButton("Check selected for updates…")
        self.b_check.clicked.connect(self.check_selected)
        self.b_update = MatrixButton("Update now…", "primary", "update")
        self.b_update.clicked.connect(lambda: self._update(False))
        self.b_update_item = MatrixButton("Update selected item…")
        self.b_update_item.clicked.connect(lambda: self._update(True))
        self.b_cancel = MatrixButton("Stop")
        self.b_cancel.clicked.connect(self._stop)
        self.b_cancel.setEnabled(False)
        self.b_copy = MatrixButton("Copy command")
        self.b_copy.clicked.connect(self._copy_command)
        for b in (self.b_scan, self.b_check, self.b_update, self.b_update_item, self.b_cancel, self.b_copy):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        self.items = make_table(["Name", "Installed", "Available", "Status", "Detail"], stretch_col=4)
        self.items.itemSelectionChanged.connect(self._select_item)
        lay.addWidget(self.items, 2)
        self.term = TerminalView()
        self.term.setMinimumHeight(150)
        self.term.info("Update terminal: the command and its output appear here.")
        lay.addWidget(self.term, 2)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self._cancel: threading.Event | None = None
        self._bridge = _UpdateBridge()
        self._bridge.line.connect(self.term.appendPlainText)
        self._bridge.done.connect(self._update_done)
        self.scan()

    def _checkouts(self) -> dict[str, str]:
        out = {}
        for s in self.app.tools.statuses():
            p = s.config.get("install_path")
            if p:
                out[s.profile.name] = p
        return out

    def scan(self) -> None:
        self.loader.start()
        run_in_background(lambda: self.app.software.all(self._checkouts()), self._loaded,
                          lambda e: (self.loader.stop(), _say(self.msg, f"Failed: {e}", True)))

    def _loaded(self, reports: list[ss.SourceReport]) -> None:
        self.loader.stop()
        self._reports = reports
        self.sources.setRowCount(len(reports))
        for r, rep in enumerate(reports):
            status = "not installed" if not rep.present else ("error: " + rep.error if rep.error else
                                                              (rep.note[:70] if rep.note else "ok"))
            vals = [rep.title, str(len(rep.items)) if rep.present else "—", str(rep.updates) if rep.present else "—",
                    rep.update_method, fmt_ts(rep.last_check) if rep.last_check else "not checked", status]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 2 and rep.updates:
                    item.setForeground(QColor(T.warning))
                if c == 5 and rep.error:
                    item.setForeground(QColor(T.danger))
                self.sources.setItem(r, c, item)
        if reports and self.sources.currentRow() < 0:
            self.sources.selectRow(0)
        self._select()

    def _current(self) -> ss.SourceReport | None:
        r = self.sources.currentRow()
        return self._reports[r] if 0 <= r < len(self._reports) else None

    def _select(self) -> None:
        rep = self._current()
        rows = rep.items if rep else []
        self.items.setRowCount(len(rows))
        for r, i in enumerate(rows):
            for c, v in enumerate([i.name, i.installed, i.available, i.status, i.detail]):
                item = QTableWidgetItem(v)
                if c == 3:
                    item.setForeground(QColor({ss.UPDATE: T.warning, ss.UP_TO_DATE: T.success, ss.ERROR: T.danger}.get(v, T.text_muted)))
                self.items.setItem(r, c, item)
        self.b_check.setEnabled(bool(rep and rep.present and rep.key in ("flatpak", "snap", "git")))
        self.b_copy.setEnabled(bool(rep and rep.present))
        self._sync_update_buttons()
        if rep:
            _say(self.msg, rep.note or rep.update_method)

    def check_selected(self) -> None:
        rep = self._current()
        if not rep:
            return
        hosts = {"flatpak": "your Flatpak remotes (for example flathub.org)", "snap": "the Snap Store",
                 "git": "the git remotes of your configured tool checkouts"}[rep.key]
        if not confirm_dialog(self, "Check for updates", f"This contacts <b>{esc(hosts)}</b>. Nothing is downloaded or "
                              "installed.", "Check"):
            return
        self.loader.start()
        fn = {"flatpak": lambda: self.app.software.flatpak(True), "snap": lambda: self.app.software.snap(True),
              "git": lambda: self.app.software.git(self._checkouts(), True)}[rep.key]
        self.app.audit.record("software.check", source=rep.key)

        def done(new: ss.SourceReport) -> None:
            self.loader.stop()
            self._reports = [new if r.key == new.key else r for r in self._reports]
            self._loaded(self._reports)
            _say(self.msg, f"{new.title}: {new.updates} update(s) available." + (f" Error: {new.error}" if new.error else ""),
                 bool(new.error))
        run_in_background(fn, done, lambda e: (self.loader.stop(), _say(self.msg, f"Check failed: {e}", True)))

    # ---------------------------------------------------------------- running updates in the app
    def _sync_update_buttons(self) -> None:
        rep, running = self._current(), self._cancel is not None
        can = bool(rep and rep.present and rep.key in ("flatpak", "pipx", "git", "snap")) and not running
        self.b_update.setEnabled(bool(rep and rep.present and rep.key == "apt") or can)
        self.b_update.setText("Open System Updates" if rep and rep.key == "apt" else "Update now…")
        item = self._current_item()
        self.b_update_item.setEnabled(can and rep is not None and rep.key in ("pipx", "git") and item is not None)
        self.b_cancel.setEnabled(running)

    def _select_item(self) -> None:
        self._sync_update_buttons()

    def _current_item(self):
        rep, r = self._current(), self.items.currentRow()
        return rep.items[r] if rep and 0 <= r < len(rep.items) else None

    def _update(self, one: bool) -> None:
        rep = self._current()
        if not rep or self._cancel is not None:
            return
        if rep.key == "apt":
            nav = getattr(self.window(), "sidebar", None)
            if nav is not None:
                nav.select_page("sys_updates")
            return
        item = self._current_item() if one else None
        try:
            if rep.key == "git":
                if item is None:
                    _say(self.msg, "Select the tool checkout to update.", True)
                    return
                cmd = plan_update("git", item.detail, self._checkouts())
            else:
                cmd = plan_update(rep.key, item.name if (one and item) else "", self._checkouts())
        except UpdateError as e:
            _say(self.msg, str(e), True)
            return
        if not confirm_dialog(self, cmd.title, f"<p>This runs:</p><p><code>{esc(cmd.display)}</code></p><p>It contacts "
                              f"<b>{esc(cmd.contacts)}</b> and installs the updates it finds. Nothing runs as root.</p>", "Run update"):
            return
        self._cancel = threading.Event()
        cancel, key = self._cancel, rep.key
        self.term.clear()
        self.term.command(cmd.display)
        self.loader.start()
        self._sync_update_buttons()
        self.app.audit.record("software.update", source=key, argv=list(cmd.argv))
        title = cmd.title

        def work() -> None:
            code, status = run_streaming(cmd, self._bridge.line.emit, cancel)
            self._bridge.done.emit((title, key), status if code is None or status != "succeeded" else "succeeded")

        threading.Thread(target=work, name="software-update", daemon=True).start()

    def _stop(self) -> None:
        if self._cancel is not None:
            self._cancel.set()
            self.term.warn("Stopping…")

    def _update_done(self, ident, status: str) -> None:
        title, key = ident
        self._cancel = None
        self.loader.stop()
        ok = status == "succeeded"
        (self.term.ok if ok else self.term.error)({"succeeded": "Finished: the update completed.", "failed": "The update failed; see the output above.",
                                                   "cancelled": "Stopped.", "timeout": "Timed out and was stopped.",
                                                   "missing": "The program is not installed."}.get(status, status))
        self.app.maintenance.record(title, "update", "success" if ok else ("cancelled" if status == "cancelled" else "failed"),
                                    errors="" if ok else status)
        _say(self.msg, f"{title}: {status}.", not ok)
        self.scan()

    def _copy_command(self) -> None:
        rep = self._current()
        if not rep:
            return
        cmds = {"apt": "Use System Updates (confirmed, via the privileged helper).", "flatpak": "flatpak update",
                "snap": "sudo snap refresh", "pipx": "pipx upgrade <name>   (never `pip install -U` on system packages)",
                "git": "git -C <folder> pull   (review the changes first)", "appimage": "Use the application's own updater."}
        text = cmds[rep.key]
        QGuiApplication.clipboard().setText(text)
        _say(self.msg, f"Copied: {text}")


# ====================================================================== package manager
class PackageManagerPage(QWidget):
    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self._rows = []
        self._details: PackageDetails | None = None
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        t = QLabel("Package Manager")
        t.setObjectName("pageTitle")
        head.addWidget(t)
        self.loader = LoadingIndicator("scan", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        lay.addLayout(head)
        bar = QHBoxLayout()
        self.scope = QComboBox()
        self.scope.addItems(["Installed packages", "Available packages"])
        self.query = QLineEdit()
        self.query.setPlaceholderText("Package name or keyword (letters, digits, + . _ : -)")
        self.query.returnPressed.connect(self.search)
        go = MatrixButton("Search", "primary", "search")
        go.clicked.connect(self.search)
        bar.addWidget(self.scope)
        bar.addWidget(self.query, 1)
        bar.addWidget(go)
        lay.addLayout(bar)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.table = make_table(["Package", "Version", "Status", "Size", "Summary"], stretch_col=4)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._select)
        split.addWidget(self.table)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.detail = QTextBrowser()
        rl.addWidget(self.detail, 1)
        brow = QHBoxLayout()
        self.b_install = MatrixButton("Install…", "primary")
        self.b_install.clicked.connect(lambda: self._propose("install"))
        self.b_remove = MatrixButton("Remove…", "danger")
        self.b_remove.clicked.connect(lambda: self._propose("remove"))
        brow.addWidget(self.b_install)
        brow.addWidget(self.b_remove)
        rl.addLayout(brow)
        split.addWidget(right)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        lay.addWidget(split, 3)
        lay.addWidget(QLabel("Transaction history"))
        self.history = make_table(["When", "Operation", "Result", "Packages"], stretch_col=3)
        self.history.setMaximumHeight(150)
        lay.addWidget(self.history)
        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        lay.addWidget(self.msg)
        self._reload_history()
        self.search()

    def search(self) -> None:
        installed = self.scope.currentIndex() == 0
        q = self.query.text()
        if not installed:
            try:
                self.app.packages.validate_query(q)
            except ValidationError as e:
                _say(self.msg, str(e), True)
                return
        self.loader.start()
        fn = (lambda: self.app.packages.installed(q)) if installed else (lambda: self.app.packages.search_available(q))
        run_in_background(fn, self._loaded, lambda e: (self.loader.stop(), _say(self.msg, f"Search failed: {e}", True)))

    def _loaded(self, rows) -> None:
        self.loader.stop()
        self._rows = rows
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for r, p in enumerate(rows):
            status = "upgradable" if p.upgradable else p.status
            for c, v in enumerate([p.name, p.version, status, f"{p.size_kb:,} KiB" if p.size_kb else "", p.summary]):
                item = QTableWidgetItem(v)
                if c == 2 and p.upgradable:
                    item.setForeground(QColor(T.warning))
                self.table.setItem(r, c, item)
        self.table.setSortingEnabled(True)
        _say(self.msg, f"{len(rows)} package(s)." if rows else ("No matching packages. " + (
            "Is APT available on this system?" if not self.app.apt.available() else "")))
        self._select()

    def _current_name(self) -> str | None:
        r = self.table.currentRow()
        it = self.table.item(r, 0) if r >= 0 else None
        return it.text() if it else None

    def _select(self) -> None:
        name = self._current_name()
        for b in (self.b_install, self.b_remove):
            b.setEnabled(bool(name))
        if not name:
            self.detail.setHtml(f"<p style='color:{T.text_secondary}'>Select a package.</p>")
            return
        self.detail.setHtml("<p>Loading…</p>")
        run_in_background(lambda: self.app.packages.details(name), self._show_details,
                          lambda e: self.detail.setHtml(f"<p>{esc(str(e))}</p>"))

    def _show_details(self, d: PackageDetails) -> None:
        self._details = d
        f = d.fields
        rows = [("Status", d.status), ("Installed", d.installed or "—"), ("Candidate", d.candidate or "—"),
                ("Section", f.get("Section", "")), ("Priority", f.get("Priority", "")), ("Maintainer", f.get("Maintainer", "")),
                ("Installed size", f.get("Installed-Size", "") + " KiB" if f.get("Installed-Size") else ""),
                ("Homepage", f.get("Homepage", ""))]
        body = "".join(f"<tr><td style='color:{T.text_secondary}'>{k}&nbsp;</td><td>{esc(v)}</td></tr>" for k, v in rows if v)
        deps = "".join(f"<li>{esc(x)}</li>" for x in d.depends[:25]) or "<li>none listed</li>"
        origins = "".join(f"<li>{esc(o)}</li>" for o in d.origins) or "<li>none (not in any configured repository)</li>"
        desc = esc(f.get("Description", "")).replace("\n", "<br>")
        self.detail.setHtml(f"<h3>{esc(d.name)}</h3><p>{desc}</p><table cellpadding='3'>{body}</table>"
                            f"<h4>Repositories</h4><ul>{origins}</ul><h4>Depends</h4><ul>{deps}</ul>")

    def _propose(self, kind: str) -> None:
        name = self._current_name()
        if not name:
            return
        self.loader.start()

        def done(tx: Transaction) -> None:
            self.loader.stop()

            def finished(msg: str) -> None:
                _say(self.msg, msg, msg.startswith(("Failed", "Cannot")))
                self._reload_history()
            first = apply_transaction(self, self.app, tx, kind, [name], on_done=finished)
            _say(self.msg, first, first.startswith(("Failed", "Cannot")))
            self._reload_history()
        run_in_background(lambda: self.app.apt.plan(kind, [name]), done,
                          lambda e: (self.loader.stop(), _say(self.msg, f"Failed: {e}", True)))

    def _reload_history(self) -> None:
        rows = [e for e in self.app.maintenance.entries(limit=200) if e["op_type"] in ("install", "remove", "upgrade", "update")][:30]
        self.history.setRowCount(len(rows))
        for r, e in enumerate(rows):
            for c, v in enumerate([fmt_ts(e["finished_at"]), e["name"], e["result"], (e["packages_changed"] or "").replace("\n", ", ")[:120]]):
                self.history.setItem(r, c, QTableWidgetItem(v))
