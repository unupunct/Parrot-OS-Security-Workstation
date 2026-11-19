"""Wi-Fi Center: wireless adapter manager. Three columns (adapters, details, hardware overview) and a diagnostics panel.
Reading state needs no privileges; monitor-mode switching goes through the privileged helper."""
from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (QFrame, QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QStackedWidget,
                               QTextBrowser, QVBoxLayout, QWidget)

from ...application.app_controller import AppController
from ...services.adapter_service import AdapterService, WirelessAdapter
from ...workers.task import run_in_background
from ..design.components import LoadingIndicator, MatrixButton, Panel
from ..design.hardware_art import CAPTIONS, HardwareArt, kind_for
from ..design.icons import icon_pixmap
from ..design.terminal_view import TerminalView
from ..design.tokens import T
from .netsec_common import confirm_dialog

esc = html.escape


def _clear(layout) -> None:
    """Remove every widget from a layout at once (deleteLater alone leaves the old ones painted until the next event loop turn)."""
    while layout.count():
        w = layout.takeAt(0).widget()
        if w is not None:
            w.hide()
            w.setParent(None)
            w.deleteLater()


def chip(text: str, color: str = T.green) -> QLabel:
    c = QLabel(text)
    c.setStyleSheet(f"color: {color}; border: 1px solid {color}; border-radius: 12px; padding: 4px 14px; font-weight: 600;")
    c.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return c


def band_label(bands: list[str]) -> tuple[str, str]:
    n = len(bands)
    if n >= 3:
        return "Tri-band", T.green
    if n == 2:
        return "Dual-band", T.green
    if n == 1:
        return f"{bands[0]} only", T.cyan
    return "Bands unknown", T.text_muted


def bus_label(a: WirelessAdapter) -> str:
    if a.bus == "usb":
        return "USB"
    if a.bus == "pci":
        return "PCIe (internal module)" if a.form_factor == "m2" else "PCIe"
    return (a.bus or "unknown bus").upper() if a.bus else "unknown bus"


class AdapterPage(QWidget):
    """Adapter inventory, driver diagnostics and (through the privileged helper) monitor-mode switching."""

    def __init__(self, app: AppController) -> None:
        super().__init__()
        self.app = app
        self.svc = app.services.get(AdapterService)
        self._adapters: list[WirelessAdapter] = []
        lay = QVBoxLayout(self)

        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon_pixmap("wifi", T.green, 40, 2.0))
        head.addWidget(ic)
        tl = QVBoxLayout()
        tl.setSpacing(0)
        t = QLabel("Wi-Fi Center")
        t.setObjectName("pageTitle")
        sub = QLabel("Wireless adapter manager · inspect hardware, capabilities and interface status")
        sub.setObjectName("muted")
        tl.addWidget(t)
        tl.addWidget(sub)
        head.addLayout(tl)
        self.loader = LoadingIndicator("scan", 22)
        head.addWidget(self.loader)
        head.addStretch(1)
        self.refresh_btn = MatrixButton("Detect adapters", "primary", "reset")
        self.refresh_btn.clicked.connect(self.refresh)
        head.addWidget(self.refresh_btn)
        lay.addLayout(head)

        cols = QHBoxLayout()
        cols.setSpacing(14)
        # ---- column 1: adapter list
        left = Panel("Adapters")
        self.list = QListWidget()
        self.list.setSpacing(3)
        self.list.currentRowChanged.connect(self._show)
        left.add(self.list, 1)
        left.setMinimumWidth(240)
        left.setMaximumWidth(330)
        cols.addWidget(left, 2)
        # ---- column 2: adapter details
        mid = Panel("Adapter details")
        self.stack = QStackedWidget()
        self.details = QTextBrowser()                    # messages: detecting / none found / unsupported
        self.details.setFrameShape(QFrame.Shape.NoFrame)
        self.grid_host = QWidget()
        self.grid = QGridLayout(self.grid_host)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(24)
        self.grid.setVerticalSpacing(0)
        self.grid.setColumnStretch(1, 1)
        self.stack.addWidget(self.details)
        self.stack.addWidget(self.grid_host)
        mid.add(self.stack, 1)
        cols.addWidget(mid, 3)
        # ---- column 3: hardware overview
        right = Panel("Hardware overview")
        self.art = HardwareArt("generic")
        right.add(self.art, 1)
        self.kind_lbl = QLabel("")
        self.kind_lbl.setObjectName("muted")
        self.kind_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.kind_lbl.setWordWrap(True)
        right.add(self.kind_lbl)
        self.chips = QHBoxLayout()
        self.chips.setSpacing(10)
        cw = QWidget()
        cw.setLayout(self.chips)
        right.add(cw)
        cols.addWidget(right, 3)
        lay.addLayout(cols, 3)

        # ---- diagnostics panel
        diag = Panel("Diagnostics")
        row = QHBoxLayout()
        self.diag_btn = MatrixButton("Run driver diagnostics", icon_name="play")
        self.diag_btn.clicked.connect(self._diagnostics)
        row.addWidget(self.diag_btn)
        self.checks = QHBoxLayout()
        self.checks.setSpacing(28)
        row.addSpacing(18)
        row.addLayout(self.checks, 1)
        self.mon_btn = MatrixButton("Switch to monitor mode…")
        self.mon_btn.clicked.connect(lambda: self._set_mode(True))
        self.res_btn = MatrixButton("Restore normal mode")
        self.res_btn.clicked.connect(lambda: self._set_mode(False))
        row.addWidget(self.mon_btn)
        row.addWidget(self.res_btn)
        rw = QWidget()
        rw.setLayout(row)
        diag.add(rw)
        self.diag = TerminalView()
        self.diag.setMinimumHeight(120)
        diag.add(self.diag, 1)
        lay.addWidget(diag, 2)
        self.refresh()

    # ------------------------------------------------------------------ detection
    def refresh(self) -> None:
        self.refresh_btn.setEnabled(False)
        self.loader.start()
        self.details.setPlainText("Detecting…")
        self.stack.setCurrentWidget(self.details)
        run_in_background(self.svc.detect, self._loaded, lambda e: (self.loader.stop(), self.details.setPlainText(f"Failed: {e}"),
                                                                    self.refresh_btn.setEnabled(True)))

    def _loaded(self, adapters: list[WirelessAdapter]) -> None:
        self.refresh_btn.setEnabled(True)
        self.loader.stop()
        keep = self._current().interface if self._current() else None
        self._adapters = adapters
        self.list.blockSignals(True)
        self.list.clear()
        for a in adapters:
            up = a.state == "up"
            it = QListWidgetItem(f"{a.interface}  ·  {a.state.upper()}")
            it.setIcon(QIcon(icon_pixmap("wifi", T.green if up else T.danger, 22, 2.0)))
            it.setForeground(QColor(T.green if up else T.danger))
            self.list.addItem(it)
        self.list.blockSignals(False)
        if not self.svc.supported():
            self.details.setPlainText("Adapter detection requires Linux (/sys/class/net).")
            self.stack.setCurrentWidget(self.details)
            self._clear_side()
        elif not adapters:
            self.details.setPlainText("No wireless adapters detected.\n\nIf you expect one: check that it is plugged "
                                      "in, that its driver is loaded, and that rfkill is not blocking it.")
            self.stack.setCurrentWidget(self.details)
            self._clear_side()
        else:
            idx = next((i for i, a in enumerate(adapters) if a.interface == keep), 0)
            self.list.setCurrentRow(idx)
            self._show(idx)

    def _clear_side(self) -> None:
        self.art.set_kind("generic")
        self.kind_lbl.setText("")
        self._fill_layout(self.chips, [])
        self._fill_layout(self.checks, [])
        self._sync_mode_buttons()

    def _current(self) -> WirelessAdapter | None:
        r = self.list.currentRow()
        return self._adapters[r] if 0 <= r < len(self._adapters) else None

    # ------------------------------------------------------------------ rendering
    @staticmethod
    def _fill_layout(layout: QHBoxLayout, widgets: list[QWidget]) -> None:
        _clear(layout)
        for w in widgets:
            layout.addWidget(w)
        layout.addStretch(1)

    def _check(self, ok: bool | None, text: str) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        mark = QLabel("✔" if ok else "✖" if ok is False else "?")
        col = T.green if ok else T.danger if ok is False else T.warning
        mark.setFixedSize(26, 26)
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setStyleSheet(f"color: {col}; border: 1.5px solid {col}; border-radius: 13px; font-weight: 800;")
        h.addWidget(mark)
        h.addWidget(QLabel(text))
        return w

    def _row(self, r: int, key: str, value: str, color: str | None = None, dot: bool = False) -> None:
        k = QLabel(key + ":")
        k.setObjectName("muted")
        v = QLabel(("● " if dot else "") + value)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.setWordWrap(True)
        if color:
            v.setStyleSheet(f"color: {color}; font-weight: 700;")
        for w in (k, v):
            w.setContentsMargins(0, 9, 0, 9)
            w.setStyleSheet((w.styleSheet() or "") + f"border-bottom: 1px solid {T.border};")
        self.grid.addWidget(k, r, 0, Qt.AlignmentFlag.AlignTop)
        self.grid.addWidget(v, r, 1)

    def _show(self, _row: int) -> None:
        a = self._current()
        if not a:
            return
        _clear(self.grid)
        mon = {True: "Supported", False: "Not supported", None: "Unknown (needs the iw tool)"}[a.monitor_capable]
        ids = f"0x{a.vendor_id.removeprefix('0x')}:0x{a.product_id.removeprefix('0x')}" if a.vendor_id and a.product_id else "unknown"
        up = a.state == "up"
        rows = [("Interface", a.interface, None, False), ("State", a.state.upper(), T.green if up else T.danger, True),
                ("MAC address", a.mac or "unknown", None, False), ("Driver", a.driver or "unknown", None, False),
                ("Manufacturer", a.manufacturer or "unknown", None, False), ("Vendor:Device ID", ids, None, False),
                ("Bands", ", ".join(a.bands) or "unknown", None, False),
                ("Monitor mode", mon, T.green if a.monitor_capable else (T.danger if a.monitor_capable is False else None), False),
                ("Connected network", a.connected_ssid or "not connected", None, False), ("PHY", a.phy or "unknown", None, False)]
        for i, (k, v, c, d) in enumerate(rows):
            self._row(i, k, v, c, d)
        self.grid.setRowStretch(len(rows), 1)
        self.stack.setCurrentWidget(self.grid_host)
        # hardware overview
        self.art.set_kind(kind_for(a.bus, a.form_factor))
        note = CAPTIONS[kind_for(a.bus, a.form_factor)]
        if a.bus == "pci":
            note += " · form factor inferred from the bus and chassis type (the kernel does not report it)"
        self.kind_lbl.setText(note)
        band_text, band_col = band_label(a.bands)
        self._fill_layout(self.chips, [chip(bus_label(a), T.cyan), chip(a.driver or "no driver", T.green if a.driver else T.danger),
                                       chip(band_text, band_col)])
        # diagnostics summary
        bands_ok = len(a.bands)
        self._fill_layout(self.checks, [
            self._check(bool(a.driver), f"Driver loaded ({a.driver})" if a.driver else "No driver bound"),
            self._check(a.monitor_capable, {True: "Monitor mode supported", False: "Monitor mode not supported",
                                            None: "Monitor mode unknown"}[a.monitor_capable]),
            self._check(bands_ok > 0, f"{bands_ok} band{'s' if bands_ok != 1 else ''} detected" if bands_ok else "No bands reported")])
        self.diag.clear()
        self._sync_mode_buttons()

    # ------------------------------------------------------------------ actions
    def _sync_mode_buttons(self) -> None:
        a = self._current()
        helper = self.app.privileged.available()
        ok = bool(a) and helper and a.monitor_capable is not False
        tip = "" if helper else "The privileged helper is not installed (see Root Access Manager)."
        if a and a.monitor_capable is False:
            tip = "This adapter does not support monitor mode."
        for b in (self.mon_btn, self.res_btn):
            b.setEnabled(ok)
            b.setToolTip(tip)

    def _set_mode(self, monitor: bool) -> None:
        a = self._current()
        if not a:
            return
        from ...services.privileged_service import PrivilegedOp, run_privileged
        if monitor:
            busy = (f"<p style='color:{T.warning}'><b>{esc(a.interface)} is connected to {esc(a.connected_ssid)}.</b> "
                    "Switching it will disconnect it.</p>") if a.connected_ssid else ""
            text = (f"<p>Switch <b>{esc(a.interface)}</b> to monitor mode?</p>{busy}"
                    "<p>The adapter stops being a normal Wi-Fi client until you restore it. NetworkManager is told to leave it "
                    "alone, and the helper remembers its previous mode so <b>Restore normal mode</b> can undo this. "
                    "Do not use the adapter that carries your internet connection. You will be asked to authenticate.</p>")
            if not confirm_dialog(self, "Monitor mode", text, "Switch to monitor mode",
                                  "I understand this adapter will stop working as a normal Wi-Fi client until restored." if a.connected_ssid else None):
                return
            op = PrivilegedOp("iface_monitor", iface=a.interface)
        else:
            if not confirm_dialog(self, "Restore normal mode", f"<p>Restore <b>{esc(a.interface)}</b> to the mode it had before WIFI Center "
                                  "switched it? You will be asked to authenticate.</p>", "Restore"):
                return
            op = PrivilegedOp("iface_restore", iface=a.interface)
        self.app.audit.record("wifi.mode", interface=a.interface, monitor=monitor)
        self.diag.clear()
        self.diag.command(op.summary(), "run by the privileged helper after you authenticate")
        self.mon_btn.setEnabled(False)
        self.res_btn.setEnabled(False)

        def done(res) -> None:
            (self.diag.ok if res.ok else self.diag.error)(res.message)
            self.refresh()

        run_privileged(self.app.privileged, op, self.diag.appendPlainText, done)

    def _diagnostics(self) -> None:
        a = self._current()
        if not a:
            return
        self.diag.clear()
        self.diag.command(f"driver diagnostics for {a.interface}", "read-only")
        run_in_background(lambda: self.svc.diagnostics(a.interface),
                          lambda res: [self._diag_block(t, o) for t, o in res],
                          lambda e: self.diag.error(f"Failed: {e}"))

    def _diag_block(self, title: str, output: str) -> None:
        self.diag.info(f"### {title}")
        self.diag.appendPlainText(output)
