"""BluetoothDiagnostics: controller status, service and rfkill state, plain-language findings, a shareable log, and a confirmed adapter reset.

Everything is read without root. The reset toggles the adapter's Powered property through BlueZ (not a driver reload) and is refused
while any device is connected through it."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from ..services.process_runner import find_executable, run_command
from .adapter import BluetoothAdapterManager, friendly_settings
from .bluez import BluezAPI
from .models import AdapterInfo, BluetoothError, OpResult, utcnow
from .scanner import BluetoothScanner


def parse_rfkill(text: str) -> list[tuple[str, str, str]]:
    """`rfkill list bluetooth` -> [(hciN, soft 'yes'/'no', hard 'yes'/'no')]."""
    out, cur = [], None
    for line in text.splitlines():
        m = re.match(r"\s*\d+:\s+(\S+):\s+Bluetooth", line)
        if m:
            cur = [m.group(1), "no", "no"]
            out.append(cur)
        elif cur and "Soft blocked:" in line:
            cur[1] = line.split(":", 1)[1].strip()
        elif cur and "Hard blocked:" in line:
            cur[2] = line.split(":", 1)[1].strip()
    return [tuple(x) for x in out]


@dataclass
class Issue:
    level: str          # ok | info | warning | error
    text: str


@dataclass
class DiagnosticsReport:
    generated: str
    service: str                    # active | inactive | unknown
    bluez_version: str
    rfkill: str
    adapters: list[AdapterInfo]
    issues: list[Issue] = field(default_factory=list)

    def to_text(self) -> str:
        lines = [f"Bluetooth diagnostics {self.generated}", f"bluetooth.service: {self.service}", f"BlueZ: {self.bluez_version or 'unknown'}", ""]
        for a in self.adapters:
            lines += [f"[{a.name}] {a.address}  {'powered' if a.powered else 'POWERED OFF'}  alias '{a.alias}'",
                      f"  chipset: {a.manufacturer or 'unknown'}   Bluetooth {a.hci_version or 'unknown'}   bus {a.bus or '?'}   driver {a.driver or '?'}",
                      f"  USB: {a.usb_id or '-'} {a.usb_name}", f"  Classic: {a.classic}   BLE: {a.ble}",
                      f"  supported: {', '.join(friendly_settings(a.supported_settings)) or 'unknown'}",
                      f"  current: {', '.join(friendly_settings(a.current_settings)) or 'unknown'}",
                      f"  features: {', '.join(a.lmp_features) or 'unknown'}", ""]
        lines += ["rfkill:", self.rfkill or "(not available)", "", "Findings:"] + [f"  [{i.level}] {i.text}" for i in self.issues]
        return "\n".join(lines) + "\n"

    def to_json(self) -> str:
        return json.dumps({"generated": self.generated, "service": self.service, "bluez": self.bluez_version, "rfkill": self.rfkill,
                           "adapters": [{k: getattr(a, k) for k in ("name", "address", "alias", "powered", "manufacturer", "hci_version", "bus", "driver",
                                                                      "usb_id", "usb_name", "supported_settings", "current_settings", "lmp_features")} for a in self.adapters],
                           "findings": [{"level": i.level, "text": i.text} for i in self.issues]}, indent=2)


class BluetoothDiagnostics:
    def __init__(self, api: BluezAPI, manager: BluetoothAdapterManager, scanner: BluetoothScanner, run: Callable | None = None,
                 which: Callable[[str], str | None] = find_executable, sleep: Callable[[float], None] = time.sleep) -> None:
        self._api, self._mgr, self._sc = api, manager, scanner
        self._run = run or (lambda argv, t: run_command(argv, timeout=t))
        self._which = which
        self._sleep = sleep

    def _out(self, argv: list[str]) -> str:
        if not self._which(argv[0]):
            return ""
        r = self._run(argv, 8)
        return ((r.stdout or "") + ("" if getattr(r, "ok", False) else "")).strip()

    def report(self) -> DiagnosticsReport:
        state = self._out(["systemctl", "is-active", "bluetooth"]).splitlines()
        service = state[0] if state else "unknown"
        ver = self._out(["bluetoothctl", "--version"])
        m = re.search(r"(\d+\.\d+)", ver)
        rf = self._out(["rfkill", "list", "bluetooth"])
        adapters = self._mgr.list() if self._api.available() else []
        rep = DiagnosticsReport(utcnow(), service, m.group(1) if m else "", rf, adapters)
        rep.issues = self.findings(rep)
        return rep

    @staticmethod
    def findings(rep: DiagnosticsReport) -> list[Issue]:
        out: list[Issue] = []
        if rep.service not in ("active", "unknown"):
            out.append(Issue("error", f"bluetooth.service is {rep.service}: Bluetooth is not running. Start it with 'sudo systemctl start bluetooth'."))
        if not rep.adapters:
            out.append(Issue("error", "No Bluetooth controller is visible to BlueZ. Plug in an adapter, check 'rfkill list' and that its driver is loaded."))
        blocks = parse_rfkill(rep.rfkill)
        for name, soft, hard in blocks:
            if hard == "yes":
                out.append(Issue("error", f"{name} is hard-blocked (a hardware switch). Switch it on, then try again."))
            elif soft == "yes":
                out.append(Issue("warning", f"{name} is soft-blocked by rfkill. Unblock it with 'rfkill unblock bluetooth'."))
        for a in rep.adapters:
            if not a.powered:
                out.append(Issue("warning", f"{a.name} is powered off. Power it on from this page to scan with it."))
            if a.ble is False:
                out.append(Issue("info", f"{a.name} ({a.manufacturer or 'unknown chipset'}, Bluetooth {a.hci_version or '?'}) has no Low Energy support: BLE scans and the BLE Explorer need a different adapter."))
            if a.classic is False:
                out.append(Issue("info", f"{a.name} is a BLE-only controller: Classic Bluetooth scans are not possible with it."))
            if a.powered and not a.supported_settings:
                out.append(Issue("info", f"Capabilities of {a.name} could not be read (btmgmt/hciconfig missing); features are shown as unknown."))
        if not any(i.level in ("error", "warning") for i in out):
            out.append(Issue("ok", "Bluetooth service, controller and rfkill look healthy."))
        return out

    def connected_devices(self, adapter_path: str) -> list[str]:
        return [d.address for d in self._sc.devices(adapter_path) if d.connected]

    def reset_adapter(self, adapter_path: str, confirmed: bool = False) -> OpResult:
        """Power-cycle an adapter. Needs explicit confirmation and is refused while a device is connected through it."""
        if not confirmed:
            return OpResult(False, "Resetting an adapter needs explicit confirmation.")
        live = self.connected_devices(adapter_path)
        if live:
            return OpResult(False, f"Not reset: {len(live)} device(s) are connected through this adapter ({', '.join(live[:3])}). Disconnect them first.")
        try:
            self._mgr.set_powered(adapter_path, False)
            self._sleep(1.0)
            self._mgr.set_powered(adapter_path, True)
        except BluetoothError as e:
            return OpResult(False, str(e))
        return OpResult(True, "The adapter was power-cycled.")
