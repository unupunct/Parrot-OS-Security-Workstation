"""BluetoothAdapterManager: lists controllers and what they can do.

Properties come from BlueZ over D-Bus; chipset, Bluetooth version and capabilities from `btmgmt info` (works without root),
`hciconfig -a` and sysfs (driver, USB ids and the product strings the USB device reports). Nothing is assumed: a capability that
could not be read is reported as unknown, and actions are only offered for capabilities the controller declares."""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Callable

from ..services.process_runner import find_executable, run_command
from . import registry as reg
from .bluez import ADAPTER, BluezAPI
from .models import AdapterInfo, BluetoothError

SETTING_NAMES = {
    "powered": "Powered", "connectable": "Connectable", "fast-connectable": "Fast connectable", "discoverable": "Discoverable",
    "bondable": "Bondable (pairing allowed)", "link-security": "Link-level security", "ssp": "Secure Simple Pairing",
    "br/edr": "Classic Bluetooth (BR/EDR)", "le": "Bluetooth Low Energy", "advertising": "LE advertising",
    "secure-conn": "Secure Connections", "debug-keys": "Debug keys", "privacy": "LE privacy", "static-addr": "Static address",
    "phy-configuration": "PHY configuration (LE 2M/Coded)", "wide-band-speech": "Wide-band speech",
}


# ------------------------------------------------------------------ parsers (pure)
def parse_btmgmt_info(text: str) -> dict:
    """`btmgmt --index N info` -> {addr, version, manufacturer, class, supported, current, name}."""
    out: dict = {"supported": [], "current": []}
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"addr (\S+) version (\d+) manufacturer (\d+) class (0x[0-9a-fA-F]+)", s)
        if m:
            out.update(addr=m.group(1).upper(), version=int(m.group(2)), manufacturer=int(m.group(3)), cls=int(m.group(4), 16))
        elif s.startswith("supported settings:"):
            out["supported"] = s.split(":", 1)[1].split()
        elif s.startswith("current settings:"):
            out["current"] = s.split(":", 1)[1].split()
        elif s.startswith("name "):
            out["name"] = s[5:]
    return out


def parse_hciconfig(text: str) -> dict:
    out: dict = {}
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"(hci\d+):\s+Type: (\S+)\s+Bus: (\S+)", s)
        if m:
            out.update(name=m.group(1), type=m.group(2), bus=m.group(3))
        elif s in ("UP RUNNING", "DOWN", "UP RUNNING PSCAN", "UP RUNNING PSCAN ISCAN", "UP RUNNING ISCAN"):
            out["state"] = "up" if s.startswith("UP") else "down"
        elif s.startswith("HCI Version:"):
            m = re.match(r"HCI Version: (\S+) \((0x[0-9a-fA-F]+)\)(?:\s+Revision: (0x[0-9a-fA-F]+))?", s)
            if m:
                out["hci_version"] = m.group(1)
                if m.group(3):
                    out["hci_revision"] = m.group(3)
        elif s.startswith("LMP Version:"):
            m = re.match(r"LMP Version: (\S+) \(0x[0-9a-fA-F]+\)(?:\s+Subversion: (0x[0-9a-fA-F]+))?", s)
            if m:
                out["lmp_version"] = m.group(1)
                if m.group(2):
                    out["lmp_subversion"] = m.group(2)
        elif s.startswith("Manufacturer:"):
            out["manufacturer"] = re.sub(r"\s*\(\d+\)$", "", s.split(":", 1)[1].strip())
        elif s.startswith("Features:"):
            out["features"] = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]{2}", s)]
        elif s.startswith("Link policy:"):
            out["link_policy"] = s.split(":", 1)[1].split()
        elif s.startswith("Link mode:"):
            out["link_mode"] = s.split(":", 1)[1].split()
        elif s.startswith("Device Class:"):
            out["device_class"] = s.split(":", 1)[1].strip()
        elif re.match(r"(RX|TX) bytes:", s):
            m = re.search(r"errors:(\d+)", s)
            if m:
                out["errors"] = out.get("errors", 0) + int(m.group(1))
    return out


LMP_FEATURES = [  # (byte, bit, name) of LMP features page 0 that are well defined and useful to show
    (0, 0, "3-slot packets"), (0, 1, "5-slot packets"), (0, 2, "Encryption"), (0, 5, "Role switch"), (0, 6, "Hold mode"),
    (0, 7, "Sniff mode"), (1, 0, "Park state"), (1, 3, "SCO links"), (3, 1, "EDR 2 Mb/s"), (3, 2, "EDR 3 Mb/s"),
    (4, 6, "LE (controller)"), (6, 3, "Secure Simple Pairing")]


def decode_lmp_features(features: list[int]) -> list[str]:
    return [name for byte, bit, name in LMP_FEATURES if byte < len(features) and features[byte] & (1 << bit)]


def default_mgmt(index: int, timeout: float = 3.0) -> str:
    """`btmgmt --index N info`. btmgmt waits for more input when its stdin is closed, so the pipe is kept open and the process is
    ended after the answer has arrived (or the timeout passes)."""
    exe = find_executable("btmgmt")
    if not exe:
        return ""
    try:
        proc = subprocess.Popen([exe, "--index", str(index), "info"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, errors="replace")
    except OSError:
        return ""
    end = time.monotonic() + timeout
    while proc.poll() is None and time.monotonic() < end:
        time.sleep(0.1)
    if proc.poll() is None:
        proc.kill()
    try:
        return proc.stdout.read() if proc.stdout else ""
    finally:
        for f in (proc.stdin, proc.stdout):
            try:
                f and f.close()
            except OSError:
                pass


def friendly_settings(names: list[str]) -> list[str]:
    return [SETTING_NAMES.get(n, n) for n in names]


# ------------------------------------------------------------------ manager
class BluetoothAdapterManager:
    def __init__(self, api: BluezAPI, run: Callable | None = None, sysfs: Path = Path("/sys/class/bluetooth"),
                 which: Callable[[str], str | None] = find_executable, mgmt: Callable[[int], str] | None = None) -> None:
        self._api = api
        self._mgmt = mgmt or default_mgmt
        self._run = run or (lambda argv, t: run_command(argv, timeout=t))
        self._sysfs = sysfs
        self._which = which

    def available(self) -> bool:
        return self._api.available()

    def _out(self, argv: list[str], timeout: float = 10) -> str:
        if not self._which(argv[0]):
            return ""
        r = self._run(argv, timeout)
        return (r.stdout or "") if getattr(r, "ok", False) else ""

    def list(self) -> list[AdapterInfo]:
        if not self._api.available():
            raise BluetoothError("The Bluetooth service (bluetoothd) is not running or not reachable.")
        out = []
        for path, ifs in sorted(self._api.objects().items()):
            props = ifs.get(ADAPTER)
            if props is None:
                continue
            a = AdapterInfo(path=path, name=path.rsplit("/", 1)[-1], address=str(props.get("Address", "")).upper(),
                            alias=str(props.get("Alias", "")), powered=bool(props.get("Powered")),
                            discoverable=bool(props.get("Discoverable")), pairable=bool(props.get("Pairable")),
                            discovering=bool(props.get("Discovering")), modalias=str(props.get("Modalias", "")),
                            roles=list(props.get("Roles", [])), uuids=[str(u) for u in props.get("UUIDs", [])])
            self._enrich(a)
            out.append(a)
        return out

    def get(self, name_or_path: str) -> AdapterInfo:
        for a in self.list():
            if name_or_path in (a.name, a.path):
                return a
        raise BluetoothError(f"Bluetooth adapter {name_or_path} not found.")

    def _enrich(self, a: AdapterInfo) -> None:
        m = re.match(r"hci(\d+)$", a.name)
        if m:
            info = parse_btmgmt_info(self._mgmt(int(m.group(1))))
            if info.get("supported"):
                a.supported_settings, a.current_settings = info["supported"], info.get("current", [])
            if "manufacturer" in info:
                a.manufacturer = reg.company_name(info["manufacturer"])
            if "version" in info and not a.hci_version:
                a.hci_version = reg.hci_version(info["version"])
        hci = parse_hciconfig(self._out(["hciconfig", "-a", a.name]))
        if hci.get("hci_version"):
            a.hci_version = hci["hci_version"]
        if hci.get("manufacturer") and not a.manufacturer.startswith(hci["manufacturer"][:4]):
            a.manufacturer = hci["manufacturer"]
        a.bus = hci.get("bus", a.bus)
        a.hci_revision, a.lmp_subversion = hci.get("hci_revision", ""), hci.get("lmp_subversion", "")
        feats = hci.get("features", [])
        a.lmp_features = decode_lmp_features(feats)
        if not a.supported_settings and len(feats) > 4:               # btmgmt unavailable: the LMP feature bits still say it
            a.supported_settings = [n for n, on in (("br/edr", not feats[4] & 0x20), ("le", bool(feats[4] & 0x40)),
                                                    ("ssp", bool(feats[6] & 0x08) if len(feats) > 6 else False)) if on]
        self._sysfs_info(a)
        rf = self._out(["rfkill", "list", "bluetooth"])
        a.rfkill = rf.strip()

    def _sysfs_info(self, a: AdapterInfo) -> None:
        base = self._sysfs / a.name
        try:
            dev = (base / "device").resolve()
        except OSError:
            return
        drv = dev / "driver"
        try:
            if drv.exists():
                a.driver = drv.resolve().name
        except OSError:
            pass

        def rd(p: Path) -> str:
            try:
                return p.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                return ""
        usb = dev.parent
        vid, pid = rd(usb / "idVendor"), rd(usb / "idProduct")
        if vid and pid:
            a.usb_id = f"{vid}:{pid}"
            a.usb_name = " ".join(x for x in (rd(usb / "manufacturer"), rd(usb / "product")) if x)

    # ---- actions
    def set_powered(self, adapter_path: str, on: bool, active_connections: int = 0) -> None:
        """Power an adapter on or off. Powering OFF is refused while a device is connected through it."""
        if not on and active_connections:
            raise BluetoothError(f"{active_connections} device(s) are connected through this adapter; disconnect them first.")
        self._api.set_prop(adapter_path, ADAPTER, "Powered", bool(on))
