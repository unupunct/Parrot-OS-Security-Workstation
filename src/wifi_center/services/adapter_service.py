"""Wireless adapter detection via sysfs and `iw` (read-only; never changes interface state)."""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .process_runner import run_command, find_executable


@dataclass
class WirelessAdapter:
    interface: str
    state: str = "unknown"
    driver: str | None = None
    vendor_id: str | None = None
    product_id: str | None = None
    manufacturer: str | None = None
    mac: str | None = None
    bands: list[str] = field(default_factory=list)
    monitor_capable: bool | None = None  # None = could not determine
    connected_ssid: str | None = None
    phy: str | None = None


def parse_iw_phy_info(text: str) -> dict[str, dict]:
    """Parse `iw phy` output -> {phyN: {bands: [...], modes: [...]}}."""
    phys: dict[str, dict] = {}
    cur: dict | None = None
    section = ""
    for line in text.splitlines():
        m = re.match(r"^Wiphy (\S+)", line)
        if m:
            cur = {"bands": [], "modes": []}
            phys[m.group(1)] = cur
            section = ""
            continue
        if cur is None:
            continue
        s = line.strip()
        if re.match(r"^Band \d+:", s):
            section = "bands"
            continue
        if s.startswith("Supported interface modes:"):
            section = "modes"
            continue
        top_level = line.startswith("\t") and not line.startswith("\t\t")
        if top_level and s.endswith(":") and not s.startswith("*"):
            section = "other"
            continue
        if section == "modes" and s.startswith("*"):
            cur["modes"].append(s.lstrip("* ").strip())
        elif section == "bands":
            fm = re.match(r"^\* (\d+(?:\.\d+)?) MHz \[", s)
            if fm:
                mhz = float(fm.group(1))
                band = "2.4 GHz" if mhz < 3000 else "5 GHz" if mhz < 5925 else "6 GHz"
                if band not in cur["bands"]:
                    cur["bands"].append(band)
    return phys


def _read(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8").strip()
    except OSError:
        return None


class AdapterService:
    def __init__(self, sysfs_net: Path = Path("/sys/class/net")) -> None:
        self._sysfs = sysfs_net

    def supported(self) -> bool:
        return self._sysfs.is_dir()

    def detect(self) -> list[WirelessAdapter]:
        if not self.supported():
            return []
        adapters = []
        for iface in sorted(self._sysfs.iterdir()):
            if not (iface / "wireless").exists() and not (iface / "phy80211").exists():
                continue
            a = WirelessAdapter(interface=iface.name)
            a.state = _read(iface / "operstate") or "unknown"
            a.mac = _read(iface / "address")
            drv = iface / "device" / "driver"
            if drv.exists():
                a.driver = drv.resolve().name
            dev = iface / "device"
            a.vendor_id = _read(dev / "vendor") or _read(dev.resolve().parent / "idVendor")
            a.product_id = _read(dev / "device") or _read(dev.resolve().parent / "idProduct")
            phy = iface / "phy80211" / "name"
            a.phy = _read(phy)
            adapters.append(a)
        self._enrich_with_iw(adapters)
        return adapters

    def _enrich_with_iw(self, adapters: list[WirelessAdapter]) -> None:
        if not adapters or find_executable("iw") is None:
            return
        r = run_command(["iw", "phy"], timeout=10)
        if r.ok:
            phys = parse_iw_phy_info(r.stdout)
            for a in adapters:
                info = phys.get(a.phy or "")
                if info:
                    a.bands = info["bands"]
                    a.monitor_capable = "monitor" in info["modes"]
        for a in adapters:
            link = run_command(["iw", "dev", a.interface, "link"], timeout=5)
            if link.ok:
                m = re.search(r"SSID:\s*(.+)", link.stdout)
                if m:
                    a.connected_ssid = m.group(1).strip()
        # Manufacturer name only if lsusb/lspci can resolve the id pair.
        for a in adapters:
            if a.vendor_id and a.product_id:
                a.manufacturer = self._lookup_vendor(a.vendor_id, a.product_id)

    @staticmethod
    def _lookup_vendor(vendor: str, product: str) -> str | None:
        v = vendor.lower().removeprefix("0x").zfill(4)
        p = product.lower().removeprefix("0x").zfill(4)
        for tool, args in (("lsusb", ["lsusb", "-d", f"{v}:{p}"]), ("lspci", ["lspci", "-d", f"{v}:{p}"])):
            if find_executable(tool):
                r = run_command(args, timeout=5)
                if r.ok and r.stdout.strip():
                    line = r.stdout.strip().splitlines()[0]
                    m = re.search(r"ID [0-9a-f]{4}:[0-9a-f]{4}\s+(.+)$", line) or re.search(r": (.+)$", line)
                    if m:
                        return m.group(1).strip()
        return None


    def diagnostics(self, interface: str) -> list[tuple[str, str]]:
        """Read-only driver/interface diagnostics. Each entry: (title, command output or reason)."""
        if not re.match(r"^[A-Za-z0-9_.:-]{1,15}$", interface):
            raise ValueError("invalid interface name")
        checks = [
            ("Interface info (iw dev)", "iw", ["iw", "dev", interface, "info"]),
            ("Driver (ethtool -i)", "ethtool", ["ethtool", "-i", interface]),
            ("Radio block state (rfkill)", "rfkill", ["rfkill", "list", "wifi"]),
            ("Regulatory domain (iw reg get)", "iw", ["iw", "reg", "get"]),
            ("NetworkManager device", "nmcli", ["nmcli", "-p", "device", "show", interface]),
        ]
        out = []
        for title, tool, argv in checks:
            if find_executable(tool) is None:
                out.append((title, f"{tool} is not installed"))
                continue
            r = run_command(argv, timeout=10)
            out.append((title, (r.stdout or r.stderr or r.error or "no output").strip()))
        return out
