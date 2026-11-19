"""Bluetooth diagnostics through BlueZ (`bluetoothctl`) and sysfs. Discovery and read-only queries only.

No spoofing, pairing attempts, connection attempts or data access are implemented.
"""
from __future__ import annotations

import csv
import io
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..database.repository import Database
from .process_runner import run_command, find_executable

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
DIAG_TOOLS = ("bluetoothctl", "hciconfig", "hcitool", "btmon", "rfkill", "btmgmt")


@dataclass
class BtController:
    address: str
    name: str = ""
    powered: bool | None = None
    discoverable: bool | None = None
    pairable: bool | None = None


@dataclass
class BtDevice:
    address: str
    name: str = ""
    paired: bool | None = None
    connected: bool | None = None
    rssi: int | None = None


def _yes(v: str) -> bool:
    return v.strip().lower() == "yes"


def parse_show(text: str) -> BtController | None:
    m = re.search(r"^Controller ([0-9A-Fa-f:]{17})", text, re.M)
    if not m:
        return None
    c = BtController(m.group(1).upper())
    for line in text.splitlines():
        k, _, v = line.strip().partition(":")
        if k == "Alias":
            c.name = v.strip()
        elif k == "Powered":
            c.powered = _yes(v)
        elif k == "Discoverable":
            c.discoverable = _yes(v)
        elif k == "Pairable":
            c.pairable = _yes(v)
    return c


def parse_devices(text: str) -> list[BtDevice]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^(?:\[NEW\] )?Device ([0-9A-Fa-f:]{17})\s*(.*)$", line.strip())
        if m:
            out.append(BtDevice(m.group(1).upper(), m.group(2).strip()))
    return out


def parse_info(text: str, address: str) -> BtDevice:
    d = BtDevice(address.upper())
    for line in text.splitlines():
        k, _, v = line.strip().partition(":")
        if k in ("Alias", "Name") and not d.name:
            d.name = v.strip()
        elif k == "Paired":
            d.paired = _yes(v)
        elif k == "Connected":
            d.connected = _yes(v)
        elif k == "RSSI":
            m = re.search(r"\(?(-?\d+)\)?\s*$", v.strip())
            d.rssi = int(m.group(1)) if m else None
    return d


class BluetoothService:
    def __init__(self, db: Database, sysfs: Path = Path("/sys/class/bluetooth")) -> None:
        self._db = db
        self._sysfs = sysfs

    def tools(self) -> dict[str, str | None]:
        return {t: find_executable(t) for t in DIAG_TOOLS}

    def adapters(self) -> list[str]:
        if not self._sysfs.is_dir():
            return []
        return sorted(p.name for p in self._sysfs.iterdir() if re.match(r"^hci\d+$", p.name))

    def controller(self) -> BtController | None:
        if not find_executable("bluetoothctl"):
            return None
        r = run_command(["bluetoothctl", "show"], timeout=10)
        return parse_show(r.stdout) if r.ok else None

    def rfkill(self) -> str:
        if not find_executable("rfkill"):
            return "rfkill not installed"
        r = run_command(["rfkill", "list", "bluetooth"], timeout=5)
        return (r.stdout or r.stderr or r.error or "").strip() or "no Bluetooth entries"

    def known_devices(self) -> list[BtDevice]:
        """Devices BlueZ already knows (paired or previously seen), with connection status."""
        if not find_executable("bluetoothctl"):
            return []
        r = run_command(["bluetoothctl", "devices"], timeout=10)
        devs = parse_devices(r.stdout) if r.ok else []
        for d in devs:
            info = run_command(["bluetoothctl", "info", d.address], timeout=10)
            if info.ok:
                full = parse_info(info.stdout, d.address)
                d.paired, d.connected, d.rssi = full.paired, full.connected, full.rssi
        return devs

    def discover(self, seconds: int = 10) -> list[BtDevice]:
        """Passive-style standard discovery (inquiry scan) for a bounded time, started by the user."""
        if not find_executable("bluetoothctl"):
            raise RuntimeError("bluetoothctl (BlueZ) is not installed")
        seconds = max(3, min(int(seconds), 60))
        r = run_command(["bluetoothctl", "--timeout", str(seconds), "scan", "on"], timeout=seconds + 10)
        found = parse_devices(r.stdout)
        seen: dict[str, BtDevice] = {}
        for d in found:
            if d.address not in seen or (d.name and not seen[d.address].name):
                seen[d.address] = d
        return list(seen.values())

    # ---- persistence / import ----
    def record(self, devices: list[BtDevice], source: str) -> int:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._db.transaction() as c:
            for d in devices:
                c.execute(
                    "INSERT INTO bluetooth_devices(address, name, rssi, paired, connected, source, first_seen, "
                    "last_seen) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(address, source) DO UPDATE SET "
                    "name=COALESCE(NULLIF(excluded.name,''), name), rssi=excluded.rssi, paired=excluded.paired, "
                    "connected=excluded.connected, last_seen=excluded.last_seen",
                    (d.address, d.name, d.rssi, None if d.paired is None else int(d.paired),
                     None if d.connected is None else int(d.connected), source, now, now))
        return len(devices)

    def import_csv(self, text: str, source: str = "import") -> int:
        """Import an existing authorized device list: columns `address[,name]`; invalid rows are skipped."""
        rows = csv.reader(io.StringIO(text))
        devs = []
        for i, row in enumerate(rows):
            if not row or not MAC_RE.match(row[0].strip()):
                continue
            devs.append(BtDevice(row[0].strip().upper(), row[1].strip() if len(row) > 1 else ""))
        return self.record(devs, source)

    def stored(self) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM bluetooth_devices ORDER BY last_seen DESC")]
