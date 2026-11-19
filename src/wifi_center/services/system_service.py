"""Real system metrics. Nothing here is simulated; unavailable data is reported as None."""
from __future__ import annotations

import platform
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

from .process_runner import run_command


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k] = v.strip().strip('"').strip("'")
    return out


_INST = re.compile(r"^Inst\s", re.M)
_REMV = re.compile(r"^Remv\s", re.M)


def parse_apt_simulation(text: str) -> dict[str, int]:
    """Count the actions in `apt-get -s` output."""
    return {"upgrade": len(_INST.findall(text)), "remove": len(_REMV.findall(text))}


@dataclass(frozen=True)
class OsInfo:
    pretty_name: str
    kernel: str
    hostname: str
    is_parrot: bool


@dataclass(frozen=True)
class DiskInfo:
    mount: str
    total: int
    used: int
    percent: float


@dataclass(frozen=True)
class NetInterface:
    name: str
    is_up: bool
    addresses: tuple[str, ...]


class SystemService:
    def __init__(self, os_release_path: Path = Path("/etc/os-release")) -> None:
        self._os_release_path = os_release_path
        psutil.cpu_percent(interval=None)  # prime the counter

    def os_info(self) -> OsInfo:
        info: dict[str, str] = {}
        try:
            info = parse_os_release(self._os_release_path.read_text(encoding="utf-8"))
        except OSError:
            pass
        pretty = info.get("PRETTY_NAME") or f"{platform.system()} {platform.release()}"
        ident = (info.get("ID", "") + " " + info.get("ID_LIKE", "")).lower()
        return OsInfo(pretty, platform.release(), platform.node(), "parrot" in ident)

    def cpu_percent(self) -> float:
        return psutil.cpu_percent(interval=None)

    def memory(self) -> tuple[int, int, float]:
        m = psutil.virtual_memory()
        return m.used, m.total, m.percent

    def disk(self) -> DiskInfo:
        root = Path.home().anchor or "/"
        u = shutil.disk_usage(root)
        return DiskInfo(root, u.total, u.used, u.used / u.total * 100 if u.total else 0.0)

    def uptime_seconds(self) -> float:
        return time.time() - psutil.boot_time()

    def interfaces(self) -> list[NetInterface]:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        out = []
        for name, st in sorted(stats.items()):
            ips = tuple(
                a.address.split("%")[0]
                for a in addrs.get(name, [])
                if a.family.name in ("AF_INET", "AF_INET6")
            )
            out.append(NetInterface(name, st.isup, ips))
        return out

    def has_connectivity(self) -> bool:
        """Local-only check (no packets are sent): a non-loopback interface is up with an IPv4 address."""
        for i in self.interfaces():
            if i.name == "lo" or not i.is_up:
                continue
            if any(re.match(r"^\d+\.\d+\.\d+\.\d+$", a) and not a.startswith(("127.", "169.254.")) for a in i.addresses):
                return True
        return False

    def pending_updates(self) -> dict[str, int] | None:
        """Simulated apt upgrade against the *existing* package lists (no network, no root).

        Returns None when apt is not available (non-Debian host) or the query failed.
        """
        if shutil.which("apt-get") is None:
            return None
        r = run_command(["apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"], timeout=60)
        if not r.ok:
            return None
        return parse_apt_simulation(r.stdout)
