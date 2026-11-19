"""LAN device scanner (Advanced-IP-Scanner style) for the user's OWN directly attached networks.

Scope is enforced in code, not by the UI: a target must be a private subnet that is attached to one of this computer's
interfaces and have at most 1024 addresses. The sweep finds live hosts (ping, plus the ARP table the probes fill in), then
names them (reverse DNS), identifies the vendor from the MAC and records which devices are new. It sends only ping probes
and ARP; it never scans ports on its own. Checking a few well-known ports is a separate, per-device action.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import psutil

MAX_ADDRESSES = 1024
COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 515, 631, 1883, 3389, 5900, 8000, 8080, 8443, 9100, 62078)
WEB_PORTS = (80, 8080, 8000, 443, 8443)


class ScanError(ValueError):
    pass


@dataclass(frozen=True)
class LocalNet:
    iface: str
    ip: str
    network: str          # CIDR of the attached subnet

    @property
    def label(self) -> str:
        return f"{self.network}  ({self.iface}, you are {self.ip})"


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    rtt_ms: float | None = None
    tags: list[str] = field(default_factory=list)     # this computer, gateway, new
    label: str = ""                                   # your own name for the device (by MAC)
    first_seen: str = ""
    last_seen: str = ""
    ports: list[tuple[int, str]] = field(default_factory=list)

    @property
    def ip_key(self) -> tuple:
        return tuple(int(p) for p in self.ip.split("."))


# ------------------------------------------------------------------ pure helpers
def local_networks(addrs: dict | None = None, stats: dict | None = None) -> list[LocalNet]:
    addrs = addrs if addrs is not None else psutil.net_if_addrs()
    stats = stats if stats is not None else psutil.net_if_stats()
    out: list[LocalNet] = []
    for name, rows in addrs.items():
        st = stats.get(name)
        if name == "lo" or (st is not None and not st.isup):
            continue
        for a in rows:
            if getattr(a.family, "name", str(a.family)) != "AF_INET" or not a.netmask:
                continue
            try:
                net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
            except ValueError:
                continue
            if net.is_private and not net.is_loopback and not net.is_link_local and net.num_addresses > 2:
                out.append(LocalNet(name, a.address, str(net)))
    return out


def validate_target(cidr: str, nets: list[LocalNet]) -> ipaddress.IPv4Network:
    try:
        target = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        raise ScanError("enter a network such as 192.168.1.0/24") from None
    if not isinstance(target, ipaddress.IPv4Network):
        raise ScanError("only IPv4 networks are supported")
    if not target.is_private:
        raise ScanError("only private (RFC 1918) networks can be scanned")
    if target.num_addresses > MAX_ADDRESSES:
        raise ScanError(f"too large: at most {MAX_ADDRESSES} addresses (a /22) per scan")
    if not any(target.subnet_of(ipaddress.ip_network(n.network)) for n in nets):
        raise ScanError("the network must be directly attached to this computer (pick one from the list)")
    return target


def parse_proc_arp(text: str) -> dict[str, tuple[str, str]]:
    """/proc/net/arp -> ip -> (mac, interface), only for complete entries (flag 0x2)."""
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines()[1:]:
        p = line.split()
        if len(p) >= 6 and p[2] == "0x2" and p[3] != "00:00:00:00:00:00":
            out[p[0]] = (p[3].lower(), p[5])
    return out


def parse_default_gateway(route_text: str) -> str | None:
    """/proc/net/route (hex little-endian) -> default gateway."""
    for line in route_text.splitlines()[1:]:
        p = line.split()
        if len(p) >= 3 and p[1] == "00000000":
            try:
                return socket.inet_ntoa(bytes.fromhex(p[2])[::-1])
            except (ValueError, OSError):
                return None
    return None


def parse_ping_rtt(text: str) -> float | None:
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", text)
    return float(m.group(1)) if m else None


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return {62078: "iphone-sync", 9100: "jetdirect", 1883: "mqtt", 5900: "vnc"}.get(port, "")


def ping_once(ip: str, timeout_s: float = 1.0) -> float | None:
    """One ICMP echo through the system ping (no raw sockets needed). Returns the round-trip in ms, or None."""
    argv = (["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip] if os.name == "nt"
            else ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_s)))), ip])
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s + 2)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_ping_rtt(r.stdout) if r.returncode == 0 else None


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def tcp_open(ip: str, port: int, timeout_s: float = 0.6) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except OSError:
        return False


# ------------------------------------------------------------------ scanner
class LanScanner:
    def __init__(self, oui=None, known: Callable[[], dict] | None = None, save_known: Callable[[dict], None] | None = None,
                 pinger: Callable[[str], float | None] = ping_once, resolver: Callable[[str], str] = reverse_dns,
                 arp_reader: Callable[[], str] | None = None, route_reader: Callable[[], str] | None = None,
                 port_check: Callable[[str, int], bool] = tcp_open, workers: int = 64) -> None:
        self._oui = oui
        self._known, self._save = known or (lambda: {}), save_known or (lambda d: None)
        self._ping, self._resolve, self._port_check = pinger, resolver, port_check
        self._arp = arp_reader or self._read_arp
        self._route = route_reader or self._read_route
        self._workers = workers

    @staticmethod
    def _read_arp() -> str:
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    @staticmethod
    def _read_route() -> str:
        try:
            with open("/proc/net/route", encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    def networks(self) -> list[LocalNet]:
        return local_networks()

    def scan(self, cidr: str, nets: list[LocalNet] | None = None, progress: Callable[[int, int, int], None] | None = None,
             cancel: threading.Event | None = None) -> list[Device]:
        nets = nets if nets is not None else self.networks()
        target = validate_target(cidr, nets)
        mine = {n.ip for n in nets}
        hosts = [str(h) for h in target.hosts()]
        total, done = len(hosts), [0]
        rtts: dict[str, float | None] = {}
        lock = threading.Lock()
        found = [0]

        def probe(ip: str) -> None:
            if cancel is not None and cancel.is_set():
                return
            rtt = self._ping(ip)
            with lock:
                rtts[ip] = rtt
                done[0] += 1
                found[0] += 1 if rtt is not None else 0
                if progress:
                    progress(done[0], total, found[0])

        with ThreadPoolExecutor(max_workers=self._workers) as ex:
            list(ex.map(probe, hosts))
        if cancel is not None and cancel.is_set():
            return []
        arp = parse_proc_arp(self._arp())
        gateway = parse_default_gateway(self._route())
        in_target = {str(h) for h in target.hosts()}
        found_ips = {ip for ip in hosts if rtts.get(ip) is not None or ip in arp} | (mine & in_target)
        alive = sorted(found_ips, key=lambda i: tuple(int(p) for p in i.split(".")))
        with ThreadPoolExecutor(max_workers=min(32, max(len(alive), 1))) as ex:
            names = dict(zip(alive, ex.map(self._resolve, alive)))
        known = dict(self._known())
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        devices: list[Device] = []
        first_scan = not known
        for ip in alive:
            mac = arp.get(ip, ("", ""))[0]
            d = Device(ip, mac, names.get(ip, ""), (self._oui.vendor(mac) or "") if (self._oui and mac) else "", rtts.get(ip))
            if ip in mine:
                d.tags.append("this computer")
            if ip == gateway:
                d.tags.append("gateway")
            if mac:
                rec = known.get(mac)
                if rec is None:
                    rec = {"label": "", "first": now}
                    if not first_scan:
                        d.tags.append("new")
                rec.update({"last": now, "ip": ip})
                known[mac] = rec
                d.label, d.first_seen, d.last_seen = rec.get("label", ""), rec["first"], now
            devices.append(d)
        self._save(known)
        return devices

    def set_label(self, mac: str, label: str) -> None:
        known = dict(self._known())
        if mac in known:
            known[mac]["label"] = label.strip()[:60]
            self._save(known)

    def check_ports(self, ip: str, ports: tuple[int, ...] = COMMON_PORTS,
                    nets: list[LocalNet] | None = None) -> list[tuple[int, str]]:
        """TCP connect test of a short well-known list against ONE device on an attached network."""
        nets = nets if nets is not None else self.networks()
        addr = ipaddress.ip_address(ip)
        if not any(addr in ipaddress.ip_network(n.network) for n in nets):
            raise ScanError("ports can only be checked on devices of your own attached networks")
        with ThreadPoolExecutor(max_workers=16) as ex:
            res = list(ex.map(lambda p: (p, self._port_check(ip, p)), ports))
        return [(p, service_name(p)) for p, ok in res if ok]


def to_csv(devices: list[Device]) -> str:
    def q(v: str) -> str:
        v = str(v).replace('"', '""')
        return f'"{v}"' if any(c in v for c in ',"\n') else v
    rows = [",".join(["ip", "hostname", "label", "mac", "vendor", "rtt_ms", "tags", "first_seen", "last_seen"])]
    for d in devices:
        rows.append(",".join(q(x) for x in (d.ip, d.hostname, d.label, d.mac, d.vendor,
                                            "" if d.rtt_ms is None else f"{d.rtt_ms:.1f}", " ".join(d.tags), d.first_seen, d.last_seen)))
    return "\n".join(rows) + "\n"
