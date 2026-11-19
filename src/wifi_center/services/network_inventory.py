"""Local network inventory for the topology view.

Sources (all passive, nothing is probed): the default route, the kernel neighbour (ARP/NDP) cache,
and hosts already stored in the database (e.g. imported Nmap results). No device is ever invented.
"""
from __future__ import annotations

import ipaddress
import json
import platform
import re
import shutil
from dataclasses import dataclass, field

import psutil

from ..database.repository import Database
from .oui import OuiLookup
from .process_runner import run_command, find_executable


@dataclass
class NetNode:
    id: str
    label: str
    ip: str | None
    kind: str                       # self | gateway | host
    state: str = "unknown"          # self | reachable | stale | unknown
    mac: str | None = None
    vendor: str | None = None
    device_type: str | None = None  # only when known (e.g. OS guess from imported scans)
    source: str = "neighbor-cache"
    interface: str | None = None
    services: list[str] = field(default_factory=list)


@dataclass
class Topology:
    nodes: list[NetNode]
    edges: list[tuple[str, str]]
    interface: str | None = None
    note: str = ""

    @property
    def host_count(self) -> int:
        return sum(1 for n in self.nodes if n.kind == "host")


# ---------------- parsers (pure) ----------------
def parse_ip_route_json(text: str) -> tuple[str | None, str | None, str | None]:
    """`ip -j route show default` -> (gateway, device, preferred source address)."""
    try:
        routes = json.loads(text)
    except json.JSONDecodeError:
        return None, None, None
    best = min((r for r in routes if r.get("gateway")), key=lambda r: r.get("metric", 0), default=None)
    if not best:
        return None, None, None
    return best.get("gateway"), best.get("dev"), best.get("prefsrc")


def parse_ip_neigh_json(text: str) -> list[dict]:
    try:
        entries = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for e in entries:
        states = e.get("state") or []
        if not e.get("lladdr") or any(s in ("FAILED", "INCOMPLETE") for s in states):
            continue
        out.append({"ip": e["dst"], "mac": e["lladdr"].upper(), "state": states[0].lower() if states else "unknown",
                    "dev": e.get("dev")})
    return out


_ARP_LINUX = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{17})")
_ARP_WIN = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)", re.M)


def parse_arp(text: str) -> list[dict]:
    out = [{"ip": ip, "mac": mac.upper(), "state": "unknown", "dev": None} for ip, mac in _ARP_LINUX.findall(text)]
    for ip, mac, kind in _ARP_WIN.findall(text):
        out.append({"ip": ip, "mac": mac.replace("-", ":").upper(),
                    "state": "reachable" if kind.lower() == "dynamic" else "unknown", "dev": None})
    return out


def parse_route_print(text: str) -> str | None:
    m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+", text, re.M)
    return m.group(1) if m else None


def is_unicast_host(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_loopback or a.is_unspecified or str(a).endswith(".255"))


# ---------------- service ----------------
class NetworkInventoryService:
    def __init__(self, db: Database, oui: OuiLookup | None = None) -> None:
        self._db = db
        self.oui = oui or OuiLookup()

    def _route(self) -> tuple[str | None, str | None, str | None]:
        if find_executable("ip"):
            r = run_command(["ip", "-j", "route", "show", "default"], timeout=5)
            if r.ok:
                return parse_ip_route_json(r.stdout)
        if platform.system() == "Windows" and find_executable("route"):
            r = run_command(["route", "print", "-4", "0.0.0.0"], timeout=5)
            if r.ok:
                return parse_route_print(r.stdout), None, None
        return None, None, None

    def _neighbors(self) -> list[dict]:
        if find_executable("ip"):
            r = run_command(["ip", "-j", "neigh", "show"], timeout=5)
            if r.ok:
                return parse_ip_neigh_json(r.stdout)
        if find_executable("arp"):
            r = run_command(["arp", "-a"], timeout=5)
            if r.ok:
                return parse_arp(r.stdout)
        return []

    def _local_ip(self, dev: str | None, prefsrc: str | None) -> str | None:
        if prefsrc:
            return prefsrc
        addrs = psutil.net_if_addrs()
        names = [dev] if dev and dev in addrs else [n for n in addrs if n != "lo"]
        for n in names:
            for a in addrs.get(n, []):
                if a.family.name == "AF_INET" and not a.address.startswith(("127.", "169.254.")):
                    return a.address
        return None

    def snapshot(self) -> Topology:
        gateway, dev, prefsrc = self._route()
        local_ip = self._local_ip(dev, prefsrc)
        me = NetNode("self", platform.node() or "This computer", local_ip, "self", "self", source="local",
                     interface=dev)
        nodes: dict[str, NetNode] = {"self": me}
        edges: list[tuple[str, str]] = []
        hub = "self"
        if gateway:
            nodes["gateway"] = NetNode("gateway", "Gateway", gateway, "gateway", "unknown", interface=dev)
            edges.append(("self", "gateway"))
            hub = "gateway"
        for nb in self._neighbors():
            ip = nb["ip"]
            if not is_unicast_host(ip) or ip == local_ip:
                continue
            mac = nb.get("mac")
            vendor = self.oui.vendor(mac) if mac else None
            if gateway and ip == gateway:
                g = nodes["gateway"]
                g.mac, g.vendor, g.state = mac, vendor, nb["state"]
                continue
            nodes[ip] = NetNode(ip, ip, ip, "host", nb["state"], mac, vendor, interface=nb.get("dev") or dev)
            edges.append((hub, ip))
        # hosts already known from stored results (e.g. imported Nmap scans)
        for r in self._db.query("SELECT address, hostname, mac, vendor, os_guess, services_json, source "
                                "FROM network_devices ORDER BY last_seen DESC"):
            ip = r["address"]
            if ip == local_ip or ip == gateway:
                continue
            try:
                services = [str(s) for s in json.loads(r["services_json"] or "[]")]
            except json.JSONDecodeError:
                services = []
            if ip in nodes:
                n = nodes[ip]
                n.device_type, n.services = r["os_guess"], services
                n.label = r["hostname"] or n.label
                continue
            nodes[ip] = NetNode(ip, r["hostname"] or ip, ip, "host", "unknown", r["mac"], r["vendor"], r["os_guess"],
                                r["source"], None, services)
            edges.append((hub, ip))
        note = ""
        if not gateway and len(nodes) == 1:
            note = "No default route found: this computer does not appear to be connected to a network."
        return Topology(list(nodes.values()), edges, dev, note)
