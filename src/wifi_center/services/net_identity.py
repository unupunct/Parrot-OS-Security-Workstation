"""Identify the networks this computer is on, from the operating system's own structured data: `ip -j address`, `ip -j route`,
`ip -j neigh`, `resolvectl status` (or /etc/resolv.conf). The subnet is calculated from each interface's real prefix length; it is
never guessed from the address."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .process_runner import find_executable, run_command

VIRTUAL_PREFIXES = ("virbr", "docker", "veth", "br-", "tun", "tap", "vmnet", "vboxnet", "lxc", "zt", "wg", "tailscale")


@dataclass
class AddrV4:
    address: str
    prefixlen: int
    scope: str = ""

    @property
    def interface(self) -> ipaddress.IPv4Interface:
        return ipaddress.IPv4Interface(f"{self.address}/{self.prefixlen}")

    @property
    def network(self) -> str:
        return str(self.interface.network)

    @property
    def usable_hosts(self) -> int:
        n = self.interface.network
        return max(n.num_addresses - 2, 0) if n.prefixlen < 31 else n.num_addresses


@dataclass
class AddrV6:
    address: str
    prefixlen: int
    scope: str = ""

    @property
    def network(self) -> str:
        return str(ipaddress.IPv6Interface(f"{self.address}/{self.prefixlen}").network)


@dataclass
class InterfaceInfo:
    name: str
    state: str                       # up | down | unknown
    mac: str = ""
    mtu: int = 0
    kind: str = "other"              # ethernet | wifi | virtual | loopback | other
    v4: list[AddrV4] = field(default_factory=list)
    v6: list[AddrV6] = field(default_factory=list)


@dataclass
class Route:
    dst: str
    dev: str
    gateway: str = ""
    metric: int = 0
    prefsrc: str = ""
    scope: str = ""
    linkdown: bool = False


@dataclass
class Neighbor:
    ip: str
    mac: str
    dev: str
    state: str                       # REACHABLE | STALE | DELAY | PROBE | FAILED | PERMANENT ...
    family: int = 4

    @property
    def usable(self) -> bool:
        return bool(self.mac) and self.state not in ("FAILED", "INCOMPLETE")


@dataclass
class NetworkIdentity:
    interface: InterfaceInfo
    v4: AddrV4 | None = None        # the address used for this identification
    gateway: str = ""
    gateway_mac: str = ""
    dns: list[str] = field(default_factory=list)
    default_route: bool = False

    @property
    def cidr(self) -> str:
        return self.v4.network if self.v4 else ""

    @property
    def title(self) -> str:
        return f"{self.interface.name} · {self.cidr}" if self.v4 else self.interface.name


# ------------------------------------------------------------------ parsers (pure)
def _json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return []


def classify_interface(name: str, link_type: str, wireless: set[str]) -> str:
    if link_type == "loopback" or name == "lo":
        return "loopback"
    if name in wireless:
        return "wifi"
    if name.startswith(VIRTUAL_PREFIXES):
        return "virtual"
    return "ethernet" if link_type == "ether" else "other"


def parse_ip_address(text: str, wireless: set[str] | None = None) -> list[InterfaceInfo]:
    out = []
    for i in _json(text):
        state = {"UP": "up", "DOWN": "down"}.get(str(i.get("operstate", "")).upper(), "unknown")
        info = InterfaceInfo(i.get("ifname", ""), state, (i.get("address") or "").lower(), int(i.get("mtu") or 0),
                             classify_interface(i.get("ifname", ""), i.get("link_type", ""), wireless or set()))
        for a in i.get("addr_info", []):
            try:
                if a.get("family") == "inet":
                    info.v4.append(AddrV4(a["local"], int(a["prefixlen"]), a.get("scope", "")))
                elif a.get("family") == "inet6":
                    info.v6.append(AddrV6(a["local"], int(a["prefixlen"]), a.get("scope", "")))
            except (KeyError, ValueError, TypeError):
                continue
        out.append(info)
    return out


def parse_ip_route(text: str) -> list[Route]:
    out = []
    for r in _json(text):
        out.append(Route(r.get("dst", ""), r.get("dev", ""), r.get("gateway", ""), int(r.get("metric") or 0), r.get("prefsrc", ""),
                         r.get("scope", ""), "linkdown" in (r.get("flags") or [])))
    return out


def parse_ip_neigh(text: str) -> list[Neighbor]:
    out = []
    for n in _json(text):
        ip = n.get("dst", "")
        state = (n.get("state") or ["UNKNOWN"])[0]
        try:
            fam = 6 if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address) else 4
        except ValueError:
            continue
        out.append(Neighbor(ip, (n.get("lladdr") or "").lower(), n.get("dev", ""), state, fam))
    return out


def parse_resolv_conf(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*nameserver\s+(\S+)", line)
        if m:
            out.append(m.group(1))
    return out


def parse_resolvectl(text: str) -> dict[str, list[str]]:
    """`resolvectl status` -> {link name: [dns servers]} (the 'Global' section is keyed 'global')."""
    out: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"^(Global|Link \d+ \((\S+)\))", line)
        if m:
            cur = "global" if m.group(1) == "Global" else m.group(2)
            out.setdefault(cur, [])
            continue
        m = re.match(r"^\s+(?:Current DNS Server|DNS Servers):\s*(.*)$", line)
        if m and cur:
            for s in m.group(1).split():
                if s not in out[cur]:
                    out[cur].append(s)
    return out


# ------------------------------------------------------------------ identification
def identify_networks(interfaces: list[InterfaceInfo], routes: list[Route], neighbors: list[Neighbor],
                      dns_by_link: dict[str, list[str]] | None = None, dns_default: list[str] | None = None) -> list[NetworkIdentity]:
    """One identity per usable IPv4 network: the interface must be up and the address a private/global one (not loopback or link-local)."""
    out: list[NetworkIdentity] = []
    dns_by_link = dns_by_link or {}
    for itf in interfaces:
        if itf.state != "up" or itf.kind in ("loopback",):
            continue
        for a in itf.v4:
            ip = a.interface.ip
            if ip.is_loopback or ip.is_link_local:
                continue
            gws = sorted((r for r in routes if r.dst == "default" and r.dev == itf.name and r.gateway), key=lambda r: r.metric)
            gw = gws[0].gateway if gws else ""
            gw_mac = next((n.mac for n in neighbors if n.ip == gw and n.dev == itf.name and n.usable), "") if gw else ""
            dns = dns_by_link.get(itf.name) or dns_by_link.get("global") or dns_default or []
            out.append(NetworkIdentity(itf, a, gw, gw_mac, list(dns), bool(gws)))
    return out


def _wireless_interfaces(sysfs: Path = Path("/sys/class/net")) -> set[str]:
    try:
        return {p.name for p in sysfs.iterdir() if (p / "wireless").exists() or (p / "phy80211").exists()}
    except OSError:
        return set()


class NetworkIdentifier:
    def __init__(self, run: Callable | None = None, which: Callable[[str], str | None] = find_executable,
                 resolv_conf: Path = Path("/etc/resolv.conf"), wireless: Callable[[], set[str]] = _wireless_interfaces) -> None:
        self._run = run or (lambda argv, t: run_command(argv, timeout=t))
        self._which = which
        self._resolv = resolv_conf
        self._wireless = wireless

    def _out(self, argv: list[str]) -> str:
        if not self._which(argv[0]):
            return ""
        r = self._run(argv, 10)
        return r.stdout if getattr(r, "ok", False) else ""

    def interfaces(self) -> list[InterfaceInfo]:
        return parse_ip_address(self._out(["ip", "-j", "address"]), self._wireless())

    def routes(self) -> list[Route]:
        return parse_ip_route(self._out(["ip", "-j", "route"]))

    def neighbors(self) -> list[Neighbor]:
        return parse_ip_neigh(self._out(["ip", "-j", "neigh"]))

    def dns(self) -> tuple[dict[str, list[str]], list[str]]:
        by_link = parse_resolvectl(self._out(["resolvectl", "status"]))
        try:
            default = parse_resolv_conf(self._resolv.read_text(encoding="utf-8"))
        except OSError:
            default = []
        return by_link, default

    def identify(self) -> list[NetworkIdentity]:
        by_link, default = self.dns()
        return identify_networks(self.interfaces(), self.routes(), self.neighbors(), by_link, default)
