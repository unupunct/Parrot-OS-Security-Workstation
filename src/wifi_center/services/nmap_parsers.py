"""Parsers for Nmap result files: XML (-oX), normal (-oN) and grepable (-oG).

Pure functions, no I/O. XML is parsed with the standard library after rejecting DOCTYPE/ENTITY declarations
(entity-expansion attacks) and oversized input.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

MAX_BYTES = 50 * 1024 * 1024


class ParseError(ValueError):
    pass


@dataclass
class Port:
    port: int
    proto: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""

    def label(self) -> str:
        detail = " ".join(x for x in (self.product, self.version) if x)
        return f"{self.port}/{self.proto} {self.service}".strip() + (f" {detail}" if detail else "")


@dataclass
class Host:
    address: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_guess: str = ""
    status: str = "up"
    ports: list[Port] = field(default_factory=list)

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanResult:
    hosts: list[Host]
    fmt: str
    args: str = ""
    started: str = ""
    finished: str = ""
    version: str = ""


# ---------------------------------------------------------------- XML
_DANGEROUS = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.I)


def parse_xml(text: str) -> ScanResult:
    if len(text) > MAX_BYTES:
        raise ParseError("file too large")
    if _DANGEROUS.search(text):
        raise ParseError("XML with DOCTYPE/ENTITY declarations is rejected")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ParseError(f"invalid XML: {e}") from None
    if root.tag != "nmaprun":
        raise ParseError("not an Nmap XML file (root element is not <nmaprun>)")
    hosts = []
    for h in root.findall("host"):
        status = (h.find("status").get("state") if h.find("status") is not None else "up") or "up"
        host = Host(address="", status=status)
        for a in h.findall("address"):
            t = a.get("addrtype", "")
            if t in ("ipv4", "ipv6") and not host.address:
                host.address = a.get("addr", "")
            elif t == "mac":
                host.mac, host.vendor = a.get("addr", "").upper(), a.get("vendor", "")
        if not host.address:
            continue
        names = h.find("hostnames")
        if names is not None and names.find("hostname") is not None:
            host.hostname = names.find("hostname").get("name", "")
        osm = h.find("os/osmatch")
        if osm is not None:
            host.os_guess = osm.get("name", "")
        for p in h.findall("ports/port"):
            st = p.find("state")
            sv = p.find("service")
            try:
                num = int(p.get("portid", ""))
            except ValueError:
                continue
            host.ports.append(Port(num, p.get("protocol", "tcp"), st.get("state", "") if st is not None else "",
                                   sv.get("name", "") if sv is not None else "",
                                   sv.get("product", "") if sv is not None else "",
                                   sv.get("version", "") if sv is not None else ""))
        hosts.append(host)
    fin = root.find("runstats/finished")
    return ScanResult(hosts, "xml", root.get("args", ""), root.get("startstr", root.get("start", "")),
                      fin.get("timestr", "") if fin is not None else "", root.get("version", ""))


# ---------------------------------------------------------------- normal
_REPORT = re.compile(r"^Nmap scan report for (?:(\S+) \(([^)]+)\)|(\S+))\s*$")
_PORT = re.compile(r"^(\d+)/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$")
_MAC = re.compile(r"^MAC Address: ([0-9A-Fa-f:]{17})(?: \((.*)\))?")


def parse_normal(text: str) -> ScanResult:
    hosts: list[Host] = []
    cur: Host | None = None
    for line in text.splitlines():
        m = _REPORT.match(line)
        if m:
            name, ip, bare = m.groups()
            cur = Host(address=ip or bare, hostname=name or "")
            hosts.append(cur)
            continue
        if cur is None:
            continue
        pm = _PORT.match(line)
        if pm:
            port, proto, state, service, rest = pm.groups()
            cur.ports.append(Port(int(port), proto, state.split("|")[0], service, (rest or "").strip()))
            continue
        mm = _MAC.match(line)
        if mm:
            cur.mac, cur.vendor = mm.group(1).upper(), mm.group(2) or ""
        elif line.startswith("OS details:") or line.startswith("Running:"):
            cur.os_guess = cur.os_guess or line.split(":", 1)[1].strip()
        elif line.startswith("Host seems down"):
            cur.status = "down"
    if not hosts:
        raise ParseError("no 'Nmap scan report' lines found")
    return ScanResult(hosts, "normal")


# ---------------------------------------------------------------- grepable
def parse_grepable(text: str) -> ScanResult:
    by_addr: dict[str, Host] = {}
    args = ""
    for line in text.splitlines():
        if line.startswith("# Nmap") and " as: " in line:
            args = line.split(" as: ", 1)[1].strip()
        if not line.startswith("Host: "):
            continue
        parts = line.split("\t")
        head = re.match(r"Host: (\S+) \(([^)]*)\)", parts[0])
        if not head:
            continue
        addr, name = head.groups()
        host = by_addr.setdefault(addr, Host(address=addr, hostname=name))
        for field_ in parts[1:]:
            if field_.startswith("Status: "):
                host.status = field_[8:].strip().lower()
            elif field_.startswith("Ports: "):
                for entry in field_[7:].split(", "):
                    f = entry.strip().split("/")
                    if len(f) >= 5 and f[0].isdigit():
                        host.ports.append(Port(int(f[0]), f[2], f[1].split("|")[0], f[4], f[6] if len(f) > 6 else ""))
            elif field_.startswith("OS: "):
                host.os_guess = field_[4:].strip()
    if not by_addr:
        raise ParseError("no 'Host:' lines found")
    return ScanResult(list(by_addr.values()), "grepable", args)


def parse_any(text: str) -> ScanResult:
    head = text.lstrip()[:400]
    if head.startswith("<?xml") or head.startswith("<nmaprun") or "<nmaprun" in head:
        return parse_xml(text)
    if "Nmap scan report for" in text:
        return parse_normal(text)
    if re.search(r"^Host: ", text, re.M):
        return parse_grepable(text)
    raise ParseError("unrecognised format (expected Nmap XML, normal or grepable output)")
