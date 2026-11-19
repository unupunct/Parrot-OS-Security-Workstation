"""Advanced LAN discovery: planning (scope + attachment checks), host discovery (ICMP echo, ARP/NDP neighbour evidence, the
existing neighbour cache), device identification, persistent scan history with comparison, exports and an evidence-only topology.

Safety rules enforced here, not in the UI:
* a scan needs a project, and the target range must lie inside that project's authorized scope (never expanded silently);
* the range must be a subnet of a network directly attached to this computer, and at most MAX_TARGETS addresses;
* only ping probes, ARP/NDP resolution and neighbour-table reads are used: no port scans, no spoofing, no configuration changes;
* a missing answer never means a host is offline, and results are only ever deleted by an explicit user action."""
from __future__ import annotations

import csv
import html
import io
import ipaddress
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from ..database.repository import Database
from .device_classifier import classify
from .lan_scanner import ping_once, reverse_dns
from .net_identity import NetworkIdentifier, NetworkIdentity, Neighbor
from .process_runner import find_executable, run_command
from .project_service import ProjectService, ScopeError

MAX_TARGETS = 4096
MODES = {
    "quick": ("Quick Discovery", "ARP and ICMP host discovery with a short timeout."),
    "full": ("Full Subnet Discovery", "Every usable address in the range, with a retry pass for silent addresses."),
    "neighbor": ("Neighbor Discovery", "Reads the ARP and IPv6 neighbour tables only: nothing is sent."),
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DiscoveryError(ValueError):
    pass


@dataclass
class DiscoveryConfig:
    cidr: str
    mode: str = "full"
    interface: str = ""
    concurrency: int = 64
    timeout: float = 1.0
    ipv6: bool = False
    project_id: int | None = None


@dataclass
class DiscoveryPlan:
    config: DiscoveryConfig
    network: ipaddress.IPv4Network
    identity: NetworkIdentity
    targets: list[str]
    scope: list[str]
    total_addresses: int = 0         # usable addresses in the range (also set for neighbour mode, which sends no probes)

    @property
    def total(self) -> int:
        return len(self.targets)


@dataclass
class HostResult:
    ip: str
    family: int = 4
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    device_type: str = "Unknown"
    type_basis: str = "unknown"
    type_reason: str = ""
    response_method: str = ""
    latency_ms: float | None = None
    status: str = ""                       # responded | cached
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    @property
    def sort_key(self) -> tuple:
        try:
            a = ipaddress.ip_address(self.ip)
            return (a.version, int(a))
        except ValueError:
            return (9, 0)


@dataclass
class ScanOutcome:
    scan_id: int
    status: str                            # completed | cancelled | aborted
    hosts: list[HostResult]
    targets_total: int
    duration_s: float
    note: str = ""


class ScanControl:
    """Pause / resume / cancel handle shared with the worker threads."""

    def __init__(self) -> None:
        self._run = threading.Event()
        self._run.set()
        self.cancelled = threading.Event()
        self.reason = ""

    def pause(self) -> None:
        self._run.clear()

    def resume(self) -> None:
        self._run.set()

    @property
    def paused(self) -> bool:
        return not self._run.is_set()

    def cancel(self) -> None:
        self.cancelled.set()
        self._run.set()                    # wake paused workers so they can exit

    def abort(self, reason: str) -> None:
        self.reason = reason
        self.cancel()

    def checkpoint(self) -> bool:
        """Block while paused; False once cancelled."""
        self._run.wait()
        return not self.cancelled.is_set()


def mac_in(neigh: Neighbor) -> str:
    return neigh.mac if neigh.usable else ""


class NetworkDiscoveryEngine:
    def __init__(self, db: Database, oui=None, identifier: NetworkIdentifier | None = None, projects: ProjectService | None = None,
                 pinger: Callable[[str, float], float | None] = ping_once, resolver: Callable[[str], str] = reverse_dns,
                 v6_probe: Callable[[str], None] | None = None) -> None:
        self._db = db
        self._oui = oui
        self.identifier = identifier or NetworkIdentifier()
        self._projects = projects or ProjectService(db)
        self._ping, self._resolve = pinger, resolver
        self._v6_probe = v6_probe or self._default_v6_probe

    # ------------------------------------------------------------------ planning
    def plan(self, config: DiscoveryConfig, identities: list[NetworkIdentity] | None = None) -> DiscoveryPlan:
        if config.mode not in MODES:
            raise DiscoveryError("unknown scan mode")
        identities = identities if identities is not None else self.identifier.identify()
        try:
            target = ipaddress.ip_network(config.cidr.strip(), strict=False)
        except ValueError:
            raise DiscoveryError("enter a valid IPv4 network such as 192.168.1.0/24") from None
        if not isinstance(target, ipaddress.IPv4Network):
            raise DiscoveryError("only IPv4 ranges can be scanned; IPv6 uses neighbour discovery (tick the IPv6 option)")
        if not target.is_private:
            raise DiscoveryError("only private (RFC 1918) networks can be scanned")
        if target.num_addresses > MAX_TARGETS:
            raise DiscoveryError(f"too large: at most {MAX_TARGETS} addresses per scan")
        ident = next((i for i in identities if i.interface.name == config.interface), None) or \
            next((i for i in identities if i.v4 and target.subnet_of(ipaddress.ip_network(i.cidr))), None)
        if ident is None or not ident.v4 or not target.subnet_of(ipaddress.ip_network(ident.cidr)):
            raise DiscoveryError("the range must be inside a network that is directly attached to this computer")
        if not config.project_id:
            raise DiscoveryError("select a project first: scans only run inside a project's authorized scope")
        check = self._projects.check_scope(config.project_id, [str(target)])[0]
        if not check.in_scope:
            raise ScopeError(f"{target} is outside this project's authorized scope. Add it on the Authorized scope tab "
                             "(the scope is never expanded automatically).")
        scope = [e["target"] for e in self._projects.scope(config.project_id)]
        targets = [str(h) for h in target.hosts()] if config.mode != "neighbor" else []
        total = len(targets) if config.mode != "neighbor" else max(target.num_addresses - 2, 0)
        config.concurrency = max(1, min(int(config.concurrency), 256))
        config.timeout = max(0.2, min(float(config.timeout), 10.0))
        return DiscoveryPlan(config, target, ident, targets, scope, total)

    @staticmethod
    def target_count(plan: DiscoveryPlan) -> int:
        return plan.total_addresses

    # ------------------------------------------------------------------ running
    def _default_v6_probe(self, iface: str) -> None:
        """All-nodes link-local multicast echo: the standard way to make IPv6 neighbours reveal themselves."""
        if find_executable("ping"):
            run_command(["ping", "-6", "-c", "2", "-W", "1", "-I", iface, "ff02::1"], timeout=8)

    def run(self, plan: DiscoveryPlan, control: ScanControl | None = None,
            progress: Callable[[int, int, int], None] | None = None,
            change_check: Callable[[], str | None] | None = None) -> ScanOutcome:
        control = control or ScanControl()
        cfg, ident = plan.config, plan.identity
        started = time.monotonic()
        started_at = utcnow()
        total = self.target_count(plan)
        pre = {(n.ip, n.dev): n for n in self.identifier.neighbors()}
        rtts: dict[str, float | None] = {}
        lock = threading.Lock()
        done = [0]

        def probe(ip: str, timeout: float) -> None:
            if not control.checkpoint():
                return
            if change_check and done[0] % 16 == 0:
                why = change_check()
                if why:
                    control.abort(why)
                    return
            rtt = self._ping(ip, timeout)
            with lock:
                if rtt is not None or ip not in rtts:
                    rtts[ip] = rtt
                done[0] += 1
                if progress:
                    progress(min(done[0], total), total, sum(1 for v in rtts.values() if v is not None))

        if cfg.mode in ("quick", "full"):
            with ThreadPoolExecutor(max_workers=cfg.concurrency) as ex:
                list(ex.map(lambda ip: probe(ip, cfg.timeout if cfg.mode == "full" else min(cfg.timeout, 0.5)), plan.targets))
            if cfg.mode == "full" and control.checkpoint():          # retry pass: a first ping can be lost
                silent = [ip for ip in plan.targets if rtts.get(ip) is None]
                done[0] = max(done[0] - len(silent), 0)
                with ThreadPoolExecutor(max_workers=cfg.concurrency) as ex:
                    list(ex.map(lambda ip: probe(ip, cfg.timeout), silent))
        elif progress:
            progress(total, total, 0)
        if cfg.ipv6 and cfg.interface and control.checkpoint():
            self._v6_probe(cfg.interface)
        status = "cancelled" if control.cancelled.is_set() else "completed"
        if control.reason:
            status = "aborted"
        post = self.identifier.neighbors()
        hosts = self._build_hosts(plan, rtts, pre, post)
        duration = time.monotonic() - started
        note = control.reason if status == "aborted" else ""
        scan_id = self._save(plan, started_at, duration, total, status, hosts, note)
        return ScanOutcome(scan_id, status, hosts, total, duration, note)

    def _build_hosts(self, plan: DiscoveryPlan, rtts: dict[str, float | None], pre: dict, post: list[Neighbor]) -> list[HostResult]:
        cfg, ident, net = plan.config, plan.identity, plan.network
        mine = {a.address for i in self.identifier.interfaces() for a in i.v4}
        mine |= {a.address for i in self.identifier.interfaces() for a in i.v6}
        dev = ident.interface.name
        neigh4 = {n.ip: n for n in post if n.family == 4 and n.dev == dev}
        entries: dict[str, HostResult] = {}
        for ip, n in neigh4.items():
            try:
                if ipaddress.ip_address(ip) not in net:
                    continue
            except ValueError:
                continue
            rtt = rtts.get(ip)
            fresh = n.state in ("REACHABLE", "DELAY", "PROBE")
            if rtt is not None:
                method, status = "icmp", "responded"
            elif n.usable and fresh and cfg.mode != "neighbor":
                method, status = "arp", "responded"
            elif n.usable:
                method, status = "neighbor-cache", "cached"
            else:
                continue
            entries[ip] = HostResult(ip, 4, mac_in(n), "", "", response_method=method, latency_ms=rtt, status=status)
        for ip, rtt in rtts.items():                                      # answered ping but no neighbour entry (e.g. routed)
            if rtt is not None and ip not in entries:
                entries[ip] = HostResult(ip, 4, "", "", "", response_method="icmp", latency_ms=rtt, status="responded")
        for ip in mine:
            try:
                if ipaddress.ip_address(ip) in net and ip not in entries:
                    entries[ip] = HostResult(ip, 4, ident.interface.mac, response_method="local", status="responded")
            except ValueError:
                pass
        if cfg.ipv6 and cfg.interface:
            for n in post:
                if n.family == 6 and n.dev == cfg.interface and n.usable:
                    entries[n.ip] = HostResult(n.ip, 6, n.mac, response_method="ndp", status="responded" if n.state != "STALE" else "cached")
        # names, vendors, classification
        ips = sorted(entries)
        with ThreadPoolExecutor(max_workers=min(32, max(len(ips), 1))) as ex:
            names = dict(zip(ips, ex.map(self._resolve, ips)))
        known = {r["mac"]: dict(r) for r in self._db.query("SELECT * FROM nd_devices")}
        now = utcnow()
        by_mac: dict[str, list[str]] = {}
        for h in entries.values():
            if h.mac:
                by_mac.setdefault(h.mac, []).append(h.ip)
        for ip, h in entries.items():
            h.hostname = names.get(ip, "")
            h.vendor = (self._oui.vendor(h.mac) or "") if (self._oui and h.mac) else ""
            is_self, is_gw = ip in mine, ip == ident.gateway
            c = classify(ip, h.mac, h.vendor, h.hostname, is_self=is_self, is_gateway=is_gw)
            h.device_type, h.type_basis, h.type_reason = c.device_type, c.basis, c.reason
            if is_self:
                h.tags.append("this computer")
            if is_gw:
                h.tags.append("gateway")
            rec = known.get(h.mac) if h.mac else None
            if h.mac and rec is None and known:
                h.tags.append("new")
            if rec and rec["last_ip"] and rec["last_ip"] != ip and h.family == 4:
                h.tags.append("ip changed")
            if h.mac and len([i for i in by_mac.get(h.mac, []) if ":" not in i]) > 1 and h.family == 4:
                h.tags.append("multiple IPs")
            h.first_seen = rec["first_seen"] if rec else now
            h.last_seen = now
        return sorted(entries.values(), key=lambda h: h.sort_key)

    # ------------------------------------------------------------------ persistence
    def _save(self, plan: DiscoveryPlan, started_at: str, duration: float, total: int, status: str, hosts: list[HostResult],
              note: str) -> int:
        cfg = plan.config
        params = {"concurrency": cfg.concurrency, "timeout": cfg.timeout, "ipv6": cfg.ipv6}
        with self._db.transaction() as c:
            cur = c.execute(
                "INSERT INTO nd_scans(project_id, started_at, finished_at, duration_s, interface, cidr, mode, targets_total, "
                "hosts_found, status, scope_json, params_json, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cfg.project_id, started_at, utcnow(), round(duration, 2), plan.identity.interface.name, str(plan.network), cfg.mode,
                 total, len(hosts), status, json.dumps(plan.scope), json.dumps(params), note))
            sid = cur.lastrowid
            for h in hosts:
                c.execute("INSERT INTO nd_hosts(scan_id, ip, family, mac, hostname, vendor, device_type, type_basis, type_reason, "
                          "response_method, latency_ms, status, tags, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (sid, h.ip, h.family, h.mac, h.hostname, h.vendor, h.device_type, h.type_basis, h.type_reason,
                           h.response_method, h.latency_ms, h.status, ",".join(h.tags), h.first_seen, h.last_seen))
                if h.mac and h.family == 4:
                    c.execute("INSERT INTO nd_devices(mac, vendor, last_ip, first_seen, last_seen) VALUES (?,?,?,?,?) "
                              "ON CONFLICT(mac) DO UPDATE SET vendor=excluded.vendor, last_ip=excluded.last_ip, last_seen=excluded.last_seen",
                              (h.mac, h.vendor, h.ip, h.first_seen, h.last_seen))
        return int(sid)

    def scans(self, project_id: int | None = None, limit: int = 100) -> list[dict]:
        sql, params = "SELECT * FROM nd_scans", []
        if project_id:
            sql += " WHERE project_id = ?"
            params.append(project_id)
        return [dict(r) for r in self._db.query(sql + " ORDER BY id DESC LIMIT ?", (*params, limit))]

    def hosts(self, scan_id: int) -> list[HostResult]:
        out = []
        for r in self._db.query("SELECT * FROM nd_hosts WHERE scan_id = ? ORDER BY id", (scan_id,)):
            d = dict(r)
            out.append(HostResult(d["ip"], d["family"], d["mac"] or "", d["hostname"] or "", d["vendor"] or "", d["device_type"] or "Unknown",
                                  d["type_basis"] or "unknown", d["type_reason"] or "", d["response_method"] or "", d["latency_ms"],
                                  d["status"] or "", [t for t in (d["tags"] or "").split(",") if t], d["first_seen"] or "", d["last_seen"] or ""))
        return sorted(out, key=lambda h: h.sort_key)

    def delete_scan(self, scan_id: int) -> None:
        """Explicit user action only; nothing in the application calls this automatically."""
        self._db.execute("DELETE FROM nd_scans WHERE id = ?", (scan_id,))

    def devices(self) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM nd_devices ORDER BY last_seen DESC")]

    def set_label(self, mac: str, label: str) -> None:
        self._db.execute("UPDATE nd_devices SET label = ? WHERE mac = ?", (label.strip()[:60], mac))

    def compare(self, older_id: int, newer_id: int) -> dict[str, list]:
        """What changed between two scans. 'not seen' is not 'offline': a host may simply not have answered."""
        def keyed(sid: int) -> dict[str, HostResult]:
            hs = self.hosts(sid)
            count: dict[str, int] = {}
            for h in hs:
                if h.mac:
                    count[h.mac] = count.get(h.mac, 0) + 1
            # a device is followed by its MAC (so an IP change is a change, not a new host); a MAC with several IPs is followed per IP
            return {(h.mac if h.mac and count[h.mac] == 1 else f"{h.mac}|{h.ip}"): h for h in hs}
        a, b = keyed(older_id), keyed(newer_id)
        changed = []
        for k in a.keys() & b.keys():
            x, y = a[k], b[k]
            diffs = [f"{label}: {old or '—'} → {new or '—'}" for label, old, new in
                     (("IP", x.ip, y.ip), ("name", x.hostname, y.hostname), ("manufacturer", x.vendor, y.vendor), ("type", x.device_type, y.device_type))
                     if old != new]
            if diffs:
                changed.append((y, "; ".join(diffs)))
        return {"new": sorted((b[k] for k in b.keys() - a.keys()), key=lambda h: h.sort_key),
                "not_seen": sorted((a[k] for k in a.keys() - b.keys()), key=lambda h: h.sort_key), "changed": changed}


# ====================================================================== exports
HOST_COLUMNS = ("ip", "mac", "hostname", "vendor", "device_type", "type_basis", "response_method", "latency_ms", "status",
                "tags", "first_seen", "last_seen")


def to_csv(hosts: list[HostResult]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(HOST_COLUMNS)
    for h in hosts:
        row = asdict(h)
        row["tags"] = " ".join(h.tags)
        w.writerow(["" if row[c] is None else row[c] for c in HOST_COLUMNS])
    return buf.getvalue()


def to_json(scan: dict | None, hosts: list[HostResult]) -> str:
    return json.dumps({"scan": scan, "hosts": [asdict(h) for h in hosts]}, indent=2, default=str)


def to_html(scan: dict | None, hosts: list[HostResult]) -> str:
    e = html.escape
    head = "".join(f"<th>{e(c)}</th>" for c in HOST_COLUMNS)
    rows = "".join("<tr>" + "".join(f"<td>{e(str(v if v is not None else ''))}</td>" for v in (
        h.ip, h.mac, h.hostname, h.vendor, h.device_type, h.type_basis, h.response_method,
        "" if h.latency_ms is None else f"{h.latency_ms:.1f}", h.status, " ".join(h.tags), h.first_seen, h.last_seen)) + "</tr>" for h in hosts)
    meta = ""
    if scan:
        meta = (f"<p>Scan {e(str(scan.get('id', '')))}: {e(str(scan.get('cidr', '')))} on {e(str(scan.get('interface', '')))}, mode "
                f"{e(str(scan.get('mode', '')))}, started {e(str(scan.get('started_at', '')))}, {e(str(scan.get('hosts_found', '')))} host(s) found of "
                f"{e(str(scan.get('targets_total', '')))} addresses, status {e(str(scan.get('status', '')))}.</p>")
    return ("<!doctype html><html><head><meta charset='utf-8'><title>Network discovery report</title><style>body{font-family:sans-serif;"
            "background:#0b120d;color:#e7f2e9;padding:24px}table{border-collapse:collapse}td,th{border:1px solid #203328;padding:4px 8px;"
            "font-size:13px}th{background:#10201a;color:#00ff66}</style></head><body><h1>Network discovery report</h1>" + meta +
            "<p><i>A missing response does not prove a host is offline. Device types marked inferred are hints, not facts.</i></p>"
            f"<table><tr>{head}</tr>{rows}</table></body></html>")


# ====================================================================== topology (evidence only)
@dataclass
class TopoNode:
    id: str
    label: str
    kind: str                 # internet | gateway | self | segment | host
    device_type: str = ""
    ip: str = ""
    mac: str = ""
    basis: str = ""           # confirmed | inferred | unknown
    detail: str = ""


@dataclass
class TopoEdge:
    a: str
    b: str
    evidence: str


@dataclass
class TopologyGraph:
    nodes: list[TopoNode]
    edges: list[TopoEdge]
    note: str = ""


def build_topology(identity: NetworkIdentity, hosts: list[HostResult]) -> TopologyGraph:
    """Only relationships the system can prove are drawn:
    * Internet - gateway: the default route points at the gateway;
    * this computer - segment: it has an interface address in the subnet;
    * every host - segment: it answered ARP/NDP on this computer's own Layer-2 segment.
    Hosts are NOT linked to the gateway: sharing a segment with it does not show how they connect to it."""
    nodes: list[TopoNode] = []
    edges: list[TopoEdge] = []
    seg = f"segment:{identity.cidr}"
    nodes.append(TopoNode(seg, f"LAN {identity.cidr}", "segment", detail=f"Layer-2 segment on {identity.interface.name}"))
    me_ip = identity.v4.address if identity.v4 else ""
    nodes.append(TopoNode("self", "This computer", "self", "This computer", me_ip, identity.interface.mac, "confirmed",
                          f"interface {identity.interface.name}"))
    edges.append(TopoEdge("self", seg, f"interface address {me_ip}/{identity.v4.prefixlen if identity.v4 else ''} is in this subnet"))
    if identity.gateway and identity.default_route:
        nodes.append(TopoNode("internet", "Internet (via default route)", "internet", detail="reachability beyond the gateway is not tested"))
        edges.append(TopoEdge("internet", f"host:{identity.gateway}", f"default route via {identity.gateway} on {identity.interface.name}"))
    for h in hosts:
        if "this computer" in h.tags:
            continue
        kind = "gateway" if "gateway" in h.tags else "host"
        nodes.append(TopoNode(f"host:{h.ip}", h.hostname or h.ip, kind, h.device_type, h.ip, h.mac, h.type_basis,
                              f"{h.vendor or 'unknown manufacturer'} · {h.response_method} · {h.status}"))
        how = "ARP/NDP neighbour on this computer's own Layer-2 segment" if h.status == "responded" else "entry in this computer's neighbour cache (not refreshed by this scan)"
        edges.append(TopoEdge(f"host:{h.ip}", seg, how))
    ids = {n.id for n in nodes}
    edges = [e for e in edges if e.a in ids and e.b in ids]
    return TopologyGraph(nodes, edges, "Lines show evidence this computer can see; they do not show how devices are wired to each other or to the router.")
