import json
import threading
import time

import pytest

from wifi_center.database.repository import Database
from wifi_center.services import network_discovery as nd
from wifi_center.services import net_identity as ni
from wifi_center.services.project_service import ProjectService, ScopeError


class FakeOui:
    def vendor(self, mac):
        return {"aa:bb:cc": "RouterCo", "00:11:22": "Seiko Epson Corp"}.get(mac[:8])


def identity(gateway="192.168.1.1", prefix=24, me="192.168.1.26"):
    itf = ni.InterfaceInfo("enp2s0", "up", "aa:00:00:00:00:26", 1500, "ethernet", [ni.AddrV4(me, prefix, "global")])
    return ni.NetworkIdentity(itf, itf.v4[0], gateway, "aa:bb:cc:00:00:01", ["192.168.1.1"], bool(gateway))


class FakeIdentifier:
    def __init__(self, pre, post, ident):
        self.pre, self.post, self.ident, self.calls = pre, post, ident, 0

    def neighbors(self):
        self.calls += 1
        return self.pre if self.calls == 1 else self.post

    def interfaces(self):
        return [self.ident.interface]

    def identify(self):
        return [self.ident]


def N(ip, mac, state="REACHABLE", dev="enp2s0", fam=4):
    return ni.Neighbor(ip, mac, dev, state, fam)


@pytest.fixture
def env():
    db = Database(":memory:")
    projects = ProjectService(db)
    pid = projects.create("Lab")
    projects.add_scope(pid, "192.168.1.0/24")
    return db, projects, pid


def engine(db, projects, pre, post, ping_alive=("192.168.1.1",), names=None, ident=None, **kw):
    ident = ident or identity()
    return nd.NetworkDiscoveryEngine(db, FakeOui(), FakeIdentifier(pre, post, ident), projects,
                                     pinger=lambda ip, t: 1.5 if ip in ping_alive else None,
                                     resolver=lambda ip: (names or {}).get(ip, ""), v6_probe=lambda i: None, **kw)


def cfg(pid, cidr="192.168.1.0/24", mode="full", **k):
    return nd.DiscoveryConfig(cidr, mode, "enp2s0", project_id=pid, **k)


# ---------------------------------------------------------------- planning: scope and safety
def test_plan_enforces_project_scope_attachment_and_size(env):
    db, projects, pid = env
    e = engine(db, projects, [], [])
    plan = e.plan(cfg(pid), [identity()])
    assert plan.total == 254 and str(plan.network) == "192.168.1.0/24" and plan.scope == ["192.168.1.0/24"]
    assert e.plan(cfg(pid, "192.168.1.0/25"), [identity()]).total == 126                           # a narrower range inside the scope is fine
    with pytest.raises(nd.DiscoveryError, match="select a project"):
        e.plan(nd.DiscoveryConfig("192.168.1.0/24", "full", "enp2s0", project_id=None), [identity()])
    projects.remove_scope(pid, "192.168.1.0/24")
    projects.add_scope(pid, "192.168.1.0/25")
    with pytest.raises(ScopeError, match="outside this project"):
        e.plan(cfg(pid, "192.168.1.0/24"), [identity()])                                           # never widened silently
    projects.add_scope(pid, "192.168.1.0/24")
    for bad, why in (("8.8.8.0/24", "private"), ("10.9.9.0/24", "attached"), ("192.168.0.0/16", "too large"),
                     ("nope", "valid IPv4"), ("::1/128", "only IPv4"), ("192.168.1.0/23", "attached")):
        with pytest.raises(nd.DiscoveryError, match=why):
            e.plan(cfg(pid, bad), [identity()])


def test_plan_clamps_concurrency_and_timeout_and_counts_neighbor_mode(env):
    db, projects, pid = env
    e = engine(db, projects, [], [])
    plan = e.plan(cfg(pid, mode="neighbor", concurrency=9999, timeout=99), [identity()])
    assert plan.config.concurrency == 256 and plan.config.timeout == 10.0 and plan.targets == [] and e.target_count(plan) == 254


# ---------------------------------------------------------------- running
def test_full_scan_finds_icmp_arp_and_cached_hosts_and_classifies(env):
    db, projects, pid = env
    pre = [N("192.168.1.30", "00:11:22:33:44:55", "STALE")]
    post = [N("192.168.1.1", "aa:bb:cc:00:00:01"), N("192.168.1.20", "02:da:19:33:a5:fb", "DELAY"), N("192.168.1.30", "00:11:22:33:44:55", "STALE"),
            N("192.168.1.40", "", "FAILED")]
    e = engine(db, projects, pre, post, names={"192.168.1.1": "router.lan"})
    seen = []
    out = e.run(e.plan(cfg(pid), [identity()]), progress=lambda d, t, f: seen.append((d, t, f)))
    by = {h.ip: h for h in out.hosts}
    assert out.status == "completed" and out.targets_total == 254 and seen[-1][1] == 254
    assert set(by) == {"192.168.1.1", "192.168.1.20", "192.168.1.26", "192.168.1.30"}               # FAILED entry is not a host
    gw = by["192.168.1.1"]
    assert (gw.response_method, gw.status, gw.latency_ms, gw.hostname, gw.vendor) == ("icmp", "responded", 1.5, "router.lan", "RouterCo")
    assert gw.device_type == "Gateway / router" and gw.type_basis == "confirmed" and "gateway" in gw.tags
    assert (by["192.168.1.20"].response_method, by["192.168.1.20"].status) == ("arp", "responded")      # no ping reply, but ARP resolved
    assert by["192.168.1.20"].device_type == "Private-MAC device" and by["192.168.1.20"].type_basis == "inferred"
    c = by["192.168.1.30"]
    assert (c.response_method, c.status, c.device_type) == ("neighbor-cache", "cached", "Printer")        # only the stale cache: not a fresh answer
    me = by["192.168.1.26"]
    assert me.response_method == "local" and "this computer" in me.tags and me.type_basis == "confirmed"


def test_neighbor_mode_sends_nothing(env):
    db, projects, pid = env
    probes = []
    post = [N("192.168.1.9", "00:11:22:33:44:55"), N("192.168.5.5", "aa:aa:aa:aa:aa:aa"), N("192.168.1.8", "aa:bb:cc:00:00:08", dev="wlp3s0")]
    e = nd.NetworkDiscoveryEngine(db, FakeOui(), FakeIdentifier([], post, identity()), projects, pinger=lambda ip, t: probes.append(ip),
                                  resolver=lambda ip: "", v6_probe=lambda i: probes.append("v6"))
    out = e.run(e.plan(cfg(pid, mode="neighbor"), [identity()]))
    assert probes == [] and [h.ip for h in out.hosts] == ["192.168.1.9", "192.168.1.26"]              # other subnet / other interface excluded
    assert out.hosts[0].status == "cached" and out.hosts[0].response_method == "neighbor-cache"


def test_ipv6_neighbours_are_added_only_when_requested(env):
    db, projects, pid = env
    post = [N("192.168.1.1", "aa:bb:cc:00:00:01"), N("fe80::2", "aa:bb:cc:dd:ee:ff", "STALE", fam=6), N("fe80::3", "aa:bb:cc:dd:ee:03", "REACHABLE", fam=6)]
    off = engine(db, projects, [], post)
    assert all(h.family == 4 for h in off.run(off.plan(cfg(pid), [identity()])).hosts)
    on = engine(db, projects, [], post)
    ident = identity()
    ident.interface.v6.append(ni.AddrV6("fe80::3", 64, "link"))                  # one of this computer's own IPv6 addresses
    on = engine(db, projects, [], post, ident=ident)
    hosts = {h.ip: h for h in on.run(on.plan(cfg(pid, ipv6=True), [ident])).hosts}
    assert "this computer" in hosts["fe80::3"].tags and hosts["fe80::3"].type_basis == "confirmed"
    assert hosts["fe80::2"].response_method == "ndp" and hosts["fe80::2"].status == "cached" and hosts["fe80::3"].status == "responded"


def test_cancel_and_network_change_abort_and_pause(env):
    db, projects, pid = env
    e = engine(db, projects, [], [N("192.168.1.1", "aa:bb:cc:00:00:01")])
    ctl = nd.ScanControl()
    ctl.cancel()
    out = e.run(e.plan(cfg(pid), [identity()]), ctl)
    assert out.status == "cancelled" and db.query_one("SELECT status FROM nd_scans")["status"] == "cancelled"     # saved, never discarded
    e2 = engine(db, projects, [], [])
    out2 = e2.run(e2.plan(cfg(pid), [identity()]), change_check=lambda: "the interface address changed")
    assert out2.status == "aborted" and "address changed" in out2.note
    ctl2 = nd.ScanControl()
    ctl2.pause()
    assert ctl2.paused
    e3 = engine(db, projects, [], [N("192.168.1.1", "aa:bb:cc:00:00:01")])
    res = {}
    t = threading.Thread(target=lambda: res.update(out=e3.run(e3.plan(cfg(pid), [identity()]), ctl2)))
    t.start()
    time.sleep(0.4)
    assert t.is_alive()                                                  # paused: no progress, no result yet
    ctl2.resume()
    t.join(10)
    assert res["out"].status == "completed"


# ---------------------------------------------------------------- history, device history, comparison, exports
def test_history_device_tags_and_comparison(env):
    db, projects, pid = env
    post1 = [N("192.168.1.1", "aa:bb:cc:00:00:01"), N("192.168.1.9", "00:11:22:33:44:55")]
    e = engine(db, projects, [], post1)
    first = e.run(e.plan(cfg(pid), [identity()]))
    assert all("new" not in h.tags for h in first.hosts)                  # the first ever scan flags nothing as new
    post2 = [N("192.168.1.1", "aa:bb:cc:00:00:01"), N("192.168.1.19", "00:11:22:33:44:55"), N("192.168.1.77", "02:aa:aa:aa:aa:aa"),
             N("192.168.1.78", "02:aa:aa:aa:aa:aa")]
    e2 = engine(db, projects, [], post2, names={"192.168.1.19": "printer.lan"})
    second = e2.run(e2.plan(cfg(pid), [identity()]))
    by = {h.ip: h for h in second.hosts}
    assert "ip changed" in by["192.168.1.19"].tags and "new" in by["192.168.1.77"].tags and "multiple IPs" in by["192.168.1.78"].tags
    assert by["192.168.1.19"].first_seen == first.hosts[1].first_seen        # device history survives across scans and IP changes
    scans = e2.scans(pid)
    assert [s["id"] for s in scans] == [second.scan_id, first.scan_id] and scans[0]["hosts_found"] == len(second.hosts)
    assert json.loads(scans[0]["scope_json"]) == ["192.168.1.0/24"]
    cmp = e2.compare(first.scan_id, second.scan_id)
    assert {h.ip for h in cmp["new"]} == {"192.168.1.77", "192.168.1.78"} and cmp["not_seen"] == []
    assert any("IP: 192.168.1.9 → 192.168.1.19" in d for _, d in cmp["changed"])
    e2.set_label("00:11:22:33:44:55", "  Office printer ")
    assert [d["label"] for d in e2.devices() if d["mac"] == "00:11:22:33:44:55"] == ["Office printer"]
    # nothing deletes history except an explicit call
    e2.delete_scan(first.scan_id)
    assert [s["id"] for s in e2.scans()] == [second.scan_id] and db.query("SELECT 1 FROM nd_hosts WHERE scan_id = ?", (first.scan_id,)) == []


def test_exports_escape_and_state_the_caveat(env):
    db, projects, pid = env
    e = engine(db, projects, [], [N("192.168.1.1", "aa:bb:cc:00:00:01")], names={"192.168.1.1": "<b>x</b>,router"})
    out = e.run(e.plan(cfg(pid), [identity()]))
    csv_text = nd.to_csv(out.hosts)
    assert csv_text.splitlines()[0].startswith("ip,mac,hostname") and '"<b>x</b>,router"' in csv_text
    data = json.loads(nd.to_json(e.scans()[0], out.hosts))
    assert data["scan"]["cidr"] == "192.168.1.0/24" and len(data["hosts"]) == len(out.hosts)
    page = nd.to_html(e.scans()[0], out.hosts)
    assert "&lt;b&gt;x&lt;/b&gt;" in page and "<b>x</b>" not in page and "does not prove a host is offline" in page


# ---------------------------------------------------------------- topology: evidence only
def test_topology_never_links_hosts_to_the_gateway(env):
    db, projects, pid = env
    post = [N("192.168.1.1", "aa:bb:cc:00:00:01"), N("192.168.1.9", "00:11:22:33:44:55"), N("192.168.1.30", "00:11:22:33:44:56", "STALE")]
    e = engine(db, projects, [], post)
    hosts = e.run(e.plan(cfg(pid), [identity()])).hosts
    g = nd.build_topology(identity(), hosts)
    ids = {n.id: n for n in g.nodes}
    assert {"self", "internet", "segment:192.168.1.0/24", "host:192.168.1.1", "host:192.168.1.9", "host:192.168.1.30"} <= set(ids)
    pairs = {(x.a, x.b) for x in g.edges}
    assert ("internet", "host:192.168.1.1") in pairs and ("self", "segment:192.168.1.0/24") in pairs
    assert ("host:192.168.1.9", "segment:192.168.1.0/24") in pairs
    assert not any("host:192.168.1.1" in (x.a, x.b) and any(o in (x.a, x.b) for o in ("host:192.168.1.9", "host:192.168.1.30")) for x in g.edges)
    stale = next(x for x in g.edges if x.a == "host:192.168.1.30")
    assert "neighbour cache" in stale.evidence and "not refreshed" in stale.evidence
    assert all(x.evidence for x in g.edges)                                 # every relationship states its evidence
    assert "do not show how devices are wired" in g.note
    no_route = nd.build_topology(identity(gateway=""), hosts)
    assert "internet" not in {n.id for n in no_route.nodes}                 # no default route: no Internet node
