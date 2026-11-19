import json
from types import SimpleNamespace

from wifi_center.services import net_identity as ni

ADDR = json.dumps([
    {"ifname": "lo", "operstate": "UNKNOWN", "link_type": "loopback", "mtu": 65536, "address": "00:00:00:00:00:00",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
    {"ifname": "enp2s0", "operstate": "UP", "link_type": "ether", "mtu": 1500, "address": "AA:00:00:00:00:01",
     "addr_info": [{"family": "inet", "local": "192.168.1.26", "prefixlen": 24, "scope": "global"},
                   {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]},
    {"ifname": "wlp3s0", "operstate": "UP", "link_type": "ether", "mtu": 1500, "address": "aa:00:00:00:00:02",
     "addr_info": [{"family": "inet", "local": "10.20.30.77", "prefixlen": 22, "scope": "global"}]},
    {"ifname": "virbr0", "operstate": "DOWN", "link_type": "ether", "mtu": 1500, "address": "aa:00:00:00:00:03",
     "addr_info": [{"family": "inet", "local": "192.168.122.1", "prefixlen": 24, "scope": "global"}]},
    {"ifname": "wlx1", "operstate": "DOWN", "link_type": "ether", "mtu": 1500, "address": "aa:00:00:00:00:04", "addr_info": []}])
ROUTE = json.dumps([
    {"dst": "default", "gateway": "192.168.1.1", "dev": "enp2s0", "metric": 100, "prefsrc": "192.168.1.26", "flags": []},
    {"dst": "default", "gateway": "192.168.1.254", "dev": "enp2s0", "metric": 700, "flags": []},
    {"dst": "192.168.1.0/24", "dev": "enp2s0", "scope": "link", "flags": []},
    {"dst": "192.168.122.0/24", "dev": "virbr0", "scope": "link", "flags": ["linkdown"]}])
NEIGH = json.dumps([
    {"dst": "192.168.1.1", "dev": "enp2s0", "lladdr": "f4:b1:c2:ba:ed:60", "state": ["REACHABLE"]},
    {"dst": "192.168.1.30", "dev": "enp2s0", "state": ["FAILED"]},
    {"dst": "fe80::2", "dev": "enp2s0", "lladdr": "aa:bb:cc:dd:ee:ff", "state": ["STALE"]}])
RESOLVECTL = """Global
       Protocols: -LLMNR
Link 2 (enp2s0)
    Current Scopes: DNS
  Current DNS Server: 192.168.1.1
         DNS Servers: 192.168.1.1 8.8.8.8
Link 3 (wlp3s0)
         DNS Servers: 10.20.30.1
"""


def test_interfaces_use_the_real_prefix_length_and_classify():
    itfs = {i.name: i for i in ni.parse_ip_address(ADDR, {"wlp3s0", "wlx1"})}
    assert itfs["enp2s0"].kind == "ethernet" and itfs["wlp3s0"].kind == "wifi" and itfs["virbr0"].kind == "virtual"
    assert itfs["lo"].kind == "loopback" and itfs["enp2s0"].state == "up" and itfs["virbr0"].state == "down"
    a = itfs["wlp3s0"].v4[0]
    assert a.network == "10.20.28.0/22" and a.usable_hosts == 1022           # a /22, not assumed to be a /24
    assert itfs["enp2s0"].v4[0].network == "192.168.1.0/24" and itfs["enp2s0"].v4[0].usable_hosts == 254
    assert itfs["enp2s0"].v6[0].network == "fe80::/64"
    assert ni.AddrV4("10.0.0.5", 31).usable_hosts == 2 and ni.AddrV4("10.0.0.5", 32).usable_hosts == 1


def test_routes_neighbors_and_dns_parsers():
    routes = ni.parse_ip_route(ROUTE)
    assert routes[0].gateway == "192.168.1.1" and routes[3].linkdown
    neigh = ni.parse_ip_neigh(NEIGH)
    assert [(n.ip, n.family, n.usable) for n in neigh] == [("192.168.1.1", 4, True), ("192.168.1.30", 4, False), ("fe80::2", 6, True)]
    assert ni.parse_resolvectl(RESOLVECTL) == {"global": [], "enp2s0": ["192.168.1.1", "8.8.8.8"], "wlp3s0": ["10.20.30.1"]}
    assert ni.parse_resolv_conf("# x" + chr(10) + "nameserver 1.1.1.1" + chr(10) + "nameserver 9.9.9.9") == ["1.1.1.1", "9.9.9.9"]
    assert ni.parse_ip_address("not json") == [] and ni.parse_ip_route("") == [] and ni.parse_ip_neigh("{}") == []


def test_identify_networks_picks_gateway_by_lowest_metric_and_skips_unusable_interfaces():
    itfs = ni.parse_ip_address(ADDR, {"wlp3s0"})
    ids = ni.identify_networks(itfs, ni.parse_ip_route(ROUTE), ni.parse_ip_neigh(NEIGH), ni.parse_resolvectl(RESOLVECTL), ["9.9.9.9"])
    assert [i.interface.name for i in ids] == ["enp2s0", "wlp3s0"]              # lo, DOWN virbr0 and address-less wlx1 are skipped
    eth, wifi = ids
    assert eth.gateway == "192.168.1.1" and eth.gateway_mac == "f4:b1:c2:ba:ed:60" and eth.cidr == "192.168.1.0/24"
    assert eth.dns == ["192.168.1.1", "8.8.8.8"] and eth.default_route
    assert wifi.gateway == "" and not wifi.default_route and wifi.dns == ["10.20.30.1"] and wifi.cidr == "10.20.28.0/22"


def test_identifier_runs_the_commands_and_tolerates_missing_tools(tmp_path):
    out = {"address": ADDR, "route": ROUTE, "neigh": NEIGH, "status": RESOLVECTL}
    seen = []

    def run(argv, t):
        seen.append(argv)
        return SimpleNamespace(ok=True, stdout=out[argv[-1]])
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 9.9.9.9")
    idf = ni.NetworkIdentifier(run, which=lambda n: "/usr/bin/" + n, resolv_conf=resolv, wireless=lambda: {"wlp3s0"})
    assert [i.interface.name for i in idf.identify()] == ["enp2s0", "wlp3s0"] and ["ip", "-j", "address"] in seen
    bare = ni.NetworkIdentifier(run, which=lambda n: None, resolv_conf=tmp_path / "missing", wireless=lambda: set())
    assert bare.identify() == [] and bare.dns() == ({}, [])
