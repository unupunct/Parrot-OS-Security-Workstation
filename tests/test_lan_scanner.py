import socket
import threading
from types import SimpleNamespace

import pytest

from wifi_center.services import lan_scanner as ls

NETS = [ls.LocalNet("enp2s0", "192.168.1.5", "192.168.1.0/24")]
ARP = ("IP address       HW type     Flags       HW address            Mask     Device\n"
       "192.168.1.1      0x1         0x2         aa:bb:cc:00:00:01     *        enp2s0\n"
       "192.168.1.20     0x1         0x2         11:22:33:44:55:66     *        enp2s0\n"
       "192.168.1.30     0x1         0x0         00:00:00:00:00:00     *        enp2s0\n")
ROUTE = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
         "enp2s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")


class FakeOui:
    def vendor(self, mac):
        return {"aa:bb:cc": "RouterCo"}.get(mac[:8])


def scanner(alive=("192.168.1.1", "192.168.1.5"), known=None):
    store = {} if known is None else known
    sc = ls.LanScanner(FakeOui(), known=lambda: store, save_known=lambda d: (store.clear(), store.update(d)),
                       pinger=lambda ip: 2.5 if ip in alive else None, resolver=lambda ip: {"192.168.1.1": "router.lan"}.get(ip, ""),
                       arp_reader=lambda: ARP, route_reader=lambda: ROUTE, port_check=lambda ip, p: p in (80, 22), workers=8)
    return sc, store


def test_target_validation_enforces_scope():
    ok = ls.validate_target("192.168.1.0/24", NETS)
    assert ok.num_addresses == 256 and str(ls.validate_target("192.168.1.0/25", NETS)) == "192.168.1.0/25"
    for bad, why in (("8.8.8.0/24", "private"), ("10.0.0.0/24", "directly attached"), ("192.168.0.0/16", "too large"),
                     ("not-a-net", "such as"), ("::1/128", "IPv4"), ("192.168.1.0/20", "too large")):
        with pytest.raises(ls.ScanError, match=why):
            ls.validate_target(bad, NETS)


def test_local_networks_filters_loopback_down_and_public():
    fam = SimpleNamespace(name="AF_INET")
    addrs = {"lo": [SimpleNamespace(family=fam, address="127.0.0.1", netmask="255.0.0.0")],
             "enp2s0": [SimpleNamespace(family=fam, address="192.168.1.5", netmask="255.255.255.0")],
             "wan0": [SimpleNamespace(family=fam, address="8.8.4.4", netmask="255.255.255.0")],
             "down0": [SimpleNamespace(family=fam, address="10.1.1.5", netmask="255.255.255.0")]}
    stats = {"lo": SimpleNamespace(isup=True), "enp2s0": SimpleNamespace(isup=True), "wan0": SimpleNamespace(isup=True),
             "down0": SimpleNamespace(isup=False)}
    assert [(n.iface, n.network) for n in ls.local_networks(addrs, stats)] == [("enp2s0", "192.168.1.0/24")]


def test_parsers():
    assert ls.parse_proc_arp(ARP) == {"192.168.1.1": ("aa:bb:cc:00:00:01", "enp2s0"), "192.168.1.20": ("11:22:33:44:55:66", "enp2s0")}
    assert ls.parse_default_gateway(ROUTE) == "192.168.1.1" and ls.parse_default_gateway("") is None
    assert ls.parse_ping_rtt("64 bytes from x: icmp_seq=1 ttl=64 time=0.412 ms") == 0.412 and ls.parse_ping_rtt("no") is None


def test_scan_finds_ping_and_arp_only_hosts_and_tags_them():
    sc, store = scanner()
    seen = []
    devs = sc.scan("192.168.1.0/24", NETS, progress=lambda d, t, f: seen.append((d, t, f)))
    by_ip = {d.ip: d for d in devs}
    assert set(by_ip) == {"192.168.1.1", "192.168.1.5", "192.168.1.20"}         # .20 answers ARP but not ping
    assert by_ip["192.168.1.1"].hostname == "router.lan" and by_ip["192.168.1.1"].vendor == "RouterCo"
    assert "gateway" in by_ip["192.168.1.1"].tags and "this computer" in by_ip["192.168.1.5"].tags
    assert by_ip["192.168.1.20"].rtt_ms is None and by_ip["192.168.1.20"].mac == "11:22:33:44:55:66"
    assert seen[-1] == (254, 254, 2) and [d.ip for d in devs] == sorted(by_ip, key=lambda i: tuple(map(int, i.split("."))))
    assert all("new" not in d.tags for d in devs)                               # the very first scan flags nothing as new
    assert set(store) == {"aa:bb:cc:00:00:01", "11:22:33:44:55:66"}


def test_new_devices_are_flagged_and_labels_kept():
    known = {"aa:bb:cc:00:00:01": {"label": "Router", "first": "2026-01-01T00:00:00+00:00"}}
    sc, store = scanner(known=known)
    devs = {d.ip: d for d in sc.scan("192.168.1.0/24", NETS)}
    assert devs["192.168.1.1"].label == "Router" and "new" not in devs["192.168.1.1"].tags
    assert "new" in devs["192.168.1.20"].tags
    sc.set_label("11:22:33:44:55:66", "  Printer  ")
    assert store["11:22:33:44:55:66"]["label"] == "Printer"


def test_cancel_and_port_check_scope_and_csv():
    sc, _ = scanner()
    ev = threading.Event()
    ev.set()
    assert sc.scan("192.168.1.0/24", NETS, cancel=ev) == []
    assert sc.check_ports("192.168.1.20", nets=NETS) == [(22, "ssh"), (80, "http")]
    with pytest.raises(ls.ScanError, match="own attached"):
        sc.check_ports("8.8.8.8", nets=NETS)
    csv = ls.to_csv([ls.Device("192.168.1.1", "aa:bb:cc:00:00:01", 'my "router"', "RouterCo", 2.5, ["gateway"])])
    assert csv.splitlines()[0].startswith("ip,hostname") and '"my ""router"""' in csv


def test_lan_page_scans_filters_and_saves_names(qapp, controller):
    import time

    from wifi_center.ui.pages.lan_scanner_page import LanScannerPage

    sc, store = scanner()
    sc.networks = lambda: NETS
    controller.lan = sc
    page = LanScannerPage(controller)
    assert page.net.count() == 1 and page.b_scan.isEnabled()
    page.scan()
    end = time.time() + 8
    while time.time() < end and not page.devices:
        qapp.processEvents()
        time.sleep(0.02)
    assert page.table.rowCount() == 3 and "3 device(s) found" in page.summary.text()
    page.search.setText("router")
    assert page.table.rowCount() == 1 and page.table.item(0, 1).text() == "192.168.1.1"
    page.table.selectRow(0)
    assert page.b_save.isEnabled() and page.b_ports.isEnabled()
    page.label.setText("Main router")
    page._save_label()
    assert store["aa:bb:cc:00:00:01"]["label"] == "Main router" and page.table.item(0, 2).text() == "Main router"
    assert page.b_scan.isEnabled()
