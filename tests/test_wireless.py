import json
import sqlite3

import pytest

from wifi_center.database.repository import Database
from wifi_center.security.input_validation import ValidationError
from wifi_center.services import kismet_service as ks
from wifi_center.services.bluetooth_service import (BluetoothService, parse_devices, parse_info, parse_show)
from wifi_center.services.oui import OuiLookup, normalise_prefix
from wifi_center.services.packet_service import (PacketService, analyze_lines, leaf_protocol, parse_capinfos,
                                                 validate_capture_path)
from wifi_center.services.wireless_service import (AccessPoint, WirelessService, band_of, freq_to_channel,
                                                   parse_iw_scan_dump, parse_nmcli, pct_to_dbm, split_terse)

NMCLI = r"""AA\:BB\:CC\:DD\:EE\:01:HomeNet:6:2437 MHz:78:WPA2
AA\:BB\:CC\:DD\:EE\:02:Cafe\: Guest:36:5180 MHz:41:WPA1 WPA2
AA\:BB\:CC\:DD\:EE\:03::11:2462 MHz:20:--
AA\:BB\:CC\:DD\:EE\:04:Corp:149:5745 MHz:60:WPA2 802.1X
AA\:BB\:CC\:DD\:EE\:05:New:1:2412 MHz:90:WPA3
"""

IW_DUMP = """BSS aa:bb:cc:dd:ee:10(on wlan0) -- associated
\tTSF: 1 usec
\tfreq: 2437
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -48.00 dBm
\tSSID: Lab
\tDS Parameter set: channel 6
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Authentication suites: PSK
BSS aa:bb:cc:dd:ee:11(on wlan0)
\tfreq: 5180
\tcapability: ESS Privacy (0x0411)
\tsignal: -70.00 dBm
\tSSID: Secure
\tRSN:\t * Version: 1
\t\t * Authentication suites: SAE
BSS aa:bb:cc:dd:ee:12(on wlan0)
\tfreq: 2412
\tcapability: ESS (0x0401)
\tsignal: -80.00 dBm
\tSSID: Open
BSS aa:bb:cc:dd:ee:13(on wlan0)
\tfreq: 2412
\tcapability: ESS Privacy (0x0411)
\tsignal: -60.00 dBm
\tSSID: OldWep
"""


# ---------- scan parsing ----------
def test_split_terse_handles_escapes():
    assert split_terse(r"AA\:BB:x\\y:z") == ["AA:BB", "x\\y", "z"]
    assert split_terse("a::c") == ["a", "", "c"]


def test_parse_nmcli():
    aps = parse_nmcli(NMCLI)
    assert len(aps) == 5
    a = aps[0]
    assert (a.bssid, a.ssid, a.channel, a.frequency_mhz, a.signal_pct) == ("AA:BB:CC:DD:EE:01", "HomeNet", 6, 2437, 78.0)
    assert a.signal_dbm == pct_to_dbm(78) == -61.0 and a.encryption == "WPA2" and a.band == "2.4 GHz"
    assert aps[1].ssid == "Cafe: Guest" and aps[1].band == "5 GHz"
    assert aps[2].ssid == "" and aps[2].encryption == "Open"
    assert aps[3].auth == "802.1X" and aps[4].auth == "SAE"


def test_parse_nmcli_ignores_garbage():
    assert parse_nmcli("\nonly:two\n") == []


def test_parse_iw_scan_dump():
    aps = {a.ssid: a for a in parse_iw_scan_dump(IW_DUMP)}
    assert aps["Lab"].encryption == "WPA2" and aps["Lab"].channel == 6 and aps["Lab"].signal_dbm == -48.0
    assert aps["Secure"].encryption == "WPA3" and aps["Secure"].auth == "SAE" and aps["Secure"].channel == 36
    assert aps["Open"].encryption == "Open"
    assert aps["OldWep"].encryption == "WEP"


@pytest.mark.parametrize("freq,chan", [(2412, 1), (2437, 6), (2472, 13), (2484, 14), (5180, 36), (5745, 149),
                                       (5955, 1), (1000, None), (None, None)])
def test_freq_to_channel(freq, chan):
    assert freq_to_channel(freq) == chan


def test_band_of():
    assert [band_of(f) for f in (2412, 5180, 6000, None)] == ["2.4 GHz", "5 GHz", "6 GHz", "?"]


# ---------- persistence / history / export ----------
@pytest.fixture
def wsvc():
    return WirelessService(Database(":memory:"), OuiLookup(()))


def ap(bssid="AA:BB:CC:DD:EE:01", ssid="Net", sig=-50.0, ch=6, freq=2437, enc="WPA2"):
    return AccessPoint(bssid, ssid, ch, freq, sig, None, enc)


def test_record_upserts_and_keeps_history(wsvc):
    wsvc.record([ap(sig=-50)])
    wsvc.record([ap(sig=-60)])
    rows = wsvc.observations()
    assert len(rows) == 1 and rows[0]["signal_dbm"] == -60 and rows[0]["first_seen"] <= rows[0]["last_seen"]
    h = wsvc.history(rows[0]["id"])
    assert [s["signal_dbm"] for s in h] == [-50, -60]


def test_same_bssid_different_ssid_and_hidden_ssid_are_distinct(wsvc):
    wsvc.record([ap(ssid="A"), ap(ssid="B"), ap(ssid="")])
    wsvc.record([ap(ssid="")])
    assert len(wsvc.observations()) == 3


def test_export_csv_json_and_formula_injection(wsvc):
    wsvc.record([ap(ssid='=HYPERLINK("http://x")'), ap(bssid="AA:BB:CC:DD:EE:02", ssid="ok,name")])
    rows = wsvc.observations()
    csv_text = wsvc.export(rows, "csv")
    assert "'=HYPERLINK" in csv_text and '"ok,name"' in csv_text
    data = json.loads(wsvc.export(rows, "json"))
    assert len(data) == 2 and set(data[0]) == set(WirelessService.COLUMNS)
    with pytest.raises(ValueError):
        wsvc.export(rows, "xml")


def test_scan_errors_are_readable(wsvc, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    from wifi_center.services.wireless_service import ScanError
    with pytest.raises(ScanError, match="No scan method"):
        wsvc.scan("wlan0")


# ---------- OUI ----------
def test_oui_formats(tmp_path):
    ieee = tmp_path / "oui.txt"
    ieee.write_text("AA-BB-CC   (hex)\t\tAcme Corp\nAABBCC     (base 16)\t\tAcme Corp\n")
    assert OuiLookup((ieee,)).vendor("aa:bb:cc:01:02:03") == "Acme Corp"
    nmap = tmp_path / "nmap-mac-prefixes"
    nmap.write_text("# comment\n112233 Widgets Inc\n")
    o = OuiLookup((nmap,))
    assert o.vendor("11-22-33-44-55-66") == "Widgets Inc" and o.vendor("00:00:00:00:00:00") is None
    manuf = tmp_path / "manuf"
    manuf.write_text("# x\n44:55:66\tShortName\tLong Name Ltd\n")
    assert OuiLookup((manuf,)).vendor("445566aabbcc") == "Long Name Ltd"
    assert not OuiLookup((tmp_path / "none",)).available
    assert normalise_prefix("zz") is None


# ---------- Kismet ----------
DEVICE = {"kismet.device.base.macaddr": "aa:bb:cc:00:00:01", "kismet.device.base.name": "KisNet",
          "kismet.device.base.type": "Wi-Fi AP", "kismet.device.base.phyname": "IEEE802.11",
          "kismet.device.base.channel": "11", "kismet.device.base.frequency": 2462000,
          "kismet.device.base.crypt": "WPA2-PSK", "kismet.device.base.manuf": "Acme",
          "kismet.device.base.first_time": 100, "kismet.device.base.last_time": 200,
          "kismet.device.base.signal": {"kismet.common.signal.last_signal": -55}}


def test_kismet_parse_device_and_ap_conversion():
    d = ks.parse_devices([DEVICE, {"junk": 1}, "x"])
    assert len(d) == 1 and d[0].is_wifi_ap and d[0].signal_dbm == -55 and d[0].frequency_mhz == 2462
    a = ks.to_access_point(d[0])
    assert (a.bssid, a.ssid, a.channel, a.encryption) == ("AA:BB:CC:00:00:01", "KisNet", 11, "WPA2-PSK")


def test_kismet_alerts_parse():
    out = ks.parse_alerts([{"kismet.alert.header": "DEAUTHFLOOD", "kismet.alert.text": "x",
                            "kismet.alert.severity": 10}, 5])
    assert len(out) == 1 and out[0].header == "DEAUTHFLOOD" and out[0].severity == 10


@pytest.mark.parametrize("url", ["http://127.0.0.1:2501", "http://localhost:2501", "https://[::1]:2501"])
def test_kismet_accepts_loopback(url):
    assert ks.validate_loopback_url(url)


@pytest.mark.parametrize("url", ["http://192.168.1.5:2501", "http://example.com", "ftp://127.0.0.1", "127.0.0.1",
                                 "http://10.0.0.1"])
def test_kismet_rejects_non_loopback(url):
    with pytest.raises(ValidationError):
        ks.validate_loopback_url(url)


def test_kismet_client_unreachable_is_readable():
    c = ks.KismetClient("http://127.0.0.1:1")
    with pytest.raises(ks.KismetError, match="cannot reach"):
        c.status()


def make_kismet_log(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE devices (devmac TEXT, device BLOB)")
    conn.execute("INSERT INTO devices VALUES (?, ?)", ("a", json.dumps(DEVICE).encode()))
    conn.execute("INSERT INTO devices VALUES (?, ?)", ("b", b"not json"))
    conn.commit()
    conn.close()


def test_read_kismet_log_readonly(tmp_path):
    p = tmp_path / "x.kismet"
    make_kismet_log(p)
    devs = ks.read_kismet_log(p)
    assert len(devs) == 1 and devs[0].name == "KisNet"
    (tmp_path / "bad.kismet").write_text("nope")
    with pytest.raises(ks.KismetError):
        ks.read_kismet_log(tmp_path / "bad.kismet")
    with pytest.raises(ks.KismetError):
        ks.read_kismet_log(tmp_path / "x.txt")


def test_log_listing_and_safe_delete(tmp_path):
    for n in ("a.kismet", "b.pcapng", "notes.txt"):
        (tmp_path / n).write_text("x")
    names = {l["name"] for l in ks.list_logs(tmp_path)}
    assert names == {"a.kismet", "b.pcapng"}
    ks.delete_log(tmp_path, "a.kismet")
    assert not (tmp_path / "a.kismet").exists()
    for bad in ("notes.txt", "../escape.kismet", "sub/a.kismet"):
        with pytest.raises(ValidationError):
            ks.delete_log(tmp_path, bad)
    assert (tmp_path / "notes.txt").exists()


# ---------- packets ----------
TSV = "\n".join([
    "1000.0\t100\t10.0.0.1\t10.0.0.2\t\t\teth:ethertype:ip:tcp:tls",
    "1000.5\t200\t10.0.0.2\t10.0.0.1\t\t\teth:ethertype:ip:tcp",
    "1001.2\t60\t\t\tfe80::1\tfe80::2\teth:ethertype:ipv6:icmpv6",
    "1003.0\t50\t\t\t\t\teth:arp",
    "garbage",
    "x\ty",
])


def test_analyze_lines():
    a = analyze_lines(TSV.splitlines())
    assert a.packets == 4 and a.total_bytes == 410 and a.duration == pytest.approx(3.0)
    assert a.protocols == {"tls": 1, "tcp": 1, "icmpv6": 1, "arp": 1}
    top = a.top_conversations()
    assert top[0] == ("10.0.0.1", "10.0.0.2", 2, 300)
    assert a.timeline[0] == [2, 300] and a.timeline[1] == [1, 60] and a.timeline[3] == [1, 50]


def test_analyze_truncation_and_empty():
    a = analyze_lines(TSV.splitlines(), max_packets=2)
    assert a.packets == 2 and a.truncated
    e = analyze_lines([])
    assert e.packets == 0 and e.duration == 0.0 and e.timeline == {}


def test_leaf_protocol():
    assert leaf_protocol("eth:ethertype:ip:udp:dns") == "dns"
    assert leaf_protocol("eth:ethertype:ip:tcp:data") == "tcp"
    assert leaf_protocol("") == "unknown"


def test_capture_path_validation(tmp_path):
    f = tmp_path / "a.pcapng"
    f.write_bytes(b"x")
    assert validate_capture_path(str(f)) == f
    (tmp_path / "a.txt").write_text("x")
    for bad in (str(tmp_path / "a.txt"), "relative.pcap", str(tmp_path / "missing.pcap"), "-r"):
        with pytest.raises(ValidationError):
            validate_capture_path(bad)


def test_parse_capinfos():
    md = parse_capinfos("File name:           x.pcap\nFile type:           Wireshark/... - pcapng\n"
                        "Number of packets:   42\nstray line\n")
    assert md.values["Number of packets"] == "42" and md.values["File type"].endswith("pcapng")


def test_analyze_without_tshark(monkeypatch, tmp_path):
    from wifi_center.services.packet_service import PacketError
    f = tmp_path / "a.pcap"
    f.write_bytes(b"x")
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(PacketError, match="not installed"):
        PacketService().analyze(str(f))


# ---------- bluetooth ----------
SHOW = """Controller AA:BB:CC:DD:EE:FF (public)
\tName: host
\tAlias: workstation
\tPowered: yes
\tDiscoverable: no
\tPairable: yes
"""


def test_bluetooth_parsers():
    c = parse_show(SHOW)
    assert c.address == "AA:BB:CC:DD:EE:FF" and c.name == "workstation" and c.powered and not c.discoverable
    assert parse_show("No default controller available") is None
    devs = parse_devices("Device 11:22:33:44:55:66 Speaker\n[NEW] Device 66:55:44:33:22:11 \nnoise")
    assert [(d.address, d.name) for d in devs] == [("11:22:33:44:55:66", "Speaker"), ("66:55:44:33:22:11", "")]
    d = parse_info("Device 11:22:33:44:55:66 (public)\n\tAlias: Speaker\n\tPaired: yes\n\tConnected: no\n"
                   "\tRSSI: 0xffffffc4 (-60)\n", "11:22:33:44:55:66")
    assert d.name == "Speaker" and d.paired and d.connected is False and d.rssi == -60


def test_bluetooth_import_validates_and_dedupes():
    svc = BluetoothService(Database(":memory:"))
    n = svc.import_csv("address,name\n11:22:33:44:55:66,Speaker\nnot-a-mac,x\n11:22:33:44:55:66,Speaker2\n\n")
    assert n == 2
    rows = svc.stored()
    assert len(rows) == 1 and rows[0]["name"] == "Speaker2"


def test_bluetooth_without_hardware(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    svc = BluetoothService(Database(":memory:"), tmp_path / "none")
    assert svc.adapters() == [] and svc.controller() is None and svc.known_devices() == []
    with pytest.raises(RuntimeError):
        svc.discover()
