import threading
from types import SimpleNamespace

import pytest

from wifi_center.bluetooth import adapter as ad
from wifi_center.bluetooth import registry as reg
from wifi_center.bluetooth.fake import FakeBluez
from wifi_center.bluetooth.models import BluetoothError, DeviceInfo, address_kind, device_from_props, validate_address
from wifi_center.bluetooth.scanner import STALE_AFTER_S, BluetoothScanner, RssiTracker

NL = chr(10)
TAB = chr(9)
BTMGMT = NL.join(["hci1:" + TAB + "Primary controller", TAB + "addr 04:42:1A:5A:2B:DC version 10 manufacturer 93 class 0x6c0104",
                  TAB + "supported settings: powered connectable discoverable bondable ssp br/edr le advertising secure-conn privacy wide-band-speech ",
                  TAB + "current settings: powered bondable ssp br/edr le secure-conn ", TAB + "name parrot #2", TAB + "short name ", ""])
HCICONFIG = NL.join(["hci1:" + TAB + "Type: Primary  Bus: USB", TAB + "BD Address: 04:42:1A:5A:2B:DC  ACL MTU: 1021:6  SCO MTU: 255:12",
                     TAB + "UP RUNNING ", TAB + "RX bytes:15035 acl:0 sco:0 events:286 errors:0", TAB + "TX bytes:34802 acl:0 sco:0 commands:209 errors:0",
                     TAB + "Features: 0xff 0xff 0xff 0xfe 0xdb 0xfd 0x7b 0x87", TAB + "Link policy: RSWITCH HOLD SNIFF PARK ",
                     TAB + "Device Class: Computer, Desktop workstation", TAB + "HCI Version: 5.1 (0xa)  Revision: 0xdfc6",
                     TAB + "LMP Version: 5.1 (0xa)  Subversion: 0xd922", TAB + "Manufacturer: Realtek Semiconductor Corporation (93)", ""])


# ---------------------------------------------------------------- registry and models
def test_registry_names_and_decoding():
    assert reg.uuid16("0000180f-0000-1000-8000-00805f9b34fb") == 0x180F and reg.uuid16("12345678-1234-1234-1234-123456789abc") is None
    assert reg.service_name("0000180f-0000-1000-8000-00805f9b34fb") == "Battery"
    assert reg.service_name("0000110b-0000-1000-8000-00805f9b34fb") == "Audio Sink (A2DP)"
    assert reg.service_name("12345678-1234-1234-1234-123456789abc") == "Custom (vendor-specific) UUID"
    assert reg.service_name("0000ffff-0000-1000-8000-00805f9b34fb") == "Unknown standard UUID"
    assert reg.characteristic_name("00002a19-0000-1000-8000-00805f9b34fb") == "Battery Level"
    assert reg.company_name(0x004C) == "Apple, Inc." and reg.company_name(0x0BAD) == "company 0x0BAD" and reg.company_name(93) == "Realtek Semiconductor"
    assert reg.class_of_device(533564) == "Audio/Video / Video display and loudspeaker"
    assert reg.class_of_device(0x7A020C) == "Phone / Smartphone" and reg.class_of_device(0x002540) == "Peripheral / Keyboard"
    assert reg.appearance_name(0x03C1) == "Input device (HID)" and reg.hci_version(10) == "5.1"


def test_device_model_infers_technology_type_and_address_privacy():
    classic = device_from_props("/p", {"Address": "20:28:BC:6F:8D:57", "Alias": "TV", "AddressType": "public", "Class": 533564, "RSSI": -68, "UUIDs": ["0000110b-0000-1000-8000-00805f9b34fb"]})
    assert classic.technology == "Classic" and classic.device_type.startswith("Audio/Video") and classic.signal_quality == "fair"
    ble = device_from_props("/p", {"Address": "5A:11:22:33:44:55", "Alias": "5A-11-22-33-44-55", "AddressType": "random", "ManufacturerData": {0x004C: b"\x01\x02"}})
    assert ble.technology == "BLE" and ble.display_name == "" and ble.manufacturer == "Apple, Inc." and ble.address_privacy == "resolvable-private"
    dual = device_from_props("/p", {"Address": "AA:BB:CC:00:00:01", "AddressType": "public", "Class": 0x200404, "Appearance": 0x0040})
    assert dual.technology == "Dual Mode" and device_from_props("/p", {"Address": "AA:BB:CC:00:00:02"}).technology == "Unknown"
    assert address_kind("C1:00:00:00:00:00", "random") == "random-static" and address_kind("01:00:00:00:00:00", "random") == "non-resolvable-private"
    assert address_kind("AA:BB:CC:00:00:01", "public") == "public"
    a = device_from_props("/p", {"Address": "AA:BB:CC:00:00:01", "UUIDs": ["b"], "ManufacturerData": {1: b"x"}})
    b = device_from_props("/p", {"Address": "AA:BB:CC:00:00:01", "UUIDs": ["b"], "ManufacturerData": {1: b"y"}})
    assert a.adv_fingerprint() != b.adv_fingerprint()                       # a changed advertisement is noticed
    assert validate_address(" aa:bb:cc:dd:ee:ff ") == "AA:BB:CC:DD:EE:FF"
    for bad in ("", "AA:BB", "GG:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF"):
        with pytest.raises(ValueError):
            validate_address(bad)


# ---------------------------------------------------------------- adapter manager
def test_btmgmt_and_hciconfig_parsers():
    m = ad.parse_btmgmt_info(BTMGMT)
    assert (m["addr"], m["version"], m["manufacturer"], m["name"]) == ("04:42:1A:5A:2B:DC", 10, 93, "parrot #2")
    assert "le" in m["supported"] and "br/edr" in m["current"] and "advertising" not in m["current"]
    h = ad.parse_hciconfig(HCICONFIG)
    assert (h["bus"], h["state"], h["hci_version"], h["manufacturer"]) == ("USB", "up", "5.1", "Realtek Semiconductor Corporation")
    caps = ad.decode_lmp_features(h["features"])
    assert {"LE (controller)", "EDR 2 Mb/s", "EDR 3 Mb/s", "Secure Simple Pairing", "Encryption"} <= set(caps)
    assert ad.parse_btmgmt_info("") == {"supported": [], "current": []} and ad.parse_hciconfig("") == {}


def make_manager(tmp_path, bt=None, with_tools=True):
    bt = bt or FakeBluez()
    path = bt.add_adapter("hci1", "04:42:1A:5A:2B:DC")
    sysfs = tmp_path / "class" / "bluetooth"
    (sysfs / "hci1").mkdir(parents=True)

    def run(argv, t):
        text = {"btmgmt": BTMGMT, "hciconfig": HCICONFIG, "rfkill": "8: hci1: Bluetooth" + NL + TAB + "Soft blocked: no"}[argv[0]]
        return SimpleNamespace(ok=True, stdout=text)

    class M(ad.BluetoothAdapterManager):
        def _sysfs_info(self, a):                                     # the real sysfs layout uses symlinks; the fake tree is flat
            a.driver, a.usb_id, a.usb_name = "btusb", "0b05:190e", "ASUS USB Bluetooth Adapter"
    return M(bt, run, sysfs, which=lambda n: "/usr/bin/" + n if with_tools else None, mgmt=lambda i: BTMGMT if with_tools else ""), bt, path


def test_adapter_list_combines_bluez_btmgmt_hciconfig_and_usb(tmp_path):
    mgr, bt, path = make_manager(tmp_path)
    (a,) = mgr.list()
    assert (a.name, a.address, a.powered, a.alias) == ("hci1", "04:42:1A:5A:2B:DC", True, "test-host")
    assert a.classic is True and a.ble is True and a.hci_version == "5.1" and a.manufacturer.startswith("Realtek")
    assert (a.driver, a.usb_id, a.bus) == ("btusb", "0b05:190e", "USB") and "Encryption" in a.lmp_features and "Soft blocked: no" in a.rfkill
    assert mgr.get("hci1").path == path
    with pytest.raises(BluetoothError):
        mgr.get("hci9")
    bare, _, _ = make_manager(tmp_path / "x", with_tools=False)
    (b,) = bare.list()
    assert b.classic is None and b.ble is None and b.manufacturer == ""                    # no tools: unknown stays unknown, never guessed
    solo = ad.BluetoothAdapterManager(bt, lambda argv, t: SimpleNamespace(ok=True, stdout=HCICONFIG if argv[0] == "hciconfig" else ""),
                                      tmp_path, which=lambda n: "/usr/bin/" + n, mgmt=lambda i: "")
    (c,) = solo.list()
    assert c.classic is True and c.ble is True and "ssp" in c.supported_settings            # derived from the LMP feature bits when btmgmt is missing
    bt.up = False
    with pytest.raises(BluetoothError, match="not running"):
        mgr.list()


def test_power_off_is_refused_while_devices_are_connected(tmp_path):
    mgr, bt, path = make_manager(tmp_path)
    with pytest.raises(BluetoothError, match="connected through this adapter"):
        mgr.set_powered(path, False, active_connections=1)
    assert bt.adapters[path]["Powered"] is True
    mgr.set_powered(path, False)
    assert bt.adapters[path]["Powered"] is False
    mgr.set_powered(path, True)
    assert bt.adapters[path]["Powered"] is True


# ---------------------------------------------------------------- scanner
class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def scene():
    bt = FakeBluez()
    path = bt.add_adapter("hci1")
    bt.add_device(path, "AA:BB:CC:00:00:01", Alias="Speaker", Class=0x240414, RSSI=-50, AddressType="public")
    bt.reveal = [(2, path, {"Address": "5A:11:22:33:44:55", "AddressType": "random", "RSSI": -70, "ManufacturerData": {0x004C: b"\x10"}}),
                 (5, path, {"Address": "AA:BB:CC:00:00:03", "Alias": "Late", "RSSI": -85, "AddressType": "public", "Class": 0x5A020C})]
    bt.rssi_script["AA:BB:CC:00:00:01"] = lambda tick: -50 - (tick % 4)
    return bt, path


def test_scan_uses_the_transport_filter_reports_progress_and_always_stops():
    bt, path = scene()
    clock = Clock()
    sc = BluetoothScanner(bt, clock, clock.sleep)
    updates = []
    res = sc.scan(path, "ble", 8, on_update=lambda ds: updates.append(len(ds)))
    assert bt.adapters[path]["_filter"] == {"Transport": "le", "DuplicateData": True}
    assert bt.adapters[path]["Discovering"] is False and ("StopDiscovery" in [c[2] for c in bt.calls if len(c) == 4])
    assert {d.address for d in res.devices} == {"AA:BB:CC:00:00:01", "5A:11:22:33:44:55", "AA:BB:CC:00:00:03"} and res.found == 3
    assert updates[0] < updates[-1] and res.duration_s >= 8                           # devices appear while scanning
    assert [d.rssi is None for d in res.devices].count(True) == 0 and res.devices[0].rssi >= res.devices[-1].rssi    # strongest first


def test_scan_modes_validation_and_cancel():
    bt, path = scene()
    clock = Clock()
    sc = BluetoothScanner(bt, clock, clock.sleep)
    assert sc.scan(path, "classic", 3).mode == "classic" and bt.adapters[path]["_filter"]["Transport"] == "bredr"
    assert sc.scan(path, "both", 3) and bt.adapters[path]["_filter"]["Transport"] == "auto"
    with pytest.raises(BluetoothError, match="does not support Classic"):
        sc.scan(path, "classic", 3, supports_classic=False)
    with pytest.raises(BluetoothError, match="does not support Bluetooth Low Energy"):
        sc.scan(path, "ble", 3, supports_ble=False)
    with pytest.raises(BluetoothError, match="unknown scan mode"):
        sc.scan(path, "wifi", 3)
    ev = threading.Event()
    ev.set()
    res = sc.scan(path, "both", 60, cancel=ev)
    assert res.cancelled and bt.adapters[path]["Discovering"] is False                  # stopped even when cancelled
    bt.adapters[path]["Powered"] = False
    with pytest.raises(BluetoothError, match="powered off"):
        sc.scan(path, "both", 3)
    bt.adapters[path]["Powered"] = True
    bt.adapters[path]["Discovering"] = True
    with pytest.raises(BluetoothError, match="already running"):
        sc.scan(path, "both", 3)


def test_a_failure_while_scanning_still_stops_discovery():
    bt, path = scene()
    clock = Clock()
    sc = BluetoothScanner(bt, clock, clock.sleep)

    def boom(ds):
        raise RuntimeError("ui crashed")
    with pytest.raises(RuntimeError):
        sc.scan(path, "both", 5, on_update=boom)
    assert bt.adapters[path]["Discovering"] is False


def test_rssi_staleness_is_flagged_only_when_the_value_stops_changing():
    clock = Clock()
    tr = RssiTracker(clock)
    d = DeviceInfo("/p", "AA:BB:CC:00:00:01", rssi=-60)
    tr.update(d)
    clock.t = STALE_AFTER_S - 1
    tr.update(d)
    assert not tr.is_stale(d) and tr.age(d) == STALE_AFTER_S - 1
    clock.t = STALE_AFTER_S + 5
    tr.update(d)
    assert tr.is_stale(d)                                      # same value for too long: possibly stale
    d.rssi = -61
    tr.update(d)
    assert not tr.is_stale(d)
    none = DeviceInfo("/p", "AA:BB:CC:00:00:02")
    tr.update(none)
    assert tr.age(none) is None and not tr.is_stale(none)      # no RSSI: unavailable, not stale
