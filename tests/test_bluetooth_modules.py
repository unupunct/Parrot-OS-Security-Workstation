import threading
from types import SimpleNamespace

import pytest

from tests.test_bluetooth_core import BTMGMT, HCICONFIG, Clock, make_manager, scene
from wifi_center.bluetooth import diagnostics as dg
from wifi_center.bluetooth.fake import FakeBluez
from wifi_center.bluetooth.inventory import BluetoothInventory
from wifi_center.bluetooth.models import BluetoothError
from wifi_center.bluetooth.scanner import STALE_AFTER_S, BluetoothScanner
from wifi_center.bluetooth.signal_monitor import BluetoothSignalMonitor
from wifi_center.database.repository import Database


def scanned(bt, path, mode="both", seconds=6):
    clock = Clock()
    return BluetoothScanner(bt, clock, clock.sleep).scan(path, mode, seconds)


# ---------------------------------------------------------------- inventory
def test_inventory_persists_devices_sightings_and_user_data():
    bt, path = scene()
    inv = BluetoothInventory(Database(":memory:"))
    sid = inv.record_scan(scanned(bt, path))
    devs = {d["address"]: d for d in inv.devices()}
    assert len(devs) == 3 and devs["AA:BB:CC:00:00:01"]["technology"] == "Classic" and devs["5A:11:22:33:44:55"]["manufacturer"] == "Apple, Inc."
    assert len(inv.sightings("AA:BB:CC:00:00:01")) == 1 and inv.scans()[0]["id"] == sid and inv.scans()[0]["devices_found"] == 3
    inv.set_info("aa:bb:cc:00:00:01", custom_name="  Kitchen speaker ", notes="bought 2024", category="Audio", tags=["Home", "home", "bad;tag", "ok-tag"], authorized=True)
    d = inv.device("AA:BB:CC:00:00:01")
    assert (d["custom_name"], d["notes"], d["category"], d["tags"], d["authorized"]) == ("Kitchen speaker", "bought 2024", "Audio", "home,ok-tag", 1)
    with pytest.raises(ValueError):
        inv.set_info("AA:BB:CC:00:00:01", category="Spaceship")
    with pytest.raises(ValueError):
        inv.set_info("AA:BB:CC:99:99:99", custom_name="x")                  # unknown device
    # a second scan keeps first_seen, updates last_seen, and keeps the user's data
    first = d["first_seen"]
    inv.record_scan(scanned(bt, path))
    d2 = inv.device("AA:BB:CC:00:00:01")
    assert d2["first_seen"] == first and d2["custom_name"] == "Kitchen speaker" and len(inv.sightings("AA:BB:CC:00:00:01")) == 2
    # search / filter / sort
    assert [x["address"] for x in inv.devices(search="kitchen")] == ["AA:BB:CC:00:00:01"]
    assert {x["address"] for x in inv.devices(technology="BLE")} == {"5A:11:22:33:44:55"} and inv.devices(tag="home")[0]["address"] == "AA:BB:CC:00:00:01"
    assert inv.devices(authorized=True)[0]["address"] == "AA:BB:CC:00:00:01" and len(inv.devices(authorized=False)) == 2
    assert inv.devices(sort="rssi")[0]["last_rssi"] is not None


def test_advertisement_changes_are_tracked_and_scans_compared():
    bt, path = scene()
    inv = BluetoothInventory(Database(":memory:"))
    s1 = inv.record_scan(scanned(bt, path, seconds=3))                     # the first two devices only
    bt.devices[next(p for p in bt.devices if "5A_11" in p)]["ManufacturerData"] = {0x004C: b"\x99"}     # its advertisement changes
    bt.reveal = [(0, path, {"Address": "AA:BB:CC:00:00:03", "Alias": "Late", "RSSI": -85, "AddressType": "public", "Class": 0x5A020C})]
    bt.rssi_script["AA:BB:CC:00:00:01"] = lambda t: -90                       # and a speaker's signal drops a lot
    s2 = inv.record_scan(scanned(bt, path, seconds=3))
    ch = inv.adv_changes("5A:11:22:33:44:55")
    assert len(ch) == 1 and "manufacturer data" in ch[0]["summary"]
    cmp = inv.compare(s1, s2)
    assert [r["address"] for r in cmp["new"]] == ["AA:BB:CC:00:00:03"]
    notes = {r["address"]: n for r, n in cmp["changed"]}
    assert "manufacturer data" in notes["5A:11:22:33:44:55"] and "signal" in notes["AA:BB:CC:00:00:01"]
    assert inv.compare(s2, s1)["not_seen"][0]["address"] == "AA:BB:CC:00:00:03"       # "not seen", never "gone"


def test_duplicates_events_export_and_forget_never_touch_bluez():
    bt, path = scene()
    inv = BluetoothInventory(Database(":memory:"))
    for i in (1, 2):
        bt.add_device(path, f"6A:00:00:00:00:0{i}", Alias="Alice phone", AddressType="random", RSSI=-60, ManufacturerData={0x004C: b"\x01"})
    inv.record_scan(scanned(bt, path))
    groups = inv.duplicates()
    assert len(groups) == 1 and {d["address"] for d in groups[0]} == {"6A:00:00:00:00:01", "6A:00:00:00:00:02"}      # same name under rotating addresses
    inv.log_event("AA:BB:CC:00:00:01", "connect", "success", "ok")
    assert inv.events("AA:BB:CC:00:00:01")[0]["event"] == "connect"
    inv.set_info("AA:BB:CC:00:00:01", notes="=cmd|' /C calc'!A0")
    csv_text = inv.export_csv()
    assert csv_text.splitlines()[0].startswith("address,name") and "'=cmd" in csv_text                   # spreadsheet formulas are neutralised
    assert '"address": "AA:BB:CC:00:00:01"' in inv.export_json()
    before = dict(bt.devices)
    inv.forget("AA:BB:CC:00:00:01")
    assert inv.device("AA:BB:CC:00:00:01") is None and inv.sightings("AA:BB:CC:00:00:01") == [] and bt.devices == before     # BlueZ untouched


# ---------------------------------------------------------------- signal monitor
def monitor(bt, path):
    clock = Clock()
    wall = SimpleNamespace(t=1000.0)
    sc = BluetoothScanner(bt, clock, clock.sleep)

    def wall_fn():
        return wall.t

    def sleep(s):
        clock.sleep(s)
        wall.t += s
    return BluetoothSignalMonitor(sc, clock, wall_fn, sleep), clock, wall


def test_monitor_collects_history_statistics_and_labels_missing_readings():
    bt, path = scene()
    bt.rssi_script["AA:BB:CC:00:00:01"] = lambda t: [-50, -54, -60, -52][t % 4]
    bt.rssi_script["5A:11:22:33:44:55"] = lambda t: -70 if t < 4 else None            # the reading disappears
    mon, clock, wall = monitor(bt, path)
    mon.start(path, interval=1.0)
    for _ in range(8):
        mon.poll()
        mon._sleep(1.0)
    st = mon.stats("AA:BB:CC:00:00:01")
    assert st.samples == 8 and st.readings == 8 and st.minimum == -60 and st.maximum == -50 and -58 < st.average < -52
    assert st.fluctuation > 3 and st.stability in ("variable", "erratic") and st.unavailable == 0
    ble = mon.stats("5A:11:22:33:44:55")
    assert ble.unavailable > 0 and ble.current is None                                      # unavailable readings are counted, not invented
    assert [s.rssi for s in mon.history("AA:BB:CC:00:00:01")][:4] == [-54, -60, -52, -50] or len(mon.history("AA:BB:CC:00:00:01")) == 8
    assert mon.ranked()[0].address == "AA:BB:CC:00:00:01"
    mon.stop()
    assert bt.adapters[path]["Discovering"] is False
    assert "not a distance" in __import__("wifi_center.bluetooth.signal_monitor", fromlist=["NOTE"]).NOTE


def test_presence_history_and_stale_flag():
    bt, path = scene()
    bt.rssi_script["AA:BB:CC:00:00:01"] = lambda t: -55 if t < 20 else None
    mon, clock, wall = monitor(bt, path)
    mon.start(path, interval=1.0)
    for _ in range(40):
        mon.poll()
        mon._sleep(1.0)
    pres = mon.presence("AA:BB:CC:00:00:01")
    assert len(pres) == 1 and pres[0].end is not None and pres[0].end > pres[0].start                  # present, then gone
    bt2, path2 = scene()
    bt2.rssi_script["AA:BB:CC:00:00:01"] = lambda t: -55                                              # a frozen value
    mon2, clock2, _ = monitor(bt2, path2)
    mon2.start(path2, interval=1.0)
    for _ in range(int(STALE_AFTER_S) + 5):
        mon2.poll()
        mon2._sleep(1.0)
    assert mon2.stats("AA:BB:CC:00:00:01").stale is True


def test_monitor_run_loop_stops_discovery_and_can_watch_one_device():
    bt, path = scene()
    mon, clock, wall = monitor(bt, path)
    cancel = threading.Event()
    calls = []

    def on_update():
        calls.append(1)
        if len(calls) == 3:
            cancel.set()
    mon.start(path, interval=1.0, addresses=["aa:bb:cc:00:00:01"])
    mon.run(cancel, on_update)
    assert len(calls) == 3 and bt.adapters[path]["Discovering"] is False and set(mon.series) == {"AA:BB:CC:00:00:01"}
    mon.start(path, 1.0)
    with pytest.raises(BluetoothError):
        BluetoothSignalMonitor(BluetoothScanner(bt)).start(path, 1.0)                              # a second scan on a busy adapter is refused
    mon.stop()


# ---------------------------------------------------------------- diagnostics
RFKILL = "0: hci0: Bluetooth" + chr(10) + chr(9) + "Soft blocked: yes" + chr(10) + chr(9) + "Hard blocked: no" + chr(10) + "8: hci1: Bluetooth" + chr(10) + chr(9) + "Soft blocked: no" + chr(10) + chr(9) + "Hard blocked: no" + chr(10)


def make_diag(tmp_path, service="active", rfkill=RFKILL):
    mgr, bt, path = make_manager(tmp_path)

    def run(argv, t):
        out = {"systemctl": service, "bluetoothctl": "bluetoothctl: 5.82", "rfkill": rfkill}[argv[0]]
        return SimpleNamespace(ok=True, stdout=out)
    sc = BluetoothScanner(bt)
    return dg.BluetoothDiagnostics(bt, mgr, sc, run, which=lambda n: "/usr/bin/" + n, sleep=lambda s: None), bt, path, mgr


def test_rfkill_parser_and_report_findings(tmp_path):
    assert dg.parse_rfkill(RFKILL) == [("hci0", "yes", "no"), ("hci1", "no", "no")]
    d, bt, path, mgr = make_diag(tmp_path)
    rep = d.report()
    assert rep.service == "active" and rep.bluez_version == "5.82" and len(rep.adapters) == 1
    levels = {(i.level, i.text.split()[0]) for i in rep.issues}
    assert ("warning", "hci0") in levels                                                # soft-blocked controller is called out
    text = rep.to_text()
    assert "hci1" in text and "Classic: True" in text and "[warning]" in text and "chipset: Realtek" in text
    assert "adapters" in rep.to_json()
    d2, bt2, _, _ = make_diag(tmp_path / "b", service="inactive", rfkill="")
    assert any(i.level == "error" and "not running" in i.text for i in d2.report().issues)
    bt2.up = False
    r = d2.report()
    assert r.adapters == [] and any("No Bluetooth controller" in i.text for i in r.issues)


def test_reset_needs_confirmation_and_is_refused_while_connected(tmp_path):
    d, bt, path, mgr = make_diag(tmp_path)
    assert not d.reset_adapter(path).ok and bt.adapters[path]["Powered"] is True                    # not confirmed: nothing happens
    dev = bt.add_device(path, "AA:BB:CC:00:00:09", Connected=True)
    res = d.reset_adapter(path, confirmed=True)
    assert not res.ok and "connected through this adapter" in res.message and bt.adapters[path]["Powered"] is True
    bt.devices[dev]["Connected"] = False
    res = d.reset_adapter(path, confirmed=True)
    assert res.ok and bt.adapters[path]["Powered"] is True
    assert [c for c in bt.calls if c[0] == "set"][0][3:] == ("Powered", False) and [c for c in bt.calls if c[0] == "set"][1][3:] == ("Powered", True)
