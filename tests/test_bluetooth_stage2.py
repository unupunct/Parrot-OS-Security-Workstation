"""Stage 2 of the Bluetooth Lab, tested against the in-memory BlueZ: device manager, inspector, BLE explorer, security auditor."""
import pytest

from wifi_center.bluetooth import ble as blemod
from wifi_center.bluetooth.auditor import BluetoothSecurityAuditor, passive_findings
from wifi_center.bluetooth.ble import BLEExplorer, decode_value, parse_hex
from wifi_center.bluetooth.devices import BluetoothDeviceManager
from wifi_center.bluetooth.fake import FakeBluez
from wifi_center.bluetooth.inspector import BluetoothDeviceInspector, parse_modalias
from wifi_center.bluetooth.inventory import BluetoothInventory
from wifi_center.bluetooth.models import BluetoothError, DeviceInfo, device_from_props
from wifi_center.bluetooth.scanner import ScanResult
from wifi_center.database.repository import Database

ADDR = "11:22:33:44:55:66"
BAT = "0000180f-0000-1000-8000-00805f9b34fb"
BAT_LEVEL = "00002a19-0000-1000-8000-00805f9b34fb"
DIS = "0000180a-0000-1000-8000-00805f9b34fb"
SERIAL = "00002a25-0000-1000-8000-00805f9b34fb"
DFU = "8ec90001-f315-4f60-9fb8-838830daea50"
CUSTOM = "12345678-0000-1000-8000-00805f9b34fb"


def world(**dev_props):
    bt = FakeBluez()
    a = bt.add_adapter()
    path = bt.add_device(a, ADDR, Name="Tracker", Alias="Tracker", AddressType="public", UUIDs=[BAT], **dev_props)
    db = Database(":memory:")
    inv = BluetoothInventory(db)
    inv.record_scan(ScanResult(adapter=a, mode="le", started_at="2026-01-01T00:00:00+00:00", duration_s=5, devices=[device_from_props(path, bt.devices[path])]))
    audit = []
    mgr = BluetoothDeviceManager(bt, inv, lambda *a, **k: audit.append((a, k)))
    exp = BLEExplorer(bt, inv)
    aud = BluetoothSecurityAuditor(bt, db, inv, mgr, exp)
    return bt, path, inv, mgr, exp, aud, audit


def test_state_changes_need_confirmation_and_are_logged():
    bt, path, inv, mgr, *_ = world()
    with pytest.raises(BluetoothError):
        mgr.connect(ADDR, confirmed=False)
    assert not any(c[2:3] == ("Connect",) for c in bt.calls)
    assert mgr.connect(ADDR, True).ok and bt.devices[path]["Connected"]
    assert mgr.disconnect(ADDR, True).ok and not bt.devices[path]["Connected"]
    assert mgr.set_trusted(ADDR, True, True).ok and bt.devices[path]["Trusted"]
    assert mgr.set_trusted(ADDR, False, True).ok and not bt.devices[path]["Trusted"]
    events = [e["event"] for e in inv.events(ADDR)]
    assert {"connect", "disconnect", "trust", "untrust"} <= set(events)


def test_failures_are_reported_and_logged():
    bt, path, inv, mgr, *_ = world()
    bt.fail[(path, "Connect")] = "Connection refused"
    r = mgr.connect(ADDR, True)
    assert not r.ok and "refused" in r.message
    assert inv.events(ADDR)[0]["result"] == "failed"
    with pytest.raises(BluetoothError):
        mgr.connect("AA:BB:CC:DD:EE:00", True)        # unknown to BlueZ


def test_pairing_uses_a_temporary_agent_and_never_stores_secrets():
    bt, path, inv, mgr, *_ = world()
    seen = {}

    class H:
        def request_confirmation(self, address, passkey):
            seen["passkey"] = passkey
            return True
        request_pin = request_passkey = lambda self, a: None
        display_passkey = display_pin = lambda self, *a: None
        authorize_service = lambda self, a, u: True
        cancel = lambda self: None

    bt.pair_script = lambda p, agent: agent.request_confirmation(ADDR, 123456)
    r = mgr.pair(ADDR, True, H())
    assert r.ok and bt.devices[path]["Paired"]
    assert seen["passkey"] == 123456 and bt.agent is None                   # agent removed afterwards
    dump = repr(inv.events(ADDR))
    assert "123456" not in dump                                             # the passkey is never recorded
    with pytest.raises(BluetoothError):
        mgr.pair(ADDR, False)


def test_rejected_pairing_removes_the_agent_and_logs_failure():
    bt, path, inv, mgr, *_ = world()

    def refuse(p, agent):
        raise BluetoothError("Authentication rejected")
    bt.pair_script = refuse
    r = mgr.pair(ADDR, True, object())
    assert not r.ok and bt.agent is None and not bt.devices[path]["Paired"]
    assert inv.events(ADDR)[0]["event"] == "pair" and inv.events(ADDR)[0]["result"] == "failed"


def test_remove_pairing_refused_while_connected_and_only_calls_bluez():
    bt, path, inv, mgr, *_ = world(Paired=True, Bonded=True, Connected=True)
    assert not mgr.remove_pairing(ADDR, True).ok
    mgr.disconnect(ADDR, True)
    r = mgr.remove_pairing(ADDR, True)
    assert r.ok and path not in bt.devices
    assert any(c[2] == "RemoveDevice" for c in bt.calls if len(c) > 2)
    assert inv.device(ADDR) is not None                                      # the inventory entry is untouched


def test_modalias_and_inspection():
    assert parse_modalias("usb:v1D6Bp0246d0552")["vendor_id"] == "1D6B"
    assert parse_modalias("bluetooth:v004Cp1234d0001")["vendor"].startswith("Apple")
    assert parse_modalias("garbage") is None
    bt, path, inv, mgr, *_ = world(Modalias="usb:v1D6Bp0246d0552", Connected=True, ServicesResolved=True)
    bt.add_gatt(path, {BAT: {BAT_LEVEL: {"flags": ["read", "notify"], "value": bytes([77])}}})
    bt.gatt[path + "/x"] = {"org.bluez.Battery1": {"Percentage": 77}}      # unrelated path: must not be picked up
    bt.gatt[path] = {"org.bluez.Battery1": {"Percentage": 77}}
    ins = BluetoothDeviceInspector(bt, inv).inspect(ADDR)
    assert ins.battery == 77 and ins.gatt_services[0]["name"] == "Battery"
    assert dict(ins.properties())["Connected"] == "yes"
    assert ins.modalias and len(ins.notes) == 1 and "signal" in ins.notes[0]      # services are resolved, but there is no RSSI outside discovery


def test_inspection_of_an_unknown_device_says_so():
    bt, path, inv, *_ = world()
    del bt.devices[path]
    ins = BluetoothDeviceInspector(bt, inv).inspect(ADDR)
    assert ins.notes and ins.device.path == ""


def connected_tree(bt, path, services):
    bt.devices[path].update(Connected=True, ServicesResolved=True)
    bt.add_gatt(path, services)


def test_gatt_tree_requires_a_connected_device_and_describes_characteristics():
    bt, path, inv, mgr, exp, *_ = world()
    with pytest.raises(BluetoothError):
        exp.tree(ADDR)
    connected_tree(bt, path, {BAT: {BAT_LEVEL: {"flags": ["read", "notify"], "value": bytes([55]), "descriptors": {"00002902-0000-1000-8000-00805f9b34fb": b"\x00\x00"}}},
                              DIS: {SERIAL: {"flags": ["read"], "value": b"SN-1"}}})
    tree = exp.tree(ADDR)
    assert [s.name for s in tree] == ["Battery", "Device Information"]
    lvl = tree[0].characteristics[0]
    assert lvl.name == "Battery Level" and lvl.readable and lvl.can_notify and not lvl.writable and lvl.descriptors
    assert tree[1].characteristics[0].sensitive
    assert decode_value(lvl.uuid, exp.read(lvl)) == "55 %"
    with pytest.raises(BluetoothError):
        exp.read(char(["write"]))


def char(flags, uuid=CUSTOM, path="/p"):
    return blemod.GattCharacteristic(path, uuid, "Custom", flags, False)


def test_notifications_are_delivered_and_unsubscribe_cleans_up():
    bt, path, inv, mgr, exp, *_ = world()
    connected_tree(bt, path, {BAT: {BAT_LEVEL: {"flags": ["read", "notify"], "value": bytes([55])}}})
    ch = exp.tree(ADDR)[0].characteristics[0]
    got = []
    exp.subscribe(ch, got.append)
    bt.push_value(ch.path, bytes([54]))
    bt.push_value(ch.path + "-other", bytes([1]))                            # a different characteristic is not delivered
    assert got == [bytes([54])] and not bt.watchers[1:] and len(bt.watchers) == 1
    exp.unsubscribe(ch)
    bt.push_value(ch.path, bytes([53]))
    assert got == [bytes([54])] and not bt.watchers
    with pytest.raises(BluetoothError):
        exp.subscribe(char(["read"]), got.append)


def test_hex_parsing_and_value_decoding():
    assert parse_hex("01 0a 0xFF") == b"\x01\x0a\xff" and parse_hex("0102") == b"\x01\x02"
    for bad in ("", "0", "zz", "01 2"):
        with pytest.raises(ValueError):
            parse_hex(bad)
    with pytest.raises(ValueError):
        parse_hex("00" * 513)
    assert decode_value("00002a00-0000-1000-8000-00805f9b34fb", b"Tracker") == "Tracker"
    assert decode_value(CUSTOM, b"abc") == ""                                # no guess for unknown characteristics


def test_writes_are_refused_unless_every_condition_holds():
    bt, path, inv, mgr, exp, *_ = world()
    connected_tree(bt, path, {CUSTOM: {CUSTOM.replace("12345678", "12345679"): {"flags": ["read", "write"], "value": b"\x00"}},
                              DFU: {DFU.replace("0001", "0002"): {"flags": ["write"]}}})
    tree = exp.tree(ADDR)
    ch, dfu = tree[0].characteristics[0], tree[1].characteristics[0]
    r = exp.write(ADDR, ch, b"\x01", confirmed=True)
    assert not r.ok and "authorised" in r.message                            # device not marked as authorised
    inv.set_info(ADDR, authorized=True)
    assert not exp.write(ADDR, ch, b"\x01", confirmed=False).ok             # no confirmation
    assert not exp.write(ADDR, ch, b"", confirmed=True).ok
    assert not exp.write(ADDR, char(["read"], path=ch.path), b"\x01", confirmed=True).ok            # no write flag
    d = exp.write(ADDR, dfu, b"\x01", confirmed=True)
    assert not d.ok and "firmware" in d.message                              # deny-listed service
    assert not any(c[2] == "WriteValue" for c in bt.calls if len(c) > 2)
    ok = exp.write(ADDR, ch, b"\x01\x02", confirmed=True)
    assert ok.ok and bt.values[ch.path] == b"\x01\x02"
    ev = inv.events(ADDR)[0]
    assert ev["event"] == "gatt-write" and "0102" not in ev["detail"].replace(" ", "")       # value not stored


def test_passive_findings_distinguish_confirmed_observed_and_unknown():
    d = DeviceInfo(path="/x", address=ADDR, address_type="public", appearance=3, uuids=["00001101-0000-1000-8000-00805f9b34fb", DFU], connected=True,
                   trusted=True, paired=False, legacy_pairing=True)
    f = {x.check: x for x in passive_findings(d)}
    assert f["address-privacy"].status == "confirmed" and f["address-privacy"].severity == "low"
    assert f["legacy-pairing"].status == "confirmed" and f["trust"].severity == "medium" and f["unpaired-link"].status == "confirmed"
    assert f["encryption"].status == "unknown"                                # never claims the link is or is not encrypted
    assert f["service-1101"].status == "observation" and f["service-dfu"].status == "observation"
    assert all(x.severity != "critical" for x in f.values())
    assert all(x.evidence and x.explanation and x.remediation and x.timestamp for x in f.values())


def test_audit_requires_authorisation_and_stores_findings():
    bt, path, inv, mgr, exp, aud, audit = world(Paired=True, Bonded=True, Trusted=True)
    with pytest.raises(BluetoothError):
        aud.audit_device(ADDR)
    assert not any(c for c in bt.calls if len(c) > 2 and c[2] in ("Connect", "Pair"))
    inv.set_info(ADDR, authorized=True)
    aid, findings = aud.audit_device(ADDR)
    assert findings and aud.findings(aid)[0].title == findings[0].title
    assert aud.audits(ADDR)[0]["deep"] == 0
    assert not any(len(c) > 2 and c[2] in ("Connect", "Pair", "ReadValue", "WriteValue") for c in bt.calls)       # passive: nothing sent to the device
    assert sum(aud.summary(findings).values()) == len(findings)
    aud.clear(ADDR)
    assert not aud.audits(ADDR)


def test_deep_audit_needs_confirmation_connection_and_only_reads():
    bt, path, inv, mgr, exp, aud, audit = world()
    inv.set_info(ADDR, authorized=True)
    with pytest.raises(BluetoothError):
        aud.audit_device(ADDR, deep=True, confirmed=False)
    with pytest.raises(BluetoothError):
        aud.audit_device(ADDR, deep=True, confirmed=True)                     # not connected
    connected_tree(bt, path, {DIS: {SERIAL: {"flags": ["read"], "value": b"SN-1"}},
                              CUSTOM: {CUSTOM.replace("12345678", "12345679"): {"flags": ["write"]}}})
    aid, findings = aud.audit_device(ADDR, deep=True, confirmed=True)
    by = {f.check: f for f in findings}
    assert by["gatt-sensitive"].status == "confirmed" and by["gatt-sensitive"].severity == "high"      # unpaired + readable serial
    assert by["gatt-open-write"].status == "observation"                      # declared only, never tested
    assert not any(len(c) > 2 and c[2] == "WriteValue" for c in bt.calls)
    assert aud.audits(ADDR)[0]["deep"] == 1
