"""Packet Analyzer: btsnoop parsing, decoding, redaction of key material and evidence-based conclusions."""
import struct
from types import SimpleNamespace

import pytest

from wifi_center.bluetooth import packets as pk
from wifi_center.bluetooth.models import BluetoothError

T0 = 1_700_000_000.0
KEY = bytes([0xAA]) * 16


def record(flags, data, t):
    return struct.pack(">IIIIq", len(data), len(data), flags, 0, int((T0 + t) * 1e6) + pk.EPOCH_DELTA_US) + data


def snoop(records, datalink=pk.DL_MONITOR):
    return pk.BTSNOOP_MAGIC + struct.pack(">II", 1, datalink) + b"".join(record(f, d, t) for f, d, t in records)


def acl(handle, cid, payload, pb=0):
    l2 = struct.pack("<HH", len(payload), cid) + payload
    return struct.pack("<HH", handle | (pb << 12), len(l2)) + l2


CMD, EVT, TX, RX = 2, 3, 4, 5
LE_CONN = bytes([0x3E, 19, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00]) + bytes.fromhex("FFEEDDCCBBAA") + bytes(8)
PAIR_REQ = bytes([1, 3, 0, 0x09, 16, 1, 1])                 # NoInputNoOutput, bonding + Secure Connections
PAIR_RSP = bytes([2, 4, 0, 0x09, 16, 1, 1])                 # KeyboardDisplay, bonding + Secure Connections
SCENE = [
    (EVT, LE_CONN, 0.0),
    (TX, acl(0x40, 6, PAIR_REQ), 0.1),
    (RX, acl(0x40, 6, PAIR_RSP), 0.2),
    (EVT, bytes([0x08, 4, 0x00, 0x40, 0x00, 0x01]), 0.3),
    (TX, acl(0x40, 4, bytes([0x12, 0x10, 0x00, 0xDE, 0xAD])), 0.4),
    (CMD, bytes([0x19, 0x20, 28]) + KEY + bytes(12), 0.5),
    (EVT, bytes([0x18, 23]) + bytes(6) + KEY + bytes([4]), 0.6),
    (TX, acl(0x40, 6, bytes([6]) + KEY), 0.65),
    (EVT, bytes([0x0E, 4, 1, 0x0B, 0x20, 0x0C]), 0.7),
    (EVT, bytes([0x05, 4, 0x00, 0x40, 0x00, 0x13]), 0.8),
]


@pytest.fixture
def capture(tmp_path):
    p = tmp_path / "bt-test-hci0.btsnoop"
    p.write_bytes(snoop(SCENE))
    return p


def test_parse_decodes_layers_connections_encryption_and_errors(capture):
    a = pk.parse_btsnoop(capture)
    assert len(a.packets) == 10 and abs(a.duration - 0.8) < 0.01 and a.packets[0].ts == pytest.approx(T0)
    texts = [p.summary for p in a.packets]
    assert "LE Connection Complete: AA:BB:CC:DD:EE:FF handle 0x0040 (success)" in texts
    assert any(t.startswith("Write Request (handle 0x0010, 2 byte(s))") for t in texts) and a.gatt_writes == 1
    assert any("Command Complete: LE Set Scan Parameters failed: Command Disallowed" in t for t in texts)
    assert a.errors and a.errors[0]["what"] == "LE Set Scan Parameters"
    assert [c["result"] for c in a.connections][0] == "success" and "disconnected: Remote User Terminated" in a.connections[-1]["result"]
    assert a.connections[-1]["address"] == "AA:BB:CC:DD:EE:FF"                         # the disconnect is tied to its connection
    assert a.encryption == [{"time": a.encryption[0]["time"], "handle": 0x40, "address": "AA:BB:CC:DD:EE:FF", "enabled": True, "result": "success"}]


def test_pairing_conclusions_state_only_what_the_flags_show(capture):
    a = pk.parse_btsnoop(capture)
    assert len(a.pairings) == 2 and a.pairings[0]["secure_connections"] and a.pairings[0]["io"] == "NoInputNoOutput"
    note = next(n for n in a.notes if n.startswith("LE pairing"))
    assert "LE Secure Connections" in note and "no MITM" in note and "does not prove" in note
    assert any("encryption-enable" in n for n in a.notes)
    legacy = snoop([(TX, acl(0x40, 6, bytes([1, 3, 0, 0x01, 16, 1, 1])), 0), (RX, acl(0x40, 6, bytes([2, 3, 0, 0x01, 16, 1, 1])), 0.1)])
    p = capture.parent / "legacy.btsnoop"
    p.write_bytes(legacy)
    assert "legacy LE pairing" in pk.parse_btsnoop(p).notes[0]
    half = capture.parent / "half.btsnoop"
    half.write_bytes(snoop([(TX, acl(0x40, 6, PAIR_REQ), 0)]))
    assert "incomplete" in pk.parse_btsnoop(half).notes[0]


def test_key_material_never_appears_in_summaries_hex_or_exports(capture):
    a = pk.parse_btsnoop(capture)
    secret = [p for p in a.packets if p.secret]
    assert len(secret) == 3 and all(p.payload == b"" and p.hex() == pk.REDACTED and pk.REDACTED in p.summary for p in secret)
    everything = a.export_csv() + a.export_json() + a.summary_text() + " ".join(p.hex() + p.summary for p in a.packets)
    assert "AA AA" not in everything and "aaaa" not in everything.lower().replace(" ", "")
    assert all("key-material" in p.tags for p in secret)


def test_exports_are_valid_and_complete(capture):
    import csv
    import io
    import json
    a = pk.parse_btsnoop(capture)
    rows = list(csv.DictReader(io.StringIO(a.export_csv())))
    assert len(rows) == 10 and rows[0]["layer"] == "HCI" and rows[4]["layer"] == "ATT"
    data = json.loads(a.export_json())
    assert data["gatt_writes"] == 1 and len(data["packets"]) == 10 and data["file"] == capture.name


def test_h4_captures_and_acl_fragments(tmp_path):
    p = tmp_path / "h4.btsnoop"
    cont = struct.pack("<HH", 0x40 | (1 << 12), 3) + b"abc"
    p.write_bytes(snoop([(0, bytes([1]) + bytes([0x03, 0x0C, 0]), 0), (1, bytes([4]) + bytes([0x0E, 4, 1, 0x03, 0x0C, 0]), 0.1),
                         (0, bytes([2]) + cont, 0.2)], pk.DL_H4))
    a = pk.parse_btsnoop(p)
    assert [x.kind for x in a.packets] == ["cmd", "evt", "acl_tx"]
    assert a.packets[0].summary == "Reset" and "Command Complete: Reset success" in a.packets[1].summary
    assert "continuation" in a.packets[2].summary


def test_damaged_and_foreign_files_are_reported_not_trusted(tmp_path, capture):
    bad = tmp_path / "bad.btsnoop"
    bad.write_bytes(capture.read_bytes() + struct.pack(">IIIIq", 5, 999999999, 3, 0, 0) + b"xx")
    a = pk.parse_btsnoop(bad)
    assert len(a.packets) == 10 and any("damaged" in n for n in a.notes)
    for content in (b"", b"\xd4\xc3\xb2\xa1" + bytes(40), b"not a capture at all, just text"):
        f = tmp_path / "x.btsnoop"
        f.write_bytes(content)
        with pytest.raises(BluetoothError, match="not a btsnoop"):
            pk.parse_btsnoop(f)
    with pytest.raises(BluetoothError):
        pk.parse_btsnoop(tmp_path / "missing.btsnoop")
    other = tmp_path / "wifi.btsnoop"
    other.write_bytes(pk.BTSNOOP_MAGIC + struct.pack(">II", 1, 105))
    assert "Unsupported data link" in pk.parse_btsnoop(other).notes[0]


def test_packet_limit_truncates_with_a_flag(tmp_path):
    p = tmp_path / "many.btsnoop"
    p.write_bytes(snoop([(CMD, bytes([0x03, 0x0C, 0]), i * 0.01) for i in range(30)]))
    a = pk.parse_btsnoop(p, max_packets=10)
    assert len(a.packets) == 10 and a.truncated and "truncated" in a.summary_text()


def test_analyzer_files_tools_and_tshark(tmp_path, capture):
    calls = []

    def run(argv, t):
        calls.append(argv)
        return SimpleNamespace(ok=True, stdout="1 0.0 host controller HCI_CMD Reset", stderr="")
    an = pk.BluetoothPacketAnalyzer(tmp_path / "store", run, lambda n: "/usr/bin/" + n if n == "tshark" else None)
    assert an.tools() == {"btmon": None, "tshark": "/usr/bin/tshark"}
    dest = an.adopt(str(capture))
    assert dest.parent == tmp_path / "store" and an.list()[0]["name"] == capture.name
    with pytest.raises(BluetoothError):
        an.adopt(str(tmp_path / "nothing.btsnoop"))
    with pytest.raises(BluetoothError):
        an.delete(str(capture))                                   # not in the store
    assert "HCI_CMD" in an.tshark_decode(str(dest), "btatt", 20) and calls[0][-2:] == ["-Y", "btatt"] and "-c" in calls[0]
    with pytest.raises(BluetoothError):
        an.tshark_decode(str(dest), "x" * 400)
    an.convert_pcapng(str(dest), str(tmp_path / "o.pcapng"))
    assert calls[-1][-3:] == ["pcapng", "-w", str(tmp_path / "o.pcapng")]
    an.delete(str(dest))
    assert an.list() == []
    none = pk.BluetoothPacketAnalyzer(tmp_path / "store", run, lambda n: None)
    with pytest.raises(BluetoothError, match="tshark is not installed"):
        none.tshark_decode(str(capture))
    with pytest.raises(BluetoothError, match="needs tshark"):
        none.convert_pcapng(str(capture), "x")
    assert "does not capture other people" in an.SCOPE_NOTE
