"""Privileged Bluetooth capture (btmon) in the helper: request validation, file hand-over and time limit."""
import os
import threading

import pytest

from tests.test_privileged import FakeProc
from wifi_center.privileged import helper_core as hc
from wifi_center.privileged import protocol as pr
from wifi_center.privileged.protocol import PrivilegedOp, ProtocolError


def test_request_validation_and_wire_format():
    ok = PrivilegedOp("bt_capture", iface="hci1", seconds=30)
    assert pr.op_from_json(pr.op_to_json(ok)) == ok and ok.action_id == "org.wificenter.helper.bluetooth-capture"
    for iface, secs in (("wlan0", 30), ("hci1; reboot", 30), ("", 30), ("hci1", 0), ("hci1", 601), ("hci1", -5)):
        with pytest.raises(ProtocolError):
            PrivilegedOp("bt_capture", iface=iface, seconds=secs)
    for bad in ('{"v":1,"kind":"bt_capture","iface":"hci0","seconds":"30"}', '{"v":1,"kind":"bt_capture","iface":"hci0","seconds":true}',
                '{"v":1,"kind":"bt_capture","iface":"hci0","seconds":9999}'):
        with pytest.raises(pr.ValidationError):
            pr.op_from_json(bad)
    assert "30 s" in ok.summary()


class WritingSpawner:
    """Pretends to be btmon: writes some bytes into the -w file named on its command line."""

    def __init__(self, payload=b"btsnoop\x00" + b"\x01" * 40, code=0, block=False):
        self.payload, self.code, self.block, self.calls = payload, code, block, []

    def spawn(self, argv, env):
        self.calls.append(list(argv))
        with open(argv[argv.index("-w") + 1], "wb") as f:
            f.write(self.payload)
        return FakeProc(["> HCI Event: Command Complete"], self.code, block=True if self.block else None)


def make(tmp_path, spawner, now=lambda: 1_700_000_000.0, exists=lambda p: True):
    chowned = []
    cap = hc.BluetoothCapture(spawner, str(tmp_path / "captures"), exists, now, chown=lambda p, u, g: chowned.append((p, u, g)))
    return cap, chowned


def run(cap, op, uid=1000, cancel=None):
    out = []
    return cap.run(op, lambda s, l: out.append((s, l)), cancel or threading.Event(), uid), out


def test_capture_is_handed_to_the_caller_before_btmon_writes(tmp_path):
    sp = WritingSpawner(block=True)
    cap, chowned = make(tmp_path, sp)
    res, out = run(cap, PrivilegedOp("bt_capture", iface="hci1", seconds=1))                # runs until the time limit stops btmon
    assert res.ok and res.status == "succeeded"
    argv = sp.calls[0]
    path = argv[argv.index("-w") + 1]
    assert argv[1:4] == ["-i", "hci1", "-w"] and argv[0].endswith("btmon") and path.startswith(str(tmp_path / "captures"))
    assert chowned == [(path, 1000, -1)] and os.path.getsize(path) > 0 and path in res.message
    assert ("info", f"capture-file: {path}") in out
    if os.name == "posix":
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_refusals(tmp_path):
    cap, _ = make(tmp_path, WritingSpawner())
    res, _ = run(cap, PrivilegedOp("bt_capture", iface="hci0", seconds=5), uid=None)
    assert res.status == "refused" and not os.path.exists(tmp_path / "captures")             # nothing created for an unknown caller
    cap2, _ = make(tmp_path, WritingSpawner(), exists=lambda p: False)
    res2, _ = run(cap2, PrivilegedOp("bt_capture", iface="hci0", seconds=5))
    assert res2.status == "refused" and "btmon" in res2.message


def test_failed_btmon_removes_the_empty_file_and_cancel_keeps_partial_data(tmp_path):
    cap, _ = make(tmp_path, WritingSpawner(payload=b"", code=1))
    res, _ = run(cap, PrivilegedOp("bt_capture", iface="hci0", seconds=5))
    assert not res.ok and res.status == "failed" and not list((tmp_path / "captures").iterdir())
    cancel = threading.Event()
    cancel.set()
    cap2, _ = make(tmp_path, WritingSpawner(block=True))
    res2, _ = run(cap2, PrivilegedOp("bt_capture", iface="hci0", seconds=60), cancel=cancel)
    assert res2.status == "cancelled" and "saved to" in res2.message and list((tmp_path / "captures").iterdir())


def test_old_captures_are_pruned_but_other_files_are_left_alone(tmp_path):
    d = tmp_path / "captures"
    d.mkdir()
    old, fresh, other = d / "bt-old-hci0.btsnoop", d / "bt-new-hci0.btsnoop", d / "notes.txt"
    for f in (old, fresh, other):
        f.write_bytes(b"x")
    now = 1_700_000_000.0
    os.utime(old, (now - 2 * 86400, now - 2 * 86400))
    os.utime(other, (now - 9 * 86400, now - 9 * 86400))
    os.utime(fresh, (now - 60, now - 60))
    cap, _ = make(tmp_path, WritingSpawner(), now=lambda: now)
    run(cap, PrivilegedOp("bt_capture", iface="hci0", seconds=5))
    assert not old.exists() and fresh.exists() and other.exists()


def test_core_passes_the_caller_uid_through(tmp_path):
    sp = WritingSpawner()
    core = hc.HelperCore(sp, exists=lambda p: True, proc_root="/nonexistent")
    core.capture = hc.BluetoothCapture(sp, str(tmp_path / "c"), lambda p: True, chown=lambda p, u, g: None)
    res = core.execute(PrivilegedOp("bt_capture", iface="hci0", seconds=5), lambda s, l: None, threading.Event(), 4242)
    assert res.ok
    assert core.execute(PrivilegedOp("bt_capture", iface="hci0", seconds=5), lambda s, l: None, threading.Event()).status == "refused"
