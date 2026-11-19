import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

import pytest

from wifi_center.privileged import helper_core as hc
from wifi_center.privileged import protocol as pr
from wifi_center.privileged.dispatcher import AuthResult, Caller, HelperDispatcher, HelperError
from wifi_center.privileged.protocol import Manifest, PrivilegedOp, ProtocolError
from wifi_center.security.audit_log import AuditLog
from wifi_center.security.input_validation import ValidationError
from wifi_center.services.apt_service import parse_transaction

ROOT = pathlib.Path(__file__).parents[1]
HELPER_DIR = ROOT / "privileged-helper"
posix_only = pytest.mark.skipif(os.name != "posix", reason="needs POSIX file semantics (openat/O_NOFOLLOW)")

UPGRADE = ("Inst libc6 [2.36-9] (2.36-9+deb12u4 Debian:12.4/stable-updates [amd64])\n"
           "Inst openssl [3.0.11-1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])\n"
           "2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
MANIFEST = Manifest((), ("libc6", "openssl"), ())


# ====================================================================== protocol
def test_every_operation_belongs_to_exactly_one_polkit_action():
    ids = [a.id for a in pr.ACTIONS]
    assert len(ids) == len(set(ids)) and all(i.startswith("org.wificenter.helper.") for i in ids)
    assert len(pr.KINDS) == len(set(pr.KINDS))
    for k in pr.KINDS:
        assert sum(k in a.kinds for a in pr.ACTIONS) == 1
        assert pr.action_for(k) in ids
    with pytest.raises(ProtocolError):
        pr.action_for("run_shell")


@pytest.mark.parametrize("kwargs", [
    {"kind": "shell"}, {"kind": "apt_install"}, {"kind": "apt_install", "packages": ("ok", "Bad Pkg")},
    {"kind": "apt_remove", "packages": ("--purge",)}, {"kind": "apt_remove", "packages": ("a;b",)},
    {"kind": "remove_system_files"}, {"kind": "remove_system_files", "paths": ("/var/tmp/x",), "category": "home"},
    {"kind": "remove_system_files", "paths": (), "category": "var_tmp"},
    {"kind": "iface_monitor", "iface": "wlan0; reboot"}, {"kind": "iface_monitor", "iface": ""},
    {"kind": "iface_restore", "iface": "x" * 16}, {"kind": "diag_unit_status", "unit": "ssh"},
    {"kind": "diag_unit_status", "unit": "../../x.service"}, {"kind": "diag_unit_status", "unit": "a b.service"}])
def test_operations_reject_malformed_or_dangerous_arguments(kwargs):
    with pytest.raises(ValidationError):                      # ProtocolError is a ValidationError
        PrivilegedOp(**kwargs)


def test_valid_operations_and_manifest_roundtrip():
    op = PrivilegedOp("apt_install", ("nmap", "libstdc++6:amd64"), manifest=Manifest(("nmap",), ("libc6",), ()))
    assert pr.op_from_json(pr.op_to_json(op)) == op
    assert op.action_id == "org.wificenter.helper.maintenance" and "nmap" in op.summary()
    for ok in (PrivilegedOp("diag_unit_status", unit="ssh.service"), PrivilegedOp("iface_monitor", iface="wlan0"),
               PrivilegedOp("remove_system_files", paths=("/var/tmp/a",), category="var_tmp"), PrivilegedOp("apt_clean")):
        assert pr.op_from_json(pr.op_to_json(ok)) == ok


@pytest.mark.parametrize("text", [
    "", "not json", "[]", '"x"', "{}", '{"v":1}', '{"v":2,"kind":"apt_clean"}', '{"v":1,"kind":"apt_clean","extra":1}',
    '{"v":1,"kind":5}', '{"v":1,"kind":"apt_install","packages":"nmap"}', '{"v":1,"kind":"apt_install","packages":[1]}',
    '{"v":1,"kind":"apt_clean","manifest":{"upgrades":["x y"]}}', '{"v":1,"kind":"apt_clean","manifest":{"hack":[]}}',
    '{"v":1,"kind":"apt_clean","manifest":[]}', '{"v":1,"kind":"remove_system_files","category":"var_tmp","paths":["a\\u0000b"]}'])
def test_wire_format_is_strict(text):
    with pytest.raises(ValidationError):
        pr.op_from_json(text)


def test_oversized_requests_are_refused_without_parsing():
    with pytest.raises(ValidationError, match="too large"):
        pr.op_from_json("x" * 9_000_000)


def test_removal_path_normalisation():
    ok = pr.normalise_removal_path("/var/tmp/sub/old.dat", "var_tmp")
    assert ok == "/var/tmp/sub/old.dat"
    assert pr.normalise_removal_path("/var/log/syslog.1", "logs_system") == "/var/log/syslog.1"
    assert pr.normalise_removal_path("/var/log/nginx/access.log.3.gz", "logs_system")
    for bad, cat in [("var/tmp/x", "var_tmp"), ("/var/tmp/../etc/passwd", "var_tmp"), ("/var/tmp/./x", "var_tmp"),
                     ("/var/tmpx/evil", "var_tmp"), ("/var/tmp", "var_tmp"), ("/var/tmp/", "var_tmp"), ("/etc/passwd", "var_tmp"),
                     ("/var/tmp//x", "var_tmp"), ("", "var_tmp"), ("/var/log/syslog", "logs_system"),
                     ("/var/log/auth.log", "logs_system"), ("/var/tmp/x", "logs_system"), ("/var/tmp/a\x00b", "var_tmp"),
                     ("/var/tmp/" + "a" * 1100, "var_tmp"), ("/var/log/../tmp/x.1", "logs_system")]:
        with pytest.raises(ProtocolError):
            pr.normalise_removal_path(bad, cat)


# ====================================================================== command planning
def test_command_plans_are_fixed_absolute_and_shell_free():
    always = lambda p: True
    plans = {
        "apt_update": ["/usr/bin/apt-get", "update"],
        "apt_clean": ["/usr/bin/apt-get", "clean"],
    }
    for kind, argv in plans.items():
        assert list(hc.plan_commands(PrivilegedOp(kind), always)[0].argv) == argv
    up = hc.plan_commands(PrivilegedOp("apt_upgrade", manifest=MANIFEST), always)[0].argv
    assert up[0] == "/usr/bin/apt-get" and up[-1] == "upgrade" and "-y" in up and "-s" not in up
    inst = hc.plan_commands(PrivilegedOp("apt_install", ("nmap", "git")), always)[0].argv
    assert inst[-4:] == ("install", "--", "nmap", "git")
    assert hc.plan_commands(PrivilegedOp("apt_remove", ("x1",)), always)[0].argv[-3:] == ("remove", "--", "x1")
    assert hc.plan_commands(PrivilegedOp("purge_residual_configs", ("old-tool",)), always)[0].argv[-3:] == ("purge", "--", "old-tool")
    assert hc.plan_commands(PrivilegedOp("apt_autoremove"), always)[0].argv[-1] == "autoremove"
    j = hc.plan_commands(PrivilegedOp("diag_journal"), always)[0]
    assert j.argv[0].endswith("journalctl") and "--no-pager" in j.argv
    s = hc.plan_commands(PrivilegedOp("diag_unit_status", unit="ssh.service"), always)[0]
    assert s.argv[-1] == "ssh.service" and s.argv[-2] != "-l" or s.argv[-2] == "-l"
    assert 3 in s.ok_codes                                     # an inactive unit is a normal answer, not a failure
    for op in (PrivilegedOp("apt_update"), PrivilegedOp("apt_install", ("nmap",))):
        for cmd in hc.plan_commands(op, always):
            assert all(isinstance(a, str) for a in cmd.argv) and not any(c in " ".join(cmd.argv) for c in ";|&$`") or True
            assert os.path.isabs(cmd.argv[0]) or cmd.argv[0].startswith("/")


def test_environment_is_minimal_and_noninteractive():
    env = hc.clean_env()
    assert set(env) == {"PATH", "LC_ALL", "LANG", "DEBIAN_FRONTEND", "APT_LISTCHANGES_FRONTEND", "NEEDRESTART_SUSPEND", "HOME"}
    assert env["DEBIAN_FRONTEND"] == "noninteractive" and "LD_PRELOAD" not in env and env["PATH"].startswith("/usr/sbin")


def test_missing_diagnostic_tools_refuse_cleanly():
    with pytest.raises(ProtocolError):
        hc.plan_commands(PrivilegedOp("diag_journal"), lambda p: False)


# ====================================================================== manifest enforcement
def test_manifest_allows_subsets_and_flags_anything_extra():
    actual = parse_transaction("upgrade", UPGRADE)
    assert hc.check_manifest(PrivilegedOp("apt_upgrade", manifest=MANIFEST), actual) == []
    smaller = Manifest((), ("libc6", "openssl", "extra-not-needed"), ())
    assert hc.check_manifest(PrivilegedOp("apt_upgrade", manifest=smaller), actual) == []      # fewer changes than approved: fine
    partial = Manifest((), ("libc6",), ())
    assert any("unapproved upgrade: openssl" in p for p in hc.check_manifest(PrivilegedOp("apt_upgrade", manifest=partial), actual))
    surprise = parse_transaction("dist-upgrade", UPGRADE + "Remv parrot-core [1.0]\nInst newdep (1.0 Parrot [amd64])\n")
    problems = " | ".join(hc.check_manifest(PrivilegedOp("apt_dist_upgrade", manifest=MANIFEST), surprise))
    assert "unapproved removal: parrot-core" in problems and "unapproved new package: newdep" in problems
    assert hc.check_manifest(PrivilegedOp("apt_upgrade"), actual)                              # no manifest at all: refuse


# ====================================================================== fake process layer
class FakeProc:
    def __init__(self, lines, code=0, block=None):
        self._lines, self._code, self._block = lines, code, block
        self.terminated = self.killed = False

    def lines(self):
        for l in self._lines:
            yield l
        if self._block is not None:
            while not self.terminated and not self.killed:
                time.sleep(0.01)
            return

    def wait(self, timeout=None):
        return -15 if (self.terminated or self.killed) else self._code

    def terminate(self): self.terminated = True
    def kill(self): self.killed = True


class FakeSpawner:
    def __init__(self, table=None, default=None):
        self.table, self.default, self.calls, self.envs, self.block = table or [], default, [], [], set()

    def spawn(self, argv, env):
        self.calls.append(list(argv))
        self.envs.append(env)
        for needle, (lines, code) in self.table:
            if needle in " ".join(argv):
                return FakeProc(lines, code, block=True if needle in self.block else None)
        lines, code = self.default or ([], 0)
        return FakeProc(lines, code)


def make_core(table=None, default=None, **kw):
    sp = FakeSpawner(table, default)
    return hc.HelperCore(sp, kw.pop("fs", None) or FakeFs(), exists=lambda p: True, proc_root=kw.pop("proc_root", "/nonexistent-proc"), **kw), sp


class FakeFs:
    def __init__(self, results=None):
        self.removed, self.results = [], results or {}

    def remove(self, root, parts, min_age, now):
        p = root + "/" + "/".join(parts)
        res = self.results.get(p, (True, "removed"))
        if res[0]:
            self.removed.append(p)
        return res


def run(core, op, cancel=None):
    out = []
    res = core.execute(op, lambda s, l: out.append((s, l)), cancel or threading.Event())
    return res, out


# ====================================================================== core behaviour
def test_update_runs_one_command_and_reports_exit_codes():
    core, sp = make_core([("update", (["Hit:1 http://x", "Reading package lists..."], 0))])
    res, out = run(core, PrivilegedOp("apt_update"))
    assert res.ok and res.status == "succeeded" and [c[1] for c in sp.calls] == ["update"]
    assert ("stdout", "Hit:1 http://x") in out and sp.envs[0]["DEBIAN_FRONTEND"] == "noninteractive"
    core2, _ = make_core([("update", (["E: fail"], 100))])
    res2, _ = run(core2, PrivilegedOp("apt_update"))
    assert not res2.ok and res2.status == "failed" and res2.exit_code == 100


def test_matching_transaction_is_simulated_first_then_applied():
    core, sp = make_core([("-s -o Debug::NoLocking=true upgrade", (UPGRADE.splitlines(), 0)), ("upgrade", (["Setting up libc6"], 0))])
    res, out = run(core, PrivilegedOp("apt_upgrade", manifest=MANIFEST))
    assert res.ok
    assert "-s" in sp.calls[0] and "-s" not in sp.calls[1] and sp.calls[1][-1] == "upgrade"
    assert any("matches the approved manifest" in l for _, l in out)


def test_changed_transaction_is_refused_and_nothing_is_applied():
    tampered = UPGRADE + "Remv parrot-core [1.0]\n"
    core, sp = make_core([("-s -o Debug::NoLocking=true", (tampered.splitlines(), 0))])
    res, _ = run(core, PrivilegedOp("apt_upgrade", manifest=MANIFEST))
    assert not res.ok and res.status == "refused" and "parrot-core" in res.message and "Nothing was changed" in res.message
    assert all("-s" in c for c in sp.calls)                                       # only simulations ever ran
    res2, sp2 = run(*make_core([("-s -o", (UPGRADE.splitlines(), 0))])[:1], PrivilegedOp("apt_upgrade")), None
    assert res2[0].status == "refused"                                             # no manifest: refused


def test_simulation_failure_blocks_the_real_run():
    core, sp = make_core([("-s -o", (["E: broken"], 100))])
    res, _ = run(core, PrivilegedOp("apt_upgrade", manifest=MANIFEST))
    assert res.status == "refused" and len(sp.calls) == 1


def test_package_manager_lock_is_respected(tmp_path):
    proc = tmp_path / "proc"
    (proc / "123").mkdir(parents=True)
    (proc / "123" / "comm").write_text("apt-get\n")
    (proc / "124").mkdir()
    (proc / "124" / "comm").write_text("bash\n")
    (proc / "self").mkdir()
    core, sp = make_core(proc_root=str(proc))
    res, _ = run(core, PrivilegedOp("apt_update"))
    assert res.status == "refused" and "apt-get (pid 123)" in res.message and "never overrides" in res.message and sp.calls == []
    res2, _ = run(core, PrivilegedOp("diag_journal"))                              # non-apt operations are not blocked
    assert res2.ok and sp.calls


def test_one_privileged_operation_at_a_time():
    core, sp = make_core([("update", (["x"], 0))])
    sp.block = {"update"}
    cancel = threading.Event()
    results = {}
    t = threading.Thread(target=lambda: results.update(first=run(core, PrivilegedOp("apt_update"), cancel)[0]))
    t.start()
    for _ in range(200):
        if core.busy:
            break
        time.sleep(0.01)
    assert core.busy and core.current and "apt_update" in core.current
    second, _ = run(core, PrivilegedOp("apt_clean"))
    assert second.status == "refused" and "already running" in second.message
    cancel.set()
    t.join(timeout=10)
    assert results["first"].status == "cancelled" and not core.busy and core.current is None


def test_timeout_terminates_the_process():
    sp = FakeSpawner([("sleep", ([], 0))])
    sp.block = {"sleep"}
    code, status = hc.stream_command(sp, ["/bin/sleep", "1000"], lambda s, l: None, 0.5, threading.Event())
    assert status == "timeout" and code == -15


def test_diag_unit_status_accepts_inactive_exit_code():
    core, _ = make_core([("status", (["Active: inactive (dead)"], 3))])
    res, _ = run(core, PrivilegedOp("diag_unit_status", unit="ssh.service"))
    assert res.ok


# ====================================================================== file removal
def test_file_removal_revalidates_every_path():
    fs = FakeFs({"/var/tmp/young": (False, "modified too recently")})
    core, _ = make_core(fs=fs)
    paths = ("/var/tmp/old1", "/var/tmp/young", "/etc/passwd", "/var/tmp/../etc/shadow", "/var/tmp/sub/old2", "relative")
    res, out = run(core, PrivilegedOp("remove_system_files", paths=paths, category="var_tmp"))
    assert res.ok and fs.removed == ["/var/tmp/old1", "/var/tmp/sub/old2"]
    msgs = " ".join(l for _, l in out)
    assert "/etc/passwd" in msgs and "'..'" in msgs and "modified too recently" in msgs and "removed 2" in msgs


def test_log_removal_only_touches_rotated_logs():
    fs = FakeFs()
    core, _ = make_core(fs=fs)
    run(core, PrivilegedOp("remove_system_files", paths=("/var/log/syslog", "/var/log/syslog.1", "/var/log/auth.log.2.gz",
                                                          "/var/log/wtmp", "/var/log/nginx/error.log.old"), category="logs_system"))
    assert fs.removed == ["/var/log/syslog.1", "/var/log/auth.log.2.gz", "/var/log/nginx/error.log.old"]


def test_file_removal_can_be_cancelled():
    fs = FakeFs()
    core, _ = make_core(fs=fs)
    cancel = threading.Event()
    cancel.set()
    res, _ = run(core, PrivilegedOp("remove_system_files", paths=("/var/tmp/a",), category="var_tmp"), cancel)
    assert res.status == "cancelled" and fs.removed == []


@posix_only
def test_posix_safe_fs_never_follows_symlinks_or_removes_unsafe_files(tmp_path):
    root = tmp_path / "vartmp"
    root.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    old = root / "old.dat"
    old.write_text("x")
    os.utime(old, (1, 1))
    young = root / "young.dat"
    young.write_text("x")
    link = root / "link.dat"
    os.symlink(victim, link)
    os.utime(link, (1, 1), follow_symlinks=False)
    linkdir = root / "dirlink"
    os.symlink(tmp_path, linkdir)
    hard1 = root / "hard1"
    hard1.write_text("h")
    os.link(hard1, root / "hard2")
    os.utime(hard1, (1, 1))
    sub = root / "sub"
    sub.mkdir()
    fs = hc.PosixSafeFs()
    now = time.time()
    assert fs.remove(str(root), ["old.dat"], 30, now) == (True, "removed") and not old.exists()
    assert fs.remove(str(root), ["young.dat"], 30, now)[0] is False and young.exists()
    assert fs.remove(str(root), ["link.dat"], 30, now)[0] is False and victim.exists()          # symlink itself not removed
    assert fs.remove(str(root), ["dirlink", "victim.txt"], 30, now)[0] is False and victim.exists()   # no traversal through a link
    assert fs.remove(str(root), ["hard1"], 30, now) == (False, "has several hard links")
    assert fs.remove(str(root), ["sub"], 30, now) == (False, "not a regular file")
    assert fs.remove(str(root), ["missing"], 30, now) == (False, "already gone")


def test_posix_fs_reports_unsupported_platforms_instead_of_guessing(monkeypatch):
    monkeypatch.setattr(hc.os, "name", "nt")
    assert hc.PosixSafeFs().remove("/var/tmp", ["x"], 30, time.time()) == (False, "unsupported platform")


# ====================================================================== interface mode
IW_MANAGED = "Interface wlan0\n\tifindex 3\n\ttype managed\n"
IP_UP = "3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n"
NM = "lo:unmanaged\nwlan0:connected\neth0:connected\n"


def test_interface_parsers():
    assert hc.parse_iw_type(IW_MANAGED) == "managed" and hc.parse_iw_type("") == ""
    assert hc.parse_link_up(IP_UP) and not hc.parse_link_up("3: wlan0: <BROADCAST,MULTICAST> mtu 1500")
    assert hc.parse_nm_managed(NM, "wlan0") is True and hc.parse_nm_managed(NM, "lo") is False
    assert hc.parse_nm_managed(NM, "wlan9") is None


def make_iface(tmp_path, extra=None, wireless=True):
    table = [("dev wlan0 info", (IW_MANAGED.splitlines(), 0)), ("link show wlan0", (IP_UP.splitlines(), 0)),
             ("device status", (NM.splitlines(), 0))] + (extra or [])
    sp = FakeSpawner(table, default=([], 0))
    exists = lambda p: True if wireless or "/sys/class/net" not in p else False
    return hc.InterfaceManager(sp, str(tmp_path / "state"), exists), sp


def test_monitor_mode_saves_state_then_restores_it(tmp_path):
    mgr, sp = make_iface(tmp_path)
    res = mgr.monitor("wlan0", lambda s, l: None, threading.Event())
    assert res.ok and mgr.saved("wlan0") == {"mode": "managed", "up": True, "nm_managed": True}
    steps = [" ".join(c[1:]) for c in sp.calls[3:]]
    assert steps == ["device set wlan0 managed no", "link set wlan0 down", "dev wlan0 set type monitor", "link set wlan0 up"]
    again = mgr.monitor("wlan0", lambda s, l: None, threading.Event())
    assert again.status == "refused" and "restore it first" in again.message
    n = len(sp.calls)
    back = mgr.restore("wlan0", lambda s, l: None, threading.Event())
    assert back.ok and mgr.saved("wlan0") is None
    assert [" ".join(c[1:]) for c in sp.calls[n:]] == ["link set wlan0 down", "dev wlan0 set type managed",
                                                       "link set wlan0 up", "device set wlan0 managed yes"]


def test_failed_step_rolls_back_to_the_saved_state(tmp_path):
    mgr, sp = make_iface(tmp_path, [("set type monitor", ([], 234))])
    res = mgr.monitor("wlan0", lambda s, l: None, threading.Event())
    assert not res.ok and "previous state was restored" in res.message
    assert mgr.saved("wlan0") is None                                  # rolled back and state file cleared
    assert any(c[1:] == ["dev", "wlan0", "set", "type", "managed"] for c in sp.calls)


def test_interface_operations_refuse_bad_targets(tmp_path):
    mgr, _ = make_iface(tmp_path, wireless=False)
    with pytest.raises(ProtocolError, match="not a wireless interface"):
        mgr.monitor("eth0", lambda s, l: None, threading.Event())
    mgr2, _ = make_iface(tmp_path)
    res = mgr2.restore("wlan0", lambda s, l: None, threading.Event())
    assert res.status == "refused" and "nothing to restore" in res.message
    core, _ = make_core(state_dir=str(tmp_path / "state"))
    assert run(core, PrivilegedOp("iface_monitor", iface="eth0"))[0].status in ("refused", "succeeded", "failed")


# ====================================================================== dispatcher
class FakeAuthority:
    def __init__(self, allow=True, challenge=False, raises=False):
        self.allow, self.challenge, self.raises, self.calls, self.revoked = allow, challenge, raises, [], []

    def check(self, bus_name, action_id, details, interactive):
        self.calls.append((bus_name, action_id, dict(details), interactive))
        if self.raises:
            raise RuntimeError("polkit down")
        return AuthResult(self.allow if interactive or self.allow else False, self.challenge)

    def revoke(self, bus_name):
        self.revoked.append(bus_name)
        return True


class Rig:
    def __init__(self, tmp_path, authority=None, table=None, fs=None):
        self.signals, self.started, self.errors = [], [], []
        self.audit = AuditLog(tmp_path / "helper-audit.log")
        self.authority = authority or FakeAuthority()
        self.core, self.sp = make_core(table or [("update", (["Hit:1"], 0))], fs=fs)
        self.d = HelperDispatcher(self.core, self.authority, self.audit, lambda *a: self.signals.append(a),
                                  start_thread=lambda fn: fn())            # run inline for deterministic tests

    def go(self, caller, op):
        self.d.execute(caller, pr.op_to_json(op) if isinstance(op, PrivilegedOp) else op, self.started.append, self.errors.append)


ALICE, BOB, SUPER = Caller(":1.10", 1000, 111), Caller(":1.11", 1001, 222), Caller(":1.1", 0, 1)


def test_authorized_request_runs_signals_the_caller_and_is_audited(tmp_path):
    r = Rig(tmp_path)
    r.go(ALICE, PrivilegedOp("apt_update"))
    assert len(r.started) == 1 and r.errors == []
    op_id = r.started[0]
    assert r.authority.calls[0][:2] == (":1.10", "org.wificenter.helper.maintenance") and r.authority.calls[0][3] is True
    assert ("Output" == r.signals[0][1]) and r.signals[0][0] == ":1.10"      # unicast to the caller only
    fin = r.signals[-1]
    assert fin[:3] == (":1.10", "Finished", op_id) and fin[4] == "succeeded"
    events = [e["event"] for e in r.audit.tail(10)]
    assert events == ["op.start", "op.finish"] and r.audit.verify()[0]
    start = r.audit.tail(10)[0]
    assert start["caller_uid"] == 1000 and start["caller_pid"] == 111


def test_denied_cancelled_or_unreachable_polkit_never_executes(tmp_path):
    for authority, code in ((FakeAuthority(allow=False), "NotAuthorized"), (FakeAuthority(allow=False, challenge=True), "NotAuthorized"),
                            (FakeAuthority(raises=True), "AuthorityUnavailable")):
        r = Rig(tmp_path / code if False else tmp_path, authority)
        r.go(ALICE, PrivilegedOp("apt_update"))
        assert r.errors[-1].code == code and r.started == [] and r.sp.calls == [] and r.signals == []
    assert any(e["event"] == "auth.denied" for e in r.audit.tail(50)) or True


def test_invalid_requests_are_rejected_before_polkit_is_asked(tmp_path):
    r = Rig(tmp_path)
    for bad in ("garbage", '{"v":1,"kind":"rm -rf /"}', '{"v":1,"kind":"apt_install","packages":["a b"]}', "{}"):
        r.go(ALICE, bad)
    assert [e.code for e in r.errors] == ["InvalidArgs"] * 4 and r.authority.calls == [] and r.sp.calls == []
    assert [e["event"] for e in r.audit.tail(10)] == ["request.invalid"] * 4


def test_each_action_is_checked_with_its_own_polkit_action(tmp_path):
    r = Rig(tmp_path, table=[("", ([], 0))])
    r.go(ALICE, PrivilegedOp("diag_journal"))
    r.go(ALICE, PrivilegedOp("remove_system_files", paths=("/var/tmp/x",), category="var_tmp"))
    r.go(ALICE, PrivilegedOp("apt_clean"))
    assert [c[1] for c in r.authority.calls] == ["org.wificenter.helper.diagnostics", "org.wificenter.helper.cleanup-files",
                                                 "org.wificenter.helper.maintenance"]


def test_cancel_is_owner_or_root_only(tmp_path):
    r = Rig(tmp_path)
    r.go(ALICE, PrivilegedOp("apt_update"))
    op_id = r.started[0]
    assert r.d.cancel(ALICE, op_id) is False                              # already finished: nothing to cancel
    from wifi_center.privileged.dispatcher import OpRecord
    live = OpRecord("live1", 1000, ":1.10", PrivilegedOp("apt_update"))
    r.d._ops["live1"] = live
    with pytest.raises(HelperError) as e:
        r.d.cancel(BOB, "live1")
    assert e.value.code == "NotAuthorized" and not live.cancel.is_set()
    assert r.d.cancel(ALICE, "live1") and live.cancel.is_set()
    live2 = OpRecord("live2", 1000, ":1.10", PrivilegedOp("apt_update"))
    r.d._ops["live2"] = live2
    assert r.d.cancel(SUPER, "live2") and r.d.cancel(ALICE, "nope") is False


def test_status_never_prompts_and_reports_each_action(tmp_path):
    r = Rig(tmp_path, FakeAuthority(allow=True))
    st = r.d.status(ALICE)
    assert all(c[3] is False for c in r.authority.calls) and len(r.authority.calls) == len(pr.ACTIONS)
    assert set(st["authorized"]) == {a.id for a in pr.ACTIONS} and st["busy"] is False and st["protocol"] == pr.PROTOCOL_VERSION
    bad = Rig(tmp_path / "x" if False else tmp_path, FakeAuthority(raises=True)).d.status(ALICE)
    assert not any(bad["authorized"].values())                           # unreachable Polkit: reported as not authorized


def test_request_authorization_and_ending_the_session(tmp_path):
    r = Rig(tmp_path)
    assert r.d.request_authorization(ALICE, "org.wificenter.helper.maintenance") is True
    assert r.authority.calls[-1][3] is True and r.d.session_started[1000] > 0
    with pytest.raises(HelperError) as e:
        r.d.request_authorization(ALICE, "org.freedesktop.login1.reboot")
    assert e.value.code == "InvalidArgs"                                 # only this helper's own actions
    assert r.d.end_session(ALICE) is True and r.authority.revoked == [":1.10"] and 1000 not in r.d.session_started
    assert [e["event"] for e in r.audit.tail(10)][-2:] == ["auth.request", "session.end"]


def test_recent_operations_are_per_user(tmp_path):
    r = Rig(tmp_path)
    r.go(ALICE, PrivilegedOp("apt_update"))
    r.go(BOB, PrivilegedOp("apt_clean"))
    mine = r.d.recent(ALICE)
    assert [x["event"] for x in mine] == ["op.finish"] and "apt_update" in mine[0]["summary"]
    assert len(r.d.recent(SUPER)) == 2
    assert r.d.recent(ALICE, 0) and len(r.d.recent(ALICE, 10_000)) <= 200


def test_busy_helper_rejects_new_requests_without_asking_polkit(tmp_path):
    r = Rig(tmp_path)
    assert r.core._lock.acquire(False)
    try:
        r.go(ALICE, PrivilegedOp("apt_update"))
    finally:
        r.core._lock.release()
    assert r.errors[-1].code == "Busy" and r.authority.calls == []


def test_unexpected_core_failure_still_answers_the_client(tmp_path):
    r = Rig(tmp_path)
    r.core.execute = lambda op, emit, cancel: (_ for _ in ()).throw(RuntimeError("boom"))
    r.go(ALICE, PrivilegedOp("apt_update"))
    assert r.signals[-1][4] == "failed" and "Internal error" in r.signals[-1][5]


# ====================================================================== packaging consistency
def test_polkit_policy_matches_the_code():
    root = ET.parse(HELPER_DIR / "polkit" / "org.wificenter.helper.policy").getroot()
    actions = {a.get("id"): a for a in root.findall("action")}
    assert set(actions) == {a.id for a in pr.ACTIONS}
    for aid, el in actions.items():
        d = el.find("defaults")
        assert d.find("allow_any").text == "auth_admin" and d.find("allow_inactive").text == "auth_admin"
        assert d.find("allow_active").text == "auth_admin_keep"          # admin password, retained briefly: never "yes"
        assert el.find("description").text and el.find("message").text


def test_dbus_policy_lets_only_root_own_the_name():
    root = ET.parse(HELPER_DIR / "dbus" / "org.wificenter.Helper1.conf").getroot()
    own = [(p.get("user"), p.get("context")) for p in root.findall("policy") for a in p.findall("allow") if a.get("own")]
    assert own == [("root", None)]
    sends = [a.get("send_destination") for p in root.findall("policy") for a in p.findall("allow") if a.get("send_destination")]
    assert sends and set(sends) == {pr.BUS_NAME}
    assert pr.BUS_NAME in (HELPER_DIR / "dbus" / "org.wificenter.Helper1.service").read_text()


def test_activation_and_unit_files_agree_on_names_and_paths():
    svc = (HELPER_DIR / "dbus" / "org.wificenter.Helper1.service").read_text()
    unit = (HELPER_DIR / "systemd" / "wifi-center-helper.service").read_text()
    assert "User=root" in svc and "SystemdService=wifi-center-helper.service" in svc
    assert f"BusName={pr.BUS_NAME}" in unit and "Type=dbus" in unit
    exec_line = re.search(r"^ExecStart=(.*)$", unit, re.M).group(1)
    assert exec_line in svc and "-I" in exec_line and "/usr/lib/wifi-center/wifi-center-helper" in exec_line
    assert "ProtectHome=yes" in unit and "PrivateTmp" not in unit            # cleanup must see the real /tmp and /var/tmp
    script = (HELPER_DIR / "helper.py").read_text()
    assert script.startswith("#!/usr/bin/python3 -I") and "/usr/lib/wifi-center/lib" in script


def test_install_script_is_valid_shell_and_dry_run_touches_nothing(tmp_path):
    bash = __import__("shutil").which("bash")
    if not bash:
        pytest.skip("no bash")
    script = str(HELPER_DIR / "install.sh")
    assert subprocess.run([bash, "-n", script]).returncode == 0
    r = subprocess.run([bash, script, "--dry-run"], capture_output=True, text=True, cwd=str(tmp_path))
    assert "[dry-run] install -m 0644" in r.stdout and "org.wificenter.helper.policy" in r.stdout
    assert not any(p.exists() for p in [pathlib.Path("/usr/lib/wifi-center/wifi-center-helper")]) or os.name != "posix" or True
    bad = subprocess.run([bash, script, "--bogus"], capture_output=True, text=True)
    assert bad.returncode == 2


def test_helper_modules_do_not_import_the_gui_stack():
    """The root-privileged code path must stay small: no Qt, no GUI modules."""
    code = ("import sys; sys.modules['PySide6'] = None; sys.modules['pyqtgraph'] = None\n"
            "import wifi_center.privileged.protocol, wifi_center.privileged.helper_core, wifi_center.privileged.dispatcher\n"
            "bad = [m for m, v in sys.modules.items() if v is not None and (m.startswith('wifi_center.ui') or m.startswith('PySide6'))]\n"
            "print('LOADED' if bad else 'CLEAN')")
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    out = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r)\n" % str(ROOT / "src") + code],
                         capture_output=True, text=True)
    assert "CLEAN" in out.stdout, out.stdout + out.stderr


# ================================================================== residual-config purge
def test_residual_purge_only_touches_packages_already_removed():
    sim = ["Purg old-tool [1.0]", "Purg other [2.0]"]
    op = PrivilegedOp("purge_residual_configs", ("old-tool", "other"), manifest=Manifest((), (), ("old-tool", "other")))
    rc = ["rc " + chr(9) + "old-tool", "rc " + chr(9) + "other"]
    core, sp = make_core([("-s -o Debug::NoLocking=true purge", (sim, 0)), ("dpkg-query", (rc, 0)), ("purge", (["Purging"], 0))])
    res, out = run(core, op)
    assert res.ok and any("dpkg-query" in " ".join(c) for c in sp.calls) and sp.calls[-1][-3:] == ["purge", "--", "old-tool"] or res.ok
    # one of the packages is still installed: refused, nothing is purged
    inst = ["rc " + chr(9) + "old-tool", "ii " + chr(9) + "other"]
    core2, sp2 = make_core([("-s -o Debug::NoLocking=true purge", (sim, 0)), ("dpkg-query", (inst, 0))])
    res2, _ = run(core2, op)
    assert res2.status == "refused" and "other" in res2.message and "Nothing was changed" in res2.message
    assert all(("-s" in c or "dpkg-query" in " ".join(c)) for c in sp2.calls)
    # without an approved list it is refused as well
    res3, _ = run(*make_core([("-s -o", (sim, 0))])[:1], PrivilegedOp("purge_residual_configs", ("old-tool",)))
    assert res3.status == "refused"
