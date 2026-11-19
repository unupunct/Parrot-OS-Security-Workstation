"""The package-management operations added for the Package Manager: reinstall, download-only, fix-broken, finish interrupted setup."""
import pytest

from tests.test_privileged import make_core, run
from wifi_center.privileged import helper_core as hc
from wifi_center.privileged import protocol as pr
from wifi_center.privileged.protocol import Manifest, PrivilegedOp, ProtocolError

REINSTALL_SIM = ("Inst htop [3.2.2-1] (3.2.2-1 Parrot 7 Echo Parakeet:parrot [amd64])" + chr(10)
                 + "0 upgraded, 0 newly installed, 0 reinstalled, 0 to remove and 0 not upgraded." + chr(10))
FIX_SIM = ("Inst libfoo [1.0] (1.1 Parrot:parrot [amd64])" + chr(10) + "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded." + chr(10))
ALWAYS = lambda p: True  # noqa: E731


def test_new_operations_are_known_and_belong_to_the_maintenance_permission():
    for k in ("apt_reinstall", "apt_download", "apt_fix_broken", "dpkg_configure"):
        assert k in pr.KINDS and pr.action_for(k) == "org.wificenter.helper.maintenance"
    assert {"apt_reinstall", "apt_download", "apt_fix_broken"} <= set(pr.APT_TRANSACTION_KINDS) and "dpkg_configure" not in pr.APT_TRANSACTION_KINDS


def test_packages_are_required_where_they_make_sense_and_validated():
    for kind in ("apt_reinstall", "apt_download"):
        with pytest.raises(ProtocolError):
            PrivilegedOp(kind)
        with pytest.raises(ProtocolError):
            PrivilegedOp(kind, ("--purge",))
        PrivilegedOp(kind, ("htop",))
    PrivilegedOp("apt_fix_broken")
    PrivilegedOp("dpkg_configure")


def test_exact_command_lines():
    re_ = hc.plan_commands(PrivilegedOp("apt_reinstall", ("htop",)), ALWAYS)[0].argv
    assert re_[0] == "/usr/bin/apt-get" and re_[-4:] == ("install", "--reinstall", "--", "htop") and "-y" in re_
    dl = hc.plan_commands(PrivilegedOp("apt_download", ("htop", "git")), ALWAYS)[0].argv
    assert dl[-5:] == ("install", "--download-only", "--", "htop", "git")
    fx = hc.plan_commands(PrivilegedOp("apt_fix_broken"), ALWAYS)[0].argv
    assert fx[-2:] == ("install", "-f")
    dp = hc.plan_commands(PrivilegedOp("dpkg_configure"), ALWAYS)[0]
    assert list(dp.argv) == ["/usr/bin/dpkg", "--configure", "-a", "--force-confold"]


def test_reinstall_is_simulated_as_root_and_refused_without_an_approved_manifest():
    op = PrivilegedOp("apt_reinstall", ("htop",), manifest=Manifest((), ("htop",), ()))
    core, sp = make_core([("-s -o Debug::NoLocking=true install --reinstall", (REINSTALL_SIM.splitlines(), 0)),
                          ("install --reinstall", (["Setting up htop"], 0))])
    res, out = run(core, op)
    assert res.ok and "-s" in sp.calls[0] and "-s" not in sp.calls[1] and sp.calls[1][-3:] == ["--reinstall", "--", "htop"]
    core2, sp2 = make_core([("-s -o", (REINSTALL_SIM.splitlines(), 0))])
    res2, _ = run(core2, PrivilegedOp("apt_reinstall", ("htop",)))
    assert res2.status == "refused" and all("-s" in c for c in sp2.calls)             # nothing approved: nothing ran
    # the real transaction pulls in something that was not approved -> refused
    sneaky = REINSTALL_SIM + "Inst evil-extra (1.0 Parrot:parrot [amd64])" + chr(10)
    core3, sp3 = make_core([("-s -o", (sneaky.splitlines(), 0))])
    res3, _ = run(core3, op)
    assert res3.status == "refused" and "evil-extra" in res3.message and all("-s" in c for c in sp3.calls)


def test_fix_broken_needs_an_approved_manifest_too():
    core, sp = make_core([("-s -o Debug::NoLocking=true install -f", (FIX_SIM.splitlines(), 0)), ("install -f", (["done"], 0))])
    assert run(core, PrivilegedOp("apt_fix_broken", manifest=Manifest((), ("libfoo",), ())))[0].ok
    core2, _ = make_core([("-s -o", (FIX_SIM.splitlines(), 0))])
    assert run(core2, PrivilegedOp("apt_fix_broken"))[0].status == "refused"


def test_dpkg_configure_runs_one_fixed_command_and_never_overrides_a_lock(tmp_path):
    core, sp = make_core([("dpkg --configure", (["Setting up foo (1.0) ..."], 0))])
    res, out = run(core, PrivilegedOp("dpkg_configure"))
    assert res.ok and sp.calls == [["/usr/bin/dpkg", "--configure", "-a", "--force-confold"]]
    proc = tmp_path / "proc"
    (proc / "123").mkdir(parents=True)
    (proc / "123" / "comm").write_text("apt-get")
    core2, sp2 = make_core(proc_root=str(proc))
    res2, _ = run(core2, PrivilegedOp("dpkg_configure"))
    assert res2.status == "refused" and "package manager" in res2.message.lower() and sp2.calls == []
