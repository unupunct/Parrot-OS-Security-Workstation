import json
import os
import time
from datetime import datetime, timezone

import pytest

from wifi_center.security.input_validation import ValidationError
from wifi_center.services import apt_service as apt
from wifi_center.services import package_service as pk
from wifi_center.services import software_sources as ss
from wifi_center.services import system_info_service as si
from wifi_center.services.cleanup_service import CATEGORIES, CleanupService, parse_dpkg_residual
from wifi_center.services.maintenance_service import MaintenanceService
from wifi_center.services.privileged_service import (ExecutionResult, PrivilegedOp, UnavailableBackend,
                                                     validate_package_name)
from wifi_center.services.process_runner import CommandResult


class FakeRunner:
    """Maps the start of an argv to stdout. Records every call."""

    def __init__(self, table=None):
        self.table = table or {}
        self.calls = []

    def __call__(self, argv, timeout=10):
        self.calls.append(list(argv))
        for prefix, out in self.table.items():
            if tuple(argv[:len(prefix)]) == prefix:
                if isinstance(out, CommandResult):
                    return out
                return CommandResult(tuple(argv), 0, out, "")
        return CommandResult(tuple(argv), 1, "", "unmapped", error="no fake")


UPGRADE = """Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be upgraded:
  libc6 openssl
2 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.
Inst libc6 [2.36-9] (2.36-9+deb12u4 Debian:12.4/stable-updates [amd64])
Inst openssl [3.0.11-1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])
Conf libc6 (2.36-9+deb12u4 Debian:12.4/stable-updates [amd64])
Conf openssl (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])
"""
DIST = """Calculating upgrade...
The following NEW packages will be installed:
  linux-image-6.5.0-2-amd64 libfoo2
The following packages will be REMOVED:
  parrot-tools-legacy libold1
The following packages have been kept back:
  gimp
The following packages will be upgraded:
  nmap
1 upgraded, 2 newly installed, 2 to remove and 1 not upgraded.
Need to get 87.4 MB of archives.
After this operation, 120 MB of additional disk space will be used.
Inst linux-image-6.5.0-2-amd64 (6.5.10-1 Parrot:6.1/lory [amd64])
Inst libfoo2 (1.2-1 Parrot:6.1/lory [amd64])
Remv parrot-tools-legacy [1.0-1]
Remv libold1 [0.9] [libfoo2:amd64 ]
Inst nmap [7.93-1] (7.94-3 Parrot:6.1/lory [amd64])
"""
AUTOREMOVE = """The following packages will be REMOVED:
  libjunk1 python3-orphan
0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.
After this operation, 15.3 MB disk space will be freed.
Remv libjunk1 [1.0]
Remv python3-orphan [2.1]
"""


# ---------------- transactions ----------------
def test_parse_upgrade_transaction():
    tx = apt.parse_transaction("upgrade", UPGRADE)
    assert [(c.name, c.old, c.new) for c in tx.upgrades] == [("libc6", "2.36-9", "2.36-9+deb12u4"),
                                                              ("openssl", "3.0.11-1", "3.0.11-1~deb12u2")]
    assert tx.counts == (2, 0, 0, 3) and tx.ok and not tx.is_empty and tx.upgrades[0].origin.startswith("Debian:12.4")
    assert apt.risk_flags(tx) == []


def test_parse_dist_upgrade_with_removals_and_flags():
    tx = apt.parse_transaction("dist-upgrade", DIST)
    assert [c.name for c in tx.installs] == ["linux-image-6.5.0-2-amd64", "libfoo2"]
    assert [c.name for c in tx.removes] == ["parrot-tools-legacy", "libold1"] and [c.name for c in tx.upgrades] == ["nmap"]
    assert tx.kept_back == ["gimp"] and tx.download == "87.4 MB" and tx.disk_change == "+120 MB"
    flags = " | ".join(apt.risk_flags(tx))
    assert "REMOVES 2 package(s)" in flags and "system-critical packages: parrot-tools-legacy" in flags
    assert "pulls in 2 new package(s)" in flags and "kept back" in flags


def test_parse_autoremove_and_errors():
    tx = apt.parse_transaction("autoremove", AUTOREMOVE)
    assert [c.name for c in tx.removes] == ["libjunk1", "python3-orphan"] and tx.disk_change == "-15.3 MB"
    bad = apt.parse_transaction("upgrade", "", "E: Could not get lock /var/lib/dpkg/lock-frontend")
    assert not bad.ok and "Could not get lock" in bad.error
    assert apt.parse_transaction("upgrade", "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.").is_empty


def test_risk_flags_catch_inconsistent_output():
    tx = apt.Transaction("upgrade", counts=(0, 0, 3, 0))     # APT says 3 removals but none were parsed
    assert any("does not match" in f for f in apt.risk_flags(tx))


def test_parse_upgradable():
    text = ("Listing...\nlibc6/stable-updates 2.36-9+deb12u4 amd64 [upgradable from: 2.36-9]\n"
            "nmap/lory 7.94-3 amd64 [upgradable from: 7.93-1]\nwarning line\n")
    assert [(c.name, c.old, c.new, c.origin) for c in apt.parse_upgradable(text)] == [
        ("libc6", "2.36-9", "2.36-9+deb12u4", "stable-updates"), ("nmap", "7.93-1", "7.94-3", "lory")]


# ---------------- planning is simulation only ----------------
def make_apt(table, tmp_path=None, which=lambda n: "/usr/bin/" + n):
    return apt.AptService(FakeRunner(table), which, root=tmp_path or apt.Path("/nonexistent-root"))


def test_plan_always_simulates_and_validates():
    r = FakeRunner({("apt-get",): DIST})
    svc = apt.AptService(r, lambda n: "/usr/bin/" + n)
    tx = svc.plan("dist-upgrade")
    assert tx.removes and r.calls[0][:4] == ["apt-get", "-s", "-o", "Debug::NoLocking=true"]
    svc.plan("install", ["nmap", "libfoo2:amd64"])
    assert r.calls[-1][-3:] == ["--", "nmap", "libfoo2:amd64"] and "-s" in r.calls[-1] and "-y" not in r.calls[-1]
    for evil in (["nmap; rm -rf /"], ["--purge"], ["-oAPT::x=1"], ["a b"], ["../x"], [""], ["Nmap"]):
        with pytest.raises(ValidationError):
            svc.plan("install", evil)
    with pytest.raises(ValueError):
        svc.plan("install", [])
    with pytest.raises(ValueError):
        svc.plan("full-system-wipe")


def test_plan_without_apt_or_when_apt_fails():
    assert not apt.AptService(FakeRunner(), lambda n: None).plan("upgrade").ok
    failing = apt.AptService(FakeRunner({("apt-get",): CommandResult(("apt-get",), 100, "", "E: Unable to locate package x")}),
                             lambda n: "/usr/bin/apt-get")
    tx = failing.plan("upgrade")
    assert not tx.ok and "Unable to locate package" in tx.error


def test_lock_detection_and_single_transaction(monkeypatch):
    class P:
        def __init__(self, name, pid): self.info = {"name": name, "pid": pid}
    monkeypatch.setattr(apt.psutil, "process_iter", lambda attrs=None: [P("bash", 1), P("apt-get", 42), P("dpkg", 43)])
    svc = apt.AptService(FakeRunner(), lambda n: "x")
    assert svc.lock_holders() == ["apt-get (pid 42)", "dpkg (pid 43)"]
    assert svc.begin_transaction() and not svc.begin_transaction()       # a second concurrent transaction is refused
    svc.end_transaction()
    assert svc.begin_transaction()
    svc.end_transaction()
    svc.end_transaction()                                                  # extra release is harmless


# ---------------- repositories / refresh time ----------------
SOURCES = """# Parrot
deb https://deb.parrot.sh/parrot lory main contrib non-free non-free-firmware
deb [signed-by=/usr/share/keyrings/x.gpg arch=amd64] http://example.org/repo lory main
#deb-src https://deb.parrot.sh/parrot lory main
# a plain comment line that is not a repository
deb-src https://deb.parrot.sh/parrot lory main
"""
DEB822 = """Types: deb
URIs: https://deb.parrot.sh/parrot
Suites: lory lory-security
Components: main contrib
Signed-By: /usr/share/keyrings/parrot.gpg

Types: deb
URIs: https://ppa.example.net/x
Suites: bookworm
Components: main
Enabled: no
"""


def test_parse_sources():
    repos = apt.parse_sources_list(SOURCES, "sources.list")
    active = [r for r in repos if r.enabled and r.kind == "deb"]
    assert [r.uri for r in active] == ["https://deb.parrot.sh/parrot", "http://example.org/repo"]
    assert active[0].components == ["main", "contrib", "non-free", "non-free-firmware"] and "signed-by" in active[1].options
    assert [r.enabled for r in repos if r.kind == "deb-src"] == [False, True]
    assert len(repos) == 4                                                 # the plain comment line is not a repository
    d = apt.parse_deb822_sources(DEB822, "parrot.sources")
    assert [(r.suite, r.enabled) for r in d] == [("lory", True), ("lory-security", True), ("bookworm", False)]


def test_repository_notes():
    repos = apt.parse_sources_list(SOURCES)
    notes = " ".join(apt.repository_notes(repos, "lory"))
    assert "plain http" in notes and "No enabled" not in notes
    assert "No enabled" in " ".join(apt.repository_notes([], "lory"))
    assert any("do not mention" in n for n in apt.repository_notes(
        apt.parse_sources_list("deb https://x.example/ bookworm main"), "lory"))


def test_repositories_and_last_refresh_from_a_root(tmp_path):
    etc = tmp_path / "etc/apt"
    (etc / "sources.list.d").mkdir(parents=True)
    (etc / "sources.list").write_text(SOURCES)
    (etc / "sources.list.d" / "extra.list").write_text("deb https://extra.example/ lory main\n")
    (etc / "sources.list.d" / "p.sources").write_text(DEB822)
    svc = make_apt({}, tmp_path)
    assert len(svc.repositories()) == 4 + 1 + 3
    assert svc.last_refresh() is None
    lists = tmp_path / "var/lib/apt/lists"
    lists.mkdir(parents=True)
    f = lists / "deb.parrot.sh_Release"
    f.write_text("x")
    os.utime(f, (1_700_000_000, 1_700_000_000))
    assert svc.last_refresh() == datetime.fromtimestamp(1_700_000_000, timezone.utc)
    stamp = tmp_path / "var/lib/apt/periodic/update-success-stamp"
    stamp.parent.mkdir(parents=True)
    stamp.write_text("")
    os.utime(stamp, (1_800_000_000, 1_800_000_000))
    assert svc.last_refresh() == datetime.fromtimestamp(1_800_000_000, timezone.utc)


# ---------------- packages ----------------
DPKG = ("ii \tnmap\t7.93+dfsg1-1\t4368\tThe Network Mapper\n"
        "rc \told-tool\t1.0\t12\tGone but configured\n"
        "ii \tlibc6\t2.36-9\t12000\tGNU C Library\n"
        "bad line\n")
POLICY = """nmap:
  Installed: 7.93+dfsg1-1
  Candidate: 7.94-3
  Version table:
     7.94-3 500
        500 https://deb.parrot.sh/parrot lory/main amd64 Packages
 *** 7.93+dfsg1-1 100
        100 /var/lib/dpkg/status
"""
SHOW = """Package: nmap
Version: 7.94-3
Priority: optional
Section: net
Maintainer: Debian Nmap Team
Installed-Size: 4400
Depends: libc6 (>= 2.34), libssl3 (>= 3.0.0), nmap-common (= 7.94-3)
Description: The Network Mapper
 Nmap is a utility for network exploration.
 .
 More text.
Homepage: https://nmap.org

Package: nmap
Version: 7.93-1
"""


def test_package_parsers():
    rows = pk.parse_dpkg_query(DPKG)
    assert [(r.name, r.status) for r in rows] == [("nmap", "installed"), ("old-tool", "config-files"), ("libc6", "installed")]
    assert rows[0].size_kb == 4368 and rows[0].summary == "The Network Mapper"
    assert [(r.name, r.summary) for r in pk.parse_apt_cache_search("nmap - The Network Mapper\nnmap-common - data\nnoise")] == [
        ("nmap", "The Network Mapper"), ("nmap-common", "data")]
    inst, cand, origins = pk.parse_policy(POLICY)
    assert (inst, cand) == ("7.93+dfsg1-1", "7.94-3") and origins == ["https://deb.parrot.sh/parrot lory/main amd64 (priority 500)"]
    f = pk.parse_show(SHOW)
    assert f["Version"] == "7.94-3" and "network exploration" in f["Description"] and f["Homepage"] == "https://nmap.org"


def test_package_service_search_details_and_validation():
    r = FakeRunner({("dpkg-query",): DPKG, ("apt",): "Listing...\nnmap/lory 7.94-3 amd64 [upgradable from: 7.93-1]\n",
                    ("apt-cache", "search"): "nmap - The Network Mapper\nnmap-common - data files\n",
                    ("apt-cache", "show"): SHOW, ("apt-cache", "policy"): POLICY})
    svc = pk.PackageService(apt.AptService(r, lambda n: "x"))
    inst = svc.installed()
    assert [p.name for p in inst] == ["nmap", "libc6"] and inst[0].upgradable and not inst[1].upgradable
    assert [p.name for p in svc.installed("network")] == ["nmap"]
    found = svc.search_available("nm.p")
    assert [(p.name, p.status) for p in found] == [("nmap", "installed"), ("nmap-common", "not-installed")]
    assert r.calls[-3][-1] == r"nm\.p" or any(c[-1] == r"nm\.p" for c in r.calls)          # regex metacharacters are escaped
    d = svc.details("nmap")
    assert d.status == "upgradable" and d.depends[0].startswith("libc6") and d.candidate == "7.94-3"
    for bad in ("nmap; ls", "a|b", "", "x" * 81, "$(id)", "-o"):
        with pytest.raises(ValidationError):
            svc.search_available(bad) if bad != "-o" else svc.validate_query("-o -x")
    with pytest.raises(ValidationError):
        svc.details("Bad Name")


# ---------------- privileged interface ----------------
def test_privileged_ops_are_validated_and_backend_is_honest():
    for bad in ("apt-get install x", "rm", "sudo", "apt_update; id"):
        with pytest.raises(ValidationError):
            PrivilegedOp(bad)
    with pytest.raises(ValidationError):
        PrivilegedOp("apt_install", packages=("good-pkg", "bad pkg"))
    with pytest.raises(ValidationError):
        PrivilegedOp("apt_install")
    with pytest.raises(ValidationError):
        PrivilegedOp("remove_system_files")
    assert PrivilegedOp("apt_install", packages=("nmap",)).packages == ("nmap",)
    assert validate_package_name("libstdc++6") == "libstdc++6"
    b = UnavailableBackend()
    res = b.execute(PrivilegedOp("apt_update"))
    assert not b.available() and not res.executed and "Nothing was changed" in res.message


# ---------------- maintenance history ----------------
def test_maintenance_history_records_filters_and_exports(controller):
    m = controller.maintenance
    m.record("Upgrade", "upgrade", "success", packages=["libc6", "openssl"])
    m.record("Cleanup", "cleanup", "dry run", files_removed=12)
    m.record("=evil()", "upgrade", "failed", errors="E: lock")
    assert [e["name"] for e in m.entries(op_type="upgrade")] == ["=evil()", "Upgrade"]
    assert m.entries(result="dry run")[0]["files_removed"] == 12
    assert m.last("upgrade")["name"] == "Upgrade" and m.last("cleanup") is None and m.last("cleanup", "dry run")
    assert "libc6\nopenssl" == m.entries(op_type="upgrade")[1]["packages_changed"]
    csv_text = m.export("csv")
    assert "'=evil()" in csv_text and csv_text.splitlines()[0].startswith("id,name,op_type")
    assert len(json.loads(m.export("json"))) == 3
    with pytest.raises(ValueError):
        m.record("x", "y", "maybe")
    with pytest.raises(ValueError):
        m.export("xml")


# ---------------- system information ----------------
CPUINFO = "processor : 0\nvendor_id : GenuineIntel\nmodel name\t: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz\n"
UNITS = ("  ssh.service loaded active running OpenBSD Secure Shell server\n"
         "● bad.service loaded failed failed A broken thing\n"
         "NetworkManager.service loaded active running Network Manager\nweird line\n")


def test_system_info_parsers():
    assert si.parse_cpuinfo(CPUINFO).startswith("Intel(R) Core(TM) i7")
    units = si.parse_systemctl_units(UNITS)
    assert [(u.name, u.active, u.sub) for u in units] == [("ssh.service", "active", "running"),
                                                          ("bad.service", "active"[:0] or "failed", "failed"),
                                                          ("NetworkManager.service", "active", "running")]
    assert units[0].description.startswith("OpenBSD")
    assert si.detect_desktop({"XDG_CURRENT_DESKTOP": "MATE", "XDG_SESSION_TYPE": "x11"}) == "MATE (x11)"
    assert si.detect_desktop({}).startswith("unknown")


def test_system_info_collect(controller, tmp_path, monkeypatch):
    osr = tmp_path / "os-release"
    osr.write_text('PRETTY_NAME="Parrot Security 6.1 (lory)"\nID=parrot\nID_LIKE=debian\nVERSION_CODENAME=lory\n')
    cpu = tmp_path / "cpuinfo"
    cpu.write_text(CPUINFO)
    from wifi_center.services.system_service import SystemService
    monkeypatch.setattr("shutil.which", lambda n: "/bin/" + n)
    r = FakeRunner({("systemctl", "list-units", "--type=service", "--state=running"): UNITS.splitlines()[0] + "\n",
                    ("systemctl", "list-units", "--type=service", "--state=failed"): UNITS.splitlines()[1] + "\n",
                    ("systemd-analyze",): "Startup finished in 5.1s"})
    svc = si.SystemInfoService(SystemService(osr), make_apt({}), r, osr, cpu, {"XDG_CURRENT_DESKTOP": "MATE"})
    rep = svc.collect()
    assert rep.is_parrot and rep.codename == "lory" and rep.cpu_model.startswith("Intel")
    assert [u.name for u in rep.running] == ["ssh.service"] and [u.name for u in rep.failed] == ["bad.service"]
    assert rep.desktop == "MATE" and rep.boot_analysis.startswith("Startup finished") and rep.mem_total > 0
    assert rep.uptime_seconds > 0 and rep.disks and rep.interfaces


# ---------------- software sources ----------------
FLATPAK_LIST = "org.gimp.GIMP\t2.10.34\tflathub\ncom.valvesoftware.Steam\t1.0.0\tflathub\n"
SNAP_LIST = "Name  Version  Rev  Tracking  Publisher  Notes\ncore22  20231123  1033  latest/stable  canonical✓  base\nhello  2.10  42  latest/stable  canonical✓  -\n"
SNAP_REFRESH = "Name  Version  Rev  Size  Publisher  Notes\nhello  2.11  43  70kB  canonical✓  -\n"


def sources(table, tmp_path=None, which=lambda n: "/usr/bin/" + n, apt_table=None):
    runner = FakeRunner(table)
    return ss.SoftwareSources(make_apt(apt_table or {}), runner, which, appimage_dirs=[tmp_path] if tmp_path else []), runner


def test_flatpak_detects_without_network_and_checks_only_on_request():
    s, r = sources({("flatpak", "list"): FLATPAK_LIST,
                    ("flatpak", "remote-ls"): "org.gimp.GIMP\t2.10.36\n"})
    rep = s.flatpak()
    assert [i.name for i in rep.items] == ["org.gimp.GIMP", "com.valvesoftware.Steam"] and rep.updates == 0
    assert all(i.status == ss.UNKNOWN for i in rep.items) and not any("remote-ls" in c for c in r.calls)
    rep = s.flatpak(check_updates=True)
    assert rep.updates == 1 and rep.items[0].status == ss.UPDATE and rep.items[0].available == "2.10.36"
    assert rep.items[1].status == ss.UP_TO_DATE and rep.last_check


def test_snap_and_missing_sources():
    s, r = sources({("snap", "list"): SNAP_LIST, ("snap", "refresh"): SNAP_REFRESH})
    rep = s.snap(check_updates=True)
    assert {i.name: i.status for i in rep.items} == {"core22": ss.UP_TO_DATE, "hello": ss.UPDATE}
    absent, _ = sources({}, which=lambda n: None)
    for rep in (absent.flatpak(), absent.snap(), absent.pipx(), absent.git({})):
        assert not rep.present and rep.note
    broken, _ = sources({("flatpak", "list"): CommandResult(("flatpak",), 1, "", "boom")})
    assert broken.flatpak().error == "boom"


def test_pipx_git_and_appimage(tmp_path):
    pipx = json.dumps({"venvs": {"sherlock": {"metadata": {"main_package": {"package": "sherlock-project", "package_version": "0.14"}}}}})
    s, _ = sources({("pipx", "list"): pipx})
    assert [(i.name, i.installed) for i in s.pipx().items] == [("sherlock-project", "0.14")]
    repo = tmp_path / "tool"
    (repo / ".git").mkdir(parents=True)
    head = "a" * 40
    s2, r2 = sources({("git", "-C", str(repo), "describe"): "v1.2-3-gabc\n", ("git", "-C", str(repo), "rev-parse"): head + "\n",
                      ("git", "-C", str(repo), "ls-remote"): ("b" * 40) + "\tHEAD\n"})
    rep = s2.git({"tool": str(repo), "gone": str(tmp_path / "nope")})
    assert [i.name for i in rep.items] == ["tool"] and rep.items[0].status == ss.UNKNOWN
    assert not any("ls-remote" in c for c in r2.calls)                       # no network without an explicit check
    assert s2.git({"tool": str(repo)}, check_remote=True).items[0].status == ss.UPDATE
    (tmp_path / "App-1.0.AppImage").write_bytes(b"x" * 2048)
    (tmp_path / "notes.txt").write_text("x")
    ai = ss.SoftwareSources(make_apt({}), FakeRunner(), lambda n: None, appimage_dirs=[tmp_path]).appimages()
    assert [i.name for i in ai.items] == ["App-1.0.AppImage"] and "never do that" not in ai.note and "will not" in ai.note


def test_apt_source_uses_cached_lists():
    s, r = sources({}, apt_table={("apt", "list"): "Listing...\nnmap/lory 7.94-3 amd64 [upgradable from: 7.93-1]\n"})
    rep = s.apt()
    assert rep.updates == 1 and rep.items[0].installed == "7.93-1" and rep.items[0].available == "7.94-3"
    assert "cached" in rep.note or "never been refreshed" in rep.note


# ---------------- cleanup ----------------
def make_cleanup(controller, tmp_path, runner=None):
    now = 2_000_000_000.0
    home = tmp_path / "home"
    dirs = {"tmp": tmp_path / "tmp", "var_tmp": tmp_path / "vartmp", "var_log": tmp_path / "varlog",
            "apt_cache": tmp_path / "aptcache"}
    for d in (home, *dirs.values()):
        d.mkdir(parents=True, exist_ok=True)
    app_logs = tmp_path / "applogs"
    app_logs.mkdir()
    svc = CleanupService(controller.maintenance, make_apt({}), UnavailableBackend(), runner or FakeRunner(), home,
                         dirs["tmp"], dirs["var_tmp"], dirs["var_log"], dirs["apt_cache"], app_logs, clock=lambda: now)
    return svc, home, dirs, app_logs, now


def put(path, size=100, age_days=0, now=2_000_000_000.0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    t = now - age_days * 86400
    os.utime(path, (t, t))
    return path


def scans_by_id(svc):
    return {s.category.id: s for s in svc.scan()}


def test_scan_finds_only_eligible_files_and_explains_why(controller, tmp_path):
    svc, home, d, logs, now = make_cleanup(controller, tmp_path)
    old_tmp, new_tmp = put(d["tmp"] / "old.dat", 500, 10), put(d["tmp"] / "new.dat", 500, 1)
    put(d["var_tmp"] / "x.bin", 70, 40)
    put(d["var_tmp"] / "fresh.bin", 70, 5)
    put(d["apt_cache"] / "a_1.0_amd64.deb", 1000)
    put(d["apt_cache"] / "partial" / "b.deb.part", 10)
    put(d["apt_cache"] / "lock", 0)
    put(d["var_log"] / "syslog.1", 30, 90)
    put(d["var_log"] / "syslog", 30, 90)               # the live log: never a candidate
    put(d["var_log"] / "auth.log.2.gz", 30, 5)         # too recent
    put(logs / "wifi-center.log.3", 20, 60)
    put(logs / "wifi-center.log", 20, 60)
    put(logs / "audit.log", 20, 60)
    put(home / ".cache/thumbnails/normal/t.png", 200)
    put(home / ".cache/pip/http/p.whl", 300)
    put(home / ".cache/mozilla/firefox/profile.db", 999)      # not in the allow-list
    put(home / "Documents/report.docx", 999, 400)             # user documents are never scanned
    s = scans_by_id(svc)
    names = lambda cid: sorted(os.path.basename(i.path) for i in s[cid].items)
    uid_ok = hasattr(os, "getuid")
    assert names("tmp_user") == (["old.dat"] if uid_ok else ["old.dat"])
    assert names("var_tmp") == ["x.bin"] and names("apt_cache") == ["a_1.0_amd64.deb", "b.deb.part"]
    assert names("logs_system") == ["syslog.1"] and names("logs_user") == ["wifi-center.log.3"]
    assert names("thumbnails") == ["t.png"] and names("app_caches") == ["p.whl"]
    assert s["apt_cache"].total_size == 1010 and s["tmp_user"].total_size == 500
    for c in CATEGORIES:
        assert c.why_safe and (c.id == "residual_configs") == (not c.default_selected)
    assert new_tmp.exists() and old_tmp.exists()                 # scanning never deletes


def test_dry_run_is_default_and_removes_nothing(controller, tmp_path):
    svc, home, d, logs, now = make_cleanup(controller, tmp_path)
    f = put(home / ".cache/thumbnails/t.png", 200)
    res = svc.clean(svc.scan(), ["thumbnails"])
    assert res[0].dry_run and res[0].removed == 1 and res[0].freed == 200 and f.exists()
    assert controller.maintenance.entries()[0]["result"] == "dry run"


def test_real_cleanup_of_user_categories_and_history(controller, tmp_path):
    svc, home, d, logs, now = make_cleanup(controller, tmp_path)
    a = put(home / ".cache/thumbnails/a.png", 200)
    b = put(home / ".cache/pip/b.whl", 300)
    keep = put(home / ".cache/mozilla/keep.db", 50)
    doc = put(home / "Documents/keep.txt", 50)
    res = {r.category: r for r in svc.clean(svc.scan(), ["thumbnails", "app_caches"], dry_run=False)}
    assert not a.exists() and not b.exists() and keep.exists() and doc.exists()
    assert res["thumbnails"].removed == 1 and res["app_caches"].freed == 300
    last = controller.maintenance.entries()[0]
    assert last["op_type"] == "cleanup" and last["result"] == "success" and last["files_removed"] == 1


def test_deletion_gate_blocks_everything_outside_the_allowlist(controller, tmp_path):
    svc, home, d, logs, now = make_cleanup(controller, tmp_path)
    inside = put(home / ".cache/thumbnails/x.png", 10)
    outside = put(tmp_path / "precious.txt", 10)
    doc = put(home / "Documents/d.txt", 10)
    assert svc._is_deletable("thumbnails", str(inside))
    for evil in (outside, doc, home / ".cache/thumbnails/../../Documents/d.txt", home / ".cache/thumbnails"):
        assert not svc._is_deletable("thumbnails", str(evil))
    assert not svc._is_deletable("apt_cache", str(inside)) and not svc._is_deletable("nonexistent", str(inside))
    # a tampered scan result (e.g. list edited between scan and clean) cannot make the service delete anything else
    scan = svc.scan(["thumbnails"])[0]
    scan.items.append(type(scan.items[0])(str(outside), 10)) if scan.items else scan.items.append(
        __import__("wifi_center.services.cleanup_service", fromlist=["Candidate"]).Candidate(str(outside), 10))
    res = svc.clean([scan], ["thumbnails"], dry_run=False)
    assert outside.exists() and doc.exists() and any("skipped" in e for e in res[0].errors)


def test_symlinks_are_never_followed_or_deleted_through(controller, tmp_path):
    svc, home, d, logs, now = make_cleanup(controller, tmp_path)
    target = put(tmp_path / "target_dir" / "victim.txt", 10)
    link_dir = home / ".cache/thumbnails/linkdir"
    link_dir.parent.mkdir(parents=True)
    try:
        os.symlink(target.parent, link_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    scan = svc.scan(["thumbnails"])[0]
    assert scan.count == 0                                     # the link is not walked
    assert not svc._is_deletable("thumbnails", str(link_dir / "victim.txt"))
    svc.clean([scan], ["thumbnails"], dry_run=False)
    assert target.exists()


def test_root_categories_go_to_the_backend_and_report_honestly(controller, tmp_path):
    svc, home, d, logs, now = make_cleanup(controller, tmp_path)
    f = put(d["apt_cache"] / "x.deb", 500)
    res = svc.clean(svc.scan(["apt_cache"]), ["apt_cache"], dry_run=False)
    assert f.exists() and not res[0].executed and res[0].removed == 0 and "Nothing was changed" in res[0].message
    e = controller.maintenance.entries()[0]
    assert e["result"] == "not executed" and "privileged helper" in e["errors"]

    class Recording:
        name = "rec"
        ops = []
        def available(self): return True
        def explain_unavailable(self): return ""
        def execute(self, op):
            Recording.ops.append(op)
            return ExecutionResult(True, True, "done")
    svc.backend = Recording()
    out = svc.clean(svc.scan(["apt_cache", "var_tmp"]), ["apt_cache"], dry_run=False)
    assert out[0].executed and out[0].removed == 1 and Recording.ops[0].kind == "apt_clean"


def test_autoremove_and_residual_scans_use_simulation_and_dpkg(controller, tmp_path):
    runner = FakeRunner({("dpkg-query",): "ii  nmap\nrc  old-tool\nrc  other-tool\n"})
    svc, home, d, logs, now = make_cleanup(controller, tmp_path, runner)
    svc._apt = make_apt({("apt-get",): AUTOREMOVE})
    s = scans_by_id(svc)
    assert [i.path for i in s["autoremove"].items] == ["libjunk1", "python3-orphan"] and "15.3 MB" in s["autoremove"].note
    assert [i.path for i in s["residual_configs"].items] == ["old-tool", "other-tool"]
    assert parse_dpkg_residual("rc  a\nii  b\nrc c") == ["a", "c"]
    assert svc._apt._run_cmd is not None and any(c[:2] == ["apt-get", "-s"] for c in svc._apt._run_cmd.calls)
