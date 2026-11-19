import json
import sys
from pathlib import Path
from dataclasses import replace

import pytest

from wifi_center.integrations.base import (Dependency, Health, LaunchMethod, LaunchRequest, Operation,
                                           SystemProbe, ToolIntegration, ToolProfile, parse_version)
from wifi_center.integrations.catalog import CATEGORIES, PROFILES, profile_by_id
from wifi_center.integrations.registry import build_all, build_integration
from wifi_center.security.audit_log import AuditLog
from wifi_center.security.input_validation import (ValidationError, validate_absolute_path, validate_cidr,
                                                   validate_executable, validate_hostname, validate_ip,
                                                   validate_within)
from wifi_center.security.operation_policy import PolicyViolation, authorize
from wifi_center.services.process_runner import CommandResult


class FakeProbe(SystemProbe):
    def __init__(self, executables=None, packages=None, outputs=None, existing=(), modules=()):
        self.executables = executables or {}
        self.packages = packages or {}
        self.outputs = outputs or {}       # first argv element -> stdout
        self.existing = {str(Path(e)) for e in existing}  # normalise separators (tests also run on Windows)
        self.modules = set(modules)
        self.ran = []

    def which(self, name):
        return self.executables.get(name)

    def dpkg_version(self, package):
        return self.packages.get(package)

    def python_module(self, module):
        return module in self.modules

    def run(self, argv, timeout=10.0):
        self.ran.append(list(argv))
        out = self.outputs.get(argv[0])
        if out is None:
            return CommandResult(tuple(argv), 1, "", "", error="nope")
        return CommandResult(tuple(argv), 0, out, "")

    def path_exists(self, path):
        return str(Path(path)) in self.existing


# ---------- catalog ----------
def test_catalog_covers_required_tools():
    ids = {p.id for p in PROFILES}
    assert ids == {"aircrack-ng", "kismet", "wireshark", "tshark", "sparrow-wifi", "wifite", "fern-wifi-cracker",
                   "pixiewps", "spooftooph", "bluemaho", "nmap", "burpsuite", "nikto", "sqlmap", "metasploit",
                   "john", "pskracker", "bloodhound-ce", "wifi-audit-tool"}
    assert len(ids) == len(PROFILES)
    assert all(p.category in CATEGORIES for p in PROFILES)
    assert all(p.docs_url.startswith("https://") and p.source_url.startswith("https://") for p in PROFILES)
    assert all(p.install_hint for p in PROFILES)


def test_restricted_tools_expose_no_operations():
    restricted = {p.id for p in PROFILES if p.restricted}
    assert {"aircrack-ng", "wifite", "fern-wifi-cracker", "pixiewps", "spooftooph", "bluemaho", "sqlmap",
            "metasploit", "pskracker", "wifi-audit-tool"} <= restricted
    for p in PROFILES:
        if p.restricted:
            assert p.operations == () and p.restriction_note, p.id


def test_no_operation_uses_forbidden_executable_or_free_form_args():
    for p in PROFILES:
        for op in p.operations:
            assert all(a in ("--version", "-Version", "--help") or op.method == LaunchMethod.DESKTOP
                       for a in op.args), (p.id, op.args)


# ---------- version parsing ----------
@pytest.mark.parametrize("text,regex,expected", [
    ("Nmap version 7.94SVN ( https://nmap.org )", r"Nmap version (\S+)", "7.94SVN"),
    ("TShark (Wireshark) 4.2.2 (Git v4.2.2)", None, "4.2.2"),
    ("Kismet 2023-07-R1", r"Kismet\s+(\S+)", "2023-07-R1"),
    ("1.7.2#stable", None, "1.7.2#stable".split("#")[0]),
    ("no version here", None, None),
    ("", None, None),
])
def test_parse_version(text, regex, expected):
    assert parse_version(text, regex) == expected


# ---------- detection ----------
def test_detect_installed_via_path_and_version_from_output():
    probe = FakeProbe({"nmap": "/usr/bin/nmap"}, outputs={"/usr/bin/nmap": "Nmap version 7.94 ( x )"})
    integ = build_integration("nmap", probe)
    d = integ.detect_installation()
    assert d.installed and d.path == "/usr/bin/nmap" and d.via == "path"
    assert integ.get_version() == "7.94"
    assert probe.ran == [["/usr/bin/nmap", "--version"]]


def test_version_falls_back_to_package_metadata():
    probe = FakeProbe({"nmap": "/usr/bin/nmap"}, packages={"nmap": "7.93+dfsg1-1"})
    assert build_integration("nmap", probe).get_version() == "7.93+dfsg1-1"


def test_detect_via_package_only():
    probe = FakeProbe(packages={"kismet": "2023.07.R1-1"})
    d = build_integration("kismet", probe).detect_installation()
    assert d.installed and d.via == "package" and d.path is None


def test_not_installed():
    integ = build_integration("nmap", FakeProbe())
    assert not integ.detect_installation().installed
    assert integ.get_version() is None
    assert integ.get_health_status().level == Health.MISSING


def test_restricted_tool_version_is_never_executed():
    probe = FakeProbe({"aircrack-ng": "/usr/bin/aircrack-ng"}, packages={"aircrack-ng": "1:1.7-5"})
    integ = build_integration("aircrack-ng", probe)
    assert integ.get_version() == "1:1.7-5"
    assert probe.ran == []  # no version_args => nothing executed


def test_git_checkout_detection_and_describe():
    probe = FakeProbe(outputs={"git": "v1.2-3-gabc\n"},
                      existing={"/opt/sw/wifi_audit.py", "/opt/sw", "/opt/sw/.git"})
    integ = build_integration("wifi-audit-tool", probe, {"install_path": "/opt/sw"})
    d = integ.detect_installation()
    assert d.installed and d.via == "config"
    assert integ.get_version() == "v1.2-3-gabc"


def test_config_override_and_validation():
    probe = FakeProbe(existing={"/home/u/nmap"})
    integ = build_integration("nmap", probe, {"executable_override": "/home/u/nmap"})
    assert integ.detect_installation().via == "config"
    bad = build_integration("nmap", FakeProbe(), {"executable_override": "/nope"})
    assert bad.validate_configuration()
    wrong_dir = build_integration("wifi-audit-tool", FakeProbe(existing={"/x"}), {"install_path": "/x"})
    assert "wifi_audit.py" in wrong_dir.validate_configuration()[0]


# ---------- dependencies / health ----------
def test_dependency_checks_and_health():
    probe = FakeProbe({"wifi_audit.py": "/x/wifi_audit.py", "iw": "/usr/sbin/iw"})
    integ = build_integration("wifi-audit-tool", probe)
    deps = {d.dependency.name: d.satisfied for d in integ.check_dependencies()}
    assert deps == {"airodump-ng": False, "aireplay-ng": False, "iw": True, "colorama": False}
    h = integ.get_health_status()
    assert h.level == Health.ERROR and "airodump-ng" in h.detail


def test_optional_dependency_gives_warning_not_error():
    probe = FakeProbe({"wireshark": "/usr/bin/wireshark"})
    assert build_integration("wireshark", probe).get_health_status().level == Health.WARNING
    probe2 = FakeProbe({"wireshark": "/usr/bin/wireshark", "tshark": "/usr/bin/tshark"})
    assert build_integration("wireshark", probe2).get_health_status().level == Health.OK


def test_bloodhound_docker_states():
    none = build_integration("bloodhound-ce", FakeProbe())
    assert not none.detect_installation().installed
    no_compose = FakeProbe({"docker": "/usr/bin/docker"}, outputs={"docker": "specterops/bloodhound\n"})
    # same fake output for every docker call -> compose "works"; image list matches
    integ = build_integration("bloodhound-ce", no_compose)
    d = integ.detect_installation()
    assert d.installed and d.via == "docker"
    assert integ.check_dependencies()[0].satisfied


def test_all_integrations_work_on_empty_system():
    for tid, integ in build_all(FakeProbe()).items():
        assert integ.get_health_status().level == Health.MISSING, tid
        assert isinstance(integ.get_capabilities(), list)


# ---------- launching / policy ----------
def test_launch_builds_declared_request_only():
    probe = FakeProbe({"nmap": "/usr/bin/nmap"})
    integ = build_integration("nmap", probe)
    req = integ.launch_supported_operation("version", None)
    assert req.argv == ("/usr/bin/nmap", "--version") and req.method == LaunchMethod.CLI
    with pytest.raises(ValueError):
        integ.launch_supported_operation("scan", None)
    with pytest.raises(ValueError):
        integ.launch_supported_operation("version", {"extra": "--script x"})


def test_restricted_tool_cannot_launch():
    probe = FakeProbe({"sqlmap": "/usr/bin/sqlmap"})
    with pytest.raises(ValueError):
        build_integration("sqlmap", probe).launch_supported_operation("version", None)


def test_policy_denies_restricted_and_tampered_requests():
    nmap = profile_by_id("nmap")
    good = LaunchRequest("nmap", "version", ("/usr/bin/nmap", "--version"), LaunchMethod.CLI, 10)
    authorize(nmap, good)
    for bad in (
        replace(good, argv=("/usr/bin/nmap", "--script", "vuln")),
        replace(good, operation_id="scan"),
        replace(good, argv=("/usr/bin/sudo", "--version")),
        replace(good, tool_id="kismet"),
        replace(good, method=LaunchMethod.DESKTOP),
        replace(good, argv=()),
    ):
        with pytest.raises(PolicyViolation):
            authorize(nmap, bad)
    sqlmap = profile_by_id("sqlmap")
    with pytest.raises(PolicyViolation):
        authorize(sqlmap, LaunchRequest("sqlmap", "version", ("/usr/bin/sqlmap", "--version"), LaunchMethod.CLI, 5))


def test_policy_blocks_forbidden_executable_even_with_declared_op():
    evil = ToolProfile(id="x", name="X", description="", category="c", executables=("aireplay-ng",),
                       docs_url="https://x", source_url="https://x", install_hint="",
                       operations=(Operation("run", "Run", "", LaunchMethod.CLI, ()),))
    with pytest.raises(PolicyViolation):
        authorize(evil, LaunchRequest("x", "run", ("/usr/sbin/aireplay-ng",), LaunchMethod.CLI, 5))


def test_parse_and_export_results():
    integ = ToolIntegration(profile_by_id("nmap"), FakeProbe())
    out = integ.export_results("a\n\nb\n")
    assert out["lines"] == 2 and out["tool"] == "nmap"
    json.dumps(out)


# ---------- validation ----------
def test_path_validation(tmp_path):
    f = tmp_path / "f"
    f.write_text("x")
    assert validate_absolute_path(str(f), kind="file") == f
    for bad in ("", "relative/x", str(tmp_path / ".." / "x"), "/x\x00y", str(tmp_path / "nope")):
        with pytest.raises(ValidationError):
            validate_absolute_path(bad)
    with pytest.raises(ValidationError):
        validate_absolute_path(str(f), kind="dir")


@pytest.mark.skipif(sys.platform == "win32", reason="exec bit is POSIX only")
def test_validate_executable_requires_exec_bit(tmp_path):
    f = tmp_path / "f"
    f.write_text("x")
    f.chmod(0o644)
    with pytest.raises(ValidationError):
        validate_executable(str(f))
    f.chmod(0o755)
    validate_executable(str(f))


def test_traversal_guard(tmp_path):
    (tmp_path / "ok").mkdir()
    assert validate_within(tmp_path, "ok").name == "ok"
    for bad in ("../x", "ok/../../x"):
        with pytest.raises(ValidationError):
            validate_within(tmp_path, bad)


def test_network_validators():
    assert validate_ip("192.168.1.1") == "192.168.1.1"
    assert validate_cidr("10.0.0.5/24") == "10.0.0.0/24"
    with pytest.raises(ValidationError):
        validate_cidr("10.0.0.0/8", max_hosts=1024)
    for bad in ("999.1.1.1", "a b", "1.1.1.1; ls"):
        with pytest.raises(ValidationError):
            validate_ip(bad)
    assert validate_hostname("Example.COM") == "example.com"
    for bad in ("-bad.com", "a..b", "x;y.com", ""):
        with pytest.raises(ValidationError):
            validate_hostname(bad)


# ---------- audit log ----------
def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    for i in range(3):
        log.record("e", n=i)
    assert log.verify() == (True, 3)
    last = log.tail(1)[0]["hash"]
    assert AuditLog(tmp_path / "audit.log").record("e2")["prev"] == last  # chain resumes after restart
    assert log.verify() == (True, 4)
    log = AuditLog(tmp_path / "audit.log")
    lines = (tmp_path / "audit.log").read_text().splitlines()
    lines[1] = lines[1].replace('"n": 1', '"n": 9')
    assert lines[1] != json.dumps({})
    (tmp_path / "audit.log").write_text("\n".join(lines) + "\n")
    assert log.verify()[0] is False


# ---------- tool manager ----------
def test_tool_manager_scan_persists_and_summarises(controller):
    from wifi_center.services.tool_manager import ToolManager
    probe = FakeProbe({"nmap": "/usr/bin/nmap", "tshark": "/usr/bin/tshark", "wireshark": "/usr/bin/wireshark"},
                      outputs={"/usr/bin/nmap": "Nmap version 7.94", "/usr/bin/tshark": "TShark 4.2.2",
                               "/usr/bin/wireshark": "Wireshark 4.2.2"})
    tm = ToolManager(controller.db, probe)
    assert tm.summary()["scanned"] == 0
    res = tm.scan_all()
    assert len(res) == len(PROFILES)
    s = tm.summary()
    assert s["total"] == len(PROFILES) and s["installed"] == 3 and s["healthy"] == 3
    row = controller.db.query_one("SELECT version, installed FROM tools WHERE id='nmap'")
    assert row["version"] == "7.94" and row["installed"] == 1
    tm.scan_all()
    assert controller.db.query_one("SELECT COUNT(*) n FROM tool_versions WHERE tool_id='nmap'")["n"] == 1
    assert controller.db.query_one("SELECT status FROM integration_health WHERE tool_id='kismet'")["status"] == "missing"


def test_tool_manager_config_roundtrip_and_validation(controller, tmp_path):
    from wifi_center.services.tool_manager import ToolManager
    tm = ToolManager(controller.db, FakeProbe())
    d = tmp_path / "wa"
    d.mkdir()
    tm.set_config("wifi-audit-tool", install_path=str(d))
    assert tm.get_config("wifi-audit-tool") == {"install_path": str(d)}
    with pytest.raises(ValidationError):
        tm.set_config("wifi-audit-tool", install_path="relative/dir")
    with pytest.raises(ValidationError):
        tm.set_config("nmap", executable_override=str(tmp_path / "missing"))
    with pytest.raises(KeyError):
        tm.set_config("not-a-tool")
    controller.db.execute("UPDATE tools SET config_json='{garbage' WHERE id='wifi-audit-tool'")
    assert tm.get_config("wifi-audit-tool") == {}
