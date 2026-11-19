import json
from pathlib import Path

import pytest

from tests.test_tools import FakeProbe
from wifi_center.integrations.base import LaunchMethod, LaunchRequest
from wifi_center.integrations.catalog import profile_by_id
from wifi_center.integrations.nmap_args import SCAN_PROFILES, build_args, validate_args, validate_target
from wifi_center.integrations.registry import build_integration
from wifi_center.security.input_validation import ValidationError
from wifi_center.security.operation_policy import PolicyViolation, authorize
from wifi_center.services import nmap_parsers as np_
from wifi_center.services import password_policy as pp
from wifi_center.services import report_import as ri
from wifi_center.services.bloodhound_service import BloodHoundService, parse_docker_ps, parse_docker_stats
from wifi_center.services.nmap_service import NmapService
from wifi_center.services.project_service import ProjectService, ScopeError

XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -oX - 10.0.0.0/24" start="1700000000" startstr="Tue Nov 14 2023" version="7.94">
<host><status state="up" reason="syn-ack"/><address addr="10.0.0.1" addrtype="ipv4"/>
<address addr="aa:bb:cc:dd:ee:01" addrtype="mac" vendor="Acme"/><hostnames><hostname name="router.lan" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port></ports>
<os><osmatch name="Linux 5.X" accuracy="95"/></os></host>
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/>
<service name="microsoft-ds"/></port></ports></host>
<host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host>
<runstats><finished timestr="Tue Nov 14 2023" summary="done"/></runstats></nmaprun>"""

NORMAL = """Starting Nmap 7.94
Nmap scan report for router.lan (10.0.0.1)
Host is up (0.0010s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
MAC Address: AA:BB:CC:DD:EE:01 (Acme)

Nmap scan report for 10.0.0.5
Host is up.
"""

GREPABLE = """# Nmap 7.94 scan initiated Tue Nov 14 as: nmap -oG - 10.0.0.0/24
Host: 10.0.0.1 (router.lan)\tStatus: Up
Host: 10.0.0.1 (router.lan)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9 (protocol 2.0)/, 80/open/tcp//http//nginx 1.18.0/\tIgnored State: closed (998)
Host: 10.0.0.5 ()\tStatus: Up
"""


# ---------------- parsers ----------------
def test_parse_xml():
    r = np_.parse_xml(XML)
    assert [h.address for h in r.hosts] == ["10.0.0.1", "10.0.0.5", "10.0.0.9"]
    h = r.hosts[0]
    assert (h.hostname, h.mac, h.vendor, h.os_guess) == ("router.lan", "AA:BB:CC:DD:EE:01", "Acme", "Linux 5.X")
    assert [p.label() for p in h.open_ports] == ["22/tcp ssh OpenSSH 8.9", "80/tcp http nginx 1.18.0"]
    assert len(h.ports) == 3 and r.hosts[2].status == "down" and r.version == "7.94" and "nmap -sT" in r.args


def test_parse_normal_and_grepable_agree_on_hosts():
    n, g = np_.parse_normal(NORMAL), np_.parse_grepable(GREPABLE)
    for r in (n, g):
        assert [h.address for h in r.hosts] == ["10.0.0.1", "10.0.0.5"]
        assert [p.port for p in r.hosts[0].open_ports] == [22, 80]
        assert r.hosts[0].hostname == "router.lan"
    assert n.hosts[0].mac == "AA:BB:CC:DD:EE:01" and n.hosts[0].vendor == "Acme"
    assert n.hosts[0].ports[0].product.startswith("OpenSSH 8.9") and "nmap -oG" in g.args


def test_parse_any_detects_formats_and_rejects_garbage():
    assert np_.parse_any(XML).fmt == "xml" and np_.parse_any(NORMAL).fmt == "normal"
    assert np_.parse_any(GREPABLE).fmt == "grepable"
    for bad in ("hello", "", "<html></html>", "<?xml version='1.0'?><other/>"):
        with pytest.raises(np_.ParseError):
            np_.parse_any(bad)


def test_xml_entity_expansion_is_rejected():
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(np_.ParseError, match="DOCTYPE"):
        np_.parse_xml(bomb)


# ---------------- nmap command safety ----------------
def good_args(tmp_path, profile="ports", targets=("10.0.0.0/24",)):
    xml = tmp_path / "scans" / "wifi-center-nmap-abc.xml"
    return build_args(profile, list(targets), str(xml))


def test_validator_accepts_planned_scans_only(tmp_path):
    for p in SCAN_PROFILES:
        validate_args(good_args(tmp_path, p))
    bad_cases = [
        ("--script", "vuln"), ("-A",), ("-O",), ("-iL", "/etc/passwd"), ("-D", "RND:5"), ("-S", "1.2.3.4"),
        ("--script=default",), ("-sU",), ("-p-",),
    ]
    base = good_args(tmp_path)
    for extra in bad_cases:
        with pytest.raises(PolicyViolation):
            validate_args(extra + base)               # extra option in front
        with pytest.raises(PolicyViolation):
            validate_args(base[:3] + extra + base[3:])   # injected between approved flags
    with pytest.raises(PolicyViolation):
        validate_args(base + ("--script", "vuln"))    # smuggled in as a "target"
    with pytest.raises(PolicyViolation):
        validate_args(base[:-1])                      # no targets
    for xml in ("/tmp/evil.xml", str(tmp_path / "wifi-center-nmap-a.xml"), "relative.xml",
                str(tmp_path / "scans" / "x.xml")):
        args = list(base)
        args[args.index("-oX") + 1] = xml
        with pytest.raises(PolicyViolation):
            validate_args(tuple(args))
    with pytest.raises(PolicyViolation):
        validate_args(good_args(tmp_path, targets=tuple(f"10.0.0.{i}" for i in range(65))))


@pytest.mark.parametrize("t", ["-oN", "--script", "10.0.0.1; rm -rf /", "$(id)", "a b", "10.0.0.0/8", "", "999.1.1.1"])
def test_targets_reject_injection_and_huge_ranges(t):
    with pytest.raises(ValidationError):
        validate_target(t)


def test_targets_accept_valid():
    assert validate_target("10.0.0.5") == "10.0.0.5" and validate_target("192.168.1.7/24") == "192.168.1.0/24"
    assert validate_target("Host.Example.com") == "host.example.com"


def test_integration_builds_scan_and_policy_authorises(tmp_path):
    probe = FakeProbe({"nmap": "/usr/bin/nmap"})
    integ = build_integration("nmap", probe)
    xml = tmp_path / "scans" / "wifi-center-nmap-1.xml"
    req = integ.launch_supported_operation("scan", {"profile": "discovery", "targets": ["10.0.0.0/24"],
                                                    "xml_path": str(xml)})
    assert req.argv[:2] == ("/usr/bin/nmap", "-sn") and req.method == LaunchMethod.CLI
    authorize(profile_by_id("nmap"), req)
    tampered = LaunchRequest("nmap", "scan", req.argv + ("--script", "vuln"), LaunchMethod.CLI, 5)
    with pytest.raises(PolicyViolation):
        authorize(profile_by_id("nmap"), tampered)
    with pytest.raises(PolicyViolation):                       # ...and the builder itself refuses bad plans
        integ.launch_supported_operation("scan", {"profile": "discovery", "targets": ["--script"], "xml_path": str(xml)})
    with pytest.raises(ValueError):
        integ.launch_supported_operation("scan", {"profile": "discovery"})


# ---------------- scope + planning ----------------
@pytest.fixture
def env(controller):
    pid = controller.projects.create("Lab")
    controller.projects.add_scope(pid, "10.0.0.0/24")
    controller.projects.add_scope(pid, "192.168.5.9")
    controller.projects.add_scope(pid, "Lab.Example.com")
    integ = build_integration("nmap", FakeProbe({"nmap": "/usr/bin/nmap"}))
    return controller, pid, integ


def test_scope_checks(env):
    c, pid, _ = env
    res = {x.target: x.in_scope for x in c.projects.check_scope(
        pid, ["10.0.0.7", "10.0.0.0/25", "10.0.1.7", "10.0.0.0/16", "192.168.5.9", "192.168.5.10", "lab.example.com",
              "other.example.com", "::1", "bad target"])}
    assert res == {"10.0.0.7": True, "10.0.0.0/25": True, "10.0.1.7": False, "10.0.0.0/16": False, "192.168.5.9": True,
                   "192.168.5.10": False, "lab.example.com": True, "other.example.com": False, "::1": False,
                   "bad target": False}


def test_plan_requires_confirmation_scope_and_project(env, tmp_path):
    c, pid, integ = env
    with pytest.raises(ScopeError, match="confirmation"):
        c.nmap.plan_scan(integ, pid, ["10.0.0.5"], "discovery", confirmed=False)
    with pytest.raises(ScopeError, match="authorized scope"):
        c.nmap.plan_scan(integ, pid, ["10.0.0.5", "8.8.8.8"], "discovery", confirmed=True)
    with pytest.raises(ValidationError):
        c.nmap.plan_scan(integ, 999, ["10.0.0.5"], "discovery", confirmed=True)
    with pytest.raises(ValidationError):
        c.nmap.plan_scan(integ, pid, ["10.0.0.5"], "aggressive", confirmed=True)
    with pytest.raises(ValidationError):
        c.nmap.plan_scan(integ, pid, [], "discovery", confirmed=True)
    plan = c.nmap.plan_scan(integ, pid, ["10.0.0.5", "10.0.0.0/25"], "services", confirmed=True)
    assert plan.targets == ["10.0.0.5", "10.0.0.0/25"] and plan.xml_path.parent.name == "scans"
    authorize(profile_by_id("nmap"), plan.request)


# ---------------- import, history, comparison ----------------
def test_import_feeds_inventory_and_dedupes(env, tmp_path):
    c, pid, _ = env
    f = tmp_path / "scan1.xml"
    f.write_text(XML)
    sid = c.nmap.import_file(str(f), pid)
    assert c.nmap.import_file(str(f), pid) == sid and len(c.nmap.scans()) == 1       # same file: no duplicate
    hosts = c.nmap.hosts(sid)
    assert [h["address"] for h in hosts] == ["10.0.0.1", "10.0.0.5", "10.0.0.9"] and len(hosts[0]["ports"]) == 3
    dev = c.db.query("SELECT address, services_json FROM network_devices ORDER BY address")
    assert [d["address"] for d in dev] == ["10.0.0.1", "10.0.0.5"]                  # the down host is not an inventory device
    assert json.loads(dev[0]["services_json"])[0] == "22/tcp ssh OpenSSH 8.9"
    c.nmap.import_text(XML, pid)                                                        # re-import updates, not duplicates
    assert c.db.query_one("SELECT COUNT(*) n FROM network_devices")["n"] == 2


def test_dashboard_inventory_sees_imported_hosts(env):
    from wifi_center.services.network_inventory import NetworkInventoryService
    c, pid, _ = env
    c.nmap.import_text(XML, pid)
    svc = NetworkInventoryService(c.db)
    svc._route, svc._neighbors = (lambda: ("10.0.0.1", "eth0", "10.0.0.50")), (lambda: [])
    ids = {n.id for n in svc.snapshot().nodes}
    assert "10.0.0.5" in ids and "10.0.0.9" not in ids


def test_compare_scans(env):
    c, pid, _ = env
    old = c.nmap.import_text(XML, pid)
    newer_xml = (XML.replace('<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" '
                             'version="1.18.0"/></port>', '<port protocol="tcp" portid="8080"><state state="open"/>'
                             '<service name="http-proxy"/></port>')
                 .replace('product="OpenSSH" version="8.9"', 'product="OpenSSH" version="9.6"')
                 .replace('<address addr="10.0.0.5" addrtype="ipv4"/>', '<address addr="10.0.0.77" addrtype="ipv4"/>'))
    new = c.nmap.import_text(newer_xml, pid)
    d = c.nmap.compare(old, new)
    assert d.new_hosts == ["10.0.0.77"] and d.gone_hosts == ["10.0.0.5"]
    ch = d.changes[0]
    assert ch["address"] == "10.0.0.1" and ch["opened"] == ["8080/tcp"] and ch["closed"] == ["80/tcp"]
    assert ch["changed"] == [("22/tcp", "ssh OpenSSH 8.9", "ssh OpenSSH 9.6")]
    assert c.nmap.compare(new, new).is_empty


def test_export_csv_json_neutralises_formulas(env):
    c, pid, _ = env
    evil = XML.replace('product="nginx"', 'product="=HYPERLINK(&quot;http://x&quot;)"')
    sid = c.nmap.import_text(evil, pid)
    text = c.nmap.export(sid, "csv")
    assert "'=HYPERLINK" in text and text.splitlines()[0].startswith("address,hostname")
    assert json.loads(c.nmap.export(sid, "json"))["hosts"][0]["address"] == "10.0.0.1"
    with pytest.raises(ValueError):
        c.nmap.export(sid, "xml")


def test_finish_planned_imports_scan_output(env):
    c, pid, integ = env
    plan = c.nmap.plan_scan(integ, pid, ["10.0.0.5"], "ports", confirmed=True)
    with pytest.raises(np_.ParseError):
        c.nmap.finish_planned(plan)                       # scan produced nothing
    plan.xml_path.write_text(XML)
    sid = c.nmap.finish_planned(plan)
    row = c.db.query_one("SELECT kind, target, project_id FROM scans WHERE id=?", (sid,))
    assert (row["kind"], row["target"], row["project_id"]) == ("scan", "10.0.0.5", pid)


# ---------------- projects / findings ----------------
def test_findings_remediation_tracking(controller):
    ps = controller.projects
    pid = ps.create("Acme external")
    f = ps.add_finding(pid, "Outdated OpenSSH", "high", "old", "upgrade", "nmap", "10.0.0.1:22")
    ps.add_finding(pid, "Banner disclosure", "low")
    assert [x["severity"] for x in ps.findings(pid)] == ["high", "low"]
    ps.update_finding(f, status="in_progress", remediation_notes="ticket 42", due_date="2026-12-01")
    assert ps.findings(pid, "in_progress")[0]["remediation_notes"] == "ticket 42"
    ps.update_finding(f, status="resolved")
    assert ps.severity_summary(pid) == {"low": 1}          # resolved findings drop out of the open summary
    for bad in ({"severity": "urgent"}, {"status": "done"}, {"id": 5}):
        with pytest.raises(ValidationError):
            ps.update_finding(f, **bad)
    with pytest.raises(ValidationError):
        ps.add_finding(pid, "", "low")
    with pytest.raises(ValidationError):
        ps.add_finding(pid, "x", "nope")
    ps.delete_finding(f)
    assert len(ps.findings(pid)) == 1


def test_evidence_references_notes(controller, tmp_path):
    ps = controller.projects
    pid = ps.create("P")
    ev = tmp_path / "shot.png"
    ev.write_bytes(b"abc")
    eid = ps.add_evidence(pid, str(ev), "screenshot")
    assert ps.verify_evidence(eid) == "ok"
    ev.write_bytes(b"changed")
    assert ps.verify_evidence(eid) == "changed"
    ev.unlink()
    assert ps.verify_evidence(eid) == "missing"
    with pytest.raises(ValidationError):
        ps.add_evidence(pid, "relative/file")
    assert ps.add_reference(pid, "https://example.com/app") == "https://example.com/app"
    for bad in ("javascript:alert(1)", "ftp://x", "not a url", "file:///etc/passwd"):
        with pytest.raises(ValidationError):
            ps.add_reference(pid, bad)
    ps.add_note(pid, "first note")
    ps.add_note(pid, "   ")
    assert [n["body"] for n in ps.notes(pid)] == ["first note"]
    ps.delete(pid)
    assert ps.get(pid) is None and ps.evidence(pid) == []
    assert Path(tmp_path).exists()                          # deleting a project never touches files on disk


# ---------------- report import ----------------
NIKTO_XML = """<?xml version="1.0"?><niktoscan><scandetails targetip="10.0.0.5" targethostname="web" targetport="80">
<item id="999957" osvdbid="0" method="GET"><description>The X-Frame-Options header is not present.</description>
<uri>/</uri></item><item id="001"><description>Server leaks inodes via ETags</description><uri>/index.html</uri></item>
</scandetails></niktoscan>"""
NIKTO_JSON = json.dumps([{"host": "web", "ip": "10.0.0.5", "port": "80", "vulnerabilities": [
    {"id": "1", "method": "GET", "url": "/admin/", "msg": "Admin login page found."}]}])
NIKTO_CSV = '"web","10.0.0.5","80","OSVDB-0","GET","/x","Interesting file"\n'
BURP = """<?xml version="1.0"?><issues><issue><name>SQL injection</name><host ip="1.2.3.4">https://app.test</host>
<path>/login</path><severity>High</severity><confidence>Certain</confidence><issueDetail>&lt;b&gt;param&lt;/b&gt; q</issueDetail>
<remediationBackground>Use prepared statements</remediationBackground></issue>
<issue><name>Cookie without secure flag</name><host>https://app.test</host><path>/</path><severity>Information</severity></issue></issues>"""
MSF = """<?xml version="1.0"?><MetasploitV5><hosts><host><address>10.0.0.8</address><name>db1</name><os-name>Linux</os-name>
<services><service><port>5432</port><proto>tcp</proto><name>postgresql</name><state>open</state><info>PostgreSQL 14</info></service></services>
<vulns><vuln><name>Weak configuration</name><info>trust auth</info></vuln></vulns></host></hosts></MetasploitV5>"""
GENERIC_CSV = "title,severity,description,location,recommendation\nOpen redirect,medium,desc,/r,validate\n,high,nameless,,\n"


def test_report_parsers():
    n = ri.parse_nikto(NIKTO_XML)
    assert len(n.findings) == 2 and n.findings[0].location == "10.0.0.5:80/"
    assert ri.parse_nikto(NIKTO_JSON).findings[0].location == "10.0.0.5:80/admin/"
    assert ri.parse_nikto(NIKTO_CSV).findings[0].title == "Interesting file"
    b = ri.parse_burp(BURP)
    assert [f.severity for f in b.findings] == ["high", "info"] and "param" in b.findings[0].description
    assert "<b>" not in b.findings[0].description and b.findings[0].recommendation == "Use prepared statements"
    m = ri.parse_metasploit(MSF)
    assert m.hosts.hosts[0].ports[0].service == "postgresql" and m.findings[0].location == "10.0.0.8"
    g = ri.parse_generic(GENERIC_CSV)
    assert [f.title for f in g.findings] == ["Open redirect"]          # row without a title is skipped
    assert ri.parse_generic('[{"title":"x","severity":"CRITICAL"}]').findings[0].severity == "critical"
    for fn, bad in ((ri.parse_burp, "<other/>"), (ri.parse_metasploit, "<x/>"), (ri.parse_nikto, "<niktoscan/>"),
                    (ri.parse_generic, "a,b\n1,2\n")):
        with pytest.raises(np_.ParseError):
            fn(bad)
    with pytest.raises(np_.ParseError):
        ri.parse_burp('<!DOCTYPE x [<!ENTITY a "b">]><issues/>')


def test_severity_and_format_detection():
    assert [ri.norm_severity(x) for x in ("High", "Information", "moderate", "weird", None)] == [
        "high", "info", "medium", "info", "info"]
    assert [ri.detect_format(t) for t in (NIKTO_XML, BURP, MSF, GENERIC_CSV)] == ["nikto", "burp", "metasploit", "generic"]


def test_import_file_organises_findings_once(controller, tmp_path):
    pid = controller.projects.create("P")
    f = tmp_path / "burp.xml"
    f.write_text(BURP)
    r = controller.report_import.import_file(pid, str(f))
    assert (r["tool"], r["findings"], r["duplicate"]) == ("burp", 2, False)
    assert controller.report_import.import_file(pid, str(f))["duplicate"] is True
    assert len(controller.projects.findings(pid)) == 2
    assert controller.projects.findings(pid)[0]["source_tool"] == "burp"
    m = tmp_path / "msf.xml"
    m.write_text(MSF)
    r = controller.report_import.import_file(pid, str(m), nmap=controller.nmap)
    assert r["hosts"] == 1 and controller.nmap.hosts(controller.nmap.scans(pid)[0]["id"])[0]["address"] == "10.0.0.8"
    with pytest.raises(ValidationError):
        controller.report_import.import_file(pid, "relative.xml")
    with pytest.raises(ValidationError):
        controller.report_import.import_file(pid, str(f), fmt="sqlmap-magic")


# ---------------- password policy ----------------
def test_policy_rules():
    pol = pp.Policy()
    assert pp.evaluate("Tr0ub4dor&3-horse-battery", pol) == []
    assert "too_short" in pp.evaluate("Ab1!", pol)
    assert "few_classes" in pp.evaluate("alllowercaseletters", pol)
    assert "repeats" in pp.evaluate("Aaaaa-bcd1-XYZ-9", pol)
    assert "sequence" in pp.evaluate("Good-1234-Pass-Q!", pol) and "sequence" in pp.evaluate("xx-qwerty-Aa1!-xx", pol)
    assert "contains_username" in pp.evaluate("Alice-is-Here-9!", pol, "alice")
    assert "contains_username" not in pp.evaluate("Alice-is-Here-9!", pol, "al")
    assert "blocklisted" in pp.evaluate("Summer2024!", pol, None, {"summer"}) \
        and "blocklisted" in pp.evaluate("summer", pp.Policy(min_length=1), None, {"summer"})
    assert "whitespace_edge" in pp.evaluate(" Tr0ub4dor&3-horse ", pol)
    assert "too_long" in pp.evaluate("A1!" * 50, pol)


def test_audit_never_keeps_password_text(tmp_path):
    text = "alice:Password1!\nbob:Xk9#vL2$mQ8@wR5!\n\ncarol:abc\n"
    rep = pp.audit(pp.parse_entries(text, userpass=True), pp.Policy(), {"password"})
    assert (rep.total, rep.passed, rep.failed) == (3, 1, 2)
    assert rep.by_rule["too_short"] >= 1
    blob = repr(rep.results) + pp.summary_text(rep)
    assert "Password1" not in blob and "Xk9" not in blob and "abc" not in blob.replace("abcdefghijklmnopqrstuvwxyz", "")
    assert [r.label for r in rep.results] == ["alice", "bob", "carol"]
    plain = pp.parse_entries("a:b\nsecret\n")
    assert [(l, u, p) for l, u, p in plain] == [("line 1", None, "a:b"), ("line 2", None, "secret")]


def test_blocklist_loading_and_limits(tmp_path):
    f = tmp_path / "bl.txt"
    f.write_text("Summer\n\nWINTER\n")
    assert pp.load_blocklist(f) == {"summer", "winter"}
    rep = pp.audit([("l", None, "x")] * 3, pp.Policy())
    assert rep.total == 3


# ---------------- bloodhound ----------------
def test_docker_parsers():
    ps = "\n".join(json.dumps(d) for d in [
        {"Names": "bloodhound-bloodhound-1", "Image": "specterops/bloodhound:latest", "Status": "Up 2 hours (healthy)",
         "Ports": "127.0.0.1:8080->8080/tcp"},
        {"Names": "bloodhound-graph-db-1", "Image": "neo4j:4.4", "Status": "Exited (0) 1 hour ago"},
        {"Names": "unrelated", "Image": "nginx", "Status": "Up 1 day"}])
    cs = parse_docker_ps(ps + "\nnot json")
    assert [c.name for c in cs] == ["bloodhound-bloodhound-1", "bloodhound-graph-db-1"]   # "unrelated" is ignored
    assert cs[0].healthy and not cs[1].healthy
    assert parse_docker_stats(json.dumps({"Name": "x", "CPUPerc": "1.5%", "MemUsage": "100MiB / 8GiB"})) == {
        "x": ("1.5%", "100MiB / 8GiB")}


def test_bloodhound_status_without_docker(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    st = BloodHoundService().status()
    assert not st.docker_installed and "not installed" in st.message


def test_bloodhound_service_check_is_loopback_only():
    from wifi_center.security.input_validation import ValidationError
    with pytest.raises(ValidationError):
        BloodHoundService.check_service("http://10.0.0.5:8080")
    assert "not reachable" in BloodHoundService.check_service("http://127.0.0.1:1", timeout=2)
