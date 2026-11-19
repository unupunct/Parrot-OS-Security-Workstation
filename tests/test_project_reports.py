"""Phase 9 services: assessment reports, evidence integrity, report log, project history."""
import csv
import io
import json

import pytest

from wifi_center.database.repository import Database
from wifi_center.services.project_reports import ProjectReportService, ReportOptions
from wifi_center.services.project_service import ProjectService


@pytest.fixture
def world(tmp_path):
    db = Database(":memory:")
    ps = ProjectService(db)
    rs = ProjectReportService(db, ps, lambda: "2026-11-19T12:00:00+00:00")
    pid = ps.create("Office <Wi-Fi>")
    ps.add_scope(pid, "192.168.1.0/24", "office LAN")
    f1 = ps.add_finding(pid, "Open guest network", "high", "Guest SSID has no encryption", "Enable WPA3", "wifi", "Guest-AP")
    f2 = ps.add_finding(pid, "Old firmware", "low", "Router firmware is 3 years old", "Update", "manual")
    ps.update_finding(f2, status="resolved", remediation_notes="Updated 2026-11-10")
    ev = tmp_path / "scan.txt"
    ev.write_text("nmap output")
    e1 = ps.add_evidence(pid, str(ev), "scan of the guest VLAN", f1)
    ps.add_note(pid, "client asked to avoid office hours")
    ps.add_reference(pid, "https://example.com/advisory", "Vendor advisory")
    return db, ps, rs, pid, f1, f2, ev, e1


def test_report_content_scope_findings_summary_and_escaping(world):
    db, ps, rs, pid, *_ = world
    r = rs.build(pid, ReportOptions(prepared_by="A. Analyst", client="ACME"))
    assert r.open_by_severity["high"] == 1 and r.open_by_severity["low"] == 0 and r.status_counts["resolved"] == 1
    html = rs.to_html(r)
    for needle in ("Executive summary", "192.168.1.0/24", "Open guest network", "Enable WPA3", "Updated 2026-11-10", "Client: ACME", "Prepared by: A. Analyst",
                   "Method and limitations", "scan.txt (ok)", "2026-11-19T12:00:00+00:00"):
        assert needle in html
    assert "Office &lt;Wi-Fi&gt;" in html and "Office <Wi-Fi>" not in html            # project text is escaped
    assert "client asked" not in html and "scan.txt</td>" in html and "<small>" in html
    assert str(ps.evidence(pid)[0]["path"]) not in html                              # local paths are opt-in


def test_options_notes_paths_and_resolved_filter(world):
    db, ps, rs, pid, f1, f2, ev, e1 = world
    r = rs.build(pid, ReportOptions(include_notes=True, include_paths=True, include_resolved=False))
    assert [f["title"] for f in r.findings] == ["Open guest network"]
    html, js = rs.to_html(r), json.loads(rs.to_json(r))
    assert "client asked" in html and str(ev) in html and js["evidence"][0]["path"] == str(ev)
    assert "path" not in json.loads(rs.to_json(rs.build(pid)))["evidence"][0]


def test_evidence_integrity_is_rechecked_when_the_report_is_built(world):
    db, ps, rs, pid, f1, f2, ev, e1 = world
    assert rs.build(pid).integrity_problems == []
    ev.write_text("tampered")
    r = rs.build(pid)
    assert [e["state"] for e in r.integrity_problems] == ["changed"] and "Evidence integrity" in rs.to_html(r)
    assert json.loads(rs.to_json(r))["summary"]["evidence_integrity_problems"] == 1
    ev.unlink()
    assert rs.build(pid).evidence[0]["state"] == "missing"
    assert rs.build(pid, ReportOptions(verify_evidence=False)).evidence[0]["state"] == "not checked"


def test_empty_project_reports_honestly(world):
    db, ps, rs, *_ = world
    empty = ps.create("Empty")
    r = rs.build(empty)
    html = rs.to_html(r)
    assert "No findings are recorded" in html and "No authorised scope is recorded" in html and not r.findings
    assert list(csv.reader(io.StringIO(rs.to_csv(r)))) [1:] == []
    with pytest.raises(ValueError):
        rs.build(9999)


def test_csv_json_and_files_with_a_verifiable_log(world, tmp_path, qapp):
    db, ps, rs, pid, *_ = world
    r = rs.build(pid)
    rows = list(csv.DictReader(io.StringIO(rs.to_csv(r))))
    assert [x["severity"] for x in rows] == ["high", "low"] and rows[0]["evidence_files"] == "scan.txt"
    out = {}
    for fmt in ("html", "json", "csv", "pdf"):
        out[fmt] = rs.write(r, tmp_path / f"rep.{fmt}", fmt)
        assert out[fmt].stat().st_size > 100
    assert out["pdf"].read_bytes()[:5] == b"%PDF-"
    log = rs.generated(pid)
    assert len(log) == 4 and {g["fmt"] for g in log} == {"html", "json", "csv", "pdf"} and all(len(g["sha256"]) == 64 for g in log)
    gid = next(g["id"] for g in log if g["fmt"] == "json")
    assert rs.verify_generated(gid) == "ok"
    out["json"].write_text("{}")
    assert rs.verify_generated(gid) == "changed"
    rs.forget_generated(gid)
    assert out["json"].exists() and len(rs.generated(pid)) == 3            # the file stays; only the log entry goes
    out["html"].unlink()
    assert rs.verify_generated(next(g["id"] for g in rs.generated(pid) if g["fmt"] == "html")) == "missing"
    with pytest.raises(ValueError):
        rs.write(r, tmp_path / "x.docx", "docx")


def test_overview_and_activity_timeline(world, tmp_path):
    db, ps, rs, pid, f1, f2, *_ = world
    db.execute("UPDATE findings SET updated_at = datetime('now', '+1 hour') WHERE id = ?", (f2,))      # an edit later than the creation second
    rs.write(rs.build(pid), tmp_path / "t.html", "html")
    (row,) = rs.overview()
    assert (row["findings"], row["open"], row["evidence"], row["notes"], row["scope"], row["reports"]) == (2, 1, 1, 1, 1, 1)
    texts = [a["text"] for a in rs.activity(pid)]
    for needle in ("Project created", "Finding added: Open guest network [high]", "Finding updated: Old firmware — Resolved", "Note added", "Evidence added: scan.txt",
                   "Scope entry added: 192.168.1.0/24", "Report generated (HTML)"):
        assert any(t.startswith(needle) for t in texts), needle
    times = [a["time"] for a in rs.activity(pid)]
    assert times == sorted(times, reverse=True)


def test_bundle_export_and_project_delete_keeps_files(world, tmp_path):
    db, ps, rs, pid, f1, f2, ev, e1 = world
    b = json.loads(rs.export_bundle(pid))
    assert b["project"]["name"] == "Office <Wi-Fi>" and len(b["findings"]) == 2 and b["evidence"][0]["path"] == str(ev) and b["notes"]
    ps.delete(pid)
    assert ev.exists() and rs.overview() == [] and rs.generated() == []


def test_evidence_listing_linking_and_removal_never_touch_files(world, tmp_path):
    db, ps, rs, pid, f1, f2, ev, e1 = world
    other = ps.create("Other")
    g = ps.add_finding(other, "Elsewhere", "info")
    rows = ps.evidence_all()
    assert rows[0]["project"] == "Office <Wi-Fi>" and rows[0]["finding"] == "Open guest network" and len(ps.evidence_all(other)) == 0
    ps.link_evidence(e1, f2)
    assert ps.evidence_all(pid)[0]["finding"] == "Old firmware"
    ps.link_evidence(e1, None)
    assert ps.evidence_all(pid)[0]["finding"] is None
    from wifi_center.security.input_validation import ValidationError
    with pytest.raises(ValidationError):
        ps.link_evidence(e1, g)                                   # a finding of another project
    with pytest.raises(ValidationError):
        ps.link_evidence(9999, None)
    ps.remove_evidence(e1)
    assert ps.evidence(pid) == [] and ev.exists()
