import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QFileDialog

from tests.test_netsec import BURP, GENERIC_CSV, MSF, NIKTO_XML, XML
from tests.test_tools import FakeProbe
from wifi_center.services.tool_manager import ToolManager
from wifi_center.ui.pages import assessment_pages as ap
from wifi_center.ui.pages import discovery_pages as dp
from wifi_center.ui.pages.assessment_pages import AssessmentPage, FindingDialog, PasswordAuditPage, WebSecurityPage


@pytest.fixture
def env(controller, qapp):
    controller.tools = ToolManager(controller.db, FakeProbe(
        {"nmap": "/usr/bin/nmap", "burpsuite": "/usr/bin/burpsuite", "sqlmap": "/usr/bin/sqlmap"}))
    controller.tools.scan_all()
    pid = controller.projects.create("Lab")
    controller.projects.add_scope(pid, "10.0.0.0/24")
    controller.settings.set("projects.active", pid)
    return controller, pid


def patch_dialog(monkeypatch, module, answer):
    calls = []
    monkeypatch.setattr(module, "confirm_dialog", lambda *a, **k: (calls.append(a), answer)[1])
    return calls


# ---------------- discovery ----------------
def test_scan_requires_scope_and_confirmation(env, monkeypatch):
    c, pid = env
    started = []
    monkeypatch.setattr(c.operations, "start", lambda *a, **k: started.append(a) or 1)
    page = dp.NetworkDiscoveryPage(c)
    page.profile.setCurrentIndex(0)
    calls = patch_dialog(monkeypatch, dp, True)
    # out-of-scope target: refused before any confirmation is even shown
    page.targets.setText("10.0.0.5 8.8.8.8")
    page._review_scan()
    assert "authorized scope" in page.scan_msg.text() and started == [] and calls == []
    # option-injection attempt in the targets box
    page.targets.setText("--script vuln")
    page._review_scan()
    assert started == [] and "Cannot start" in page.scan_msg.text()
    # declined confirmation
    patch_dialog(monkeypatch, dp, False)
    page.targets.setText("10.0.0.5")
    page._review_scan()
    assert started == [] and "cancelled" in page.scan_msg.text()


def test_confirmed_scan_runs_validated_command_and_imports_results(env, monkeypatch):
    c, pid = env
    seen = {}

    def fake_start(profile, request, title=None):
        seen["request"] = request
        return 77

    monkeypatch.setattr(c.operations, "start", fake_start)
    calls = patch_dialog(monkeypatch, dp, True)
    page = dp.NetworkDiscoveryPage(c)
    page.targets.setText("10.0.0.5, 10.0.0.0/25")
    page._review_scan()
    assert calls and "10.0.0.5" in calls[0][2]
    argv = seen["request"].argv
    assert argv[0] == "/usr/bin/nmap" and "--script" not in argv and argv[-2:] == ("10.0.0.5", "10.0.0.0/25")
    assert any(e["event"] == "scan.confirmed" for e in c.audit.tail(5))
    assert page._op_id == 77 and not page.start_btn.isEnabled() and page.cancel_btn.isEnabled()
    page._planned.xml_path.write_text(XML)                  # what nmap would have produced
    page._on_finished(77, "succeeded")
    assert page._op_id is None and "results saved" in page.scan_msg.text()
    assert page.host_table.rowCount() == 3 and page.tabs.currentIndex() == 2


def test_failed_scan_imports_nothing(env, monkeypatch):
    c, pid = env
    monkeypatch.setattr(c.operations, "start", lambda *a, **k: 5)
    patch_dialog(monkeypatch, dp, True)
    page = dp.NetworkDiscoveryPage(c)
    page.targets.setText("10.0.0.5")
    page._review_scan()
    page._on_finished(5, "cancelled")
    assert "cancelled" in page.scan_msg.text() and c.nmap.scans() == []


def test_scope_tab_and_import_history_compare(env, tmp_path, monkeypatch):
    c, pid = env
    page = dp.NetworkDiscoveryPage(c)
    page.scope_input.setText("not a target!")
    page._add_scope()
    assert "invalid" in page.scope_msg.text().lower()
    page.scope_input.setText("192.168.9.0/24")
    page._add_scope()
    assert page.scope_table.rowCount() == 2
    page.scope_table.selectRow(1)
    page._remove_scope()
    assert page.scope_table.rowCount() == 1
    f = tmp_path / "s.xml"
    f.write_text(XML)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(f), ""))
    page._import()
    assert "Imported as scan" in page.scan_msg.text() and page.scan_pick.count() == 1
    row = next(r for r in range(page.host_table.rowCount()) if page.host_table.item(r, 0).text() == "10.0.0.1")
    page.host_table.selectRow(row)                       # (the table is sortable, so find the row by address)
    assert "22" in page.host_detail.toPlainText()
    older = c.nmap.import_text(XML, pid)
    newer = c.nmap.import_text(XML.replace('portid="22"', 'portid="2222"'), pid)
    page._reload_scans()
    page.cmp_a.setCurrentIndex(page.cmp_a.findData(older))
    page.cmp_b.setCurrentIndex(page.cmp_b.findData(newer))
    page._compare()
    assert "2222/tcp" in page.diff_view.toPlainText()


def test_bad_import_reports_error_not_crash(env, tmp_path, monkeypatch):
    c, pid = env
    f = tmp_path / "bad.txt"
    f.write_text("this is not nmap output")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(f), ""))
    page = dp.NetworkDiscoveryPage(c)
    page._import()
    assert "Import failed" in page.scan_msg.text() and c.nmap.scans() == []


def test_mapping_page_draws_only_scan_hosts(env):
    c, pid = env
    c.nmap.import_text(XML, pid)
    page = dp.NetworkMappingPage(c)
    ids = {n.id for n in page._topo.nodes}
    assert ids == {"self", "10.0.0.1", "10.0.0.5"}               # the down host is not drawn
    page.view.select("10.0.0.1")
    assert "22/tcp ssh" in page.detail.toPlainText()
    empty = dp.NetworkMappingPage(c)
    empty.bar.reload()
    c.nmap.delete_scan(c.nmap.scans()[0]["id"])
    empty._reload_scans()
    assert [n.kind for n in empty._topo.nodes] == ["self"] and empty.view.empty_btn.isVisibleTo(empty.view)


# ---------------- assessment ----------------
def test_assessment_findings_flow(env, monkeypatch):
    c, pid = env
    page = AssessmentPage(c)
    fid = c.projects.add_finding(pid, "Weak TLS", "high", "d", "r", "nikto", "10.0.0.5:443")
    page._reload()
    assert page.ftable.rowCount() == 1 and "1</b> high" in page.summary.text()
    page.ftable.selectRow(0)
    assert "d" in page.fdetail.toPlainText()
    dlg = FindingDialog(page, page._findings[0])
    dlg.status.setCurrentText("resolved")
    dlg.due.setText("2026-13-45")
    dlg._accept()
    assert "Due date" in dlg.err.text()
    dlg.due.setText("2026-12-31")
    dlg.remediation.setPlainText("patched")
    dlg._accept()
    c.projects.update_finding(fid, **dlg.values())
    page._reload()
    assert "No unresolved" in page.summary.text()
    assert c.projects.findings(pid)[0]["remediation_notes"] == "patched"
    page.status_filter.setCurrentText("open")
    assert page.ftable.rowCount() == 0
    # delete asks for confirmation
    page.status_filter.setCurrentIndex(0)
    page.ftable.selectRow(0)
    patch_dialog(monkeypatch, ap, False)
    page._delete_finding()
    assert len(c.projects.findings(pid)) == 1
    patch_dialog(monkeypatch, ap, True)
    page._delete_finding()
    assert c.projects.findings(pid) == []


def test_assessment_imports_and_integrations(env, tmp_path, monkeypatch):
    c, pid = env
    page = AssessmentPage(c)
    for text, fmt, name in ((NIKTO_XML, "nikto", "n.xml"), (BURP, "burp", "b.xml"), (GENERIC_CSV, "generic", "g.csv"),
                            (MSF, "metasploit", "m.xml")):
        f = tmp_path / name
        f.write_text(text)
        monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, _f=f, **k: (str(_f), ""))
        page._import(fmt)
        assert "Import failed" not in page.msg.text(), (fmt, page.msg.text())
    assert len(c.projects.findings(pid)) == 2 + 2 + 1 + 1
    page._import("nikto")                                         # the same (msf) file again: recognised, not re-imported
    assert "already imported" in page.msg.text() and len(c.projects.findings(pid)) == 6
    bad = tmp_path / "bad.xml"
    bad.write_text("<html>not a report</html>")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(bad), ""))
    page._import("nikto")
    assert "Import failed" in page.msg.text()
    assert "Restricted integration" in page.msf_lbl.text() and "Not installed" in page.bh_lbl.text()
    page.bh_url.setText("http://192.168.1.9:8080")
    page._check_bh()
    assert "loopback" in page.bh_lbl.text()


def test_evidence_integrity_in_ui(env, tmp_path, monkeypatch):
    c, pid = env
    page = AssessmentPage(c)
    ev = tmp_path / "proof.txt"
    ev.write_text("one")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(ev), ""))
    page._add_evidence()
    assert page.etable.rowCount() == 1
    page._verify_evidence()
    assert "unchanged" in page.etable.item(0, 4).text()
    ev.write_text("two")
    page._verify_evidence()
    assert "CHANGED" in page.etable.item(0, 4).text()


# ---------------- web security ----------------
def test_web_security_page(env):
    c, pid = env
    page = WebSecurityPage(c)
    lbl, btn = page._cards["burpsuite"]
    assert btn is not None and btn.isEnabled()                    # desktop launch supported
    lbl_sql, btn_sql = page._cards["sqlmap"]
    assert btn_sql is None and "Restricted" in lbl_sql.text()      # no launch for a restricted tool
    assert page._cards["nikto"][1] is None                         # CLI-only tool: no desktop launch button
    page.ref_input.setText("javascript:alert(1)")
    page._add_ref()
    assert page.refs.count() == 0
    page.ref_input.setText("https://app.example.com/login")
    page._add_ref()
    assert page.refs.count() == 1
    page.refs.setCurrentRow(0)
    page._remove_ref()
    assert page.refs.count() == 0


# ---------------- password audit ----------------
def test_password_audit_page_never_shows_or_stores_passwords(env):
    c, pid = env
    page = PasswordAuditPage(c)
    page.userpass.setChecked(True)
    page.input.setPlainText("alice:Password1!\nbob:Xk9#vL2$mQ8@wR5!\ncarol:abc")
    page._evaluate()
    shown = "\n".join(page.table.item(r, c_).text() for r in range(page.table.rowCount()) for c_ in range(3))
    assert "Password1" not in shown and "abc" not in shown.replace("abcdefghijklmnopqrstuvwxyz", "")
    assert "3 entries evaluated" in page.summary.toPlainText()
    page._save_finding()
    f = c.projects.findings(pid)[0]
    assert f["source_tool"] == "policy-audit" and "Xk9" not in (f["description"] or "")
    assert not any("Password1" in str(e) for e in c.audit.tail(20))
    page.input.setPlainText("")
    page._evaluate()
    assert "at least one" in page.msg.text()
    assert "not installed" in page.john.text()
