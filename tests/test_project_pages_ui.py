import time

import pytest

pytest.importorskip("PySide6")
from wifi_center.ui.pages import project_pages as pp


def wait(qapp, cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def env(qapp, controller, tmp_path, monkeypatch):
    pid = controller.projects.create("Branch office")
    controller.projects.add_scope(pid, "10.0.0.0/24")
    fid = controller.projects.add_finding(pid, "Default admin password", "critical", "Router uses the vendor default", "Change it", "manual", "10.0.0.1")
    ev = tmp_path / "proof.txt"
    ev.write_text("login screenshot text")
    confirms = []
    monkeypatch.setattr(pp, "confirm_dialog", lambda *a, **k: (confirms.append(a[1]), True)[1])
    return controller, pid, fid, ev, confirms


def save_to(monkeypatch, path):
    monkeypatch.setattr(pp.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(path), "")))


def test_reports_page_previews_generates_checks_and_keeps_files(qapp, env, tmp_path, monkeypatch):
    c, pid, fid, ev, confirms = env
    c.projects.add_evidence(pid, str(ev), "proof", fid)
    page = pp.ReportsPage(c)
    assert page.bar.project_id() == pid and page.b_gen.isEnabled()
    page.preview()
    assert wait(qapp, lambda: "Default admin password" in page.view.toPlainText())
    assert "proof.txt (ok)" in page.view.toPlainText() and "Method and limitations" in page.view.toPlainText()
    out = tmp_path / "report.html"
    save_to(monkeypatch, out)
    page.client.setText("ACME")
    page.generate()
    assert wait(qapp, lambda: out.exists() and page.table.rowCount() == 1)
    assert "Client: ACME" in out.read_text(encoding="utf-8")
    page.table.selectRow(0)
    page.check()
    assert "exactly as it was generated" in page.msg.text()
    out.write_text("edited")
    page.check()
    assert "modified" in page.msg.text()
    page.forget()
    assert page.table.rowCount() == 0 and out.exists() and "Remove from list" in confirms
    pdf = tmp_path / "report.pdf"
    save_to(monkeypatch, pdf)
    page.fmt.setCurrentText("PDF")
    page.generate()
    assert pdf.read_bytes()[:5] == b"%PDF-" and page.table.rowCount() == 1


def test_reports_page_without_a_project_is_inert(qapp, controller):
    page = pp.ReportsPage(controller)
    assert not page.b_gen.isEnabled()
    page.preview()
    assert "project first" in page.msg.text()


def test_evidence_page_add_link_verify_and_remove(qapp, env, tmp_path, monkeypatch):
    c, pid, fid, ev, confirms = env
    page = pp.EvidencePage(c)
    assert page.bar.project_id() is None and not page.b_add.isEnabled()          # "All projects": nothing to add to
    page.bar.reload(select=pid)
    page.reload()
    monkeypatch.setattr(pp.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(ev), "")))
    page.bar.combo.setCurrentIndex(page.bar.combo.findData(pid))
    page.reload()
    page.add()
    assert page.table.rowCount() == 1 and page.table.item(0, 1).text() == "proof.txt" and "SHA-256" in page.msg.text()
    page.table.selectRow(0)
    assert page.path.text() == str(ev) and page.b_link.isEnabled()
    monkeypatch.setattr(pp.QInputDialog, "getItem", staticmethod(lambda parent, t, label, items, *a, **k: (items[1], True)))
    page.link()
    assert page.table.item(0, 3).text() == "Default admin password"
    page.verify_all()
    assert wait(qapp, lambda: page.table.item(0, 6).text() == "✔ unchanged")
    ev.write_text("tampered")
    page.verify_all()
    assert wait(qapp, lambda: page.table.item(0, 6).text() == "✖ CHANGED") and "changed or missing" in page.msg.text()
    page.table.selectRow(0)
    page.remove()
    assert page.table.rowCount() == 0 and ev.exists() and "Remove evidence reference" in confirms


def test_project_history_shows_activity_exports_and_deletes_without_touching_files(qapp, env, tmp_path, monkeypatch):
    c, pid, fid, ev, confirms = env
    c.projects.add_evidence(pid, str(ev), "proof")
    c.projects.add_note(pid, "kickoff call")
    page = pp.ProjectHistoryPage(c)
    assert page.table.rowCount() == 1
    page.table.selectRow(0)
    text = page.timeline.toPlainText()
    for needle in ("Project created", "Finding added: Default admin password [critical]", "Note added", "Evidence added: proof.txt", "Scope entry added: 10.0.0.0/24"):
        assert needle in text
    assert [page.table.item(0, i).text() for i in (4, 5, 6, 7, 8)] == ["1", "1", "1", "1", "1"]
    out = tmp_path / "bundle.json"
    save_to(monkeypatch, out)
    page.export()
    assert out.exists() and "Default admin password" in out.read_text(encoding="utf-8") and "keep it private" in page.msg.text()
    page.delete()
    assert page.table.rowCount() == 0 and ev.exists() and c.projects.get(pid) is None and "Delete project" in confirms
    assert "No projects yet" in page.timeline.toPlainText()


def test_phase_9_pages_are_registered_not_placeholders(qapp, controller):
    from wifi_center.ui.main_window import MainWindow
    w = MainWindow(controller)
    for pid, cls in (("reports", pp.ReportsPage), ("evidence", pp.EvidencePage), ("project_history", pp.ProjectHistoryPage)):
        assert isinstance(w._create_page(pid), cls)
