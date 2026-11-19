import json

import pytest

pytest.importorskip("PySide6")
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QFileDialog

from wifi_center.ui.pages import osint_pages as op
from wifi_center.ui.pages.osint_pages import OsintWorkspacePage


@pytest.fixture
def opened(monkeypatch):
    urls = []
    monkeypatch.setattr(op.QDesktopServices, "openUrl", staticmethod(lambda u: urls.append(u.toString()) or True))
    return urls


@pytest.fixture
def page(controller, qapp, opened):
    controller.projects.create("Case A", "investigation")
    return OsintWorkspacePage(controller, "explorer")


def row_of(page, slug):
    return next(i for i, d in enumerate(page._rows) if d["slug"] == slug)


def test_all_modes_open_with_correct_presets(controller, qapp):
    for mode, forced in (("explorer", None), ("username", "username"), ("email", "email"), ("domain", "domain"),
                         ("ip", "ip")):
        p = OsintWorkspacePage(controller, mode)
        assert p.forced_type == forced and p.kind.isEnabled() == (forced is None)
        assert p.table.rowCount() > 0
    ip_rows = [d["slug"] for d in OsintWorkspacePage(controller, "ip")._rows]
    assert "ipinfo" in ip_rows and "github" not in ip_rows and "courtlistener" not in ip_rows
    assert ip_rows.index("ipinfo") < ip_rows.index("ddg")       # tools made for IPs come before generic search engines
    user_rows = {d["slug"] for d in OsintWorkspacePage(controller, "username")._rows}
    assert "github" in user_rows and "ipinfo" not in user_rows and "wikipedia" not in user_rows


def test_search_validates_before_anything_happens(page, opened):
    page.term.setText("")
    page.search()
    assert "enter a search term" in page.msg.text()
    page.kind.setCurrentIndex(1)                         # force "username"
    page.term.setText("../../etc")
    page.search()
    assert "usernames may only" in page.msg.text() and page._term == ""
    assert opened == []


def test_open_builds_safe_url_records_and_warns(page, opened):
    pid = page.bar.project_id()
    page.term.setText("alice")
    page.search()
    assert page._kind == "username"
    page._open(row_of(page, "github"))
    assert opened == ["https://github.com/alice"]
    assert page.app.osint.results_for(pid, "alice") == {"github": "inconclusive"}   # opened, nothing concluded
    assert "does not confirm" in page.msg.text()
    page._open(row_of(page, "whatsmyname"))                                         # no term support
    assert opened[-1] == "https://whatsmyname.app/" and QGuiApplication.clipboard().text() == "alice"
    assert any(e["event"] == "osint.open" for e in page.app.audit.tail(5))


def test_every_open_button_works_with_or_without_a_term(page, monkeypatch):
    opened = []
    monkeypatch.setattr(op.QDesktopServices, "openUrl", staticmethod(lambda u: opened.append(u.toString()) or True))
    assert all(page.table.cellWidget(r, 5).isEnabled() for r in range(page.table.rowCount()))
    page._open(row_of(page, "github"))                                              # searchable resource, no term typed yet
    assert opened[-1] == "https://github.com/" and "home page was opened" in page.msg.text()
    page.term.setText("alice")
    page.search()
    page._open(row_of(page, "github"))
    assert opened[-1] == "https://github.com/alice"                                 # with a term: the ready-made search
    from wifi_center.services import osint_service as osv
    assert all(osv.site_home(r).startswith("https://") for r in page.app.osint.resources())     # every catalogue entry has a home page


def test_recording_results_and_five_state_vocabulary(page):
    pid = page.bar.project_id()
    page.term.setText("alice")
    page.search()
    r = row_of(page, "github")
    combo = page.table.cellWidget(r, 4)
    assert combo.isEnabled() and [combo.itemData(i) for i in range(combo.count())] == [
        None, "confirmed", "possible", "none", "inconclusive", "unavailable"]
    assert [combo.itemText(i) for i in range(1, 6)] == ["Confirmed result", "Possible match", "No result",
                                                        "Inconclusive", "Resource unavailable"]
    combo.setCurrentIndex(combo.findData("possible"))
    assert page.app.osint.results_for(pid, "alice")["github"] == "possible"
    page._populate()                                                              # re-render keeps the recorded state
    assert page.table.cellWidget(row_of(page, "github"), 4).currentData() == "possible"


def test_results_locked_without_an_investigation(controller, qapp, opened):
    p = OsintWorkspacePage(controller, "username")          # no investigation exists yet
    p.term.setText("bob")
    p.search()
    assert p.bar.project_id() is None
    assert not p.table.cellWidget(0, 4).isEnabled()
    p._open(row_of(p, "github"))
    assert opened == ["https://github.com/bob"] and controller.osint.records(1) == []   # nothing stored anywhere


def test_favorites_and_category_filter(page):
    r = row_of(page, "crtsh")
    page._cell_clicked(r, 0)
    assert page.app.osint.get("crtsh")["favorite"] == 1
    page.cats.setCurrentRow(1)                              # ★ Saved
    assert [d["slug"] for d in page._rows] == ["crtsh"]
    page.cats.setCurrentRow(2 + 2)                          # Domain research
    assert page._rows == [] or all("Domain research" in d["categories"] for d in page._rows)
    page.cats.setCurrentRow(0)
    page.filter.setText("gravatar")
    assert [d["slug"] for d in page._rows] == ["gravatar"]


def test_availability_check_requires_confirmation(page, monkeypatch):
    calls = []
    monkeypatch.setattr(page.app.osint, "check_one", lambda tpl, timeout=6.0: calls.append(tpl) or "reachable")
    monkeypatch.setattr(op, "confirm_dialog", lambda *a, **k: False)
    page.filter.setText("github")
    page._check_availability()
    assert calls == []                                      # declined: no network traffic
    shown = []
    monkeypatch.setattr(op, "confirm_dialog", lambda parent, title, text, *a, **k: shown.append(text) or True)
    page._check_availability()
    for _ in range(100):
        qapp = QGuiApplication.instance()
        qapp.processEvents()
        import time
        time.sleep(0.02)
        if calls and not page.loader.active:
            break
    assert "github.com" in shown[0] and "never sent" in shown[0]
    assert page.app.osint.get("github")["availability"] == "reachable"
    assert "reachable" in page.table.item(row_of(page, "github"), 3).text()


def test_notes_save_url_and_export(page, monkeypatch, tmp_path):
    pid = page.bar.project_id()
    page.term.setText("alice")
    page.search()
    page.table.selectRow(row_of(page, "github"))
    assert page.save_url.isEnabled()
    page._save_url()
    assert page.app.projects.references(pid)[0]["url"] == "https://github.com/alice"
    page.note.setPlainText("profile photo matches the one in the press release")
    page._save_note()
    assert page.app.projects.notes(pid)[0]["body"].startswith("[alice · GitHub profile] ")
    page.app.osint.set_result(pid, "alice", "github", "possible")
    out = tmp_path / "case.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), ""))
    page._export("json")
    data = json.loads(out.read_text())
    assert data["records"][0]["search_term"] == "alice" and data["saved_urls"] and data["notes"]


def test_remove_custom_resource_asks_first(page, monkeypatch):
    slug = page.app.osint.add_custom("Mine", "https://x.example.org/?q={term}", ["Public websites"], ["text"])
    page._populate()
    page.table.selectRow(row_of(page, slug))
    assert not page.remove_btn.isHidden() or page.remove_btn.isVisibleTo(page)
    monkeypatch.setattr(op, "confirm_dialog", lambda *a, **k: False)
    page._remove_custom()
    assert page.app.osint.get(slug)
    monkeypatch.setattr(op, "confirm_dialog", lambda *a, **k: True)
    page._remove_custom()
    assert page.app.osint.get(slug) is None
    page.table.selectRow(row_of(page, "github"))
    assert page.remove_btn.isHidden()                       # built-ins cannot be removed


def test_palette_lists_osint_resources_without_launching_anything(controller):
    from wifi_center.ui.palette import build_commands
    opened_pages = []
    cmds = build_commands(controller, opened_pages.append, lambda t: None, lambda t, o: None, lambda u: None, {})
    osint = [c for c in cmds if c.group == "OSINT"]
    assert len(osint) >= 50 and any(c.title == "Shodan host" for c in osint)
    osint[0].run()
    assert opened_pages == ["osint"]                         # navigates only; never opens a site by itself
