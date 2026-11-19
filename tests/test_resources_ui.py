import time

import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QDialog, QFileDialog, QInputDialog

from wifi_center.services import resource_catalog as rc
from wifi_center.services.resource_library import LibraryService
from wifi_center.ui.pages import resource_pages as rp
from wifi_center.ui.pages.resource_pages import DocumentationPage, ResourceLibraryPage


def wait_until(qapp, cond, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


class FakeDialog:
    values_to_return: dict = {}

    def __init__(self, *a, **k):
        pass

    def exec(self):
        return QDialog.DialogCode.Accepted

    def values(self):
        return dict(FakeDialog.values_to_return)


@pytest.fixture
def page(controller, qapp, tmp_path):
    controller.settings.set("general.resources_dir", str(tmp_path / "lib"))
    p = ResourceLibraryPage(controller, "wordlists")
    p.tabs.setCurrentIndex(1)          # tab 0 is the read-only "On this system" view
    return p


def src(tmp_path, name="list.txt", text="alpha\nbravo\ncharlie\n"):
    p = tmp_path / "in" / name
    p.parent.mkdir(exist_ok=True)
    p.write_text(text)
    return str(p)


def do_import(page, qapp, monkeypatch, tmp_path, name="list.txt", text="alpha\nbravo\ncharlie\n", **extra):
    FakeDialog.values_to_return = {"src": src(tmp_path, name, text), "folder": "Sets", "name": None,
                                   "source_url": "https://example.org/list", "license": "MIT", "attribution": "Ann",
                                   "acquired_at": "2026-11-19", "entry_id": None, **extra}
    monkeypatch.setattr(rp, "ImportDialog", FakeDialog)
    page._import()
    assert wait_until(qapp, lambda: not page.loader.active)


def test_import_shows_metadata_and_integrity_flow(page, qapp, monkeypatch, tmp_path):
    assert "(library root)" in page.nav.item(3).text() and page.table.rowCount() == 0
    do_import(page, qapp, monkeypatch, tmp_path)
    assert page.table.rowCount() == 1 and "Imported" in page.msg.text()
    page.nav.setCurrentRow(0)
    page.table.selectRow(0)
    det = page.details.toPlainText()
    for needle in ("SHA-256", "https://example.org/list", "MIT", "Ann", "Sets/list.txt", "3"):
        assert needle in det
    assert "not verified" in page.table.item(0, 5).text()
    page._verify_one()
    assert wait_until(qapp, lambda: "unchanged" in page.table.item(0, 5).text())
    (page.lib.root / "Sets" / "list.txt").write_text("tampered\n")
    page._verify_all()
    assert wait_until(qapp, lambda: "CHANGED" in page.table.item(0, 5).text())
    assert "changed or missing" in page.msg.text()
    assert any(e["event"] == "library.verify" for e in page.app.audit.tail(5))


def test_duplicate_import_is_reported_not_stored(page, qapp, monkeypatch, tmp_path):
    do_import(page, qapp, monkeypatch, tmp_path)
    do_import(page, qapp, monkeypatch, tmp_path, name="copy.txt")
    assert page.table.rowCount() == 1 and "identical" in page.msg.text()
    do_import(page, qapp, monkeypatch, tmp_path, name="list.txt", text="other\n")      # name clash, new content
    assert "already exists" in page.msg.text() and page.table.rowCount() == 1


def test_remove_and_delete_need_confirmation_and_differ(page, qapp, monkeypatch, tmp_path):
    do_import(page, qapp, monkeypatch, tmp_path)
    page.table.selectRow(0)
    f = page.lib.root / "Sets" / "list.txt"
    monkeypatch.setattr(rp, "confirm_dialog", lambda *a, **k: False)
    page._remove(True)
    assert f.exists() and page.table.rowCount() == 1                       # declined: nothing happens
    monkeypatch.setattr(rp, "confirm_dialog", lambda *a, **k: True)
    page._remove(False)                                                   # untrack: the file stays
    assert f.exists() and page.table.rowCount() == 0
    assert page.nav.item(2).text().startswith("Untracked files in folder (1)")
    page.nav.setCurrentRow(2)
    assert page.table.rowCount() == 1 and page.b_adopt.isVisibleTo(page)
    page.table.selectRow(0)
    page._adopt()
    assert wait_until(qapp, lambda: not page.loader.active and page.lib.files())
    page.nav.setCurrentRow(0)
    page.table.selectRow(0)
    page._remove(True)                                                    # explicit delete
    assert not f.exists() and page.lib.files() == []


def test_rename_favorite_search_and_folder_views(page, qapp, monkeypatch, tmp_path):
    do_import(page, qapp, monkeypatch, tmp_path)
    page.nav.setCurrentRow(0)
    page.table.selectRow(0)
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("better.txt", True))
    page._rename()
    page.table.selectRow(0)
    assert "better.txt" in page.details.toPlainText()
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("../bad.txt", True))
    page._rename()
    assert "file names may use" in page.msg.text()
    page._toggle_favorite()
    page.nav.setCurrentRow(1)
    assert page.table.rowCount() == 1
    page.nav.setCurrentRow(3 + 1)                                         # the "Sets" folder
    assert page.table.rowCount() == 1
    page.search.setText("zzz")
    assert page.table.rowCount() == 0
    page.search.clear()
    page._show_duplicates()
    assert "No duplicate" in page.msg.text()


def test_catalog_tab_actions_follow_entry_kind(page, qapp, monkeypatch):
    assert page.ctable.rowCount() == 10 and page.tabs.count() == 4
    rows = {page.ctable.item(r, 0).data(0x0100): r for r in range(10)}      # Qt.UserRole
    shown = lambda *bs: [not b.isHidden() for b in bs]
    page.ctable.selectRow(rows["probable-wordlists"])
    assert shown(page.c_open, page.c_check, page.c_import, page.c_gen) == [True, True, True, False]
    assert "CC-BY-SA-4.0" in page.cdetails.toPlainText() and "does not download" in page.cdetails.toPlainText()
    page.ctable.selectRow(rows["synthetic-strong"])
    assert shown(page.c_open, page.c_check, page.c_import, page.c_gen) == [False, False, False, True]
    page.ctable.selectRow(rows["local-supplied"])
    assert shown(page.c_open, page.c_check, page.c_import, page.c_gen) == [False, False, True, False]


def test_generate_creates_a_tracked_synthetic_file(page, qapp, monkeypatch):
    rows = {page.ctable.item(r, 0).data(0x0100): r for r in range(10)}
    page.ctable.selectRow(rows["synthetic-strong"])
    monkeypatch.setattr(QInputDialog, "getInt", lambda *a, **k: (60, True))
    page._cat_generate()
    d = page.lib.files()[0]
    assert d["folder"] == "Generated" and d["line_count"] == 60 and "Synthetic" in d["license"]
    assert page.ctable.item(rows["synthetic-strong"], 3).text() == "1"
    assert any(h["action"] == "generate" for h in page.lib.history())
    assert page.htable.rowCount() >= 1


def test_source_check_is_explicit_and_warns_on_license_change(page, qapp, monkeypatch):
    calls = []
    monkeypatch.setattr(LibraryService, "check_source", staticmethod(
        lambda e, timeout=8.0: calls.append(e.id) or {"available": True, "license": "GPL-3.0", "license_matches": False,
                                                       "detail": "repository exists, license GPL-3.0"}))
    rows = {page.ctable.item(r, 0).data(0x0100): r for r in range(10)}
    page.ctable.selectRow(rows["probable-wordlists"])
    shown = []
    monkeypatch.setattr(rp, "confirm_dialog", lambda parent, title, text, *a, **k: shown.append(text) or False)
    page._cat_check()
    assert calls == [] and "api.github.com" in shown[0] and "Nothing is downloaded" in shown[0]
    monkeypatch.setattr(rp, "confirm_dialog", lambda *a, **k: True)
    page._cat_check()
    assert wait_until(qapp, lambda: calls and not page.loader.active)
    assert "WARNING" in page.msg.text() and "CC-BY-SA-4.0" in page.msg.text()
    assert any(h["action"] == "source-check" for h in page.lib.history())


def test_import_dialog_requires_acknowledgement_and_valid_date(controller, qapp, tmp_path):
    controller.settings.set("general.resources_dir", str(tmp_path / "lib"))
    dlg = rp.ImportDialog(None, controller.wordlists, rc.entry("probable-wordlists"), src(tmp_path))
    assert not dlg.ok.isEnabled() and dlg.source.text().startswith("https://github.com/berzerk0")
    assert dlg.license.text() == "CC-BY-SA-4.0" and "BY-SA" in dlg.attribution.text()
    dlg.ack.setChecked(True)
    assert dlg.ok.isEnabled()
    dlg.acquired.setText("yesterday")
    dlg._accept()
    assert "date must look like" in dlg.err.text()
    dlg.acquired.setText("2026-11-19")
    dlg._accept()
    assert dlg.result() == QDialog.DialogCode.Accepted
    v = dlg.values()
    assert v["entry_id"] == "probable-wordlists" and v["acquired_at"] == "2026-11-19"


def test_change_folder_updates_the_setting_and_view(page, qapp, monkeypatch, tmp_path):
    new = tmp_path / "elsewhere"
    new.mkdir()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(new))
    page._change_root()
    assert page.app.settings.get("general.resources_dir") == str(new) and str(new) in page.path_lbl.text()


def test_local_resources_library_is_separate_and_has_no_catalog(controller, qapp, tmp_path):
    controller.settings.set("general.local_resources_dir", str(tmp_path / "local"))
    p = ResourceLibraryPage(controller, "local")
    assert p.title == "Local Resources" and p.tabs.count() == 2 and p.lib.root == tmp_path / "local"
    assert not hasattr(p, "ctable")


def test_documentation_hub_lists_tools_and_local_guides(controller, qapp, monkeypatch):
    opened = []
    monkeypatch.setattr(rp.QDesktopServices, "openUrl", staticmethod(lambda u: opened.append(u.toString()) or True))
    page = DocumentationPage(controller)
    titles = [page.table.item(r, 0).text() for r in range(page.table.rowCount())]
    assert "Nmap documentation" in titles and any("NETWORK SECURITY" in t.upper() or "OSINT" in t.upper() for t in titles)
    page.kind.setCurrentText("Tool documentation")
    assert all("documentation" in page.table.item(r, 0).text() for r in range(page.table.rowCount()))
    page.search.setText("nmap")
    page.table.selectRow(0)
    page._open()
    assert opened == ["https://nmap.org/docs.html"] and opened   # nothing opens until Open is pressed


def test_system_tab_lists_and_copies_into_library(page, qapp, tmp_path, monkeypatch):
    sysdir = tmp_path / "usr_wordlists"
    (sysdir / "dirb").mkdir(parents=True)
    (sysdir / "rockyou.txt").write_bytes(b"one" + bytes([10]) + b"two" + bytes([10]))
    (sysdir / "dirb" / "common.txt").write_bytes(b"a" + bytes([10]))
    page.sys_root = str(sysdir)
    page._sys_reload()
    assert page.sys_tree.topLevelItemCount() == 2 and "2 entries" in page.sys_note.text()
    monkeypatch.setattr(rp, "confirm_dialog", lambda *a, **k: False)
    page._sys_import_all()
    assert page.lib.files() == []                                  # declining copies nothing
    monkeypatch.setattr(rp, "confirm_dialog", lambda *a, **k: True)
    page._sys_import_all()
    assert wait_until(qapp, lambda: len(page.lib.files()) == 2 and "Copied 2" in page.msg.text())
    assert {f["path"] for f in page.lib.files()} == {"wordlists/rockyou.txt", "wordlists/dirb/common.txt"}
    assert (sysdir / "rockyou.txt").exists()                       # originals untouched
    page._sys_import_all()
    assert wait_until(qapp, lambda: "Copied 0" in page.msg.text())  # second run: duplicates skipped
