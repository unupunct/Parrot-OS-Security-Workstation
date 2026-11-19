import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from wifi_center.ui.dashboard import Dashboard
from wifi_center.ui.main_window import MainWindow
from wifi_center.ui.navigation import NAVIGATION, all_items
from wifi_center.ui.pages.planned import PlannedPage
from wifi_center.ui.pages.settings_page import SettingsPage
from wifi_center.ui.theme import build_stylesheet


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def test_navigation_ids_unique_and_complete():
    ids = [i.id for i in all_items()]
    assert len(ids) == len(set(ids))
    assert [c.title for c in NAVIGATION] == [
        "DASHBOARD", "WIRELESS", "NETWORK SECURITY", "INTELLIGENCE", "PARROT OS MANAGER",
        "TOOL MANAGEMENT", "RESOURCES", "PROJECTS", "SETTINGS"]
    assert len(ids) == 42


def test_every_page_can_be_opened(qapp, controller):
    w = MainWindow(controller)
    for item in all_items():
        w.sidebar.select_page(item.id)
        assert w.current_page == item.id
        assert w.topbar.workspace.text() == item.title
    assert isinstance(w._pages["overview"], Dashboard)
    assert isinstance(w._pages["settings"], SettingsPage)
    assert isinstance(w._pages["wordlists"], PlannedPage)
    w.close()


def test_global_search_navigates(qapp, controller):
    w = MainWindow(controller)
    w.topbar.search.setText("kismet")
    w.topbar.search.returnPressed.emit()
    assert w.current_page == "kismet"
    w.close()


def test_layout_and_last_page_persist(qapp, controller):
    w = MainWindow(controller)
    w.sidebar.select_page("cleanup")
    w.sidebar._cats["WIRELESS"].setExpanded(False)
    w.close()
    assert controller.settings.get("general.last_page") == "cleanup"
    assert "WIRELESS" in controller.settings.get("ui.collapsed_categories")
    w2 = MainWindow(controller)
    assert w2.current_page == "cleanup"
    assert not w2.sidebar._cats["WIRELESS"].isExpanded()
    w2.close()


def test_dashboard_reads_database(qapp, controller):
    controller.db.execute("INSERT INTO projects(name) VALUES ('Lab A')")
    pid = controller.db.query_one("SELECT id FROM projects")["id"]
    controller.db.execute("INSERT INTO findings(project_id,title,severity) VALUES (?,?,?)", (pid, "x", "high"))
    d = Dashboard(controller)
    assert "Lab A" in d.proj_lbl.text()
    assert "High" in d.find_lbl.text()
    assert "No running operations" in d.live_lbl.text()


def test_stylesheet_uses_accent():
    assert "#20C979" in build_stylesheet("#20C979")
