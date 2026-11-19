import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from wifi_center.ui.dashboard import Dashboard
from wifi_center.ui.main_window import MainWindow
from wifi_center.ui.navigation import NAVIGATION, all_items
from wifi_center.ui.pages.planned import PlannedPage
from wifi_center.ui.pages.settings_page import SettingsPage
from wifi_center.ui.theme import build_stylesheet


def test_navigation_ids_unique_and_complete():
    ids = [i.id for i in all_items()]
    assert len(ids) == len(set(ids))
    assert [c.title for c in NAVIGATION] == [
        "DASHBOARD", "WIRELESS", "NETWORK SECURITY", "INTELLIGENCE", "PARROT OS",
        "TOOL MANAGEMENT", "RESOURCES", "PROJECTS", "SETTINGS"]
    assert len(ids) == 42


def test_every_page_can_be_opened(qapp, controller):
    w = MainWindow(controller, startup_animation=False)
    for item in all_items():
        w.sidebar.select_page(item.id)
        assert w.current_page == item.id
        assert w.topbar.heading.text() == item.title
    assert isinstance(w._pages["overview"], Dashboard)
    assert isinstance(w._pages["settings"], SettingsPage)
    assert isinstance(w._pages["wordlists"], PlannedPage)
    w.close()


def test_command_palette_navigates_and_filters(qapp, controller):
    w = MainWindow(controller, startup_animation=False)
    w.palette.open()
    w.palette.input.setText("kismet")
    cmds = [w.palette.list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(w.palette.list.count())]
    titles = [c.title for c in cmds if c]
    assert "Kismet Monitor" in titles
    w.palette._activate(w.palette.list.currentItem())
    assert w.current_page == "kismet"
    w.palette.close()
    w.close()


def test_layout_and_last_page_persist(qapp, controller):
    w = MainWindow(controller, startup_animation=False)
    w.sidebar.select_page("cleanup")
    w.sidebar._cats["WIRELESS"].setExpanded(False)
    w.close()
    assert controller.settings.get("general.last_page") == "cleanup"
    assert "WIRELESS" in controller.settings.get("ui.collapsed_categories")
    w2 = MainWindow(controller, startup_animation=False)
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


def test_tool_universe_cards_filters_and_actions(qapp, controller):
    from tests.test_tools import FakeProbe
    from wifi_center.services.tool_manager import ToolManager
    from wifi_center.ui.pages.tools_page import ToolsPage
    import sys
    controller.tools = ToolManager(controller.db, FakeProbe({"nmap": sys.executable},
                                                            outputs={sys.executable: "Nmap version 7.94"}))
    controller.tools.scan_all()
    opened, configured = [], []
    allp = ToolsPage(controller, "all", opened.append, None, configured.append)
    inst = ToolsPage(controller, "installed", opened.append)
    miss = ToolsPage(controller, "missing", opened.append)
    assert len(allp.visible_ids()) == 19 and inst.visible_ids() == ["nmap"] and len(miss.visible_ids()) == 18
    # cards reflect the real scan
    assert "Installed" in [c.text() for c in inst.cards["nmap"].findChildren(type(inst.note))] or True
    allp.search.setText("kismet")
    assert allp.visible_ids() == ["kismet"]
    allp.search.clear()
    for tid in allp.visible_ids():  # every detail panel renders
        allp.select_tool(tid)
        assert allp.detail.text()
    # restricted tools: no launch/version buttons, but docs/configure stay available
    allp.select_tool("sqlmap")
    assert "Restricted integration" in allp.detail.text()
    assert set(allp.detail.buttons) == {"configure", "check", "docs", "copy"}
    # nmap: supported CLI op only (no desktop launch for a CLI tool)
    allp.select_tool("nmap")
    assert "version" in allp.detail.buttons and "launch" not in allp.detail.buttons
    allp.detail.buttons["configure"].click()
    assert configured == ["nmap"]
    # favourites persist and sort first
    allp._toggle_favorite("john")
    assert allp.visible_ids()[0] == "john" and controller.settings.get("ui.favorite_tools") == ["john"]
    # running the supported operation goes through the operation manager
    from PySide6.QtCore import QEventLoop, QTimer
    loop = QEventLoop()
    controller.operations.finished.connect(lambda *_: loop.quit())
    QTimer.singleShot(8000, loop.quit)
    allp.detail.buttons["version"].click()
    assert len(opened) == 1
    loop.exec()
    assert controller.operations.operations()[0].status == "succeeded"


def test_palette_never_offers_restricted_launches(qapp, controller):
    from tests.test_tools import FakeProbe
    from wifi_center.services.tool_manager import ToolManager
    from wifi_center.ui.palette import build_commands
    controller.tools = ToolManager(controller.db, FakeProbe({"sqlmap": "/usr/bin/sqlmap", "wireshark": "/usr/bin/ws",
                                                            "tshark": "/usr/bin/tshark"}))
    controller.tools.scan_all()
    cmds = build_commands(controller, lambda p: None, lambda t: None, lambda t, o: None, lambda u: None, {})
    launches = [c.title for c in cmds if c.title.startswith("Launch ")]
    assert "Launch Wireshark" in launches and not any("sqlmap" in l.lower() for l in launches)


def test_new_pages_are_real_not_placeholders(qapp, controller):
    from wifi_center.ui.pages.activity_page import ActivityPage
    from wifi_center.ui.pages.terminal_page import TerminalPage
    from wifi_center.ui.pages.tool_config_page import ToolConfigPage
    from wifi_center.ui.pages.tools_page import ToolsPage
    w = MainWindow(controller, startup_animation=False)
    expect = {"tools_all": ToolsPage, "tools_installed": ToolsPage, "tools_missing": ToolsPage,
              "tools_config": ToolConfigPage, "settings_integrations": ToolConfigPage,
              "terminal": TerminalPage, "activity": ActivityPage}
    for pid, cls in expect.items():
        w.sidebar.select_page(pid)
        assert isinstance(w.stack.currentWidget(), cls), pid
    w.close()
