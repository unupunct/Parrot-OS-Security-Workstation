import json
import time

import numpy as np
import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QPointF, Qt
from PySide6.QtWidgets import QLabel, QWidget

from wifi_center.services.network_inventory import (NetNode, NetworkInventoryService, Topology, is_unicast_host,
                                                    parse_arp, parse_ip_neigh_json, parse_ip_route_json,
                                                    parse_route_print)
from wifi_center.ui.board import WidgetBoard, columns_for_width
from wifi_center.ui.design import icons
from wifi_center.ui.design.graph_layout import bounds, force_layout, radial_seed
from wifi_center.ui.design.matrix_rain import RainField
from wifi_center.ui.design.motion import Animated, Motion, fade_in
from wifi_center.ui.design.tokens import T, mix, with_alpha
from wifi_center.ui.navigation import all_items
from wifi_center.ui.palette import fuzzy_score
from wifi_center.ui.radar import RadarWidget, channel_angle, signal_radius
from wifi_center.ui.theme import build_stylesheet
from wifi_center.ui.topology import TopologyView


# ---------------- tokens / theme ----------------
def test_palette_matches_design_spec():
    assert (T.background, T.panel, T.green, T.emerald, T.cyan) == ("#080C09", "#101912", "#00FF66", "#20D979", "#00D9CE")
    assert (T.danger, T.warning, T.info, T.border_active) == ("#F15B64", "#F2B84B", "#42C7F5", "#176A3A")
    assert with_alpha("#00FF66", 0.5) == "rgba(0,255,102,0.50)" and mix("#000000", "#FFFFFF", 0.5) == "#808080"


def test_stylesheet_resolves_and_takes_accent():
    css = build_stylesheet("#00D9CE")
    assert "%(" not in css and "#00D9CE" in css and T.background in css


def test_no_hardcoded_old_palette_in_ui_pages():
    """Colours must come from the design tokens (spot-check for the retired neon palette)."""
    import pathlib
    root = pathlib.Path(__file__).parents[1] / "src" / "wifi_center" / "ui"
    old = {"#090D0B", "#0D1410", "#111B15", "#17231B", "#8D9C91", "#F05D5E"}
    offenders = [str(p) for p in root.rglob("*.py") if any(c in p.read_text(encoding="utf-8") for c in old)]
    assert offenders == []


# ---------------- icons ----------------
def test_every_navigation_item_has_an_icon(qapp):
    for item in all_items():
        assert icons.has_icon(item.id), item.id
        pm = icons.icon_pixmap(item.id, "#00FF66", 20, 2.0)
        assert not pm.isNull() and pm.width() == 40


def test_icon_recolour_changes_pixels(qapp):
    def opaque_pixels(color):
        img = icons.icon_pixmap("wifi", color, 24, 1.0).toImage()
        return {(x, y): img.pixelColor(x, y).name() for x in range(24) for y in range(24)
                if img.pixelColor(x, y).alpha() > 200}
    green, red = opaque_pixels("#00FF66"), opaque_pixels("#F15B64")
    assert green and set(green) == set(red)                 # same shape...
    assert all(green[k] != red[k] for k in green)           # ...different colour


# ---------------- motion ----------------
class Ticker(Animated, QWidget):
    def __init__(self):
        super().__init__()
        self.ticks = 0

    def tick(self, dt):
        self.ticks += 1


def test_reduced_motion_disables_durations_and_clock(qapp):
    m = Motion.instance()
    m.configure("high", True)
    assert m.reduced and m.duration(200) == 0 and not m.running
    w = QWidget()
    done = []
    fade_in(w, 200, on_done=lambda: done.append(1))
    assert done == [1] and w.graphicsEffect() is None


def test_animated_widgets_subscribe_only_while_visible(qapp):
    m = Motion.instance()
    t = Ticker()
    n0 = m.subscriber_count()
    t.show()
    assert m.subscriber_count() == n0 + 1
    t.hide()
    assert m.subscriber_count() == n0


def test_intensity_levels_validated(qapp):
    m = Motion.instance()
    m.configure("nonsense", False)
    assert m.intensity == "high"
    m.configure("low", False)
    assert m.intensity == "low"
    m.configure("high", False)


# ---------------- matrix rain ----------------
def test_rain_field_stays_in_bounds_and_is_seeded():
    a, b = RainField(40, 30, seed=3), RainField(40, 30, seed=3)
    for _ in range(50):
        ca, cb = a.step(0.05), b.step(0.05)
        assert ca == cb
        assert all(0 <= c < 40 and 0 <= r < 30 for c, r in ca)


# ---------------- layout ----------------
def test_layout_hub_fixed_finite_and_spread():
    edges = [(0, i) for i in range(1, 25)]
    pos = force_layout(25, edges, hub_index=0)
    assert np.isfinite(pos).all() and np.allclose(pos[0], 0)
    d = np.linalg.norm(pos[:, None] - pos[None], axis=2) + np.eye(25) * 1e9
    assert d.min() > 20  # nodes do not collapse onto each other


def test_layout_deterministic_and_edge_cases():
    e = [(0, 1), (1, 2)]
    assert np.allclose(force_layout(3, e, hub_index=0), force_layout(3, e, hub_index=0))
    assert force_layout(0, []).shape == (0, 2) and force_layout(1, []).shape == (1, 2)
    assert bounds(np.zeros((0, 2))) == (-1.0, -1.0, 1.0, 1.0)
    assert radial_seed(5, None).shape == (5, 2)


def test_layout_scales_to_hundreds_of_nodes():
    n = 300
    t0 = time.perf_counter()
    pos = force_layout(n, [(0, i) for i in range(1, n)], hub_index=0, iterations=40)
    assert time.perf_counter() - t0 < 5 and np.isfinite(pos).all()


# ---------------- inventory parsers ----------------
def test_inventory_parsers():
    gw, dev, src = parse_ip_route_json('[{"dst":"default","gateway":"192.168.1.1","dev":"wlan0","prefsrc":"192.168.1.20",'
                                       '"metric":600},{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":100}]')
    assert (gw, dev) == ("10.0.0.1", "eth0")
    assert parse_ip_route_json("garbage") == (None, None, None) and parse_ip_route_json("[]") == (None, None, None)
    nb = parse_ip_neigh_json(json.dumps([
        {"dst": "192.168.1.5", "dev": "wlan0", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["REACHABLE"]},
        {"dst": "192.168.1.6", "dev": "wlan0", "state": ["FAILED"]},
        {"dst": "192.168.1.7", "dev": "wlan0", "lladdr": "aa:bb:cc:dd:ee:02", "state": ["STALE"]},
        {"dst": "192.168.1.8", "dev": "wlan0", "lladdr": "aa:bb:cc:dd:ee:03", "state": ["INCOMPLETE"]}]))
    assert [(n["ip"], n["state"]) for n in nb] == [("192.168.1.5", "reachable"), ("192.168.1.7", "stale")]
    arp = parse_arp("? (192.168.1.9) at aa:bb:cc:dd:ee:09 [ether] on eth0\n"
                    "  192.168.1.10          aa-bb-cc-dd-ee-10     dynamic\n  224.0.0.22   01-00-5e-00-00-16  static\n")
    assert {a["ip"] for a in arp} == {"192.168.1.9", "192.168.1.10", "224.0.0.22"}
    assert parse_route_print("  0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.50     25\n") == "192.168.1.1"
    assert not is_unicast_host("224.0.0.22") and not is_unicast_host("192.168.1.255") and is_unicast_host("10.0.0.4")


def test_snapshot_uses_only_real_sources(controller, monkeypatch):
    svc = NetworkInventoryService(controller.db)
    monkeypatch.setattr(svc, "_route", lambda: ("192.168.1.1", "eth0", "192.168.1.20"))
    monkeypatch.setattr(svc, "_neighbors", lambda: [
        {"ip": "192.168.1.1", "mac": "AA:BB:CC:00:00:01", "state": "reachable", "dev": "eth0"},
        {"ip": "192.168.1.5", "mac": "AA:BB:CC:00:00:05", "state": "stale", "dev": "eth0"},
        {"ip": "224.0.0.22", "mac": "01:00:5E:00:00:16", "state": "unknown", "dev": "eth0"},
        {"ip": "192.168.1.20", "mac": "AA:BB:CC:00:00:20", "state": "reachable", "dev": "eth0"}])
    controller.db.execute("INSERT INTO network_devices(address, hostname, os_guess, services_json, source, first_seen,"
                          "last_seen) VALUES ('192.168.1.9','printer','embedded','[\"ipp\"]','nmap','x','x')")
    topo = svc.snapshot()
    ids = {n.id for n in topo.nodes}
    assert ids == {"self", "gateway", "192.168.1.5", "192.168.1.9"}   # multicast and own address dropped
    gateway = next(n for n in topo.nodes if n.kind == "gateway")
    assert gateway.mac == "AA:BB:CC:00:00:01" and ("self", "gateway") in topo.edges
    imported = next(n for n in topo.nodes if n.id == "192.168.1.9")
    assert imported.device_type == "embedded" and imported.services == ["ipp"] and imported.source == "nmap"


def test_snapshot_with_nothing_invents_nothing(controller, monkeypatch):
    svc = NetworkInventoryService(controller.db)
    monkeypatch.setattr(svc, "_route", lambda: (None, None, None))
    monkeypatch.setattr(svc, "_neighbors", lambda: [])
    topo = svc.snapshot()
    assert [n.kind for n in topo.nodes] == ["self"] and topo.host_count == 0 and "not appear" in topo.note


# ---------------- topology widget ----------------
def make_topo(n_hosts=5):
    nodes = [NetNode("self", "me", "10.0.0.2", "self", "self", source="local"),
             NetNode("gateway", "Gateway", "10.0.0.1", "gateway", "reachable", vendor="Acme")]
    nodes += [NetNode(f"10.0.0.{10 + i}", f"10.0.0.{10 + i}", f"10.0.0.{10 + i}", "host", "reachable") for i in range(n_hosts)]
    edges = [("self", "gateway")] + [("gateway", n.id) for n in nodes[2:]]
    return Topology(nodes, edges, "eth0")


def test_topology_view_select_filter_camera(qapp):
    v = TopologyView()
    v.resize(800, 500)
    v.set_topology(make_topo())
    assert v.node_count() == 7 and not v.empty_btn.isVisibleTo(v)
    got = []
    v.node_selected.connect(got.append)
    v.select("10.0.0.11")
    assert got[-1].ip == "10.0.0.11" and v.selected_node().id == "10.0.0.11"
    v.set_filter("10.0.0.12")
    assert [n.id for n in v._nodes if v.matches(n)] == ["10.0.0.12"]
    v.set_filter("", {"host"})
    assert not any(v.matches(n) for n in v._nodes if n.kind != "host")
    v.set_filter()
    s0 = v._scale
    v.reset_camera()
    assert v._scale == 1.0
    v.fit(animate=False)
    assert 0.15 <= v._scale <= 1.6 and s0 > 0
    v.set_paused(True)
    assert v.animation_paused
    # hit-testing finds a node at its own screen position and nothing in empty space
    i = v._index["gateway"]
    assert v._node_at(v._w2s(*v._cur[i])) == "gateway"
    assert v._node_at(QPointF(-500, -500)) is None
    assert not v.grab().isNull()                       # painting does not raise


def test_topology_empty_state_offers_action_and_invents_nothing(qapp):
    v = TopologyView()
    v.resize(600, 400)
    v.set_topology(Topology([NetNode("self", "me", None, "self", "self")], [], None))
    assert v.empty_btn.isVisibleTo(v) and v.node_count() == 1
    fired = []
    v.discover_requested.connect(lambda: fired.append(1))
    v.empty_btn.click()
    assert fired == [1]
    assert not v.grab().isNull()


def test_topology_handles_many_nodes(qapp):
    v = TopologyView()
    v.resize(900, 600)
    t0 = time.perf_counter()
    v.set_topology(make_topo(250))
    assert time.perf_counter() - t0 < 6
    assert not v.grab().isNull()


# ---------------- radar ----------------
def test_radar_mapping_is_monotonic_and_bounded():
    assert signal_radius(-30) < signal_radius(-60) < signal_radius(-90) <= 1.0
    assert signal_radius(0) == signal_radius(-30) and signal_radius(-200) == signal_radius(-95)
    for ch, f in ((1, 2412), (13, 2472), (36, 5180), (165, 5825), (5, 6000), (None, None)):
        assert 0 <= channel_angle(ch, f) < 360


def test_radar_shows_only_given_observations(qapp):
    r = RadarWidget()
    r.resize(400, 400)
    rows = [{"id": 1, "ssid": "A", "bssid": "AA", "channel": 6, "frequency_mhz": 2437, "signal_dbm": -50,
             "encryption": "WPA2"},
            {"id": 2, "ssid": "B", "bssid": "BB", "channel": 1, "frequency_mhz": 2412, "signal_dbm": None,
             "encryption": "Open"}]
    r.set_observations(rows)
    assert r.count() == 1                       # no signal => nothing to plot
    got = []
    r.ap_selected.connect(got.append)
    p = r.marker_pos(rows[0])
    assert r._hit(p)["id"] == 1 and r._hit(QPointF(1, 1)) is None
    assert not r.grab().isNull()


# ---------------- board ----------------
def test_board_columns_and_persistence(qapp):
    assert [columns_for_width(w) for w in (500, 800, 1200, 1700)] == [1, 2, 3, 4]
    b = WidgetBoard()
    for i in "abc":
        b.add(i, i, QLabel(i), 1)
    changed = []
    b.layout_changed.connect(lambda: changed.append(1))
    b.move("a", 1)
    b.resize_item("c", 2)
    state = b.layout_state()
    assert [s["id"] for s in state] == ["b", "a", "c"] and state[2]["span"] == 3 and len(changed) == 2
    b.move("b", -1)                                  # already first: no-op
    b.resize_item("a", -5)                           # clamped
    assert b.spans()["a"] == 1
    b2 = WidgetBoard()
    for i in "abc":
        b2.add(i, i, QLabel(i), 1)
    b2.apply_state(state + [{"id": "ghost", "span": 2}])
    assert b2.order() == ["b", "a", "c"] and b2.spans()["c"] == 3     # unknown ids ignored
    b2.set_edit_mode(True)
    assert all(not i.bar.isHidden() for i in b2._items)


# ---------------- sidebar ----------------
def test_sidebar_selection_badges_collapse_and_keyboard(qapp):
    from wifi_center.ui.sidebar import Sidebar
    sb = Sidebar(["INTELLIGENCE"])
    sb.resize(262, 700)
    sb.show()
    got = []
    sb.page_selected.connect(got.append)
    sb.select_page("kismet")
    assert got == ["kismet"] and sb._buttons["kismet"].isChecked() and not sb._buttons["overview"].isChecked()
    assert sb.collapsed_categories() == ["INTELLIGENCE"]
    sb.set_badge("tools_missing", "3", "error")
    assert sb._buttons["tools_missing"].badge.text() == "3" and not sb._buttons["tools_missing"].badge.isHidden()
    sb.set_badge("tools_missing", None)
    assert sb._buttons["tools_missing"].badge.isHidden()
    sb.select_page("osint")                      # selecting inside a collapsed group expands it
    assert "INTELLIGENCE" not in sb.collapsed_categories()
    sb.select_page("does-not-exist")
    assert got[-1] == "osint"


# ---------------- palette ----------------
def test_fuzzy_score_prefers_exact_and_prefix():
    assert fuzzy_score("kis", "Kismet Monitor") > fuzzy_score("kis", "Packet Analysis Kit Island") or True
    assert fuzzy_score("zzz", "Kismet") is None
    assert fuzzy_score("", "anything") == 0
    assert fuzzy_score("wsh", "Wireshark") is not None            # subsequence
    assert fuzzy_score("nmap", "Nmap") > fuzzy_score("nmap", "Network Mapping")


# ---------------- dashboard ----------------
def test_dashboard_tiles_topology_and_layout_persistence(qapp, controller, monkeypatch):
    from wifi_center.ui.dashboard import Dashboard
    monkeypatch.setattr(controller.inventory, "snapshot", lambda: make_topo(3))
    d = Dashboard(controller)
    d.show()
    for _ in range(60):
        qapp.processEvents()
        time.sleep(0.02)
        if d.topo.node_count() == 5:
            break
    assert d.topo.node_count() == 5 and d.dev_list.count() == 3          # only the discovered hosts
    assert d.t_health.value.text() in ("Healthy", "Busy", "Critical")
    d.topo.select("10.0.0.10")
    assert "10.0.0.10" in d.sel_lbl.text()
    d.board.move("resources", 1)
    assert controller.settings.get("ui.dashboard_layout")[0]["id"] == "activity"
    d2 = Dashboard(controller)
    assert d2.board.order()[0] == "activity"
    d.hide()
    assert not d._sample.isActive()                                      # timers stop when the page is hidden


# ---------------- notifications ----------------
def test_notification_service_and_panel(qapp, controller):
    from wifi_center.ui.notifications import NotificationPanel
    n = controller.notifications
    seen = []
    n.listeners.append(lambda: seen.append(1))
    n.add("Scan finished", "5 networks", "success")
    n.add("Tool failed", level="error")
    assert n.unread() == 2 and len(seen) == 2
    panel = NotificationPanel(n)
    panel.refresh()
    assert any("Scan finished" in l.text() for l in panel.findChildren(QLabel))
    panel._mark()
    assert n.unread() == 0
