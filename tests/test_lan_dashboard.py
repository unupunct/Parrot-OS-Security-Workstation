import time

import pytest

pytest.importorskip("PySide6")
from wifi_center.services import net_identity as ni
from wifi_center.services import network_discovery as nd
from wifi_center.ui.pages import lan_dashboard as ld


class FakeOui:
    def vendor(self, mac):
        return {"aa:bb:cc": "RouterCo", "00:11:22": "Seiko Epson Corp"}.get(mac[:8])


class FakeIdentifier:
    def __init__(self, ident, post):
        self.ident, self.post = ident, post

    def identify(self):
        return [self.ident]

    def neighbors(self):
        return self.post

    def interfaces(self):
        return [self.ident.interface]


def make_ident():
    itf = ni.InterfaceInfo("enp2s0", "up", "aa:00:00:00:00:26", 1500, "ethernet", [ni.AddrV4("192.168.1.26", 24, "global")])
    return ni.NetworkIdentity(itf, itf.v4[0], "192.168.1.1", "aa:bb:cc:00:00:01", ["192.168.1.1"], True)


def wait(qapp, cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def dash(qapp, controller, monkeypatch):
    ident = make_ident()
    post = [ni.Neighbor("192.168.1.1", "aa:bb:cc:00:00:01", "enp2s0", "REACHABLE"), ni.Neighbor("192.168.1.30", "00:11:22:33:44:55", "enp2s0", "STALE")]
    controller.netdisc = nd.NetworkDiscoveryEngine(controller.db, FakeOui(), FakeIdentifier(ident, post), controller.projects,
                                                   pinger=lambda ip, t: 2.0 if ip == "192.168.1.1" else None, resolver=lambda ip: "",
                                                   v6_probe=lambda i: None)
    pid = controller.projects.create("Lab")
    confirms = []
    monkeypatch.setattr(ld, "confirm_dialog", lambda *a, **k: (confirms.append(a[1]), True)[1])
    d = ld.DiscoveryDashboard(controller, lambda: pid)
    assert wait(qapp, lambda: d.nets.count() == 1)
    d.confirms, d.pid = confirms, pid
    return d


def test_identification_fills_the_form_from_the_real_prefix(qapp, dash):
    assert dash.cidr.text() == "192.168.1.0/24" and dash.c_gw.value.text() == "192.168.1.1" and dash.c_pot.value.text() == "254"
    html = dash.info.toPlainText()
    assert "192.168.1.26/24" in html and "255.255.255.0" in html and "aa:bb:cc:00:00:01" in html and "calculated from this interface" in html


def test_scan_is_blocked_until_the_range_is_in_the_authorized_scope(qapp, dash, controller):
    assert not dash.b_go.isEnabled() and dash.b_scope.isVisibleTo(dash) and "NOT inside" in dash.scope_lbl.text()
    dash._add_scope()                                                     # explicit, confirmed action
    assert controller.projects.scope(dash.pid)[0]["target"] == "192.168.1.0/24" and "dash" not in dash.confirms[-1]
    assert dash.b_go.isEnabled() and not dash.b_scope.isVisibleTo(dash)
    dash.cidr.setText("192.168.1.0/23")                                   # widening is not silently allowed
    assert not dash.b_go.isEnabled() and dash.b_scope.isVisibleTo(dash)


def test_confirmed_scan_runs_stores_results_and_builds_the_topology(qapp, dash, controller):
    controller.projects.add_scope(dash.pid, "192.168.1.0/24")
    dash._update_scope_state()
    dash.mode.setCurrentIndex(0)                                          # quick
    dash._review()
    assert dash.confirms[-1] == "Confirm network discovery"
    assert wait(qapp, lambda: dash._control is None and dash.hosts)
    ips = {h.ip: h for h in dash.hosts}
    assert set(ips) == {"192.168.1.1", "192.168.1.26", "192.168.1.30"} and ips["192.168.1.30"].status == "cached"
    assert dash.table.rowCount() == 3 and dash.c_found.value.text() == "3" and "Done" in dash.progress_lbl.text()
    assert "does not prove a host is offline" in dash.progress_lbl.text()
    assert controller.db.query_one("SELECT COUNT(*) n FROM nd_scans")["n"] == 1
    assert any(e["event"] == "netdisc.scan" for e in controller.audit.tail(8))
    dash.search.setText("epson")
    assert dash.table.rowCount() == 1
    dash.search.clear()
    dash.table.selectRow(0)
    assert "Confirmed" in dash.detail.toPlainText() or "Why:" in dash.detail.toPlainText()
    ids = {n.id for n in dash._graph.nodes}
    assert {"self", "internet", "segment:192.168.1.0/24", "host:192.168.1.30"} <= ids
    dash.topo.select("host:192.168.1.30")
    assert "neighbour cache" in dash.topo_detail.toPlainText()


def test_pause_cancel_buttons_and_failed_plan(qapp, dash, controller):
    dash.cidr.setText("8.8.8.0/24")
    dash._review()
    assert "private" in dash.progress_lbl.text() or "Cannot start" in dash.progress_lbl.text()
    assert dash.b_pause.isEnabled() is False and dash.b_cancel.isEnabled() is False
    ctl = nd.ScanControl()
    dash._control = ctl
    dash._set_running(True)
    assert dash.b_pause.isEnabled() and dash.b_cancel.isEnabled() and not dash.b_go.isEnabled()
    dash._pause()
    assert ctl.paused and dash.b_pause.text() == "Resume"
    dash._pause()
    assert not ctl.paused
    dash._cancel()
    assert ctl.cancelled.is_set()
    dash._control = None
    dash._set_running(False)


def test_history_compare_and_explicit_delete(qapp, dash, controller):
    controller.projects.add_scope(dash.pid, "192.168.1.0/24")
    dash._update_scope_state()
    for _ in range(2):
        dash._review()
        assert wait(qapp, lambda: dash._control is None)
        time.sleep(0.05)
    dash.reload_history()
    assert dash.hist.rowCount() == 2
    dash.hist.selectAll()
    dash._compare()
    out = dash.cmp_out.toPlainText()
    assert "Scan 1 → scan 2" in out and "does NOT prove they are offline" in out and "New in the later scan (0)" in out
    dash.hist.selectRow(0)
    dash._delete_scan()
    assert dash.confirms[-1] == "Delete scan" and dash.hist.rowCount() == 1 and controller.netdisc.devices()    # devices survive deletion
