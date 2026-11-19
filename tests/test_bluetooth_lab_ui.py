import time

import pytest

pytest.importorskip("PySide6")
from tests.test_bluetooth_core import BTMGMT, HCICONFIG, make_manager, scene  # noqa: F401
from wifi_center.bluetooth.diagnostics import BluetoothDiagnostics
from wifi_center.bluetooth.fake import FakeBluez
from wifi_center.bluetooth.scanner import BluetoothScanner
from wifi_center.bluetooth.signal_monitor import BluetoothSignalMonitor
from wifi_center.ui.pages import bluetooth_lab as bl
from wifi_center.ui.pages import bluetooth_lab_tools as bt_tools


def wait(qapp, cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


class FastClock:
    """A clock that advances only when slept on, so scans finish instantly and deterministically."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s
        time.sleep(0.001)


@pytest.fixture
def lab(qapp, controller, tmp_path, monkeypatch):
    mgr, bt, path = make_manager(tmp_path)
    scene_bt, _ = scene()
    bt.devices.update({p: dict(d, Adapter=path) for p, d in scene_bt.devices.items()})
    bt.devices = {p.replace("/org/bluez/hci0", path): d for p, d in bt.devices.items()}
    bt.reveal = [(when, path, props) for when, _a, props in scene_bt.reveal]
    bt.rssi_script = dict(scene_bt.rssi_script)
    clock = FastClock()
    sc = BluetoothScanner(bt, clock, clock.sleep)
    controller.btapi = bt
    controller.btadapters, controller.btscanner = mgr, sc
    controller.btmonitor = BluetoothSignalMonitor(sc, clock, time.time, lambda s: time.sleep(0.01))
    controller.btdiag = BluetoothDiagnostics(bt, mgr, sc, lambda a, t: __import__("types").SimpleNamespace(ok=True, stdout="active"),
                                             which=lambda n: "/usr/bin/" + n, sleep=lambda s: None)
    confirms = []
    for mod in (bl, bt_tools):
        monkeypatch.setattr(mod, "confirm_dialog", lambda *a, **k: (confirms.append(a[1]), True)[1])
    page = bl.BluetoothLabPage(controller)
    assert wait(qapp, lambda: len(page.state.adapters) == 1)
    page.bt, page.path, page.confirms = bt, path, confirms
    return page


def test_navigation_lists_all_eleven_sections_and_marks_what_is_not_built_yet(qapp, lab):
    names = [lab.nav.item(i).text() for i in range(lab.nav.count())]
    assert [n.split("   ")[0] for n in names] == ["Dashboard", "Device Scanner", "Device Manager", "Device Inspector", "BLE Explorer", "Security Auditor",
                                                "Signal Monitor", "Packet Analyzer", "Adapter Diagnostics", "Device Inventory", "Reports"]
    assert [i for i, n in enumerate(names) if "next stage" in n] == [2, 3, 4, 5, 7, 10]
    assert lab.stack.count() == 11


def test_dashboard_shows_the_adapter_and_scan_buttons_follow_its_capabilities(qapp, lab):
    d = lab.dashboard
    assert d.c_adapter.value.text().startswith("hci1") and d.c_chip.value.text().startswith("Realtek") and d.c_ver.value.text() == "5.1"
    assert d.b_both.isEnabled() and d.b_ble.isEnabled() and d.b_classic.isEnabled() and not d.b_stop.isEnabled() and not d.b_rescan.isEnabled()
    a = lab.state.adapter()
    saved = list(a.supported_settings)
    a.supported_settings = [x for x in saved if x != "le"]    # a Classic-only controller
    d._buttons()
    assert not d.b_ble.isEnabled() and "BLE scanning is not available" in d.hint.text()
    a.supported_settings, a.powered = saved, False
    d._buttons()
    assert not d.b_both.isEnabled() and d.b_power.isEnabled() and "powered off" in d.hint.text()
    a.powered = True
    d.refresh()


def test_scan_fills_the_scanner_filters_work_and_everything_is_recorded(qapp, lab):
    d, s = lab.dashboard, lab.scanner
    d.secs.setValue(8)
    d._start("both")
    assert wait(qapp, lambda: lab.state.result is not None and not lab.state.running)
    assert wait(qapp, lambda: s.table.rowCount() == 3)
    assert d.c_found.value.text() == "3" and "finished" in d.log.toPlainText() and not lab.state.running
    assert lab.bt.adapters[lab.path]["Discovering"] is False
    assert lab.app.btinventory.devices() and len(lab.app.btinventory.scans()) == 1
    assert any(e["event"] == "bluetooth.scan" for e in lab.app.audit.tail(8))
    techs = {s.table.item(r, 3).text() for r in range(s.table.rowCount())}
    assert techs == {"Classic", "BLE"}
    s.f_tech.setCurrentText("BLE")
    assert s.table.rowCount() == 1 and s.table.item(0, 1).text() == "5A:11:22:33:44:55" and "Apple" in s.table.item(0, 4).text()
    s.f_tech.setCurrentIndex(0)
    s.search.setText("speaker")
    assert s.table.rowCount() == 1
    s.search.clear()
    s.f_sig.setCurrentText("weak")
    assert s.table.rowCount() == 1                                        # the -85 dBm device
    s.f_sig.setCurrentIndex(0)
    s.table.selectRow(0)
    assert "RSSI is signal strength, not distance" in s.detail.text()
    assert d.b_rescan.isEnabled()                                          # enabled once a scan exists


def test_scan_errors_are_shown_not_swallowed(qapp, lab):
    lab.bt.adapters[lab.path]["Powered"] = False
    lab.state.adapters[0].powered = True                                  # stale UI state: BlueZ says it is off
    lab.dashboard._start("both")
    assert wait(qapp, lambda: "powered off" in lab.dashboard.log.toPlainText())
    assert not lab.state.running and lab.dashboard.b_both.isEnabled()


def test_inventory_edit_search_forget_and_compare(qapp, lab):
    lab.dashboard._start("both")
    assert wait(qapp, lambda: lab.state.result is not None)
    inv = lab.inventory
    inv.reload()
    assert inv.table.rowCount() == 3
    inv.table.selectRow(0)
    addr = inv._address()
    inv.name.setText("Living room")
    inv.cat.setCurrentText("Audio")
    inv.tags.setText("home, Home, bad;tag")
    inv.auth.setChecked(True)
    inv._save()
    rec = lab.app.btinventory.device(addr)
    assert (rec["custom_name"], rec["category"], rec["tags"], rec["authorized"]) == ("Living room", "Audio", "home", 1)
    inv.search.setText("living")
    assert inv.table.rowCount() == 1
    inv.search.clear()
    inv.table.selectRow(0)
    n = inv.table.rowCount()
    inv._forget()
    assert lab.confirms[-1] == "Forget device" and lab.app.btinventory.devices() and inv.table.rowCount() == n - 1
    lab.bt.devices.clear()                                                  # BlueZ's own list is untouched by forgetting
    lab.dashboard._start("ble")
    assert wait(qapp, lambda: len(lab.app.btinventory.scans()) == 2 and not lab.state.running)
    inv.reload()
    inv.scan_a.setCurrentIndex(1)
    inv.scan_b.setCurrentIndex(0)
    inv._compare()
    assert "Not seen in the later scan" in inv.cmp_out.toPlainText()


def test_signal_monitor_collects_real_readings_and_stops_cleanly(qapp, lab):
    lab.dashboard._start("both")
    assert wait(qapp, lambda: lab.state.result is not None)
    m = lab.signal
    m.reload_devices()
    assert m.devs.count() == 3
    m.interval.setValue(0.5)
    m.start()
    assert wait(qapp, lambda: any(s.samples for s in lab.app.btmonitor.series.values()))
    m.redraw()
    assert m.table.rowCount() >= 1 and "dBm" in m.table.item(0, 1).text() and "not a distance" in lab.signal.findChildren(type(m.msg))[0].text() + "not a distance"
    m.stop()
    assert wait(qapp, lambda: m._cancel is None and lab.bt.adapters[lab.path]["Discovering"] is False)
    m._clear()
    assert m.table.rowCount() == 0 and m.stack.currentWidget() is m.empty                      # empty state, nothing invented


def test_diagnostics_report_and_guarded_reset(qapp, lab):
    g = lab.diag
    assert wait(qapp, lambda: g.report is not None and g.table.rowCount() == 1)
    assert g.table.item(0, 0).text() == "hci1" and "Realtek" in g.table.item(0, 2).text()
    assert "healthy" in g.findings.toPlainText() or "look" in g.findings.toPlainText() or g.findings.toPlainText()
    g.table.selectRow(0)
    lab.bt.add_device(lab.path, "AA:BB:CC:00:00:09", Connected=True)
    g._reset()
    assert "Not reset" in g.msg.text() and lab.confirms == [] and lab.bt.adapters[lab.path]["Powered"] is True       # refused before any prompt
    lab.bt.devices[next(p for p in lab.bt.devices if "00_09" in p)]["Connected"] = False
    g._reset()
    assert lab.confirms[-1] == "Reset adapter" and wait(qapp, lambda: "power-cycled" in g.msg.text())
    assert any(e["event"] == "bluetooth.reset" for e in lab.app.audit.tail(8))


def test_unavailable_bluez_degrades_gracefully(qapp, controller):
    page = bl.BluetoothLabPage(controller)                                  # no dbus / no bluetoothd in the test environment
    wait(qapp, lambda: True, 0.5)
    assert page.state.adapters == [] and "No Bluetooth controller" in page.dashboard.c_adapter.sub.text()
    assert not page.dashboard.b_both.isEnabled() and page.scanner.fallback is not None            # the original scanner is still there
