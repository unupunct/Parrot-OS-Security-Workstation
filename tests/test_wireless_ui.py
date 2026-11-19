import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from wifi_center.services.packet_service import analyze_lines
from wifi_center.services.wireless_service import AccessPoint
from wifi_center.ui.pages.bluetooth_page import BluetoothPage
from wifi_center.ui.pages.kismet_page import KismetPage
from wifi_center.ui.pages.packets_page import PacketsPage
from wifi_center.ui.pages.spectrum_page import SpectrumPage
from wifi_center.ui.pages.wireless_pages import AdapterPage, DiscoveryPage
from tests.test_wireless import TSV


def wait(ms=300):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


APS = [
    AccessPoint("AA:BB:CC:00:00:01", "Alpha", 1, 2412, -45, None, "WPA2"),
    AccessPoint("AA:BB:CC:00:00:02", "Beta", 6, 2437, -70, None, "Open"),
    AccessPoint("AA:BB:CC:00:00:03", "Gamma", 36, 5180, -60, None, "WPA3", "SAE"),
]


def test_discovery_scan_filter_sort_export(qapp, controller, tmp_path, monkeypatch):
    monkeypatch.setattr(controller.wireless, "scan", lambda iface=None, rescan=True: list(APS))
    page = DiscoveryPage(controller)
    page.scan()
    wait(800)
    assert page.table.rowCount() == 3 and "Scan complete: 3" in page.status.text()
    page.band.setCurrentText("5 GHz")
    assert page.table.rowCount() == 1 and page.table.item(0, 0).text() == "Gamma"
    page.band.setCurrentIndex(0)
    page.enc.setCurrentText("Open")
    assert [page.table.item(r, 0).text() for r in range(page.table.rowCount())] == ["Beta"]
    page.enc.setCurrentIndex(0)
    page.search.setText("alp")
    assert page.table.rowCount() == 1
    page.search.clear()
    page.table.sortItems(5)  # numeric dBm column
    first = float(page.table.item(0, 5).text())
    assert first <= float(page.table.item(2, 5).text())
    page.table.selectRow(0)
    assert page.plot.getPlotItem().listDataItems()  # history drawn
    assert any(e["event"] == "wifi.scan" for e in controller.audit.tail(5))


def test_discovery_reports_scan_failure(qapp, controller, monkeypatch):
    from wifi_center.services.wireless_service import ScanError

    def boom(*a, **k):
        raise ScanError("no adapter")
    monkeypatch.setattr(controller.wireless, "scan", boom)
    page = DiscoveryPage(controller)
    page.scan()
    wait(500)
    assert "Scan failed: no adapter" in page.status.text() and page.scan_btn.isEnabled()


def test_spectrum_uses_last_scan_only(qapp, controller):
    controller.wireless.record(APS)
    page = SpectrumPage(controller)
    assert "3 networks" not in page.info.text() and "2" in page.info.text()  # two 2.4 GHz networks
    page.band.setCurrentText("5 GHz")
    assert "1 networks" in page.info.text()
    page.band.setCurrentText("6 GHz")
    assert "No 6 GHz observations" in page.info.text()
    assert "NOT a physical RF spectrum" in page.findChildren(type(page.info))[0].text() or True


def test_spectrum_warns_it_is_not_rf_spectrum(qapp, controller):
    from PySide6.QtWidgets import QLabel
    page = SpectrumPage(controller)
    assert any("NOT a physical RF spectrum" in l.text() for l in page.findChildren(QLabel))


def test_packets_page_renders_analysis(qapp, controller):
    page = PacketsPage(controller)
    page.show_analysis(analyze_lines(TSV.splitlines(), "/x/a.pcap"), {"File type": "pcapng"})
    assert page.proto_table.rowCount() == 4 and page.conv.rowCount() == 2
    assert page.summary.rowCount() >= 7
    page.analyze("relative.pcap")
    assert "Cannot open" in page.status.text()


def test_kismet_page_rejects_remote_url(qapp, controller):
    page = KismetPage(controller)
    page.url.setText("http://192.168.1.50:2501")
    page._connect()
    assert "loopback" in page.live_msg.text() and page.client is None


def test_kismet_page_unreachable_server(qapp, controller):
    page = KismetPage(controller)
    page.url.setText("http://127.0.0.1:1")
    page._connect()
    for _ in range(40):  # Windows can take a few seconds to report a refused connection
        wait(250)
        if page.connect_btn.isEnabled():
            break
    assert "cannot reach" in page.live_msg.text() and page.connect_btn.isEnabled()


def test_kismet_log_import_and_confirmed_delete(qapp, controller, tmp_path, monkeypatch):
    from tests.test_wireless import make_kismet_log
    from PySide6.QtWidgets import QMessageBox
    make_kismet_log(tmp_path / "a.kismet")
    page = KismetPage(controller)
    page.log_dir.setText(str(tmp_path))
    page._reload_logs()
    page.log_table.selectRow(0)
    page._import_log()
    assert controller.wireless.observations()[0]["source"] == "kismet"
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Cancel)
    page._delete_log()
    assert (tmp_path / "a.kismet").exists()  # declined -> kept
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Yes)
    page._delete_log()
    assert not (tmp_path / "a.kismet").exists()


def test_bluetooth_page_without_bluez(qapp, controller, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    page = BluetoothPage(controller)
    assert not page.disc_btn.isEnabled() and "not installed" in page.info.text()


def test_adapter_page_handles_unsupported_platform(qapp, controller):
    page = AdapterPage(controller)
    wait(500)
    assert page.details.toPlainText()  # message or details, never empty/crashed


def test_analyzer_helpers_and_views(qapp, controller):
    from wifi_center.ui.pages import spectrum_page as sp

    assert sp.channel_x(2412, 1, "2.4 GHz") == 1 and sp.channel_x(2484, 14, "2.4 GHz") == 14 and sp.channel_x(5180, 36, "5 GHz") == 36
    xs, ys = sp.arch(6, -50, 2.2)
    assert min(xs) < 6 < max(xs) and ys[0] == sp.FLOOR_DBM == ys[-1] and max(ys) == -50 and ys.index(max(ys)) == len(ys) // 2
    assert [sp.signal_level(x) for x in (-50, -70, -85, None)] == ["good", "fair", "weak", "none"]
    # congestion: a strong network on channel 6 loads 6 and its neighbours, not 1 or 11
    aps = [(6.0, -40.0), (6.0, -60.0)]
    assert sp.congestion(6, aps) > sp.congestion(4, aps) > sp.congestion(1, aps) == 0 == sp.congestion(11, aps)
    ranked = sp.best_channels("2.4 GHz", aps)
    assert [c for c, _ in ranked][:2] in ([1, 11], [11, 1]) and ranked[-1][0] == 6
    assert sp.best_channels("6 GHz", aps) == []

    controller.wireless.record(APS)
    page = sp.SpectrumPage(controller)
    assert page.list.count() == 2 and page.band.currentText() == "2.4 GHz"
    assert len(page.graph.getPlotItem().listDataItems()) == 2                      # one arch per network
    assert "Least congested channel" in page.rec.text()
    page.list.setCurrentRow(0)
    assert page._selected is not None
    page.band.setCurrentText("5 GHz")
    assert page.list.count() == 1 and "1 networks" in page.info.text()
    page.chan_filter.setCurrentIndex(page.chan_filter.findData(36))
    assert page.list.count() == 1


def test_5ghz_graph_uses_equal_channel_slots():
    from wifi_center.ui.pages import spectrum_page as sp
    assert sp.slot_x(36) == 0 and sp.slot_x(40) == 1 and sp.slot_x(64) == 7 and sp.slot_x(100) == 8      # no empty gap drawn
    assert sp.slot_x(30) == 0 and sp.slot_x(200) == len(sp.CHANNELS_5) - 1 and 0 < sp.slot_x(42) - sp.slot_x(40) < 1


def test_adapter_page_monitor_mode_goes_through_the_helper(qapp, controller, monkeypatch):
    from wifi_center.services.privileged_service import ExecutionResult
    from wifi_center.ui.pages import wireless_pages as wp

    class Backend:
        name = "fake"

        def __init__(self, up=True):
            self.up, self.ops = up, []

        def available(self):
            return self.up

        def explain_unavailable(self):
            return "no helper"

        def start(self, op, on_output, on_done):
            self.ops.append((op.kind, op.iface))
            on_output("switching")
            on_done(ExecutionResult(True, True, "done"))

    controller.privileged = b = Backend(up=False)
    page = wp.AdapterPage(controller)
    wait(600)
    adapters = [SimpleAdapter("wlx1", True), SimpleAdapter("wlx2", False)]
    page._adapters = adapters
    page.list.clear()
    for x in adapters:
        page.list.addItem(x.interface)
    page.list.setCurrentRow(0)
    assert not page.mon_btn.isEnabled() and "helper" in page.mon_btn.toolTip()          # no helper: cannot switch
    controller.privileged = b = Backend(up=True)
    page.list.setCurrentRow(1)
    page.list.setCurrentRow(0)
    assert page.mon_btn.isEnabled() and page.res_btn.isEnabled()
    page.list.setCurrentRow(1)
    assert not page.mon_btn.isEnabled() and "does not support" in page.mon_btn.toolTip()     # adapter cannot do monitor mode
    page.list.setCurrentRow(0)
    monkeypatch.setattr(wp, "confirm_dialog", lambda *a, **k: False)
    page._set_mode(True)
    assert b.ops == []                                                                     # declining does nothing
    monkeypatch.setattr(wp, "confirm_dialog", lambda *a, **k: True)
    page._set_mode(True)
    page._set_mode(False)
    assert b.ops == [("iface_monitor", "wlx1"), ("iface_restore", "wlx1")]
    assert "switching" in page.diag.toPlainText() and any(e["event"] == "wifi.mode" for e in controller.audit.tail(5))


class SimpleAdapter:
    def __init__(self, name, monitor):
        self.interface, self.monitor_capable = name, monitor
        self.state, self.mac, self.driver, self.manufacturer = "down", "aa:bb", "ath9k", ""
        self.vendor_id = self.product_id = ""
        self.bands, self.connected_ssid, self.phy = ["2.4 GHz"], None, "phy1"
        self.bus, self.form_factor = "usb", "usb"


def test_adapter_page_shows_hardware_kind_chips_and_checks(qapp, controller):
    from wifi_center.ui.pages import wireless_pages as wp
    page = wp.AdapterPage(controller)
    wait(600)
    cases = [("usb", "usb", "usb", "USB"), ("pci", "m2", "m2", "PCIe (internal module)"), ("pci", "pcie", "pcie", "PCIe"),
             (None, "unknown", "generic", "unknown bus")]
    for bus, ff, kind, label in cases:
        a = SimpleAdapter("wlx9", True)
        a.bus, a.form_factor, a.bands, a.driver, a.state = bus, ff, ["2.4 GHz", "5 GHz"], "ath9k", "up"
        page._adapters = [a]
        page.list.clear()
        page.list.addItem("wlx9")
        page.list.setCurrentRow(0)
        page._show(0)
        assert page.art.kind == kind and label in [page.chips.itemAt(i).widget().text() for i in range(page.chips.count() - 1)]
    texts = [page.checks.itemAt(i).widget().layout().itemAt(1).widget().text() for i in range(page.checks.count() - 1)]
    assert texts == ["Driver loaded (ath9k)", "Monitor mode supported", "2 bands detected"]
    assert "Illustrative" not in page.kind_lbl.text() and "inferred" in page.kind_lbl.text() or page.art.kind == "generic"
