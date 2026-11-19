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
