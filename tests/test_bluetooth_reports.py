"""Bluetooth reports: content, honesty about status and scope, escaping and file output."""
import csv
import io
import json

import pytest

from tests.test_bluetooth_packets import SCENE, snoop
from tests.test_bluetooth_stage2 import ADDR, world
from wifi_center.bluetooth import packets as pk
from wifi_center.bluetooth.models import BluetoothError
from wifi_center.bluetooth.reports import BluetoothReportGenerator


def gen_world():
    bt, path, inv, mgr, exp, aud, audit = world(Paired=True, Bonded=True, Trusted=True, Connected=True, ServicesResolved=True)
    bt.devices[path]["UUIDs"] = ["00001101-0000-1000-8000-00805f9b34fb"]
    inv.set_info(ADDR, custom_name="Tag <b>1</b>", notes="secret note", authorized=True)
    aud.audit_device(ADDR)
    return inv, aud


def test_report_contains_findings_with_status_evidence_and_limits():
    inv, aud = gen_world()
    g = BluetoothReportGenerator(inv, aud, lambda: "2026-11-19T10:00:00+00:00")
    r = g.build()
    assert r.audited == 1 and sum(r.totals.values()) == len(r.devices[0].findings) > 0
    html = g.to_html(r)
    for needle in ("Bluetooth Security Report", "Evidence.", "Remediation.", "Confirmed (verified", "Observation (declared by the device, not tested)",
                   "Unknown (cannot be determined", "How to read this report", "2026-11-19T10:00:00+00:00"):
        assert needle in html
    assert "<b>1</b>" not in html and "&lt;b&gt;1&lt;/b&gt;" in html            # user-controlled text is escaped
    assert "secret note" not in html and "secret note" not in g.to_json(r)      # notes are excluded unless asked for
    assert "secret note" in g.to_json(g.build(include_notes=True))


def test_unaudited_and_unauthorised_devices_get_no_findings():
    inv, aud = gen_world()
    from wifi_center.bluetooth.models import device_from_props
    from wifi_center.bluetooth.scanner import ScanResult
    other = device_from_props("/x", {"Address": "AA:AA:AA:AA:AA:01", "Alias": "Stranger"})
    inv.record_scan(ScanResult(adapter="/a", mode="ble", started_at="2026-01-01T00:00:00+00:00", duration_s=1, devices=[other]))
    g = BluetoothReportGenerator(inv, aud)
    r = g.build()
    stranger = next(d for d in r.devices if d.info["address"] == "AA:AA:AA:AA:AA:01")
    assert not stranger.audited and not stranger.findings and not stranger.info["authorized"]
    assert "not audited" in g.to_html(r)
    rows = list(csv.DictReader(io.StringIO(g.to_csv(r))))
    assert any(x["finding"] == "not audited" and x["authorised"] == "no" for x in rows)
    only = g.build(addresses=["aa:aa:aa:aa:aa:01"])
    assert [d.info["address"] for d in only.devices] == ["AA:AA:AA:AA:AA:01"]


def test_capture_summary_is_included_without_payloads(tmp_path):
    inv, aud = gen_world()
    p = tmp_path / "c.btsnoop"
    p.write_bytes(snoop(SCENE))
    g = BluetoothReportGenerator(inv, aud)
    r = g.build(analysis=pk.parse_btsnoop(p))
    html, js = g.to_html(r), json.loads(g.to_json(r))
    assert "Packet capture" in html and js["capture"]["packets"] == 10 and "not an over-the-air capture" in js["capture"]["scope"]
    assert "AA AA" not in html and "aaaaaaaa" not in html.lower()


def test_files_are_written_in_every_format(tmp_path, qapp):
    inv, aud = gen_world()
    g = BluetoothReportGenerator(inv, aud)
    r = g.build()
    for fmt in ("html", "json", "csv", "pdf"):
        out = g.write(r, tmp_path / f"report.{fmt}", fmt)
        assert out.exists() and out.stat().st_size > 200
    assert (tmp_path / "report.pdf").read_bytes()[:5] == b"%PDF-"
    assert g.write(r, tmp_path / "noext", "json").name == "noext.json"
    with pytest.raises(BluetoothError):
        g.write(r, tmp_path / "x.docx", "docx")
