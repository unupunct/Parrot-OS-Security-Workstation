"""BluetoothReportGenerator: HTML, PDF, JSON and CSV reports from the inventory, the auditor's stored findings and (optionally) a
packet-capture summary.

The report says what each statement rests on: findings keep their status (confirmed / observation / unknown), evidence, explanation and
remediation. Devices that were never audited are listed as such and get no findings; devices not marked as authorised are inventory
rows only. Pairing keys, PINs and capture payloads are never included. Free-text notes are left out unless asked for."""
from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import SEVERITIES, BluetoothError, Finding, utcnow

esc = html.escape
SEV_COLOR = {"informational": "#5b6770", "low": "#1f7aa8", "medium": "#b7791f", "high": "#c53030", "critical": "#9b1c1c"}
STATUS_TEXT = {"confirmed": "Confirmed (verified from this computer)", "observation": "Observation (declared by the device, not tested)",
               "unknown": "Unknown (cannot be determined from this computer)"}
FORMATS = ("html", "pdf", "json", "csv")
LIMITATIONS = (
    "Findings marked Observation are what a device advertises or declares; they were not tested and may not be exploitable.",
    "Findings marked Unknown could not be determined from this computer; the report does not guess.",
    "Signal strength is not distance, and a device that was not seen in a scan is not proof it is absent.",
    "Link encryption cannot be read from the host Bluetooth stack, so it is reported as unknown unless a capture shows it.",
    "Only devices marked as owned or authorised in the inventory are assessed. Nothing in this report was obtained by guessing keys or PINs or by attacking encryption.",
)


@dataclass
class DeviceSection:
    info: dict                                   # inventory row (subset)
    audited: bool = False
    audit_time: str = ""
    deep: bool = False
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Report:
    title: str
    generated: str
    devices: list[DeviceSection]
    capture: dict | None = None
    limitations: tuple[str, ...] = LIMITATIONS

    @property
    def totals(self) -> dict[str, int]:
        return {s: sum(1 for d in self.devices for f in d.findings if f.severity == s) for s in reversed(SEVERITIES)}

    @property
    def audited(self) -> int:
        return sum(1 for d in self.devices if d.audited)


class BluetoothReportGenerator:
    def __init__(self, inventory, auditor, now=utcnow) -> None:
        self.inventory, self.auditor, self._now = inventory, auditor, now

    # ------------------------------------------------------------------ data
    def build(self, addresses: list[str] | None = None, include_notes: bool = False, analysis=None, title: str = "Bluetooth Security Report") -> Report:
        rows = self.inventory.devices(sort="name")
        if addresses is not None:
            wanted = {a.upper() for a in addresses}
            rows = [r for r in rows if r["address"] in wanted]
        sections = []
        for r in rows:
            info = {k: r[k] for k in ("address", "name", "custom_name", "category", "tags", "technology", "device_type", "manufacturer", "address_type",
                                      "first_seen", "last_seen", "last_rssi", "authorized")}
            if include_notes:
                info["notes"] = r["notes"]
            sec = DeviceSection(info)
            audits = self.auditor.audits(r["address"], 1)
            if audits:
                a = audits[0]
                sec.audited, sec.audit_time, sec.deep = True, a["started_at"], bool(a["deep"])
                sec.findings = self.auditor.findings(a["id"])
            sections.append(sec)
        cap = None
        if analysis is not None:
            cap = {"file": Path(analysis.path).name, "packets": len(analysis.packets), "duration_s": round(analysis.duration, 1),
                   "connections": len(analysis.connections), "encryption_events": len(analysis.encryption), "pairings": len(analysis.pairings),
                   "gatt_writes": analysis.gatt_writes, "errors": len(analysis.errors), "notes": list(analysis.notes),
                   "scope": "HCI capture of this computer's own controller; not an over-the-air capture."}
        return Report(title, self._now(), sections, cap)

    # ------------------------------------------------------------------ renderers
    @staticmethod
    def _name(info: dict) -> str:
        return info["custom_name"] or info["name"] or "(unnamed)"

    def to_json(self, report: Report) -> str:
        return json.dumps({
            "title": report.title, "generated": report.generated, "summary": report.totals, "audited_devices": report.audited, "limitations": list(report.limitations),
            "capture": report.capture,
            "devices": [{**d.info, "audited": d.audited, "audit_time": d.audit_time, "deep_audit": d.deep,
                         "findings": [{"title": f.title, "severity": f.severity, "status": f.status, "evidence": f.evidence, "explanation": f.explanation,
                                       "remediation": f.remediation, "timestamp": f.timestamp, "check": f.check} for f in d.findings]} for d in report.devices]},
            indent=2)

    def to_csv(self, report: Report) -> str:
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["device", "address", "authorised", "severity", "status", "finding", "evidence", "explanation", "remediation", "timestamp"])
        for d in report.devices:
            if not d.findings:
                w.writerow([self._name(d.info), d.info["address"], "yes" if d.info["authorized"] else "no", "", "", "audited, no findings" if d.audited else "not audited",
                            "", "", "", ""])
            for f in d.findings:
                w.writerow([self._name(d.info), d.info["address"], "yes" if d.info["authorized"] else "no", f.severity, f.status, f.title, f.evidence, f.explanation,
                            f.remediation, f.timestamp])
        return out.getvalue()

    def to_html(self, report: Report) -> str:
        t = report.totals
        parts = [f"<h1>{esc(report.title)}</h1><p class='meta'>Generated {esc(report.generated)} by WIFI Center · Bluetooth Lab. "
                 f"{len(report.devices)} device(s) in scope, {report.audited} audited.</p>",
                 "<h2>Summary</h2><p>" + (" ".join(f"<span class='sev' style='background:{SEV_COLOR[s]}'>{n} {s}</span>" for s, n in t.items() if n) or "No findings.") + "</p>"]
        parts.append("<h2>Devices</h2><table><tr><th>Name</th><th>Address</th><th>Type</th><th>Technology</th><th>Manufacturer</th><th>Authorised</th><th>Audit</th></tr>" +
                     "".join(f"<tr><td>{esc(self._name(d.info))}</td><td>{esc(d.info['address'])}</td><td>{esc(d.info['category'] or d.info['device_type'])}</td>"
                             f"<td>{esc(d.info['technology'])} <small>(inferred)</small></td><td>{esc(d.info['manufacturer'] or '—')}</td>"
                             f"<td>{'yes' if d.info['authorized'] else 'no'}</td><td>{('deep' if d.deep else 'standard') + ' · ' + esc(d.audit_time) if d.audited else 'not audited'}</td></tr>"
                             for d in report.devices) + "</table>")
        parts.append("<h2>Findings</h2>")
        shown = False
        for d in report.devices:
            if not d.findings:
                continue
            shown = True
            parts.append(f"<h3>{esc(self._name(d.info))} <small>{esc(d.info['address'])}</small></h3>")
            for f in d.findings:
                parts.append(f"<div class='finding'><div class='ft'><span class='sev' style='background:{SEV_COLOR[f.severity]}'>{esc(f.severity)}</span> {esc(f.title)}</div>"
                             f"<p class='st'>{esc(STATUS_TEXT[f.status])}</p><p><b>Evidence.</b> {esc(f.evidence)}</p><p><b>What it means.</b> {esc(f.explanation)}</p>"
                             f"<p><b>Remediation.</b> {esc(f.remediation)}</p><p class='meta'>{esc(f.timestamp)}</p></div>")
        if not shown:
            parts.append("<p>No stored findings for the devices in this report. Mark a device as authorised in the inventory and run the Security Auditor first.</p>")
        if report.capture:
            c = report.capture
            parts.append(f"<h2>Packet capture</h2><p>{esc(c['file'])}: {c['packets']} packet(s) over {c['duration_s']} s; {c['connections']} connection event(s), "
                         f"{c['encryption_events']} encryption change(s), {c['pairings']} pairing message(s), {c['gatt_writes']} GATT write(s), {c['errors']} error status(es).</p>"
                         f"<p class='meta'>{esc(c['scope'])}</p>" + ("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in c["notes"]) + "</ul>" if c["notes"] else ""))
        parts.append("<h2>How to read this report</h2><ul>" + "".join(f"<li>{esc(x)}</li>" for x in report.limitations) + "</ul>")
        css = ("body{font-family:Arial,Helvetica,sans-serif;color:#1b2227;margin:28px;font-size:13px}h1{font-size:22px}h2{font-size:17px;border-bottom:1px solid #ccd3d8;"
               "padding-bottom:3px;margin-top:22px}h3{font-size:14px}small,.meta{color:#5b6770}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd3d8;"
               "padding:4px 7px;text-align:left;vertical-align:top}th{background:#eef1f3}.sev{color:#fff;border-radius:9px;padding:1px 8px;font-size:11px;font-weight:bold}"
               ".finding{border:1px solid #ccd3d8;border-radius:6px;padding:6px 10px;margin:8px 0;page-break-inside:avoid}.ft{font-weight:bold}.st{color:#3b4650;font-style:italic}")
        return f"<!doctype html><html><head><meta charset='utf-8'><title>{esc(report.title)}</title><style>{css}</style></head><body>{''.join(parts)}</body></html>"

    # ------------------------------------------------------------------ output
    def write(self, report: Report, path: str | Path, fmt: str) -> Path:
        fmt = fmt.lower()
        if fmt not in FORMATS:
            raise BluetoothError(f"unknown report format: {fmt}")
        p = Path(path)
        if p.suffix.lower() != f".{fmt}":
            p = p.with_suffix(f".{fmt}")
        if fmt == "pdf":
            self._write_pdf(self.to_html(report), p)
        else:
            p.write_text({"html": self.to_html, "json": self.to_json, "csv": self.to_csv}[fmt](report), encoding="utf-8", newline="")
        return p

    @staticmethod
    def _write_pdf(html_text: str, path: Path) -> None:
        try:
            from PySide6.QtCore import QMarginsF
            from PySide6.QtGui import QPageLayout, QPageSize, QPdfWriter, QTextDocument
        except ImportError as e:                            # the report engine is part of Qt; without it only HTML/JSON/CSV
            raise BluetoothError("PDF output needs PySide6's PDF support; use HTML and print it to PDF instead.") from e
        writer = QPdfWriter(str(path))
        writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
        writer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
        writer.setTitle("Bluetooth Security Report")
        doc = QTextDocument()
        doc.setHtml(html_text)
        doc.print_(writer)
