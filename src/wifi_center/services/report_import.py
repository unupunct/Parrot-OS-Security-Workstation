"""Import existing assessment reports as organised findings. Reports are only read, never executed.

Supported: Nikto (XML, CSV, JSON), Burp Suite issue export (XML), Metasploit workspace export (XML) and a generic
findings file (CSV/JSON: title, severity, description, location, recommendation) for any other tool.
Format details follow each tool's documented output; verify against real exports from your versions.
"""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from ..database.repository import Database
from ..security.input_validation import ValidationError
from .nmap_parsers import Host, MAX_BYTES, ParseError, Port, ScanResult
from .project_service import ProjectService, SEVERITIES, sha256_file

_DANGEROUS = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.I)
SEVERITY_ALIASES = {"informational": "info", "information": "info", "note": "info", "none": "info",
                    "moderate": "medium", "warning": "medium", "severe": "high", "important": "high",
                    "false positive": "info"}


@dataclass
class ImportedFinding:
    title: str
    severity: str
    description: str = ""
    location: str = ""
    recommendation: str = ""


@dataclass
class ImportOutcome:
    tool: str
    findings: list[ImportedFinding]
    hosts: ScanResult | None = None     # Metasploit exports also carry hosts and services


def norm_severity(value: str | None, default: str = "info") -> str:
    v = (value or "").strip().lower()
    v = SEVERITY_ALIASES.get(v, v)
    return v if v in SEVERITIES else default


def _xml_root(text: str) -> ET.Element:
    if len(text) > MAX_BYTES:
        raise ParseError("file too large")
    if _DANGEROUS.search(text):
        raise ParseError("XML with DOCTYPE/ENTITY declarations is rejected")
    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        raise ParseError(f"invalid XML: {e}") from None


def _t(el: ET.Element | None, tag: str) -> str:
    if el is None:
        return ""
    child = el.find(tag)
    return (child.text or "").strip() if child is not None else ""


# ---------------- Nikto ----------------
def parse_nikto(text: str) -> ImportOutcome:
    s = text.lstrip()
    findings: list[ImportedFinding] = []
    if s.startswith("<"):
        root = _xml_root(text)
        for scan in root.iter("scandetails"):
            host = f"{scan.get('targetip', '')}:{scan.get('targetport', '')}".strip(":")
            for item in scan.findall("item"):
                desc = _t(item, "description")
                uri = _t(item, "uri")
                findings.append(ImportedFinding(desc[:140] or f"Nikto item {item.get('id', '')}", "low",
                                                desc, f"{host}{uri}"))
    elif s.startswith("[") or s.startswith("{"):
        data = json.loads(text)
        for entry in (data if isinstance(data, list) else [data]):
            host = f"{entry.get('ip') or entry.get('host', '')}:{entry.get('port', '')}".strip(":")
            for v in entry.get("vulnerabilities", []):
                msg = str(v.get("msg", ""))
                findings.append(ImportedFinding(msg[:140] or f"Nikto item {v.get('id', '')}", "low", msg,
                                                f"{host}{v.get('url', '')}"))
    else:
        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 7 and row[0].lower() != "hostname":
                findings.append(ImportedFinding(row[6][:140], "low", row[6], f"{row[1]}:{row[2]}{row[5]}"))
    if not findings:
        raise ParseError("no Nikto items found")
    return ImportOutcome("nikto", findings)


# ---------------- Burp ----------------
def parse_burp(text: str) -> ImportOutcome:
    root = _xml_root(text)
    if root.tag != "issues":
        raise ParseError("not a Burp issues export (root element is not <issues>)")
    out = []
    for i in root.findall("issue"):
        host = _t(i, "host")
        out.append(ImportedFinding(_t(i, "name") or "Burp issue", norm_severity(_t(i, "severity")),
                                   re.sub(r"<[^>]+>", " ", _t(i, "issueDetail") or _t(i, "issueBackground")).strip(),
                                   host + _t(i, "path"),
                                   re.sub(r"<[^>]+>", " ", _t(i, "remediationBackground")).strip()))
    if not out:
        raise ParseError("no issues found")
    return ImportOutcome("burp", out)


# ---------------- Metasploit workspace XML ----------------
def parse_metasploit(text: str) -> ImportOutcome:
    root = _xml_root(text)
    if not root.tag.startswith("MetasploitV"):
        raise ParseError("not a Metasploit XML export")
    hosts, findings = [], []
    for h in root.iter("host"):
        addr = _t(h, "address")
        if not addr:
            continue
        host = Host(addr, _t(h, "name"), _t(h, "mac").upper(), "", _t(h, "os-name"), "up")
        for sv in h.iter("service"):
            try:
                host.ports.append(Port(int(_t(sv, "port")), _t(sv, "proto") or "tcp", _t(sv, "state") or "open",
                                       _t(sv, "name"), _t(sv, "info")))
            except ValueError:
                continue
        for v in h.iter("vuln"):
            findings.append(ImportedFinding(_t(v, "name") or "Metasploit vulnerability record", "medium",
                                            _t(v, "info"), addr, ""))
        hosts.append(host)
    if not hosts and not findings:
        raise ParseError("no hosts or vulnerabilities in the export")
    return ImportOutcome("metasploit", findings, ScanResult(hosts, "metasploit-xml"))


# ---------------- generic ----------------
def parse_generic(text: str) -> ImportOutcome:
    s = text.lstrip()
    rows: list[dict] = []
    if s.startswith("[") or s.startswith("{"):
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get("findings", [])
    else:
        rows = list(csv.DictReader(io.StringIO(text)))
    out = []
    for r in rows:
        if not isinstance(r, dict) or not (r.get("title") or "").strip():
            continue
        out.append(ImportedFinding(str(r["title"]).strip()[:300], norm_severity(r.get("severity")),
                                   str(r.get("description") or ""), str(r.get("location") or ""),
                                   str(r.get("recommendation") or "")))
    if not out:
        raise ParseError("no findings with a 'title' were found (expected columns: title, severity, description, "
                         "location, recommendation)")
    return ImportOutcome("generic", out)


PARSERS = {"nikto": parse_nikto, "burp": parse_burp, "metasploit": parse_metasploit, "generic": parse_generic}


def detect_format(text: str) -> str:
    s = text.lstrip()[:2000]
    if "<MetasploitV" in s:
        return "metasploit"
    if "<issues" in s:
        return "burp"
    if "<niktoscan" in s or "scandetails" in s:
        return "nikto"
    return "generic"


class ReportImportService:
    def __init__(self, db: Database, projects: ProjectService) -> None:
        self._db = db
        self._projects = projects

    def import_file(self, project_id: int, path: str, fmt: str | None = None, nmap=None) -> dict:
        p = Path(path)
        if not p.is_absolute() or not p.is_file():
            raise ValidationError("choose an existing report file")
        if p.stat().st_size > MAX_BYTES:
            raise ParseError("file too large")
        if fmt is not None and fmt not in PARSERS:
            raise ValidationError(f"unknown report format: {fmt}")
        digest = sha256_file(p)
        if self._db.query_one("SELECT id FROM imported_reports WHERE project_id=? AND sha256=?", (project_id, digest)):
            return {"duplicate": True, "findings": 0, "tool": fmt or "", "hosts": 0}
        text = p.read_text(encoding="utf-8", errors="replace")
        fmt = fmt or detect_format(text)
        if fmt not in PARSERS:
            raise ValidationError(f"unknown report format: {fmt}")
        outcome = PARSERS[fmt](text)
        for f in outcome.findings:
            self._projects.add_finding(project_id, f.title, f.severity, f.description, f.recommendation,
                                       outcome.tool, f.location, f"{p.name}")
        hosts = 0
        if outcome.hosts is not None and nmap is not None:
            nmap.import_result(outcome.hosts, project_id, str(p), digest, "import-metasploit")
            hosts = len(outcome.hosts.hosts)
        self._db.execute("INSERT INTO imported_reports(project_id, tool, filename, sha256, finding_count) "
                         "VALUES (?,?,?,?,?)", (project_id, outcome.tool, p.name, digest, len(outcome.findings)))
        self._projects.touch(project_id)
        return {"duplicate": False, "findings": len(outcome.findings), "tool": outcome.tool, "hosts": hosts}
