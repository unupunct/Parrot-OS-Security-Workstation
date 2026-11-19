"""Assessment reports and project history.

A report is built from what is stored for one project: authorised scope, findings (with status, location, remediation tracking),
evidence files (their SHA-256 is re-checked when the report is built, and changed or missing files are flagged), notes, references and
imported tool reports. Nothing is invented: a project without findings produces a report that says so. The report states its scope and
limits. Free-text notes and local file paths are left out unless the user opts in. Every generated report is logged with the SHA-256 of
the file so it can later be shown to be unchanged."""
from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..database.repository import Database
from .project_service import SEVERITIES, ProjectService, sha256_file

esc = html.escape
FORMATS = ("html", "pdf", "json", "csv")
SEV_COLOR = {"critical": "#9b1c1c", "high": "#c53030", "medium": "#b7791f", "low": "#1f7aa8", "info": "#5b6770"}
STATUS_TEXT = {"open": "Open", "in_progress": "In progress", "resolved": "Resolved", "accepted": "Risk accepted"}
OPEN_STATES = ("open", "in_progress")
LIMITATIONS = (
    "This report lists what was recorded in the project. Findings are only as complete as the testing that produced them; the absence of a finding is not proof that an issue does not exist.",
    "Testing was limited to the authorised scope listed above. Targets outside it were not assessed.",
    "Severity ratings are the assessor's judgement unless a finding names a tool as its source, in which case they follow that tool's rating.",
    "Evidence files are referenced, not embedded. Their SHA-256 values were recomputed when this report was generated; a file marked changed or missing no longer matches what was recorded.",
)


@dataclass
class ReportOptions:
    title: str = ""
    prepared_by: str = ""
    client: str = ""
    include_notes: bool = False
    include_resolved: bool = True
    include_paths: bool = False
    verify_evidence: bool = True


@dataclass
class ProjectReport:
    title: str
    generated: str
    project: dict
    options: ReportOptions
    scope: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)       # each with an "evidence" list
    evidence: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    imports: list[dict] = field(default_factory=list)

    @property
    def open_by_severity(self) -> dict[str, int]:
        return {s: sum(1 for f in self.findings if f["severity"] == s and f["status"] in OPEN_STATES) for s in reversed(SEVERITIES)}

    @property
    def status_counts(self) -> dict[str, int]:
        return {k: sum(1 for f in self.findings if f["status"] == k) for k in STATUS_TEXT}

    @property
    def integrity_problems(self) -> list[dict]:
        return [e for e in self.evidence if e.get("state") in ("changed", "missing")]


class ProjectReportService:
    def __init__(self, db: Database, projects: ProjectService, now=None) -> None:
        self.db, self.projects = db, projects
        self._now = now or (lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    # ------------------------------------------------------------------ evidence integrity
    def evidence_state(self, row: dict) -> str:
        p = Path(row["path"])
        if not p.is_file():
            return "missing"
        return "ok" if sha256_file(p) == row["sha256"] else "changed"

    # ------------------------------------------------------------------ build
    def build(self, project_id: int, options: ReportOptions | None = None) -> ProjectReport:
        o = options or ReportOptions()
        project = self.projects.get(project_id)
        if project is None:
            raise ValueError("that project does not exist")
        evidence = self.projects.evidence(project_id)
        for e in evidence:
            e["state"] = self.evidence_state(e) if o.verify_evidence else "not checked"
            e["name"] = Path(e["path"]).name
        findings = self.projects.findings(project_id)
        if not o.include_resolved:
            findings = [f for f in findings if f["status"] in OPEN_STATES]
        for f in findings:
            f["evidence"] = [e for e in evidence if e["finding_id"] == f["id"]]
        imports = [dict(r) for r in self.db.query("SELECT tool, filename, sha256, finding_count, imported_at FROM imported_reports WHERE project_id=? ORDER BY id", (project_id,))]
        return ProjectReport(o.title.strip() or f"{project['name']} — Security Assessment Report", self._now(), project, o, self.projects.scope(project_id), findings, evidence,
                             self.projects.notes(project_id) if o.include_notes else [], self.projects.references(project_id), imports)

    # ------------------------------------------------------------------ renderers
    def to_json(self, r: ProjectReport) -> str:
        def ev(e: dict) -> dict:
            d = {"file": e["name"], "sha256": e["sha256"], "description": e["description"], "state": e["state"], "added_at": e["added_at"]}
            if r.options.include_paths:
                d["path"] = e["path"]
            return d
        return json.dumps({
            "title": r.title, "generated": r.generated, "prepared_by": r.options.prepared_by, "client": r.options.client,
            "project": {"name": r.project["name"], "kind": r.project["kind"], "created_at": r.project["created_at"], "updated_at": r.project["updated_at"]},
            "scope": [{"target": s["target"], "kind": s["kind"], "note": s["note"]} for s in r.scope],
            "summary": {"open_by_severity": r.open_by_severity, "status_counts": r.status_counts, "findings": len(r.findings), "evidence_integrity_problems": len(r.integrity_problems)},
            "findings": [{**{k: f.get(k) for k in ("id", "title", "severity", "status", "description", "recommendation", "remediation_notes", "due_date", "location",
                                                      "source_tool", "source_ref", "created_at", "updated_at")}, "evidence": [ev(e) for e in f["evidence"]]} for f in r.findings],
            "evidence": [ev(e) for e in r.evidence], "references": [{"url": x["url"], "label": x["label"]} for x in r.references],
            "imported_reports": r.imports, "notes": [{"body": n["body"], "created_at": n["created_at"]} for n in r.notes], "limitations": list(LIMITATIONS)}, indent=2)

    def to_csv(self, r: ProjectReport) -> str:
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["id", "severity", "status", "title", "location", "source_tool", "description", "recommendation", "remediation_notes", "due_date", "evidence_files", "created_at"])
        for f in r.findings:
            w.writerow([f["id"], f["severity"], f["status"], f["title"], f.get("location") or "", f.get("source_tool") or "", f.get("description") or "",
                        f.get("recommendation") or "", f.get("remediation_notes") or "", f.get("due_date") or "", "; ".join(e["name"] for e in f["evidence"]), f["created_at"]])
        return out.getvalue()

    def to_html(self, r: ProjectReport) -> str:
        o, p = r.options, r.project
        meta = " · ".join(x for x in (f"Client: {esc(o.client)}" if o.client else "", f"Prepared by: {esc(o.prepared_by)}" if o.prepared_by else "",
                                      f"Generated {esc(r.generated)} by WIFI Center") if x)
        parts = [f"<h1>{esc(r.title)}</h1><p class='meta'>{meta}</p>"]
        oc = r.open_by_severity
        total_open = sum(oc.values())
        parts.append("<h2>Executive summary</h2><p>" + (f"{len(r.findings)} finding(s) recorded; <b>{total_open}</b> still open. " if r.findings else "No findings are recorded for this project. ") +
                     " ".join(f"<span class='sev' style='background:{SEV_COLOR[s]}'>{n} {s}</span>" for s, n in oc.items() if n) + "</p>")
        sc = r.status_counts
        if r.findings:
            parts.append("<p>" + " · ".join(f"{STATUS_TEXT[k]}: {n}" for k, n in sc.items() if n) + "</p>")
        if r.integrity_problems:
            parts.append("<p class='warn'><b>Evidence integrity:</b> " + f"{len(r.integrity_problems)} evidence file(s) no longer match the recorded SHA-256 or are missing (see Evidence).</p>")
        parts.append("<h2>Scope of the assessment</h2>" + ("<table><tr><th>Target</th><th>Type</th><th>Note</th></tr>" + "".join(
            f"<tr><td>{esc(s['target'])}</td><td>{esc(s['kind'])}</td><td>{esc(s['note'] or '')}</td></tr>" for s in r.scope) + "</table>"
            if r.scope else "<p>No authorised scope is recorded for this project.</p>"))
        parts.append("<h2>Findings</h2>")
        if not r.findings:
            parts.append("<p>None recorded.</p>")
        for f in r.findings:
            facts = [("Status", STATUS_TEXT.get(f["status"], f["status"])), ("Location", f.get("location")), ("Source", f.get("source_tool")), ("Due", f.get("due_date"))]
            parts.append(f"<div class='finding'><div class='ft'><span class='sev' style='background:{SEV_COLOR[f['severity']]}'>{esc(f['severity'])}</span> {esc(f['title'])}</div>"
                         f"<p class='meta'>{' · '.join(f'{esc(k)}: {esc(str(v))}' for k, v in facts if v)}</p>"
                         + (f"<p><b>Description.</b> {esc(f['description'])}</p>" if f.get("description") else "")
                         + (f"<p><b>Recommendation.</b> {esc(f['recommendation'])}</p>" if f.get("recommendation") else "")
                         + (f"<p><b>Remediation notes.</b> {esc(f['remediation_notes'])}</p>" if f.get("remediation_notes") else "")
                         + (f"<p><b>Evidence.</b> {', '.join(esc(e['name']) + ' (' + esc(e['state']) + ')' for e in f['evidence'])}</p>" if f["evidence"] else "") + "</div>")
        if r.evidence:
            rows = "".join(f"<tr><td>{esc(e['name'])}" + (f"<br><small>{esc(e['path'])}</small>" if o.include_paths else "") + f"</td><td>{esc(e['description'] or '')}</td>"
                           f"<td><small>{esc(e['sha256'] or '')}</small></td><td class='{'warn' if e['state'] in ('changed', 'missing') else ''}'>{esc(e['state'])}</td></tr>" for e in r.evidence)
            parts.append("<h2>Evidence</h2><table><tr><th>File</th><th>Description</th><th>SHA-256 (recorded)</th><th>Check now</th></tr>" + rows + "</table>")
        if r.imports:
            parts.append("<h2>Imported tool reports</h2><table><tr><th>Tool</th><th>File</th><th>Findings</th><th>Imported</th></tr>" + "".join(
                f"<tr><td>{esc(i['tool'])}</td><td>{esc(i['filename'])}</td><td>{i['finding_count']}</td><td>{esc(i['imported_at'])}</td></tr>" for i in r.imports) + "</table>")
        if r.references:
            parts.append("<h2>References</h2><ul>" + "".join(f"<li>{esc(x['label'] or x['url'])} — {esc(x['url'])}</li>" for x in r.references) + "</ul>")
        if r.notes:
            parts.append("<h2>Notes</h2>" + "".join(f"<p class='meta'>{esc(n['created_at'])}</p><p>{esc(n['body'])}</p>" for n in r.notes))
        parts.append("<h2>Method and limitations</h2><ul>" + "".join(f"<li>{esc(x)}</li>" for x in LIMITATIONS) + "</ul>")
        css = ("body{font-family:Arial,Helvetica,sans-serif;color:#1b2227;margin:28px;font-size:13px}h1{font-size:23px}h2{font-size:17px;border-bottom:1px solid #ccd3d8;padding-bottom:3px;margin-top:22px}"
               "small,.meta{color:#5b6770}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd3d8;padding:4px 7px;text-align:left;vertical-align:top}th{background:#eef1f3}"
               ".sev{color:#fff;border-radius:9px;padding:1px 8px;font-size:11px;font-weight:bold}.finding{border:1px solid #ccd3d8;border-radius:6px;padding:6px 10px;margin:8px 0}"
               ".ft{font-weight:bold}.warn{color:#9b1c1c}")
        return f"<!doctype html><html><head><meta charset='utf-8'><title>{esc(r.title)}</title><style>{css}</style></head><body>{''.join(parts)}</body></html>"

    # ------------------------------------------------------------------ output and log
    def write(self, r: ProjectReport, path: str | Path, fmt: str) -> Path:
        fmt = fmt.lower()
        if fmt not in FORMATS:
            raise ValueError(f"unknown report format: {fmt}")
        p = Path(path)
        if p.suffix.lower() != f".{fmt}":
            p = p.with_suffix(f".{fmt}")
        if fmt == "pdf":
            from .pdf_export import html_to_pdf
            html_to_pdf(self.to_html(r), p, r.title)
        else:
            p.write_text({"html": self.to_html, "json": self.to_json, "csv": self.to_csv}[fmt](r), encoding="utf-8", newline="")
        self.db.execute("INSERT INTO generated_reports(project_id, title, fmt, path, sha256, size, options) VALUES (?,?,?,?,?,?,?)",
                        (r.project["id"], r.title, fmt, str(p), sha256_file(p), p.stat().st_size,
                         json.dumps({k: v for k, v in vars(r.options).items() if k not in ("title",)})))
        self.projects.touch(r.project["id"])
        return p

    def generated(self, project_id: int | None = None) -> list[dict]:
        sql, params = "SELECT g.*, p.name AS project FROM generated_reports g JOIN projects p ON p.id = g.project_id", ()
        if project_id is not None:
            sql, params = sql + " WHERE g.project_id = ?", (project_id,)
        return [dict(x) for x in self.db.query(sql + " ORDER BY g.id DESC", params)]

    def verify_generated(self, report_id: int) -> str:
        """'ok' | 'changed' | 'missing' for a report file recorded earlier."""
        row = self.db.query_one("SELECT path, sha256 FROM generated_reports WHERE id = ?", (report_id,))
        if row is None or not Path(row["path"]).is_file():
            return "missing"
        return "ok" if sha256_file(Path(row["path"])) == row["sha256"] else "changed"

    def forget_generated(self, report_id: int) -> None:
        """Remove the log entry only. The report file is never deleted."""
        self.db.execute("DELETE FROM generated_reports WHERE id = ?", (report_id,))

    # ------------------------------------------------------------------ project history
    def overview(self) -> list[dict]:
        rows = []
        for p in self.projects.list():
            n = lambda sql: self.db.query_one(sql, (p["id"],))[0]            # noqa: E731
            rows.append({**p, "findings": n("SELECT COUNT(*) FROM findings WHERE project_id=?"),
                         "open": n("SELECT COUNT(*) FROM findings WHERE project_id=? AND status IN ('open','in_progress')"),
                         "evidence": n("SELECT COUNT(*) FROM evidence WHERE project_id=?"), "notes": n("SELECT COUNT(*) FROM project_notes WHERE project_id=?"),
                         "scope": n("SELECT COUNT(*) FROM scope_entries WHERE project_id=?"), "reports": n("SELECT COUNT(*) FROM generated_reports WHERE project_id=?")})
        return rows

    def activity(self, project_id: int, limit: int = 500) -> list[dict]:
        """A timeline built from the timestamps already stored (no separate log to drift out of date)."""
        q = lambda sql: [dict(r) for r in self.db.query(sql, (project_id,))]          # noqa: E731
        ev: list[tuple[str, str, str]] = []
        for p in q("SELECT created_at FROM projects WHERE id=?"):
            ev.append((p["created_at"], "project", "Project created"))
        for f in q("SELECT title, severity, status, created_at, updated_at FROM findings WHERE project_id=?"):
            ev.append((f["created_at"], "finding", f"Finding added: {f['title']} [{f['severity']}]"))
            if f["updated_at"] and f["updated_at"] != f["created_at"]:
                ev.append((f["updated_at"], "finding", f"Finding updated: {f['title']} — {STATUS_TEXT.get(f['status'], f['status'])}"))
        for n in q("SELECT created_at FROM project_notes WHERE project_id=?"):
            ev.append((n["created_at"], "note", "Note added"))
        for e in q("SELECT path, added_at FROM evidence WHERE project_id=?"):
            ev.append((e["added_at"], "evidence", f"Evidence added: {Path(e['path']).name}"))
        for s in q("SELECT target, added_at FROM scope_entries WHERE project_id=?"):
            ev.append((s["added_at"], "scope", f"Scope entry added: {s['target']}"))
        for i in q("SELECT tool, filename, finding_count, imported_at FROM imported_reports WHERE project_id=?"):
            ev.append((i["imported_at"], "import", f"Imported {i['tool']} report {i['filename']} ({i['finding_count']} finding(s))"))
        for g in q("SELECT fmt, title, generated_at FROM generated_reports WHERE project_id=?"):
            ev.append((g["generated_at"], "report", f"Report generated ({g['fmt'].upper()}): {g['title']}"))
        ev.sort(key=lambda x: x[0], reverse=True)
        return [{"time": t, "kind": k, "text": x} for t, k, x in ev[:limit]]

    def export_bundle(self, project_id: int) -> str:
        """Everything stored for a project as one JSON document (full paths and notes included: for the owner's own backup)."""
        r = self.build(project_id, ReportOptions(include_notes=True, include_paths=True, verify_evidence=False))
        return json.dumps({"project": r.project, "scope": r.scope, "findings": [{k: v for k, v in f.items() if k != "evidence"} for f in r.findings],
                           "evidence": r.evidence, "notes": r.notes, "references": r.references, "imported_reports": r.imports,
                           "generated_reports": self.generated(project_id), "activity": self.activity(project_id)}, indent=2, default=str)
