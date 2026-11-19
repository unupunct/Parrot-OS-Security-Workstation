# Projects, Evidence, Reports and Project History

These four pages work on the same stored data: an assessment **project** with its authorised scope, findings, notes, evidence
references, imported tool reports and references. Everything stays in the local database.

## Reports

Pick a project, choose options, **Preview**, then **Generate** as HTML, PDF, JSON (full data) or CSV (findings only).

A report contains: an executive summary (open findings by severity, status counts), the authorised scope, every finding with its
status, location, source, recommendation and remediation notes, an evidence table, imported tool reports, references, and a
"Method and limitations" section. Rules the generator follows:

* **Nothing is invented.** A project without findings or scope produces a report that says so.
* **Evidence integrity is re-checked** when the report is built (SHA-256 of each file again). Files that changed or went missing
  are flagged in the summary and the evidence table.
* **Private details are opt-in:** your free-text notes and the local file paths of evidence are left out unless you tick the boxes.
* **Every generated report is logged** (time, format, path, SHA-256). *Check file* later tells you whether it is unchanged, changed
  or missing. *Remove from list* only removes the log entry; the report file is never deleted by the app.

## Evidence

All evidence files referenced by your projects (or one project). Files are **referenced, not copied**: WIFI Center stores the path and
a SHA-256 so tampering or loss is detected. *Verify all* re-hashes the files. *Link to finding* attaches evidence to a finding of the
same project. *Remove reference* forgets the entry; the file on disk is never touched.

## Project History

One row per project (findings, open findings, evidence, scope entries, notes, reports) and a timeline of what happened, built from the
timestamps stored with each finding, note, evidence file, scope entry, import and report. Timestamps have one-second resolution,
so two edits within the same second appear as one. *Export project* writes everything as JSON (full paths and notes included, so
keep it private). *Delete project* removes the project's database records after confirmation; evidence and report files on disk are
never deleted.

## Not part of this phase

Bluetooth findings keep their own report in the Bluetooth Lab (Reports section); they are not merged into project reports.
