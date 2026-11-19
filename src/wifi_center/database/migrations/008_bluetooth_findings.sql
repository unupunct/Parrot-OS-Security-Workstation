-- Bluetooth Security Auditor results. Local only; removed only by an explicit user action.
CREATE TABLE bt_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    started_at TEXT NOT NULL,
    deep INTEGER NOT NULL DEFAULT 0,
    checks_run INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE bt_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL REFERENCES bt_audits(id),
    address TEXT NOT NULL,
    ts TEXT NOT NULL,
    check_id TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    explanation TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_bt_findings_addr ON bt_findings(address, audit_id);
