-- Advanced LAN discovery: every scan and its results are kept until the user explicitly deletes them.
CREATE TABLE nd_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_s REAL,
    interface TEXT,
    cidr TEXT NOT NULL,
    mode TEXT NOT NULL,
    targets_total INTEGER NOT NULL DEFAULT 0,
    hosts_found INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    scope_json TEXT,
    params_json TEXT,
    note TEXT
);
CREATE INDEX idx_ndscans_started ON nd_scans(started_at);

CREATE TABLE nd_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES nd_scans(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    family INTEGER NOT NULL DEFAULT 4,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,
    type_basis TEXT,
    type_reason TEXT,
    response_method TEXT,
    latency_ms REAL,
    status TEXT,
    tags TEXT,
    first_seen TEXT,
    last_seen TEXT
);
CREATE INDEX idx_ndhosts_scan ON nd_hosts(scan_id);

CREATE TABLE nd_devices (
    mac TEXT PRIMARY KEY,
    label TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    vendor TEXT,
    last_ip TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
