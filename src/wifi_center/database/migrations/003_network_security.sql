CREATE UNIQUE INDEX idx_netdev_identity ON network_devices(address, source, COALESCE(project_id, 0));

CREATE TABLE scope_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('ip','cidr','host')),
    note TEXT,
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project_id, target)
);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    tool TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT,
    args TEXT,
    started_at TEXT,
    finished_at TEXT,
    source_file TEXT,
    source_sha256 TEXT,
    host_count INTEGER NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE scan_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    hostname TEXT,
    mac TEXT,
    vendor TEXT,
    os_guess TEXT,
    status TEXT NOT NULL DEFAULT 'up'
);
CREATE INDEX idx_scan_hosts_scan ON scan_hosts(scan_id);

CREATE TABLE scan_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT
);
CREATE INDEX idx_scan_ports_scan ON scan_ports(scan_id, address);

ALTER TABLE findings ADD COLUMN remediation_notes TEXT;
ALTER TABLE findings ADD COLUMN due_date TEXT;
ALTER TABLE findings ADD COLUMN location TEXT;
ALTER TABLE findings ADD COLUMN source_ref TEXT;

CREATE TABLE project_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE project_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT 'url',
    url TEXT NOT NULL,
    label TEXT,
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project_id, url)
);

CREATE TABLE imported_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project_id, sha256)
);
