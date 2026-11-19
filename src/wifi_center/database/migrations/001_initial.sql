CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE tools (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    executable TEXT,
    install_path TEXT,
    installed INTEGER NOT NULL DEFAULT 0,
    version TEXT,
    integration_status TEXT NOT NULL DEFAULT 'unknown',
    config_json TEXT NOT NULL DEFAULT '{}',
    last_checked TEXT
);

CREATE TABLE tool_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_id TEXT NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    version TEXT,
    detected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE integration_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_id TEXT NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    detail TEXT,
    checked_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tool_id TEXT,
    op_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    privileged INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    exit_code INTEGER,
    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL
);

CREATE TABLE operation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id INTEGER NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    stream TEXT NOT NULL,
    line TEXT NOT NULL,
    ts TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_oplogs_op ON operation_logs(operation_id);

CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'assessment',
    scope TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE wireless_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    ssid TEXT,
    bssid TEXT NOT NULL,
    channel INTEGER,
    frequency_mhz INTEGER,
    signal_dbm REAL,
    encryption TEXT,
    auth TEXT,
    vendor TEXT,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX idx_wobs_bssid ON wireless_observations(bssid);

CREATE TABLE network_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    address TEXT NOT NULL,
    hostname TEXT,
    mac TEXT,
    vendor TEXT,
    os_guess TEXT,
    services_json TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    status TEXT NOT NULL DEFAULT 'open',
    description TEXT,
    recommendation TEXT,
    source_tool TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    description TEXT,
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE osint_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    url_template TEXT NOT NULL,
    description TEXT,
    builtin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE osint_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    search_term TEXT NOT NULL,
    resource_id INTEGER REFERENCES osint_resources(id) ON DELETE SET NULL,
    url TEXT,
    result TEXT NOT NULL DEFAULT 'inconclusive'
        CHECK (result IN ('confirmed','possible','none','inconclusive','unavailable')),
    notes TEXT,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    category TEXT,
    size_bytes INTEGER,
    sha256 TEXT,
    source_url TEXT,
    license TEXT,
    attribution TEXT,
    acquired_at TEXT,
    last_verified TEXT
);

CREATE TABLE maintenance_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    op_type TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    packages_changed TEXT,
    files_removed INTEGER,
    result TEXT,
    errors TEXT,
    log_ref TEXT
);

CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    body TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    read INTEGER NOT NULL DEFAULT 0
);
