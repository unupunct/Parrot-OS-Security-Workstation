-- Bluetooth Lab inventory. Everything stays on this computer; records are only deleted by an explicit user action.
CREATE TABLE bt_devices (
    address TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    custom_name TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    technology TEXT NOT NULL DEFAULT '',
    device_type TEXT NOT NULL DEFAULT '',
    address_type TEXT NOT NULL DEFAULT '',
    manufacturer TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_rssi INTEGER,
    authorized INTEGER NOT NULL DEFAULT 0,
    adv_fingerprint TEXT NOT NULL DEFAULT ''
);

CREATE TABLE bt_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    duration_s REAL,
    adapter TEXT,
    mode TEXT,
    devices_found INTEGER NOT NULL DEFAULT 0,
    cancelled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE bt_sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES bt_scans(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    ts TEXT NOT NULL,
    rssi INTEGER,
    name TEXT,
    technology TEXT,
    uuids TEXT,
    mfr_data TEXT,
    adv_fingerprint TEXT,
    paired INTEGER,
    connected INTEGER
);
CREATE INDEX idx_btsight_addr ON bt_sightings(address, ts);
CREATE INDEX idx_btsight_scan ON bt_sightings(scan_id);

CREATE TABLE bt_adv_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    ts TEXT NOT NULL,
    summary TEXT NOT NULL
);
CREATE INDEX idx_btadv_addr ON bt_adv_changes(address, ts);

CREATE TABLE bt_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    ts TEXT NOT NULL,
    event TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX idx_btevent_addr ON bt_events(address, ts);
