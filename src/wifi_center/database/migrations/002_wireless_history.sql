ALTER TABLE wireless_observations ADD COLUMN signal_pct REAL;
ALTER TABLE wireless_observations ADD COLUMN band TEXT;
CREATE UNIQUE INDEX idx_wobs_identity ON wireless_observations(bssid, COALESCE(ssid, ''), source);

CREATE TABLE wireless_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL REFERENCES wireless_observations(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    signal_dbm REAL,
    signal_pct REAL,
    channel INTEGER,
    frequency_mhz INTEGER
);
CREATE INDEX idx_wsamples_obs ON wireless_samples(observation_id, ts);

CREATE TABLE bluetooth_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    name TEXT,
    rssi INTEGER,
    paired INTEGER,
    connected INTEGER,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(address, source)
);
