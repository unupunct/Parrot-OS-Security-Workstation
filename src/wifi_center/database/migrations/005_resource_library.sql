ALTER TABLE resources ADD COLUMN library TEXT NOT NULL DEFAULT 'wordlists';
ALTER TABLE resources ADD COLUMN format TEXT;
ALTER TABLE resources ADD COLUMN line_count INTEGER;
ALTER TABLE resources ADD COLUMN entry_id TEXT;
ALTER TABLE resources ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0;
ALTER TABLE resources ADD COLUMN mtime REAL;
ALTER TABLE resources ADD COLUMN notes TEXT;
ALTER TABLE resources ADD COLUMN added_at TEXT NOT NULL DEFAULT (datetime('now'));
CREATE INDEX idx_resources_sha ON resources(sha256);

CREATE TABLE resource_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    library TEXT NOT NULL,
    resource_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT,
    ts TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_reshist_lib ON resource_history(library, id);
