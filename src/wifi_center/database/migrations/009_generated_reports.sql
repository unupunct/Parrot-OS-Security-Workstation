-- Reports generated from assessment projects. Kept until the user removes the entry; the report FILE itself is never deleted by the app.
CREATE TABLE generated_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    fmt TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    options TEXT NOT NULL DEFAULT '{}',
    generated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_generated_reports_project ON generated_reports(project_id, id);
