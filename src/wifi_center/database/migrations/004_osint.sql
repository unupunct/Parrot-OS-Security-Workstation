ALTER TABLE osint_resources ADD COLUMN slug TEXT;
ALTER TABLE osint_resources ADD COLUMN categories TEXT NOT NULL DEFAULT '';
ALTER TABLE osint_resources ADD COLUMN input_types TEXT NOT NULL DEFAULT 'text';
ALTER TABLE osint_resources ADD COLUMN needs_account INTEGER NOT NULL DEFAULT 0;
ALTER TABLE osint_resources ADD COLUMN supports_term INTEGER NOT NULL DEFAULT 1;
ALTER TABLE osint_resources ADD COLUMN source TEXT NOT NULL DEFAULT '';
ALTER TABLE osint_resources ADD COLUMN availability TEXT;
ALTER TABLE osint_resources ADD COLUMN checked_at TEXT;
ALTER TABLE osint_resources ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX idx_osint_slug ON osint_resources(slug);

CREATE UNIQUE INDEX idx_osint_record_identity
    ON osint_records(COALESCE(project_id, 0), search_term, COALESCE(resource_id, 0));
