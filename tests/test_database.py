import sqlite3

import pytest

from wifi_center.application.settings import Settings, SettingsError
from wifi_center.database.repository import Database, MigrationError, discover_migrations
from wifi_center.services.backup_service import BackupError, BackupService

EXPECTED_TABLES = {
    "tools", "tool_versions", "integration_health", "operations", "operation_logs",
    "wireless_observations", "network_devices", "projects", "findings", "evidence",
    "osint_resources", "osint_records", "resources", "maintenance_history", "settings",
    "notifications", "schema_migrations",
}


def test_migrations_create_all_tables():
    db = Database(":memory:")
    names = {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert EXPECTED_TABLES <= names
    assert db.schema_version() == len(discover_migrations())


def test_migrate_is_idempotent(tmp_path):
    p = tmp_path / "a.db"
    Database(p).close()
    db = Database(p)
    assert db.query_one("SELECT COUNT(*) n FROM schema_migrations")["n"] == len(discover_migrations())


def test_failed_migration_rolls_back(tmp_path):
    mdir = tmp_path / "m"
    mdir.mkdir()
    (mdir / "001_a.sql").write_text("CREATE TABLE a (x INTEGER);")
    (mdir / "002_b.sql").write_text("CREATE TABLE b (x INTEGER); INSERT INTO nope VALUES (1);")
    with pytest.raises(MigrationError):
        Database(tmp_path / "x.db", migrations_dir=mdir)
    conn = sqlite3.connect(tmp_path / "x.db")
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "a" in tables and "b" not in tables


def test_newer_schema_refused(tmp_path):
    mdir = tmp_path / "m"
    mdir.mkdir()
    (mdir / "001_a.sql").write_text("CREATE TABLE a (x INTEGER);")
    p = tmp_path / "x.db"
    db = Database(p, migrations_dir=mdir)
    db.execute("INSERT INTO schema_migrations(version, name) VALUES (5, 'future')")
    db.close()
    with pytest.raises(MigrationError):
        Database(p, migrations_dir=mdir)


def test_bad_migration_numbering(tmp_path):
    (tmp_path / "002_x.sql").write_text("SELECT 1;")
    with pytest.raises(MigrationError):
        discover_migrations(tmp_path)


def test_transaction_rollback():
    db = Database(":memory:")
    with pytest.raises(RuntimeError):
        with db.transaction() as c:
            c.execute("INSERT INTO projects(name) VALUES ('x')")
            raise RuntimeError
    assert db.query_one("SELECT COUNT(*) n FROM projects")["n"] == 0


def test_foreign_keys_and_severity_constraint():
    db = Database(":memory:")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO findings(project_id, title, severity) VALUES (99, 't', 'low')")
    pid = db.execute("INSERT INTO projects(name) VALUES ('p')")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO findings(project_id, title, severity) VALUES (?, 't', 'bogus')", (pid,))


def test_settings_defaults_validation_roundtrip():
    s = Settings(Database(":memory:"))
    assert s.get("appearance.accent") == "#00FF66"
    s.set("appearance.accent", "#20C979")
    assert s.get("appearance.accent") == "#20C979"
    with pytest.raises(SettingsError):
        s.set("appearance.accent", "red")
    with pytest.raises(SettingsError):
        s.set("nope", 1)
    with pytest.raises(SettingsError):
        s.get("nope")


def test_corrupt_setting_falls_back_to_default():
    db = Database(":memory:")
    db.execute("INSERT INTO settings(key, value) VALUES ('appearance.accent', '\"notahex\"')")
    assert Settings(db).get("appearance.accent") == "#00FF66"


def test_backup_create_list_and_restore(tmp_path):
    db = Database(tmp_path / "live.db")
    svc = BackupService(db, tmp_path / "bk")
    Settings(db).set("appearance.accent", "#00D5C8")
    b = svc.create("manual")
    assert BackupService.verify(b)
    Settings(db).set("appearance.accent", "#F2B84B")
    svc.stage_restore(b)
    db.close()
    db2 = Database(tmp_path / "live.db")  # staged restore applied on open
    assert Settings(db2).get("appearance.accent") == "#00D5C8"
    assert len(svc.list()) >= 2  # includes the pre-restore safety backup


def test_restore_rejects_outside_and_corrupt(tmp_path):
    db = Database(tmp_path / "live.db")
    svc = BackupService(db, tmp_path / "bk")
    outside = tmp_path / "evil.db"
    outside.write_bytes(b"x")
    with pytest.raises(BackupError):
        svc.stage_restore(outside)
    (tmp_path / "bk").mkdir(exist_ok=True)
    bad = tmp_path / "bk" / "wifi-center-bad.db"
    bad.write_bytes(b"not a database at all")
    with pytest.raises(BackupError):
        svc.stage_restore(bad)


def test_backup_prunes(tmp_path):
    db = Database(tmp_path / "live.db")
    svc = BackupService(db, tmp_path / "bk", keep=3)
    for _ in range(5):
        svc.create()
    assert len(svc.list()) == 3
