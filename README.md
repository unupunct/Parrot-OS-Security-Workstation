# WIFI Center

Security workstation and system management platform for Parrot OS (PySide6 / Python 3).

**Status: Phases 1-8 of 10 plus the Matrix Pro redesign.** Working: UI shell, command palette, network command-center dashboard, tool integration manager, wireless workspace, scoped network discovery, assessment projects and findings, OSINT research workspace, wordlist and local resource libraries, Parrot OS manager (changes are applied through the Polkit-guarded privileged helper, see docs/ROOT_ACCESS.md), Root Access Manager, settings, SQLite migrations and backup.
live dashboard (real system data), settings, SQLite schema with migrations, backup/restore, structured logging.
All other sidebar pages show an honest "not implemented yet" notice with their planned phase.

## Run (development)

```bash
pip install -r requirements.txt
python main.py
```

## Test

```bash
pip install pytest
python -m pytest
```

Full documentation, install instructions and screenshots will be added as the project matures.
