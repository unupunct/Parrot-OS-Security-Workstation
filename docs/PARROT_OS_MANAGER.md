# Parrot OS manager (Phase 7)

Seven pages under **PARROT OS** (and System & Hardware): overview, System Information, System Updates, Software Updates,
Package Manager, System Cleanup and Maintenance History. Everything is built to run as your normal user.

## What works now, and what waits for Phase 8

| Works as a normal user today | Needs the privileged helper (Phase 8) |
|---|---|
| Reading system, hardware, services, repositories | `apt-get update` (refreshing package lists) |
| Checking for updates with `apt-get -s` (simulation) | Applying upgrades, installs, removals |
| Package search, details, dependency and repository info | APT cache clean, autoremove, purging residual configs |
| Cleanup scan, preview and dry run | Removing system-owned files (/var/tmp, /var/log) |
| Cleaning **your own** temp files, thumbnails, safe caches, old WIFI Center logs | |
| Detecting Flatpak, Snap, pipx, git and AppImage software | |
| Maintenance history and export | |

Until the helper exists the application says so plainly (`UnavailableBackend`): the full confirmation flow still shows the
exact proposed transaction and the equivalent `sudo` command, **nothing is executed**, and the attempt is recorded as
"not executed". The privileged interface is typed (`PrivilegedOp` with validated package names and paths): the GUI never
builds shell commands for root.

## Update workflow (System Updates)

1. Check network connectivity (local interface check, no packets) 2. Check repository configuration 3. Refresh package
metadata (needs root: until then the cached lists are used and their age is shown) 4. Retrieve the real transaction
proposal (`apt-get -s`) 5. Display the changes 6. Ask for confirmation 7. Execute 8. Show live output 9. Record 10. Report.

* Removals, new packages pulled in by an upgrade, kept-back packages, protected system packages (for example `parrot-*`,
  `linux-image-*`, `systemd`, `apt`) and any mismatch between APT's summary and the parsed list are flagged, and a flagged
  transaction needs an extra acknowledgement.
* One transaction at a time inside the application; if `apt`, `dpkg`, PackageKit or similar is running, the operation is
  refused with the process names. Locks are never overridden.

## Software Updates

APT (cached lists, no network), Flatpak, Snap, pipx, git checkouts of tools you configured and AppImages. Checking Flatpak,
Snap or git contacts remote servers, so it only happens when you press the button (after a confirmation). Updates other than
APT are never applied by WIFI Center; the exact command is shown. Global pip packages and manually installed tools are
never touched, and AppImages are never executed to ask for update information.

## System Cleanup

Nine categories, each with a plain-language reason it is considered safe. The scan only walks allow-listed locations (never
documents, settings, projects or active data). Deletion re-checks every path immediately beforehand: inside an allowed root,
a regular file, no symbolic link anywhere on the path. Dry run is on by default; real deletion needs an explicit
acknowledgement. "Residual package configuration" is off by default because purging deletes system config files.

## Verification status

The APT, dpkg, `apt-cache`, `systemctl` and `flatpak`/`snap`/`pipx` parsers were written against their documented/stable
output and tested with sample output, not against a live Parrot OS machine. Please run the System Updates page on Parrot
OS before relying on it, and report any output that does not parse. Compatibility target is Python 3.11 (Parrot OS 6); a test
guards against 3.12-only syntax, but the suite itself has only been run on Python 3.13 so far.

## Package Manager (redesigned)

* **Views**: Installed, Available (search), Upgradable (with a count) and Config left (removed packages whose configuration remains).
  Each row has a status badge; the right-hand panel is context-sensitive: Install / Update, Reinstall, Remove, Download only,
  Preview, View files, View changelog and Properties are enabled only when they make sense for the selected package.
* **Details panel**: Details, Dependencies (forward, reverse and a two-level tree), Files, Changelog (the one shipped with the
  package, offline; the repository copy is fetched only on request) and Verify (`dpkg --verify` of the installed files).
* **Safety**: every change is simulated with `apt-get -s`, shows every package that will be installed, upgraded or removed, needs
  an explicit approval, runs through the privileged helper with an approved manifest that the helper re-checks as root, and is
  recorded. `remove` keeps configuration files. Nothing runs autoremove, purge or cache cleaning on its own. A running package
  manager is never overridden, and a half-finished installation (`dpkg --audit`) is reported with an offer to finish it.
* **More menu**: Broken packages (dpkg audit plus APT's simulated repair; "Finish interrupted installation" and "Fix
  dependencies"), Orphaned packages (confirmed removal), Cache manager (size, largest files, confirmed clean) and Repositories
  (read-only: your APT sources are never edited).
* **Transaction history and activity**: every package operation, with success / failure, time and details, is kept until you press
  **Clear history…** and confirm; the activity graph counts the operations that really ran per day.
* New privileged operations (maintenance permission): `apt_reinstall`, `apt_download`, `apt_fix_broken` and `dpkg_configure`.
  After updating WIFI Center, re-run `sudo ./privileged-helper/install.sh` so the installed helper knows them.

