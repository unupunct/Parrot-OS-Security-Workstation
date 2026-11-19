# Root Access Manager and the privileged helper

WIFI Center always runs as your normal user. Anything that needs root is done by a small **privileged helper**
(`org.wificenter.Helper1`, a D-Bus service on the system bus) after **Polkit** has asked you to authenticate.

## What it can and cannot do

The helper accepts a fixed list of operations, each re-validated as root; it is not a shell and takes no free-form commands.

| Polkit action | Operations |
|---|---|
| `org.wificenter.helper.maintenance` | `apt-get update/upgrade/dist-upgrade/install/reinstall/download-only/remove/autoremove/clean`, `apt-get install -f` (fix broken dependencies), `dpkg --configure -a` (finish an interrupted installation), purge of leftover package configs |
| `org.wificenter.helper.cleanup-files` | delete old files in `/var/tmp` and rotated logs in `/var/log` (allow-listed roots, ages and name patterns) |
| `org.wificenter.helper.network-interface` | put a wireless interface in monitor mode and restore it afterwards (saved state, rollback) |
| `org.wificenter.helper.diagnostics` | read the system journal and a service's status (read-only) |

Safety properties (all covered by `tests/test_privileged.py`):

* Package changes carry a **manifest** of what you approved. The helper re-simulates the transaction as root and refuses
  anything outside it (unexpected removals, new dependencies, extra upgrades). A config purge is also refused unless each
  package is already removed (dpkg state `rc`).
* Fixed absolute command paths, clean environment, no shell, one operation at a time, never overrides APT/dpkg locks.
* File removal uses `openat`/`O_NOFOLLOW`; symlinks and anything outside the allow-listed roots are skipped.
* Fails closed: if Polkit cannot be reached, nothing runs. No password is stored or seen by the application.
* Every request, denial and result goes to a hash-chained audit log, `/var/log/wifi-center/helper-audit.log`.
* Output is sent only to the caller that started the operation.

## Install / remove

```bash
sudo ./privileged-helper/install.sh --dry-run   # show what would be done
sudo ./privileged-helper/install.sh             # install (also restarts a running helper)
sudo ./privileged-helper/install.sh --uninstall
```

Dependencies (not installed for you): `python3-dbus python3-gi python3-psutil polkitd`.

## Using it

Open **Root Access Manager** (or Permissions). It shows whether the helper is reachable, which permissions you currently
hold, the running operation, and what the helper did for you. **Authorize now…** shows the Polkit dialog;
**End privileged session** revokes the retained authorization. Polkit keeps an authorization for a few minutes
(`auth_admin_keep`) and does not report its exact end time.

Polkit sends the password prompt to an authentication agent of the **caller's own login session**. Start the app from the
desktop (menu or shortcut). A copy started over SSH or via `su` has no agent and every request is denied.

## Testing the helper without the GUI

```bash
python3 -m wifi_center.privileged.cli status
python3 -m wifi_center.privileged.cli run diag_journal
python3 -m wifi_center.privileged.cli run apt_upgrade      # refused: no approved manifest
python3 -m wifi_center.privileged.cli recent
```
