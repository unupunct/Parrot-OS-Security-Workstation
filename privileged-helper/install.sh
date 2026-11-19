#!/usr/bin/env bash
# Install (or remove) the WIFI Center privileged helper on Parrot OS / Debian.
#   sudo ./privileged-helper/install.sh            install
#   sudo ./privileged-helper/install.sh --dry-run  show what would be done
#   sudo ./privileged-helper/install.sh --uninstall
# Nothing outside the paths listed below is touched; repositories, sudoers and the firewall are never modified.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
LIB=/usr/lib/wifi-center
FILES=(
  "$LIB/wifi-center-helper"
  "/usr/share/polkit-1/actions/org.wificenter.helper.policy"
  "/usr/share/dbus-1/system.d/org.wificenter.Helper1.conf"
  "/usr/share/dbus-1/system-services/org.wificenter.Helper1.service"
  "/lib/systemd/system/wifi-center-helper.service"
)
DRY=0; MODE=install
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --uninstall) MODE=uninstall ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

run() { if [ "$DRY" = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }

if [ "$DRY" = 0 ] && [ "$(id -u)" -ne 0 ]; then
  echo "This script must run as root (use sudo)." >&2
  exit 1
fi

if [ "$MODE" = uninstall ]; then
  run systemctl stop wifi-center-helper.service 2>/dev/null || true
  for f in "${FILES[@]}"; do run rm -f -- "$f"; done
  run rm -rf -- "$LIB/lib"
  run rmdir --ignore-fail-on-non-empty "$LIB" 2>/dev/null || true
  run systemctl daemon-reload
  run systemctl reload dbus 2>/dev/null || true
  echo "Helper removed. Its audit log (/var/log/wifi-center/helper-audit.log) was kept."
  exit 0
fi

# ---- dependency check (no packages are installed for you) ----
missing=()
command -v python3 >/dev/null || missing+=(python3)
python3 -c 'import dbus' 2>/dev/null || missing+=(python3-dbus)
python3 -c 'import gi' 2>/dev/null || missing+=(python3-gi)
python3 -c 'import psutil' 2>/dev/null || missing+=(python3-psutil)
{ command -v pkcheck >/dev/null || [ -d /usr/share/polkit-1 ]; } || missing+=(polkitd)
if [ "${#missing[@]}" -gt 0 ]; then
  echo "Missing dependencies: ${missing[*]}" >&2
  echo "Install them first, for example:  sudo apt install ${missing[*]}" >&2
  [ "$DRY" = 1 ] || exit 1
fi

[ -d "$REPO/src/wifi_center" ] || { echo "Cannot find $REPO/src/wifi_center" >&2; exit 1; }

# ---- install (root-owned copies, never symlinks to a user-writable tree) ----
run install -d -m 0755 "$LIB" "$LIB/lib"
run rm -rf -- "$LIB/lib/wifi_center"
run cp -r -- "$REPO/src/wifi_center" "$LIB/lib/wifi_center"
run find "$LIB/lib/wifi_center" -name '__pycache__' -type d -prune -exec rm -rf {} +
run chown -R root:root "$LIB"
run chmod -R go-w "$LIB"
run install -m 0755 -o root -g root "$HERE/helper.py" "$LIB/wifi-center-helper"
run install -m 0644 -o root -g root "$HERE/polkit/org.wificenter.helper.policy" /usr/share/polkit-1/actions/org.wificenter.helper.policy
run install -m 0644 -o root -g root "$HERE/dbus/org.wificenter.Helper1.conf" /usr/share/dbus-1/system.d/org.wificenter.Helper1.conf
run install -m 0644 -o root -g root "$HERE/dbus/org.wificenter.Helper1.service" /usr/share/dbus-1/system-services/org.wificenter.Helper1.service
run install -m 0644 -o root -g root "$HERE/systemd/wifi-center-helper.service" /lib/systemd/system/wifi-center-helper.service
run install -d -m 0750 -o root -g root /var/log/wifi-center
run systemctl daemon-reload
run systemctl reload dbus 2>/dev/null || true
run systemctl try-restart wifi-center-helper.service 2>/dev/null || true     # pick up new helper code if it is running
echo "Installed. Open WIFI Center → Root Access Manager to check the helper's status."
