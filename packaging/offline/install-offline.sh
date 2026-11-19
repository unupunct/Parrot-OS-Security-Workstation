#!/usr/bin/env bash
# Install WIFI Center from this folder without downloading anything.
#   sudo ./install-offline.sh            install
#   ./install-offline.sh --dry-run       show what apt would do (no root needed)
# It verifies SHA256SUMS first, then lets apt install the .deb together with any dependency .deb files you placed in ./debs
# (see fetch-deps.sh). If a dependency is missing and no network is available, apt names it and nothing is installed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

cd "$HERE"
if [ "$DRY" = 0 ] && [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo ./install-offline.sh" >&2; exit 1; fi
command -v apt-get >/dev/null || { echo "apt-get not found: this installer is for Debian-based systems such as Parrot OS." >&2; exit 1; }

echo "Checking file integrity (SHA256SUMS)..."
sha256sum --quiet -c SHA256SUMS || { echo "A file does not match SHA256SUMS: do not install. Get a fresh copy." >&2; exit 1; }

shopt -s nullglob
main=( ./wifi-center_*_all.deb )
[ "${#main[@]}" -eq 1 ] || { echo "Expected exactly one wifi-center_*_all.deb here." >&2; exit 1; }
extra=( ./debs/*.deb )
echo "Package: ${main[0]#./}   dependency packages supplied: ${#extra[@]}"

opts=(-y --no-install-recommends)
[ "$DRY" = 1 ] && opts=(-s --no-install-recommends)
if ! apt-get install "${opts[@]}" "${main[0]}" "${extra[@]}"; then
  echo >&2
  echo "Installation failed. If apt reports unmet dependencies and this computer is offline, run ./fetch-deps.sh on an online" >&2
  echo "machine with the same Parrot OS version, copy the resulting ./debs folder here, and try again." >&2
  exit 1
fi
[ "$DRY" = 1 ] || echo "Done. Start WIFI Center from the application menu or with: wifi-center"
