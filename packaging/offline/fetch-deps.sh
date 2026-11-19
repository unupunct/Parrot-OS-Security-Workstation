#!/usr/bin/env bash
# Run this ONCE on an ONLINE Parrot/Debian machine with the same release and architecture as the target.
# It downloads WIFI Center's dependency packages (and their dependencies) into ./debs, which install-offline.sh then uses.
# It only downloads: nothing is installed or changed on this machine. (apt may refresh its package lists, which needs root.)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS="@DEPS@"
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo ./fetch-deps.sh" >&2; exit 1; }
apt-get update
apt-get install --download-only --reinstall -y $DEPS
mkdir -p "$HERE/debs"
cp -v /var/cache/apt/archives/*.deb "$HERE/debs/"
echo "Done: $(ls "$HERE/debs" | wc -l) packages in $HERE/debs. Copy this whole folder to the offline machine."
