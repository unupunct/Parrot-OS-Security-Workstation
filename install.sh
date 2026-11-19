#!/usr/bin/env bash
# WIFI Center installer for Parrot OS / Debian: downloads the latest release package from GitHub, checks its SHA-256 and installs it with apt.
#
#   curl -fsSL https://raw.githubusercontent.com/unupunct/Parrot-OS-Security-Workstation/main/install.sh | sudo bash
#
# Prefer reading it first:  curl -fsSLO <that URL>; less install.sh; sudo bash install.sh
# Options (pass after "bash -s --" when piping):
#   --version X.Y.Z     install that release instead of the latest
#   --from-dir DIR      use wifi-center_*.deb and SHA256SUMS from DIR (no download; offline use)
#   --dry-run           show what would happen, change nothing
#   --uninstall         remove the package (keeps the audit log and your data)
#
# What it does NOT do: it does not add repositories, change sudoers, touch the firewall, or install anything except the wifi-center package
# and the dependencies apt resolves for it. The checksum protects against a corrupted download; it cannot prove who published the release.
set -euo pipefail

REPO="unupunct/Parrot-OS-Security-Workstation"
VERSION=""; FROM_DIR=""; DRY=0; UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --from-dir) FROM_DIR="${2:?--from-dir needs a folder}"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
run() { if [ "$DRY" = 1 ]; then say "[dry-run] $*"; else "$@"; fi; }

[ -r /etc/os-release ] || die "cannot identify the operating system"
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in *" debian "*|*" parrot "*|*" ubuntu "*) ;; *) die "this installer supports Debian-based systems (Parrot OS, Debian, Ubuntu); found: ${PRETTY_NAME:-unknown}" ;; esac
command -v apt-get >/dev/null || die "apt-get not found"
if [ "$DRY" = 0 ] && [ "$(id -u)" -ne 0 ]; then die "run as root, for example: curl -fsSL <url> | sudo bash"; fi

if [ "$UNINSTALL" = 1 ]; then
  run apt-get remove -y wifi-center
  say "Removed. The helper's audit log (/var/log/wifi-center) and your data in ~/.config and ~/.local/share/wifi-center were kept."
  exit 0
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

if [ -n "$FROM_DIR" ]; then
  cp -- "$FROM_DIR"/wifi-center_*_all.deb "$FROM_DIR/SHA256SUMS" "$TMP/" 2>/dev/null || die "no wifi-center_*_all.deb and SHA256SUMS in $FROM_DIR"
else
  command -v curl >/dev/null || die "curl is required (sudo apt install curl)"
  command -v python3 >/dev/null || die "python3 is required"
  if [ -n "$VERSION" ]; then api="https://api.github.com/repos/$REPO/releases/tags/v${VERSION#v}"; else api="https://api.github.com/repos/$REPO/releases/latest"; fi
  say "Looking up the release: $api"
  curl -fsSL -H 'Accept: application/vnd.github+json' "$api" -o "$TMP/release.json" || die "could not read the release (is it published? network?)"
  urls="$(python3 - "$TMP/release.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
for a in r.get("assets", []):
    n = a["name"]
    if (n.startswith("wifi-center_") and n.endswith("_all.deb")) or n == "SHA256SUMS":
        print(a["browser_download_url"])
PY
)"
  [ -n "$urls" ] || die "the release has no wifi-center .deb / SHA256SUMS assets"
  for u in $urls; do say "Downloading ${u##*/}"; curl -fsSL "$u" -o "$TMP/${u##*/}"; done
fi

cd "$TMP"
deb="$(ls wifi-center_*_all.deb 2>/dev/null | head -n1)"; [ -n "$deb" ] || die "package file missing"
grep " $deb\$" SHA256SUMS > sums.one || die "SHA256SUMS has no entry for $deb"
sha256sum --quiet -c sums.one || die "checksum mismatch for $deb: not installing"
say "Checksum OK: $deb"
say "Installing $deb (dependencies are resolved by apt)"
run apt-get install -y --no-install-recommends "./$deb"
[ "$DRY" = 1 ] || say "Done. Start WIFI Center from the application menu or run: wifi-center"
