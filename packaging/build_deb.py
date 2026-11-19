"""Build the wifi-center .deb without dpkg-deb (so it can be built on any OS).

    python packaging/build_deb.py [--out dist]

The package is architecture-independent (pure Python). It installs the application and the privileged helper side by side under
/usr/lib/wifi-center (the helper's code is root-owned, as the helper requires), a launcher in /usr/bin, a desktop entry and icon, the
Polkit action file, the D-Bus policy and service files, the systemd unit, and the documentation. Builds are reproducible: the same
sources give the same bytes (fixed timestamps, root ownership, sorted entries).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import re
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from wifi_center import __version__ as PY_VERSION                 # noqa: E402

PACKAGE = "wifi-center"
MAINTAINER = "unupunct <unupunct@users.noreply.github.com>"
HOMEPAGE = "https://github.com/unupunct/Parrot-OS-Security-Workstation"
LIB = "usr/lib/wifi-center"
EPOCH = 1_767_225_600                                               # fixed mtime (2026-01-01) for reproducible output

DEPENDS = ["python3 (>= 3.10)", "python3-pyside6.qtcore", "python3-pyside6.qtgui", "python3-pyside6.qtwidgets", "python3-pyqtgraph",
           "python3-psutil", "python3-dbus", "python3-gi", "polkitd | policykit-1"]
RECOMMENDS = ["bluez", "iw", "rfkill", "ethtool", "usbutils", "nmap", "tshark"]
SUGGESTS = ["kismet", "aircrack-ng", "wireshark", "network-manager"]
DESCRIPTION = ("Security workstation and system manager for Parrot OS\n"
               " WIFI Center brings wireless and Bluetooth analysis, scoped network discovery, assessment projects and\n"
               " reports, OSINT research, a tool manager and Parrot OS maintenance into one Qt application. Privileged\n"
               " changes go through a small Polkit-guarded helper that validates every request and keeps an audit log.\n"
               " .\n"
               " Use it only on networks and devices you own or are authorised to test.")

LAUNCHER = """#!/bin/sh
# WIFI Center launcher
export PYTHONPATH=/usr/lib/wifi-center/lib${PYTHONPATH:+:$PYTHONPATH}
exec /usr/bin/python3 -m wifi_center "$@"
"""
DESKTOP = """[Desktop Entry]
Type=Application
Name=WIFI Center
Comment=Security workstation and system management for Parrot OS
Exec=wifi-center
Icon=wifi-center
Terminal=false
Categories=System;Security;Network;
Keywords=wifi;bluetooth;security;network;parrot;
StartupWMClass=wifi-center
"""
POSTINST = """#!/bin/sh
set -e
if [ "$1" = configure ]; then
    python3 -m compileall -q /usr/lib/wifi-center/lib >/dev/null 2>&1 || true
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        systemctl reload dbus >/dev/null 2>&1 || true
        systemctl try-restart wifi-center-helper.service >/dev/null 2>&1 || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications || true; fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor >/dev/null 2>&1 || true; fi
    echo "WIFI Center installed. Start it from the application menu or run: wifi-center"
fi
exit 0
"""
PRERM = """#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = upgrade ] || [ "$1" = deconfigure ]; then
    if [ -d /run/systemd/system ]; then systemctl stop wifi-center-helper.service >/dev/null 2>&1 || true; fi
fi
exit 0
"""
POSTRM = """#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
    find /usr/lib/wifi-center -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
    rmdir /usr/lib/wifi-center/lib /usr/lib/wifi-center 2>/dev/null || true
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        systemctl reload dbus >/dev/null 2>&1 || true
    fi
fi
if [ "$1" = purge ]; then
    echo "WIFI Center: the helper's audit log (/var/log/wifi-center) and each user's data (~/.config and ~/.local/share/wifi-center) were kept."
fi
exit 0
"""
COPYRIGHT_HEAD = "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: WIFI Center\nSource: " + HOMEPAGE + "\n\nFiles: *\nCopyright: 2026 unupunct\n"


def deb_version(py_version: str = PY_VERSION) -> str:
    """1.0.0rc1 -> 1.0.0~rc1 (a pre-release sorts before the final release in dpkg)."""
    return re.sub(r"(\d)(a|b|rc)(\d+)$", r"\1~\2\3", py_version)


def _files() -> list[tuple[str, bytes, int]]:
    """(path inside the package, content, mode) for everything the package installs."""
    out: list[tuple[str, bytes, int]] = []

    def add(dest: str, src: Path | bytes, mode: int = 0o644) -> None:
        out.append((dest, src.read_bytes().replace(b"\r\n", b"\n") if isinstance(src, Path) else src, mode))

    for p in sorted((ROOT / "src" / "wifi_center").rglob("*")):
        rel = p.relative_to(ROOT / "src")
        if p.is_file() and "__pycache__" not in rel.parts and p.suffix not in (".pyc", ".pyo", ".db"):
            add(f"{LIB}/lib/{rel.as_posix()}", p)
    h = ROOT / "privileged-helper"
    add(f"{LIB}/wifi-center-helper", h / "helper.py", 0o755)
    add("usr/share/polkit-1/actions/org.wificenter.helper.policy", h / "polkit" / "org.wificenter.helper.policy")
    add("usr/share/dbus-1/system.d/org.wificenter.Helper1.conf", h / "dbus" / "org.wificenter.Helper1.conf")
    add("usr/share/dbus-1/system-services/org.wificenter.Helper1.service", h / "dbus" / "org.wificenter.Helper1.service")
    add("lib/systemd/system/wifi-center-helper.service", h / "systemd" / "wifi-center-helper.service")
    add("usr/bin/wifi-center", LAUNCHER.encode(), 0o755)
    add("usr/share/applications/wifi-center.desktop", DESKTOP.encode())
    add("usr/share/icons/hicolor/scalable/apps/wifi-center.svg", ROOT / "src" / "wifi_center" / "resources" / "icons" / "wifi-center.svg")
    docs = f"usr/share/doc/{PACKAGE}"
    for d in sorted((ROOT / "docs").glob("*.md")):
        add(f"{docs}/{d.name}", d)
    add(f"{docs}/README.md", ROOT / "README.md")
    body = (ROOT / "LICENSE").read_text(encoding="utf-8").replace("\r\n", "\n").split("\n", 2)[2].strip("\n")
    add(f"{docs}/copyright", (COPYRIGHT_HEAD + "License: MIT\n" + "".join(f" {ln}\n" if ln.strip() else " .\n" for ln in body.split("\n"))).encode())
    log = f"{PACKAGE} ({deb_version()}) unstable; urgency=low\n\n  * Release {PY_VERSION}.\n\n -- {MAINTAINER}  Thu, 01 Jan 2026 00:00:00 +0000\n"
    add(f"{docs}/changelog.gz", gzip.compress(log.encode(), 9, mtime=0))
    out.sort(key=lambda x: x[0])
    return out


def _tar(entries: list[tuple[str, bytes, int]], dirs: bool) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        seen: set[str] = set()

        def meta(name: str, size: int, mode: int, kind: bytes) -> tarfile.TarInfo:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.type, ti.mtime = size, mode, kind, EPOCH
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            return ti
        if dirs:
            for path, _c, _m in entries:
                parts = path.split("/")[:-1]
                for i in range(1, len(parts) + 1):
                    d = "./" + "/".join(parts[:i])
                    if d not in seen:
                        seen.add(d)
                        tf.addfile(meta(d + "/", 0, 0o755, tarfile.DIRTYPE))
        for path, content, mode in entries:
            tf.addfile(meta("./" + path, len(content), mode, tarfile.REGTYPE), io.BytesIO(content))
    return gzip.compress(buf.getvalue(), 9, mtime=0)


def _ar(members: list[tuple[str, bytes]]) -> bytes:
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        out += f"{name:<16}{EPOCH:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
        out += data + (b"\n" if len(data) % 2 else b"")
    return bytes(out)


def control_text(files: list[tuple[str, bytes, int]]) -> str:
    size = (sum(len(c) for _p, c, _m in files) + 1023) // 1024
    return (f"Package: {PACKAGE}\nVersion: {deb_version()}\nSection: utils\nPriority: optional\nArchitecture: all\nMaintainer: {MAINTAINER}\n"
            f"Installed-Size: {size}\nDepends: {', '.join(DEPENDS)}\nRecommends: {', '.join(RECOMMENDS)}\nSuggests: {', '.join(SUGGESTS)}\n"
            f"Homepage: {HOMEPAGE}\nDescription: {DESCRIPTION}\n")


def build(out_dir: Path, filename: str | None = None) -> Path:
    files = _files()
    md5 = "".join(f"{hashlib.md5(c).hexdigest()}  {p}\n" for p, c, _m in files).encode()
    ctrl = [("control", control_text(files).encode(), 0o644), ("md5sums", md5, 0o644), ("postinst", POSTINST.encode(), 0o755),
            ("prerm", PRERM.encode(), 0o755), ("postrm", POSTRM.encode(), 0o755)]
    deb = _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", _tar(ctrl, dirs=False)), ("data.tar.gz", _tar(files, dirs=True))])
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / (filename or f"{PACKAGE}_{deb_version()}_all.deb")
    path.write_bytes(deb)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist"))
    a = ap.parse_args()
    p = build(Path(a.out))
    print(f"{p}  ({p.stat().st_size // 1024} KiB, sha256 {hashlib.sha256(p.read_bytes()).hexdigest()[:16]}…)")
