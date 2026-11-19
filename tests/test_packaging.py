"""The .deb and the release bundle: structure, ownership, checksums, reproducibility and consistency with the helper's expectations."""
import gzip
import hashlib
import io
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
import build_deb as bd                                              # noqa: E402
import build_release as br                                          # noqa: E402


def read_ar(data: bytes) -> dict[str, bytes]:
    assert data[:8] == b"!<arch>\n"
    out, pos = {}, 8
    while pos < len(data):
        hdr = data[pos:pos + 60]
        assert hdr[58:60] == b"`\n"
        name, size = hdr[:16].decode().strip(), int(hdr[48:58])
        out[name] = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size % 2)
    return out


@pytest.fixture(scope="module")
def deb(tmp_path_factory):
    p = bd.build(tmp_path_factory.mktemp("deb"))
    members = read_ar(p.read_bytes())
    data = tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]))
    ctrl = tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]))
    return p, members, data, ctrl


def test_archive_layout_and_control_fields(deb):
    p, members, data, ctrl = deb
    assert list(members) == ["debian-binary", "control.tar.gz", "data.tar.gz"] and members["debian-binary"] == b"2.0\n"
    control = ctrl.extractfile("./control").read().decode()
    fields = dict(re.findall(r"^([A-Za-z-]+): (.*)$", control, re.M))
    assert fields["Package"] == "wifi-center" and fields["Architecture"] == "all" and fields["Version"] == bd.deb_version()
    assert "python3-pyside6.qtwidgets" in fields["Depends"] and "polkitd | policykit-1" in fields["Depends"]
    assert set(ctrl.getnames()) == {"./control", "./md5sums", "./postinst", "./prerm", "./postrm"}
    assert p.name == f"wifi-center_{bd.deb_version()}_all.deb"


def test_version_conversion_orders_prereleases_before_final():
    assert bd.deb_version("1.0.0rc1") == "1.0.0~rc1" and bd.deb_version("1.2.3") == "1.2.3" and bd.deb_version("2.0.0b2") == "2.0.0~b2"


def test_everything_is_root_owned_and_nothing_is_writable_by_others(deb):
    _p, _m, data, _c = deb
    for ti in data.getmembers():
        assert ti.uid == 0 and ti.gid == 0 and ti.uname == "root" and not ti.mode & 0o022, ti.name
        assert "__pycache__" not in ti.name and not ti.name.endswith((".pyc", ".db")) and "/tests/" not in ti.name


def test_expected_files_and_modes(deb):
    _p, _m, data, _c = deb
    names = {t.name: t for t in data.getmembers()}
    for must in ("./usr/bin/wifi-center", "./usr/lib/wifi-center/wifi-center-helper", "./usr/lib/wifi-center/lib/wifi_center/__main__.py",
                 "./usr/share/polkit-1/actions/org.wificenter.helper.policy", "./usr/share/dbus-1/system.d/org.wificenter.Helper1.conf",
                 "./usr/share/dbus-1/system-services/org.wificenter.Helper1.service", "./lib/systemd/system/wifi-center-helper.service",
                 "./usr/share/applications/wifi-center.desktop", "./usr/share/icons/hicolor/scalable/apps/wifi-center.svg",
                 "./usr/share/doc/wifi-center/ROOT_ACCESS.md", "./usr/share/doc/wifi-center/BLUETOOTH_LAB.md", "./usr/share/doc/wifi-center/copyright",
                 "./usr/share/doc/wifi-center/changelog.gz"):
        assert must in names, must
    assert names["./usr/bin/wifi-center"].mode == 0o755 and names["./usr/lib/wifi-center/wifi-center-helper"].mode == 0o755
    assert any(n.startswith("./usr/lib/wifi-center/lib/wifi_center/database/migrations/009_") for n in names)       # migrations ship with the code
    assert "./usr/lib/wifi-center/lib/wifi_center/resources/icons/wifi-center.svg" in names


def test_md5sums_match_the_payload(deb):
    _p, _m, data, ctrl = deb
    listed = dict((line.split("  ", 1)[1], line.split("  ", 1)[0]) for line in ctrl.extractfile("./md5sums").read().decode().splitlines())
    files = [t for t in data.getmembers() if t.isfile()]
    assert len(listed) == len(files)
    for t in files:
        assert hashlib.md5(data.extractfile(t).read()).hexdigest() == listed[t.name[2:]], t.name


def test_helper_paths_in_the_units_match_what_the_package_installs(deb):
    _p, _m, data, _c = deb
    names = {t.name[2:] for t in data.getmembers()}
    unit = data.extractfile("./lib/systemd/system/wifi-center-helper.service").read().decode()
    dbus = data.extractfile("./usr/share/dbus-1/system-services/org.wificenter.Helper1.service").read().decode()
    for text in (unit, dbus):
        helper = re.search(r"/usr/lib/wifi-center/wifi-center-helper", text).group(0)
        assert helper[1:] in names
    assert "/usr/share/doc/wifi-center/ROOT_ACCESS.md" in unit
    helper_src = data.extractfile("./usr/lib/wifi-center/wifi-center-helper").read().decode()
    assert '"/usr/lib/wifi-center/lib"' in helper_src and helper_src.startswith("#!/usr/bin/python3 -I")


def test_launcher_desktop_entry_and_maintainer_scripts(deb):
    _p, _m, data, ctrl = deb
    launcher = data.extractfile("./usr/bin/wifi-center").read().decode()
    assert "python3 -m wifi_center" in launcher and "/usr/lib/wifi-center/lib" in launcher
    desktop = data.extractfile("./usr/share/applications/wifi-center.desktop").read().decode()
    assert "Exec=wifi-center" in desktop and "Icon=wifi-center" in desktop and "Categories=System;Security;Network;" in desktop
    for s in ("postinst", "prerm", "postrm"):
        text = ctrl.extractfile(f"./{s}").read().decode()
        assert text.startswith("#!/bin/sh\nset -e") and text.rstrip().endswith("exit 0")
        sh = shutil.which("sh")
        if sh:
            assert subprocess.run([sh, "-n"], input=text.encode(), capture_output=True).returncode == 0, s
    assert "audit log" in ctrl.extractfile("./postrm").read().decode()                      # purge never silently deletes the audit trail
    assert "rm -rf /var/log" not in ctrl.extractfile("./postrm").read().decode()


def test_copyright_and_changelog_are_valid(deb):
    _p, _m, data, _c = deb
    copyright_text = data.extractfile("./usr/share/doc/wifi-center/copyright").read().decode()
    assert copyright_text.count("License: MIT") == 1 and "Permission is hereby granted" in copyright_text
    assert all(line.startswith((" ", "Format", "Upstream", "Source", "Files", "Copyright", "License")) or not line for line in copyright_text.splitlines())
    log = gzip.decompress(data.extractfile("./usr/share/doc/wifi-center/changelog.gz").read()).decode()
    assert log.startswith(f"wifi-center ({bd.deb_version()}) unstable")


def test_build_is_reproducible(tmp_path):
    a, b = bd.build(tmp_path / "a"), bd.build(tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()


def test_release_bundle_contents_and_checksums(tmp_path):
    files = br.build(tmp_path)
    assert {f.name for f in files} == {f"wifi-center_{bd.PY_VERSION}_all.deb", f"wifi-center-offline-{bd.PY_VERSION}.tar.gz", "install.sh", "SHA256SUMS"}
    sums = dict(reversed(line.split("  ")) for line in (tmp_path / "SHA256SUMS").read_text().splitlines())
    for name, digest in sums.items():
        assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == digest
    assert "~" not in "".join(f.name for f in files)                                           # hosts may rewrite '~' in asset names
    tf = tarfile.open(tmp_path / f"wifi-center-offline-{bd.PY_VERSION}.tar.gz")
    top = f"wifi-center-offline-{bd.PY_VERSION}/"
    names = tf.getnames()
    for n in ("install-offline.sh", "fetch-deps.sh", "README-INSTALL.txt", "SHA256SUMS", "debs/README.txt", f"wifi-center_{bd.PY_VERSION}_all.deb"):
        assert top + n in names, n
    assert tf.getmember(top + "install-offline.sh").mode == 0o755
    inner = dict(reversed(l.split("  ")) for l in tf.extractfile(top + "SHA256SUMS").read().decode().splitlines())
    for name, digest in inner.items():
        assert hashlib.sha256(tf.extractfile(top + name).read()).hexdigest() == digest
    fetch = tf.extractfile(top + "fetch-deps.sh").read().decode()
    assert "@DEPS@" not in fetch and "python3-pyside6.qtwidgets" in fetch and "polkitd" in fetch and "policykit-1" not in fetch
    for n in ("install-offline.sh", "fetch-deps.sh"):
        assert b"\r" not in tf.extractfile(top + n).read()                                        # LF endings even when built on Windows


def test_scripts_have_valid_syntax_and_safe_defaults():
    bash = shutil.which("bash")
    for rel in ("install.sh", "packaging/offline/install-offline.sh", "packaging/offline/fetch-deps.sh"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert text.startswith("#!/usr/bin/env bash") and "set -euo pipefail" in text
        if bash:
            assert subprocess.run([bash, "-n", str(ROOT / rel)], capture_output=True).returncode == 0, rel
    one = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "sha256sum --quiet -c" in one and "--uninstall" in one and "--dry-run" in one
    assert "add-apt-repository" not in one and "sudoers" not in one.replace("change sudoers", "") and "curl -fsSL" in one


def test_installer_does_not_let_os_release_overwrite_its_own_variables():
    """Regression: sourcing /etc/os-release (VERSION="7.4 (echo)") clobbered the --version value."""
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "WANT_VERSION" in text and not re.search(r"^\s*VERSION=", text, re.M)
    assert not re.search(r"^\. /etc/os-release", text, re.M) and "$( . /etc/os-release;" in text
