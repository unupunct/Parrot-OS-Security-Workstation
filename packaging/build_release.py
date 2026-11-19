"""Build everything that goes on a release page:

    python packaging/build_release.py [--out dist/release]

  wifi-center_<ver>_all.deb              the package
  wifi-center-offline-<ver>.tar.gz       .deb + install-offline.sh + fetch-deps.sh + README-INSTALL.txt + SHA256SUMS
  install.sh                             the one-line installer
  SHA256SUMS                             checksums of the three files above

Nothing is uploaded or published by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import re
import shutil
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_deb as bd                                              # noqa: E402

ROOT = bd.ROOT


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def dep_names() -> str:
    """Plain package names for fetch-deps.sh (first alternative of each dependency, python3 itself excluded)."""
    names = []
    for d in bd.DEPENDS + bd.RECOMMENDS:
        n = re.split(r"[ (|]", d.strip())[0]
        if n and n != "python3":
            names.append(n)
    return " ".join(dict.fromkeys(names))


def offline_tar(deb: Path, out: Path) -> Path:
    ver = bd.PY_VERSION
    top = f"wifi-center-offline-{ver}"
    files: dict[str, tuple[bytes, int]] = {
        deb.name: (deb.read_bytes(), 0o644),
        "install-offline.sh": ((ROOT / "packaging/offline/install-offline.sh").read_bytes().replace(b"\r\n", b"\n"), 0o755),
        "fetch-deps.sh": ((ROOT / "packaging/offline/fetch-deps.sh").read_bytes().replace(b"\r\n", b"\n").replace(b"@DEPS@", dep_names().encode()), 0o755),
        "README-INSTALL.txt": ((ROOT / "packaging/offline/README-INSTALL.txt").read_bytes().replace(b"\r\n", b"\n"), 0o644),
        "debs/README.txt": (b"Dependency packages for offline installation go here (see ../fetch-deps.sh).\n", 0o644),
    }
    files["SHA256SUMS"] = ("".join(f"{hashlib.sha256(c).hexdigest()}  {n}\n" for n, (c, _m) in sorted(files.items()) if n != "debs/README.txt").encode(), 0o644)
    path = out / f"{top}.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for name, (content, mode) in sorted(files.items()):
            ti = tarfile.TarInfo(f"{top}/{name}")
            ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(content), mode, bd.EPOCH, 0, 0, "root", "root"
            tf.addfile(ti, io.BytesIO(content))
    return path


def build(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    # release file names avoid '~' (some hosts rewrite it); the version INSIDE the package keeps it so dpkg orders pre-releases correctly
    deb = bd.build(out, f"{bd.PACKAGE}_{bd.PY_VERSION}_all.deb")
    tar = offline_tar(deb, out)
    inst = out / "install.sh"
    inst.write_bytes((ROOT / "install.sh").read_bytes().replace(b"\r\n", b"\n"))
    sums = out / "SHA256SUMS"
    sums.write_text("".join(f"{sha256(p)}  {p.name}\n" for p in (deb, tar, inst)), encoding="utf-8", newline="\n")
    return [deb, tar, inst, sums]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "release"))
    a = ap.parse_args()
    shutil.rmtree(a.out, ignore_errors=True)
    for p in build(Path(a.out)):
        print(f"{p.name:48} {p.stat().st_size // 1024:>6} KiB")
