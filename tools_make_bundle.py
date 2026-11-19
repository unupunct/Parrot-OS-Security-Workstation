"""Build dist/wifi-center-dev.tar.gz for copying to a Linux machine (LF line endings, sensible modes)."""
import fnmatch, io, pathlib, tarfile

TEXT = {".py", ".sh", ".md", ".toml", ".txt", ".policy", ".conf", ".service", ".sql", ".xml", ".json", ".cfg", ".ini", ".desktop", ".svg", ".html", ".css"}
SKIP_DIRS = {".git", "dist", "__pycache__", ".pytest_cache", ".venv", "build", ".idea", "screenshots"}
SKIP_FILES = ("*.pyc", "*.db", "tools_make_bundle.py")
root = pathlib.Path(__file__).resolve().parent
out = root / "dist" / "wifi-center-dev.tar.gz"
out.parent.mkdir(exist_ok=True)
n = 0
with tarfile.open(out, "w:gz") as tf:
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if not p.is_file() or any(part in SKIP_DIRS or part.endswith(".egg-info") for part in rel.parts):
            continue
        if any(fnmatch.fnmatch(p.name, pat) for pat in SKIP_FILES):
            continue
        data = p.read_bytes()
        if p.suffix.lower() in TEXT or p.name in ("LICENSE", ".gitignore", ".gitattributes"):
            data = data.replace(b"\r\n", b"\n")
        ti = tarfile.TarInfo("wifi-center/" + rel.as_posix())
        ti.size, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0, "root", "root"
        ti.mode = 0o755 if p.suffix == ".sh" or p.name == "helper.py" else 0o644
        tf.addfile(ti, io.BytesIO(data))
        n += 1
print(n, "files,", round(out.stat().st_size / 1024), "KiB")
