"""Read-only view of the wordlists already installed on the system (Parrot/Kali: /usr/share/wordlists).

Nothing is copied, downloaded, opened for writing or executed: entries are listed with where their links point,
their size and whether they are compressed. The folder is the distribution's own; the app only reads its metadata.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SYSTEM_ROOT = "/usr/share/wordlists"
MAX_ENTRIES = 3000            # one folder level is never listed beyond this


@dataclass(frozen=True)
class SystemEntry:
    name: str
    path: str                 # the entry as listed (a link stays a link)
    target: str               # where a symbolic link points ('' when it is not a link)
    kind: str                 # file | dir | broken
    size: int                 # bytes for files; 0 for folders
    children: int             # direct entries for folders; 0 otherwise
    compressed: bool

    @property
    def is_dir(self) -> bool:
        return self.kind == "dir"


def describe(path: str) -> SystemEntry:
    p = Path(path)
    target = ""
    try:
        if p.is_symlink():
            target = os.readlink(p)
    except OSError:
        pass
    try:
        if p.is_dir():
            try:
                n = sum(1 for _ in os.scandir(p))
            except OSError:
                n = 0
            return SystemEntry(p.name, str(p), target, "dir", 0, n, False)
        if p.is_file():
            return SystemEntry(p.name, str(p), target, "file", p.stat().st_size, 0, p.suffix.lower() in (".gz", ".bz2", ".xz", ".zip"))
    except OSError:
        pass
    return SystemEntry(p.name, str(p), target, "broken", 0, 0, False)


def list_folder(path: str = SYSTEM_ROOT, limit: int = MAX_ENTRIES) -> list[SystemEntry]:
    """One level of a folder: folders first, then files, each sorted by name."""
    try:
        with os.scandir(path) as it:
            names = sorted((e.name for e in it), key=str.lower)[:limit]
    except OSError:
        return []
    out = [describe(os.path.join(path, n)) for n in names]
    return sorted(out, key=lambda e: (not e.is_dir, e.name.lower()))


def line_count(path: str, max_bytes: int = 2_000_000_000) -> int | None:
    """Count lines of a plain-text file (None for compressed, oversized or unreadable files)."""
    p = Path(path)
    try:
        if p.suffix.lower() in (".gz", ".bz2", ".xz", ".zip") or p.stat().st_size > max_bytes:
            return None
        n = 0
        with open(p, "rb") as f:
            while chunk := f.read(1 << 20):
                n += chunk.count(b"\n")
        return n
    except OSError:
        return None


# ------------------------------------------------------------------ copying into the app's own library
@dataclass(frozen=True)
class CopyItem:
    src: str                  # the real file (links resolved)
    folder: str               # library folder ('' = library root)
    name: str
    size: int


@dataclass
class CopyPlan:
    items: list[CopyItem]
    skipped: list[str]
    truncated: bool = False

    @property
    def total(self) -> int:
        return sum(i.size for i in self.items)


MAX_COPY_FILES = 400
MAX_COPY_DEPTH = 2


def _clean(part: str) -> str:
    return "".join(c if (c.isalnum() or c in " _.-()+") else "_" for c in part).strip(" .") or "file"


def plan_copy(paths: list[str], max_files: int = MAX_COPY_FILES) -> CopyPlan:
    """Which files copying these entries would create. A file goes to the library root; a folder's files go to
    a library folder of the same name (nested files are flattened into their name). Links are resolved, loops and
    anything beyond MAX_COPY_DEPTH levels are skipped, and the plan is capped at max_files."""
    items: list[CopyItem] = []
    skipped: list[str] = []
    seen: set[str] = set()
    truncated = False

    def add(real: Path, folder: str, name: str) -> None:
        nonlocal truncated
        key = str(real)
        if key in seen:
            return
        if len(items) >= max_files:
            truncated = True
            return
        seen.add(key)
        try:
            items.append(CopyItem(key, folder, name, real.stat().st_size))
        except OSError:
            skipped.append(f"{name}: unreadable")

    for raw in paths:
        p = Path(raw)
        try:
            real = p.resolve(strict=True)
        except OSError:
            skipped.append(f"{p.name}: link target is missing")
            continue
        if real.is_file():
            add(real, "", _clean(p.name))
            continue
        top = _clean(p.name)[:60]
        base_depth = len(real.parts)
        for dirpath, dirnames, filenames in os.walk(real, followlinks=False):
            depth = len(Path(dirpath).parts) - base_depth
            if depth + 1 >= MAX_COPY_DEPTH:
                dirnames[:] = []
            dirnames.sort()
            for fn in sorted(filenames):
                fp = Path(dirpath) / fn
                if fp.is_symlink() and not fp.exists():
                    skipped.append(f"{fn}: broken link")
                    continue
                rel = fp.relative_to(real)
                flat = "_".join(_clean(x) for x in rel.parts)[:120]
                add(fp.resolve(), top, flat)
    return CopyPlan(items, skipped, truncated)
