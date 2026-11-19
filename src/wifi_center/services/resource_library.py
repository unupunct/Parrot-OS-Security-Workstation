"""Local-first resource library (wordlists and other reference files).

Files live under a user-chosen root; the database stores metadata (hash, size, format, source, license, history).
Nothing is downloaded, and nothing is deleted unless the user explicitly asks for that one file.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..database.repository import Database
from ..security.input_validation import ValidationError, validate_within
from . import resource_catalog as rc

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-()+]{0,119}$")
FOLDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,59}$")
TEXT_SUFFIXES = {".txt", ".lst", ".dic", ".dict", ".csv", ".tsv", ".list", ".md", ".json", ".log"}
CHUNK = 1024 * 1024
MAX_LINECOUNT_BYTES = 200 * 1024 * 1024


class LibraryError(ValueError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sniff_format(path: Path) -> str:
    """Human-readable format from the extension and the first bytes."""
    try:
        with path.open("rb") as f:
            head = f.read(4096)
    except OSError:
        return "unknown"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:4] == b"%PDF":
        return "pdf"
    if b"\x00" in head:
        return "binary"
    suffix = path.suffix.lower()
    return {".csv": "csv", ".tsv": "tsv", ".md": "markdown", ".json": "json"}.get(suffix, "text")


def hash_and_count(path: Path, count_lines: bool) -> tuple[str, int | None]:
    h = hashlib.sha256()
    lines = 0
    last = b""
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
            if count_lines:
                lines += chunk.count(b"\n")
                last = chunk[-1:]
    if count_lines and last and last != b"\n":
        lines += 1
    return h.hexdigest(), (lines if count_lines else None)


@dataclass
class ImportResult:
    id: int
    duplicate_of: int | None = None


class LibraryService:
    def __init__(self, db: Database, root_getter: Callable[[], Path], library: str = "wordlists") -> None:
        self._db = db
        self._root_getter = root_getter
        self.library = library

    # ---------------------------------------------------------------- paths
    @property
    def root(self) -> Path:
        return self._root_getter()

    def ensure_root(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        return self.root

    def _key(self, rel: str) -> str:
        return f"{self.library}/{rel}"

    def resolve(self, rel: str) -> Path:
        """Absolute path of a library-relative file; refuses traversal and symlinks leaving the root."""
        cur = self.root
        for part in Path(rel).parts:
            cur = cur / part
            if cur.is_symlink():
                raise LibraryError("symbolic links are not followed inside the library")
        try:
            return validate_within(self.root, rel)
        except ValidationError as e:
            raise LibraryError(str(e)) from None

    @staticmethod
    def safe_name(name: str) -> str:
        name = name.strip()
        if not NAME_RE.match(name) or name.endswith((".", " ")):
            raise LibraryError("file names may use letters, digits, space and . _ - ( ) + (max 120 characters)")
        return name

    @staticmethod
    def safe_folder(folder: str) -> str:
        folder = folder.strip().strip("/\\")
        if folder and not FOLDER_RE.match(folder):
            raise LibraryError("folder names may use letters, digits, space and . _ - (max 60 characters)")
        return folder

    # ---------------------------------------------------------------- records
    def _history(self, action: str, detail: str = "", resource_id: int | None = None) -> None:
        self._db.execute("INSERT INTO resource_history(library, resource_id, action, detail, ts) VALUES (?,?,?,?,?)",
                         (self.library, resource_id, action, detail, utcnow()))

    def history(self, resource_id: int | None = None, limit: int = 500) -> list[dict]:
        sql, params = "SELECT * FROM resource_history WHERE library = ?", [self.library]
        if resource_id:
            sql, params = sql + " AND resource_id = ?", [*params, resource_id]
        return [dict(r) for r in self._db.query(sql + " ORDER BY id DESC LIMIT ?", [*params, limit])]

    def _row(self, r) -> dict:
        d = dict(r)
        d["rel"] = d["path"].split("/", 1)[1] if "/" in d["path"] else d["path"]
        d["folder"] = str(Path(d["rel"]).parent).replace("\\", "/") if "/" in d["rel"] else ""
        d["name"] = Path(d["rel"]).name
        return d

    def files(self, folder: str | None = None, query: str = "", favorites: bool = False) -> list[dict]:
        out = []
        q = query.strip().lower()
        for r in self._db.query("SELECT * FROM resources WHERE library = ? ORDER BY path COLLATE NOCASE", (self.library,)):
            d = self._row(r)
            if folder is not None and d["folder"] != folder:
                continue
            if favorites and not d["favorite"]:
                continue
            if q and q not in d["name"].lower() and q not in (d["source_url"] or "").lower() \
                    and q not in (d["category"] or "").lower():
                continue
            out.append(d)
        return out

    def get(self, resource_id: int) -> dict | None:
        r = self._db.query_one("SELECT * FROM resources WHERE id = ? AND library = ?", (resource_id, self.library))
        return self._row(r) if r else None

    def folders(self) -> dict[str, int]:
        """Folder -> number of tracked files ('' is the library root)."""
        counts: dict[str, int] = {}
        for d in (self._row(r) for r in self._db.query("SELECT path FROM resources WHERE library = ?", (self.library,))):
            counts[d["folder"]] = counts.get(d["folder"], 0) + 1
        if self.root.is_dir():
            for p in self.root.iterdir():
                if p.is_dir() and not p.is_symlink() and not p.name.startswith("."):
                    counts.setdefault(p.name, 0)
        return counts

    def set_favorite(self, resource_id: int, on: bool) -> None:
        self._db.execute("UPDATE resources SET favorite = ? WHERE id = ? AND library = ?",
                         (int(on), resource_id, self.library))

    def set_notes(self, resource_id: int, notes: str) -> None:
        self._db.execute("UPDATE resources SET notes = ? WHERE id = ? AND library = ?", (notes, resource_id, self.library))

    # ---------------------------------------------------------------- add / import
    def _register(self, rel: str, path: Path, sha: str, lines: int | None, *, source_url: str = "", license: str = "",
                  attribution: str = "", acquired_at: str | None = None, entry_id: str | None = None,
                  category: str | None = None, action: str = "import", detail: str = "") -> int:
        st = path.stat()
        rid = self._db.execute(
            "INSERT INTO resources(library, name, path, category, size_bytes, sha256, source_url, license, attribution, "
            "acquired_at, last_verified, format, line_count, entry_id, mtime) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.library, Path(rel).name, self._key(rel), category or str(Path(rel).parent).replace("\\", "/"),
             st.st_size, sha, source_url, license, attribution, acquired_at, utcnow(), sniff_format(path), lines,
             entry_id, st.st_mtime))
        self._history(action, detail or rel, rid)
        return rid

    def duplicate_of(self, sha: str, exclude_id: int | None = None) -> int | None:
        r = self._db.query_one("SELECT id FROM resources WHERE library = ? AND sha256 = ? AND id != ?",
                               (self.library, sha, exclude_id or -1))
        return r["id"] if r else None

    def import_file(self, src: str, folder: str = "", name: str | None = None, *, source_url: str = "",
                    license: str = "", attribution: str = "", acquired_at: str | None = None,
                    entry_id: str | None = None, allow_duplicate: bool = False) -> ImportResult:
        """Copy a file you obtained yourself into the library and record where it came from."""
        s = Path(src)
        if not s.is_absolute() or not s.is_file():
            raise LibraryError("choose an existing file (absolute path)")
        if s.is_symlink():
            raise LibraryError("choose the file itself, not a symbolic link")
        folder = self.safe_folder(folder)
        fname = self.safe_name(s.name if name is None else name)
        rel = f"{folder}/{fname}" if folder else fname
        root = self.ensure_root()
        dest = self.resolve(rel)
        if dest.exists() or self._db.query_one("SELECT 1 FROM resources WHERE path = ?", (self._key(rel),)):
            raise LibraryError(f"“{rel}” already exists in the library; choose another name")
        if shutil.disk_usage(root).free < s.stat().st_size * 1.05:
            raise LibraryError("not enough free space in the library folder")
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        h = hashlib.sha256()
        try:
            with s.open("rb") as fi, tmp.open("wb") as fo:
                for chunk in iter(lambda: fi.read(CHUNK), b""):
                    h.update(chunk)
                    fo.write(chunk)
            sha = h.hexdigest()
            dup = self.duplicate_of(sha)
            if dup and not allow_duplicate:
                tmp.unlink(missing_ok=True)
                return ImportResult(0, dup)
            os.replace(tmp, dest)           # atomic: a half-copied file never appears under its final name
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        lines = hash_and_count(dest, True)[1] if (sniff_format(dest) in ("text", "csv", "tsv", "markdown", "json")
                                                  and dest.stat().st_size <= MAX_LINECOUNT_BYTES) else None
        rid = self._register(rel, dest, sha, lines, source_url=source_url, license=license, attribution=attribution,
                             acquired_at=acquired_at or utcnow()[:10], entry_id=entry_id,
                             detail=f"imported {s.name} → {rel}" + (f" (source {source_url})" if source_url else ""))
        return ImportResult(rid, dup)

    def untracked(self) -> list[str]:
        """Files present in the library folder that are not in the database (found by browsing, not guessing)."""
        root = self.root
        if not root.is_dir():
            return []
        known = {self._row(r)["rel"] for r in self._db.query("SELECT path FROM resources WHERE library = ?", (self.library,))}
        out = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and not (Path(dirpath) / d).is_symlink()]
            depth = len(Path(dirpath).relative_to(root).parts)
            if depth > 3:
                dirnames[:] = []
                continue
            for fn in filenames:
                p = Path(dirpath) / fn
                if fn.startswith(".") or fn.endswith(".part") or p.is_symlink():
                    continue
                rel = p.relative_to(root).as_posix()
                if rel not in known:
                    out.append(rel)
        return sorted(out)

    def adopt(self, rel: str) -> int:
        """Start tracking a file that is already in the library folder (nothing is moved or copied)."""
        p = self.resolve(rel)
        if not p.is_file():
            raise LibraryError("file not found")
        if self._db.query_one("SELECT 1 FROM resources WHERE path = ?", (self._key(rel),)):
            raise LibraryError("already tracked")
        fmt = sniff_format(p)
        count = fmt in ("text", "csv", "tsv", "markdown", "json") and p.stat().st_size <= MAX_LINECOUNT_BYTES
        sha, lines = hash_and_count(p, count)
        return self._register(rel, p, sha, lines, action="adopt", detail=f"started tracking {rel}")

    # ---------------------------------------------------------------- rename / remove / verify
    def rename(self, resource_id: int, new_name: str) -> None:
        d = self.get(resource_id)
        if not d:
            raise LibraryError("unknown resource")
        name = self.safe_name(new_name)
        new_rel = f"{d['folder']}/{name}" if d["folder"] else name
        src, dst = self.resolve(d["rel"]), self.resolve(new_rel)
        if dst.exists() or self._db.query_one("SELECT 1 FROM resources WHERE path = ?", (self._key(new_rel),)):
            raise LibraryError(f"“{new_rel}” already exists")
        if src.exists():
            src.rename(dst)
        self._db.execute("UPDATE resources SET name = ?, path = ? WHERE id = ?", (name, self._key(new_rel), resource_id))
        self._history("rename", f"{d['rel']} → {new_rel}", resource_id)

    def remove(self, resource_id: int, delete_file: bool = False) -> None:
        """Stop tracking a file. The file stays on disk unless `delete_file` is passed (explicit user choice)."""
        d = self.get(resource_id)
        if not d:
            return
        if delete_file:
            p = self.resolve(d["rel"])
            if p.is_file():
                p.unlink()
        self._db.execute("DELETE FROM resources WHERE id = ?", (resource_id,))
        self._history("delete-file" if delete_file else "untrack", d["rel"], resource_id)

    def verify(self, resource_id: int) -> str:
        """'ok' | 'changed' | 'missing'; refreshes size/mtime only when the content still matches."""
        d = self.get(resource_id)
        if not d:
            return "missing"
        try:
            p = self.resolve(d["rel"])
        except (LibraryError, ValidationError):
            return "missing"
        if not p.is_file():
            state = "missing"
        else:
            state = "ok" if hash_and_count(p, False)[0] == d["sha256"] else "changed"
        if state != "missing":
            self._db.execute("UPDATE resources SET last_verified = ? WHERE id = ?", (utcnow(), resource_id))
        self._history("verify", f"{d['rel']}: {state}", resource_id)
        return state

    def verify_all(self) -> dict[int, str]:
        return {d["id"]: self.verify(d["id"]) for d in self.files()}

    # ---------------------------------------------------------------- reports
    def duplicates(self) -> list[list[dict]]:
        groups: dict[str, list[dict]] = {}
        for d in self.files():
            if d["sha256"]:
                groups.setdefault(d["sha256"], []).append(d)
        return [g for g in groups.values() if len(g) > 1]

    def storage(self) -> dict:
        used = sum(d["size_bytes"] or 0 for d in self.files())
        root = self.root
        free = shutil.disk_usage(root if root.exists() else root.anchor or "/").free if (root.exists() or root.anchor) else 0
        return {"used": used, "free": free, "files": len(self.files()), "root": str(root)}

    # ---------------------------------------------------------------- catalog actions
    def generate(self, entry_id: str, count: int | None = None, seed: int | None = None) -> int:
        e = rc.entry(entry_id)
        if not e or not e.generator:
            raise LibraryError("this catalog entry cannot be generated")
        lines = rc.generate(entry_id, count, seed if seed is not None else 20260101)
        if not lines:
            raise LibraryError("nothing to generate")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        rel = f"Generated/{e.id}-{stamp}.txt"
        dest = self.resolve(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.replace(tmp, dest)
        sha, n = hash_and_count(dest, True)
        return self._register(rel, dest, sha, n, license=e.license, attribution="Generated locally by WIFI Center",
                              acquired_at=utcnow()[:10], entry_id=e.id, action="generate",
                              detail=f"generated {len(lines)} entries ({e.name})")

    @staticmethod
    def check_source(entry: rc.CatalogEntry, timeout: float = 8.0) -> dict:
        """Explicit, user-requested check that a reference source still exists and what license it declares."""
        if entry.repo:
            req = urllib.request.Request(f"https://api.github.com/repos/{entry.repo}",
                                         headers={"User-Agent": "WIFI-Center source check", "Accept": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.loads(r.read().decode("utf-8", errors="replace"))
            except urllib.error.HTTPError as e:
                return {"available": False, "detail": f"GitHub answered HTTP {e.code}"}
            except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as e:
                return {"available": False, "detail": f"not reachable: {getattr(e, 'reason', e)}"}
            lic = (data.get("license") or {}).get("spdx_id") or "none declared"
            return {"available": True, "archived": bool(data.get("archived")), "license": lic,
                    "pushed_at": data.get("pushed_at"), "license_matches": lic == entry.license or not entry.license
                    or entry.license.startswith("Varies"),
                    "detail": f"repository exists, license {lic}, last push {data.get('pushed_at')}"}
        req = urllib.request.Request(entry.source_url, method="HEAD", headers={"User-Agent": "WIFI-Center source check"})
        try:
            with urllib.request.urlopen(req, timeout=timeout):
                return {"available": True, "detail": "the page answered"}
        except urllib.error.HTTPError as e:
            return {"available": e.code < 500, "detail": f"HTTP {e.code}"}
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            return {"available": False, "detail": f"not reachable: {getattr(e, 'reason', e)}"}

    def record_source_check(self, entry_id: str, result: dict) -> None:
        self._history("source-check", f"{entry_id}: {result.get('detail', '')}")
