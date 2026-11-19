"""System cleanup: scan, explain, preview (dry run) and remove, within strict allow-listed locations.

Safety design:
* Candidates are only ever enumerated from allow-listed roots (never documents, settings, projects or active data).
* Deletion re-validates every path right before removing it: inside an allowed root, a regular file, not a symlink.
* Dry run is the default. Only user-owned locations are cleaned by this application; system locations are handed to the
  privileged helper (Phase 8), which repeats the validation.
"""
from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .apt_service import AptService, Transaction
from .maintenance_service import MaintenanceService
from .privileged_service import ExecutionResult, Manifest, PrivilegedBackend, PrivilegedOp
from .process_runner import CommandResult, run_command

Runner = Callable[[list[str], float], CommandResult]
SCAN_CAP = 50_000
DAY = 86400
SAFE_CACHE_DIRS = ("pip", "mesa_shader_cache", "fontconfig")


@dataclass(frozen=True)
class Category:
    id: str
    title: str
    why_safe: str
    needs_root: bool
    default_selected: bool = True


CATEGORIES: tuple[Category, ...] = (
    Category("apt_cache", "APT package cache", "Downloaded .deb files that APT can fetch again; installed software is "
             "unaffected.", True),
    Category("autoremove", "Unused package dependencies", "Packages APT installed automatically that nothing needs "
             "any more (from `apt-get -s autoremove`); you see the exact list first.", True),
    Category("residual_configs", "Residual package configuration", "System configuration files left behind by packages "
             "that were already removed. Off by default: purging deletes those files.", True, False),
    Category("tmp_user", "Old temporary files (yours)", "Files in /tmp that you own and nobody has modified for 7 days.",
             False),
    Category("var_tmp", "Old system temporary files", "Files in /var/tmp untouched for 30 days.", True),
    Category("logs_user", "Expired WIFI Center logs", "Rotated WIFI Center log files older than 30 days; the current "
             "log and the audit log are never touched.", False),
    Category("logs_system", "Expired system logs", "Rotated/compressed logs in /var/log older than 30 days; current "
             "logs are never touched.", True),
    Category("thumbnails", "Thumbnail cache", "Image previews your desktop regenerates on demand.", False),
    Category("app_caches", "Safe application caches", "Caches of pip, Mesa shaders and fontconfig, which are rebuilt "
             "automatically.", False),
)
CAT = {c.id: c for c in CATEGORIES}


@dataclass
class Candidate:
    path: str                # file path, or package name for package categories
    size: int = 0


@dataclass
class CategoryScan:
    category: Category
    items: list[Candidate] = field(default_factory=list)
    total_size: int = 0
    note: str = ""
    truncated: bool = False
    available: bool = True

    @property
    def count(self) -> int:
        return len(self.items)


@dataclass
class CleanResult:
    category: str
    removed: int = 0
    freed: int = 0
    errors: list[str] = field(default_factory=list)
    executed: bool = True
    dry_run: bool = False
    message: str = ""
    pending_op: PrivilegedOp | None = None     # set when an asynchronous helper must still run it


def parse_dpkg_residual(text: str) -> list[str]:
    """`dpkg-query -W -f '${db:Status-Abbrev} ${Package}\\n'`: lines starting 'rc' are removed-with-config."""
    return [l.split(None, 1)[1].strip() for l in text.splitlines() if l.startswith("rc") and len(l.split(None, 1)) == 2]


class CleanupService:
    def __init__(self, maintenance: MaintenanceService, apt: AptService, backend: PrivilegedBackend,
                 runner: Runner | None = None, home: Path | None = None, tmp: Path = Path("/tmp"),
                 var_tmp: Path = Path("/var/tmp"), var_log: Path = Path("/var/log"),
                 apt_cache: Path = Path("/var/cache/apt/archives"), app_log_dir: Path | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._maint, self._apt, self.backend = maintenance, apt, backend
        self._run = runner or (lambda argv, t: run_command(argv, timeout=t))
        self.home = home or Path.home()
        self.tmp, self.var_tmp, self.var_log, self.apt_cache = tmp, var_tmp, var_log, apt_cache
        self.app_log_dir = app_log_dir
        self._now = clock

    # ------------------------------------------------------------- allowed roots (user-owned categories)
    def _user_roots(self, cat_id: str) -> list[Path]:
        if cat_id == "tmp_user":
            return [self.tmp]
        if cat_id == "logs_user":
            return [self.app_log_dir] if self.app_log_dir else []
        if cat_id == "thumbnails":
            return [self.home / ".cache" / "thumbnails"]
        if cat_id == "app_caches":
            return [self.home / ".cache" / d for d in SAFE_CACHE_DIRS]
        return []

    @staticmethod
    def _walk(root: Path, pred: Callable[[Path, os.stat_result], bool]) -> tuple[list[Candidate], bool]:
        items: list[Candidate] = []
        if not root.is_dir() or root.is_symlink():
            return items, False
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and pred(p, st):
                    items.append(Candidate(str(p), st.st_size))
                    if len(items) >= SCAN_CAP:
                        return items, True
        return items, False

    # ------------------------------------------------------------- scanning
    def scan(self, only: list[str] | None = None) -> list[CategoryScan]:
        return [self._scan_one(c) for c in CATEGORIES if only is None or c.id in only]

    def _scan_one(self, cat: Category) -> CategoryScan:
        s = CategoryScan(cat)
        now = self._now()
        uid = os.getuid() if hasattr(os, "getuid") else None
        old = lambda days: (lambda p, st: now - st.st_mtime > days * DAY)
        owned = lambda days: (lambda p, st: now - st.st_mtime > days * DAY and (uid is None or st.st_uid == uid))
        if cat.id == "apt_cache":
            s.items, s.truncated = self._walk(self.apt_cache, lambda p, st: p.suffix == ".deb" or p.parent.name == "partial")
            s.available = self.apt_cache.is_dir()
        elif cat.id == "autoremove":
            tx = self._apt.plan("autoremove")
            if not tx.ok:
                s.available, s.note = False, tx.error
            else:
                s.items = [Candidate(c.name) for c in tx.removes]
                s.note = f"APT estimates {tx.disk_change.lstrip('-')} freed" if tx.disk_change else ""
        elif cat.id == "residual_configs":
            r = self._run(["dpkg-query", "-W", "-f", "${db:Status-Abbrev} ${Package}\n"], 30)
            s.available = r.ok
            s.items = [Candidate(n) for n in parse_dpkg_residual(r.stdout)] if r.ok else []
        elif cat.id == "tmp_user":
            s.items, s.truncated = self._walk(self.tmp, lambda p, st: owned(7)(p, st)
                                              and "systemd-private" not in str(p) and ".X11-unix" not in str(p))
            s.available = self.tmp.is_dir()
        elif cat.id == "var_tmp":
            s.items, s.truncated = self._walk(self.var_tmp, lambda p, st: old(30)(p, st) and "systemd-private" not in str(p))
            s.available = self.var_tmp.is_dir()
        elif cat.id == "logs_user":
            roots = self._user_roots("logs_user")
            if roots:
                s.items, s.truncated = self._walk(roots[0], lambda p, st: re.search(r"\.log\.\d+$|\.log\.\d+\.gz$", p.name)
                                                  is not None and old(30)(p, st))
            s.available = bool(roots) and roots[0].is_dir()
        elif cat.id == "logs_system":
            s.items, s.truncated = self._walk(self.var_log, lambda p, st: re.search(r"(\.\d+(\.gz)?|\.gz|\.old)$", p.name)
                                              is not None and old(30)(p, st))
            s.available = self.var_log.is_dir()
        elif cat.id in ("thumbnails", "app_caches"):
            for root in self._user_roots(cat.id):
                items, trunc = self._walk(root, lambda p, st: True)
                s.items += items
                s.truncated = s.truncated or trunc
            s.available = any(r.is_dir() for r in self._user_roots(cat.id))
        s.total_size = sum(i.size for i in s.items)
        return s

    # ------------------------------------------------------------- deletion
    def _is_deletable(self, cat_id: str, path: str) -> bool:
        """Final gate before removing a file: inside an allowed root, a regular file, no symlink anywhere on the way."""
        p = Path(path)
        for root in self._user_roots(cat_id):
            try:
                rel = p.relative_to(root)
            except ValueError:
                continue
            if ".." in rel.parts or root.is_symlink():
                return False
            cur = root
            for part in rel.parts:
                cur = cur / part
                if cur.is_symlink():
                    return False
            try:
                return stat.S_ISREG(p.lstat().st_mode)
            except OSError:
                return False
        return False

    def clean(self, scans: list[CategoryScan], selected: list[str], dry_run: bool = True) -> list[CleanResult]:
        results = []
        started = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        by_id = {s.category.id: s for s in scans}
        for cid in selected:
            s = by_id.get(cid)
            if not s or not s.items:
                continue
            res = CleanResult(cid, dry_run=dry_run)
            if dry_run:
                res.removed, res.freed, res.message = s.count, s.total_size, "dry run: nothing was removed"
            elif s.category.needs_root:
                res = self._privileged(s)
            else:
                for c in s.items:
                    if not self._is_deletable(cid, c.path):
                        res.errors.append(f"skipped (not an allowed regular file): {c.path}")
                        continue
                    try:
                        Path(c.path).unlink()
                        res.removed += 1
                        res.freed += c.size
                    except OSError as e:
                        res.errors.append(f"{c.path}: {e}")
            results.append(res)
            if res.pending_op is not None:        # recorded when the helper reports back (see finish_privileged)
                continue
            self._maint.record(f"Cleanup: {s.category.title}", "cleanup",
                               "dry run" if dry_run else ("success" if res.executed and not res.errors else
                                                           "not executed" if not res.executed else "failed"),
                               files_removed=res.removed, errors="\n".join(res.errors[:50]) or res.message
                               if (res.errors or not res.executed) else "", started_at=started)
        return results

    def _privileged(self, s: CategoryScan) -> CleanResult:
        cid = s.category.id
        paths = tuple(i.path for i in s.items)
        build = {"apt_cache": lambda: PrivilegedOp("apt_clean"),
                 # the helper re-simulates the transaction as root and refuses anything outside this manifest:
                 # autoremove may remove exactly the packages that were scanned; a config purge names its packages and the helper checks they are already removed (state rc)
                 "autoremove": lambda: PrivilegedOp("apt_autoremove", manifest=Manifest(removes=tuple(i.path for i in s.items))),
                 "residual_configs": lambda: PrivilegedOp("purge_residual_configs", packages=paths, manifest=Manifest(removes=paths)),
                 "var_tmp": lambda: PrivilegedOp("remove_system_files", paths=paths),
                 "logs_system": lambda: PrivilegedOp("remove_system_files", paths=paths)}
        op = build[cid]()      # only the operation for this category is built (and validated)
        if not hasattr(self.backend, "execute"):   # asynchronous backend (the D-Bus helper): the UI runs it
            return CleanResult(cid, 0, 0, [], False, False, "waiting for authorization and the helper", pending_op=op)
        out: ExecutionResult = self.backend.execute(op)
        return CleanResult(cid, s.count if out.ok else 0, s.total_size if out.ok else 0,
                           [] if out.ok else ([out.message] if out.executed else []), out.executed, False, out.message)

    def finish_privileged(self, result: CleanResult, scan: CategoryScan, exec_result: ExecutionResult) -> CleanResult:
        """Complete a category that was handed to an asynchronous helper, and record it."""
        result.pending_op = None
        result.executed = exec_result.executed
        result.removed = scan.count if exec_result.ok else 0
        result.freed = scan.total_size if exec_result.ok else 0
        result.errors = [] if exec_result.ok or not exec_result.executed else [exec_result.message]
        result.message = exec_result.message
        status = "success" if exec_result.ok else ("failed" if exec_result.executed else "not executed")
        self._maint.record(f"Cleanup: {scan.category.title}", "cleanup", status, files_removed=result.removed,
                           errors="" if exec_result.ok else exec_result.message)
        return result
