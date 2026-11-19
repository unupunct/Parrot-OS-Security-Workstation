"""Unified view of software sources: APT, Flatpak, Snap, pipx, git checkouts and AppImages.

Detection first, and honest about limits: the update *check* for Flatpak, Snap and git contacts remote servers, so it
only runs when the user asks for it. Updates for these sources are never applied here: the exact command is shown
for you to run (APT updates go through the privileged helper). Manually installed tools are never overwritten.
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .apt_service import AptService
from .process_runner import CommandResult, run_command

Runner = Callable[[list[str], float], CommandResult]
UP_TO_DATE, UPDATE, UNKNOWN, ERROR = "up to date", "update available", "not checked", "error"


@dataclass
class SourceItem:
    name: str
    installed: str = ""
    available: str = ""
    status: str = UNKNOWN
    detail: str = ""


@dataclass
class SourceReport:
    key: str
    title: str
    present: bool
    update_method: str
    items: list[SourceItem] = field(default_factory=list)
    last_check: str = ""
    error: str = ""
    note: str = ""

    @property
    def updates(self) -> int:
        return sum(1 for i in self.items if i.status == UPDATE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- parsers
def parse_flatpak_list(text: str) -> list[SourceItem]:
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if parts and parts[0].strip() and "." in parts[0]:
            out.append(SourceItem(parts[0].strip(), parts[1].strip() if len(parts) > 1 else "",
                                  detail=parts[2].strip() if len(parts) > 2 else ""))
    return out


def parse_snap_table(text: str) -> list[list[str]]:
    rows = text.strip().splitlines()
    if not rows or not rows[0].lower().startswith("name"):
        return []
    return [r.split() for r in rows[1:] if r.strip()]


def parse_pipx_json(text: str) -> list[SourceItem]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for name, venv in (data.get("venvs") or {}).items():
        main = ((venv.get("metadata") or {}).get("main_package") or {})
        out.append(SourceItem(main.get("package", name), main.get("package_version", "")))
    return out


class SoftwareSources:
    def __init__(self, apt: AptService, runner: Runner | None = None, which: Callable[[str], str | None] = shutil.which,
                 appimage_dirs: list[Path] | None = None) -> None:
        self._apt = apt
        self._run = runner or (lambda argv, t: run_command(argv, timeout=t))
        self._which = which
        home = Path.home()
        self._appimage_dirs = appimage_dirs if appimage_dirs is not None else [
            home / "Applications", home / ".local" / "bin", home / "bin", home / "Downloads"]

    # ---- APT (updates from the cached lists; no network)
    def apt(self) -> SourceReport:
        rep = SourceReport("apt", "APT (Debian/Parrot packages)", self._apt.available(),
                           "Update Package Lists, then Upgrade (confirmed, via the privileged helper)")
        if not rep.present:
            rep.note = "apt is not available on this system"
            return rep
        ups = self._apt.upgradable()
        rep.items = [SourceItem(c.name, c.old, c.new, UPDATE, c.origin) for c in ups]
        rep.last_check = _now()
        last = self._apt.last_refresh()
        rep.note = (f"Package lists last refreshed {last:%Y-%m-%d %H:%M} UTC; this view uses the cached lists."
                    if last else "Package lists have never been refreshed on this system, or the time is unknown.")
        return rep

    # ---- Flatpak
    def flatpak(self, check_updates: bool = False) -> SourceReport:
        rep = SourceReport("flatpak", "Flatpak", self._which("flatpak") is not None, "flatpak update (run it yourself)")
        if not rep.present:
            rep.note = "Flatpak is not installed."
            return rep
        r = self._run(["flatpak", "list", "--app", "--columns=application,version,origin"], 30)
        if not r.ok:
            rep.error = (r.stderr.strip().splitlines() or ["flatpak list failed"])[-1]
            return rep
        rep.items = parse_flatpak_list(r.stdout)
        if check_updates:
            u = self._run(["flatpak", "remote-ls", "--updates", "--app", "--columns=application,version"], 90)
            rep.last_check = _now()
            if not u.ok:
                rep.error = (u.stderr.strip().splitlines() or ["update check failed"])[-1]
                return rep
            avail = {p[0]: (p[1] if len(p) > 1 else "") for p in (l.split("\t") for l in u.stdout.splitlines()) if p[0]}
            for it in rep.items:
                it.status = UPDATE if it.name in avail else UP_TO_DATE
                it.available = avail.get(it.name, "")
        return rep

    # ---- Snap
    def snap(self, check_updates: bool = False) -> SourceReport:
        rep = SourceReport("snap", "Snap", self._which("snap") is not None, "snap refresh (run it yourself)")
        if not rep.present:
            rep.note = "Snap is not installed."
            return rep
        r = self._run(["snap", "list"], 30)
        if not r.ok:
            rep.error = (r.stderr.strip().splitlines() or ["snap list failed"])[-1]
            return rep
        rep.items = [SourceItem(row[0], row[1]) for row in parse_snap_table(r.stdout)]
        if check_updates:
            u = self._run(["snap", "refresh", "--list"], 90)
            rep.last_check = _now()
            if not u.ok and "All snaps up to date" not in (u.stderr + u.stdout):
                rep.error = (u.stderr.strip().splitlines() or ["update check failed"])[-1]
                return rep
            avail = {row[0]: row[1] for row in parse_snap_table(u.stdout)}
            for it in rep.items:
                it.status = UPDATE if it.name in avail else UP_TO_DATE
                it.available = avail.get(it.name, "")
        return rep

    # ---- Python application environments (pipx). Global pip is never touched.
    def pipx(self) -> SourceReport:
        rep = SourceReport("pipx", "Python applications (pipx)", self._which("pipx") is not None,
                           "pipx upgrade <name> (run it yourself)")
        if not rep.present:
            rep.note = "pipx is not installed. WIFI Center never updates global pip packages."
            return rep
        r = self._run(["pipx", "list", "--json"], 30)
        if not r.ok:
            rep.error = (r.stderr.strip().splitlines() or ["pipx list failed"])[-1]
            return rep
        rep.items = parse_pipx_json(r.stdout)
        rep.note = "Update availability is not checked automatically (it would query PyPI)."
        return rep

    # ---- git checkouts of configured tools
    def git(self, checkouts: dict[str, str], check_remote: bool = False) -> SourceReport:
        rep = SourceReport("git", "Git-based tools", self._which("git") is not None,
                           "git pull after reviewing the changes (run it yourself)")
        if not rep.present:
            rep.note = "git is not installed."
            return rep
        for name, path in sorted(checkouts.items()):
            if not (Path(path) / ".git").exists():
                continue
            ver = self._run(["git", "-C", path, "describe", "--tags", "--always"], 15)
            head = self._run(["git", "-C", path, "rev-parse", "HEAD"], 15)
            item = SourceItem(name, ver.stdout.strip() if ver.ok else "?", detail=path)
            if check_remote and head.ok:
                rem = self._run(["git", "-C", path, "ls-remote", "origin", "HEAD"], 60)
                rep.last_check = _now()
                if not rem.ok:
                    item.status, item.detail = ERROR, (rem.stderr.strip().splitlines() or ["ls-remote failed"])[-1]
                else:
                    remote = rem.stdout.split()[0] if rem.stdout.split() else ""
                    item.status = UP_TO_DATE if remote == head.stdout.strip() else UPDATE
                    item.available = remote[:10] if item.status == UPDATE else ""
            rep.items.append(item)
        rep.note = "Manually installed tools are never overwritten; the remote check compares the remote HEAD only."
        return rep

    # ---- AppImages (detected only: running one to ask for update info would execute it)
    def appimages(self) -> SourceReport:
        rep = SourceReport("appimage", "AppImage applications", True,
                           "Use the application's own updater or AppImageUpdate (WIFI Center does not run AppImages)")
        seen: set[Path] = set()
        for d in self._appimage_dirs:
            if not d.is_dir():
                continue
            for p in sorted(d.glob("*.AppImage")):
                if p.is_file() and not p.is_symlink() and p not in seen:
                    seen.add(p)
                    st = p.stat()
                    rep.items.append(SourceItem(p.name, f"{st.st_size // (1024 * 1024)} MiB",
                                                detail=f"{p.parent} · modified {datetime.fromtimestamp(st.st_mtime):%Y-%m-%d}"))
        rep.note = "Update status cannot be determined without executing the file, which WIFI Center will not do."
        return rep

    def all(self, tool_checkouts: dict[str, str] | None = None) -> list[SourceReport]:
        return [self.apt(), self.flatpak(), self.snap(), self.pipx(), self.git(tool_checkouts or {}), self.appimages()]
