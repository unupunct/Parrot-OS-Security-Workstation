"""APT: read-only inspection and *simulated* transactions. Applying anything goes through the privileged backend.

Everything here runs as the normal user: `apt-get -s` (simulate), `apt list`, `dpkg-query`, file reads. The text
formats parsed below are the stable `apt-get`/`dpkg` outputs (run with LC_ALL=C); they have been checked against
sample output and should be re-checked on a real Parrot OS system.
"""
from __future__ import annotations

import os
import re
import shutil
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import psutil

from .privileged_service import validate_package_name
from .process_runner import CommandResult, run_command

Runner = Callable[[list[str], float], CommandResult]
APT_PROCESSES = {"apt", "apt-get", "aptitude", "dpkg", "unattended-upgr", "unattended-upgrade", "packagekitd",
                 "synaptic", "apt.systemd.daily", "apt-check", "gnome-software", "muon", "pkcon"}
PROTECTED_EXACT = {"apt", "dpkg", "systemd", "libc6", "base-files", "bash", "coreutils", "login", "sudo", "init",
                   "network-manager", "grub-pc", "grub-efi-amd64", "udev", "util-linux", "polkitd", "policykit-1"}
PROTECTED_PREFIX = ("parrot-", "linux-image-", "xserver-xorg", "lightdm", "libc6", "systemd-")

_INST = re.compile(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) ([^\[\)]*?)(?: \[[^\]]*\])?\)")
_REMV = re.compile(r"^Remv (\S+)(?: \[([^\]]+)\])?")
_SUMMARY = re.compile(r"(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded")
_NEED = re.compile(r"Need to get ([\d.,]+ ?[kKMGT]?B)(?:/[\d.,]+ ?[kKMGT]?B)? of archives")
_DISK = re.compile(r"After this operation, ([\d.,]+ ?[kKMGT]?B) (?:of additional )?disk space will be (used|freed)")
_UPGRADABLE = re.compile(r"^(\S+?)/(\S+) (\S+) (\S+) \[upgradable from: ([^\]]+)\]")
_SECTION = {"The following packages will be upgraded:": "upgrade", "The following NEW packages will be installed:": "new",
            "The following packages will be REMOVED:": "remove",
            "The following packages have been kept back:": "kept"}


@dataclass
class PkgChange:
    name: str
    old: str = ""
    new: str = ""
    origin: str = ""


@dataclass
class Transaction:
    kind: str
    upgrades: list[PkgChange] = field(default_factory=list)
    installs: list[PkgChange] = field(default_factory=list)
    removes: list[PkgChange] = field(default_factory=list)
    kept_back: list[str] = field(default_factory=list)
    download: str = ""
    disk_change: str = ""
    counts: tuple[int, int, int, int] = (0, 0, 0, 0)    # upgraded, new, remove, not upgraded
    ok: bool = True
    error: str = ""
    raw: str = ""

    @property
    def is_empty(self) -> bool:
        return not (self.upgrades or self.installs or self.removes)

    def package_names(self) -> list[str]:
        return [c.name for c in (*self.upgrades, *self.installs, *self.removes)]


@dataclass
class Repository:
    kind: str                 # deb | deb-src
    uri: str
    suite: str
    components: list[str]
    source_file: str
    enabled: bool = True
    options: str = ""

    @property
    def insecure_transport(self) -> bool:
        return self.uri.startswith("http://")


# ------------------------------------------------------------------ pure parsers
def parse_transaction(kind: str, text: str, stderr: str = "") -> Transaction:
    tx = Transaction(kind, raw=text)
    section = ""
    section_names: dict[str, list[str]] = {"upgrade": [], "new": [], "remove": [], "kept": []}
    for line in text.splitlines():
        m = _INST.match(line)
        if m:
            name, old, new, origin = m.groups()
            change = PkgChange(name, old or "", new, origin.strip())
            (tx.upgrades if old else tx.installs).append(change)
            continue
        m = _REMV.match(line)
        if m:
            tx.removes.append(PkgChange(m.group(1), m.group(2) or ""))
            continue
        if line.strip() in _SECTION:
            section = _SECTION[line.strip()]
            continue
        if section and line.startswith("  "):
            section_names[section].extend(w.rstrip("*") for w in line.split())
            continue
        section = ""
        m = _SUMMARY.search(line)
        if m:
            tx.counts = tuple(int(x) for x in m.groups())  # type: ignore[assignment]
        m = _NEED.search(line)
        if m:
            tx.download = m.group(1)
        m = _DISK.search(line)
        if m:
            tx.disk_change = ("+" if m.group(2) == "used" else "-") + m.group(1)
    tx.kept_back = section_names["kept"]
    # Some versions omit Inst lines in odd cases: fall back to the announced lists
    if not tx.upgrades and section_names["upgrade"] and not tx.installs:
        tx.upgrades = [PkgChange(n) for n in section_names["upgrade"]]
    for n in section_names["new"]:
        if n not in {c.name for c in tx.installs}:
            tx.installs.append(PkgChange(n))
    for n in section_names["remove"]:
        if n not in {c.name for c in tx.removes}:
            tx.removes.append(PkgChange(n))
    errors = [l[2:].strip() for l in (stderr + "\n" + text).splitlines() if l.startswith("E:")]
    if errors:
        tx.ok, tx.error = False, "; ".join(errors)
    return tx


def parse_upgradable(text: str) -> list[PkgChange]:
    out = []
    for line in text.splitlines():
        m = _UPGRADABLE.match(line)
        if m:
            name, suite, new, _arch, old = m.groups()
            out.append(PkgChange(name, old, new, suite))
    return out


def risk_flags(tx: Transaction) -> list[str]:
    """Reasons a human should look twice before approving. Never silently accept removals or surprises."""
    flags = []
    if tx.removes:
        flags.append(f"REMOVES {len(tx.removes)} package(s): " + ", ".join(c.name for c in tx.removes[:8])
                     + (" …" if len(tx.removes) > 8 else ""))
    protected = [c.name for c in tx.removes if c.name in PROTECTED_EXACT or c.name.startswith(PROTECTED_PREFIX)]
    if protected:
        flags.append("removes system-critical packages: " + ", ".join(protected))
    if tx.kind in ("upgrade", "dist-upgrade") and tx.installs:
        flags.append(f"pulls in {len(tx.installs)} new package(s) as dependencies: "
                     + ", ".join(c.name for c in tx.installs[:8]) + (" …" if len(tx.installs) > 8 else ""))
    if tx.kept_back:
        flags.append(f"{len(tx.kept_back)} package(s) kept back: " + ", ".join(tx.kept_back[:8]))
    if tx.counts[2] != len(tx.removes) and tx.counts != (0, 0, 0, 0):
        flags.append("the removal list does not match APT's summary: do not apply without reading the full output")
    return flags


_SRC_LINE = re.compile(r"^(deb(?:-src)?)\s+(?:\[([^\]]*)\]\s+)?(\S+)\s+(\S+)(?:\s+(.*))?$")


def parse_sources_list(text: str, source_file: str = "") -> list[Repository]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        disabled = line.startswith("#")
        if disabled:
            line = line.lstrip("#").strip()
        m = _SRC_LINE.match(line)
        if not m:
            continue
        kind, opts, uri, suite, comps = m.groups()
        if disabled and not (uri.startswith(("http", "ftp", "file", "cdrom", "mirror")) and suite):
            continue
        out.append(Repository(kind, uri, suite, (comps or "").split(), source_file, not disabled, opts or ""))
    return out


def parse_deb822_sources(text: str, source_file: str = "") -> list[Repository]:
    out = []
    for stanza in re.split(r"\n\s*\n", text.strip()):
        f: dict[str, str] = {}
        for line in stanza.splitlines():
            if line.startswith("#") or ":" not in line or line[0] in " \t":
                continue
            k, v = line.split(":", 1)
            f[k.strip().lower()] = v.strip()
        if not f.get("uris"):
            continue
        enabled = f.get("enabled", "yes").lower() != "no"
        for kind in f.get("types", "deb").split():
            for uri in f["uris"].split():
                for suite in f.get("suites", "").split() or [""]:
                    out.append(Repository(kind, uri, suite, f.get("components", "").split(), source_file, enabled))
    return out


def repository_notes(repos: list[Repository], codename: str | None = None) -> list[str]:
    notes = []
    active = [r for r in repos if r.enabled and r.kind == "deb"]
    if not active:
        notes.append("No enabled package repositories were found.")
    plain = [r for r in active if r.insecure_transport]
    if plain:
        notes.append(f"{len(plain)} repository(ies) use plain http (packages are still signature-checked by APT).")
    if codename:
        mismatched = sorted({r.suite for r in active if r.suite and not r.suite.startswith(("/",)) and
                             codename not in r.suite and not r.suite.startswith(("stable", "testing", "unstable"))})
        if mismatched:
            notes.append("Some suites do not mention this release (" + codename + "): " + ", ".join(mismatched[:4]))
    return notes


# ------------------------------------------------------------------ service
class AptService:
    def __init__(self, runner: Runner | None = None, which: Callable[[str], str | None] = shutil.which,
                 root: Path = Path("/")) -> None:
        self._run_cmd = runner or (lambda argv, t: run_command(argv, timeout=t, env={**os.environ, "LC_ALL": "C"}))
        self._which = which
        self._root = root
        self._tx_lock = threading.Lock()

    # ---- availability / locks
    def available(self) -> bool:
        return self._which("apt-get") is not None

    def lock_holders(self) -> list[str]:
        """Package-manager processes currently running. We report them; we never try to override a lock."""
        found = []
        for p in psutil.process_iter(["name", "pid"]):
            try:
                if (p.info["name"] or "").lower() in APT_PROCESSES:
                    found.append(f"{p.info['name']} (pid {p.info['pid']})")
            except (psutil.Error, OSError):
                continue
        return found

    def begin_transaction(self) -> bool:
        """Only one package-manager transaction at a time inside this application."""
        return self._tx_lock.acquire(blocking=False)

    def end_transaction(self) -> None:
        try:
            self._tx_lock.release()
        except RuntimeError:
            pass

    # ---- repositories / refresh time
    def repositories(self) -> list[Repository]:
        out: list[Repository] = []
        etc = self._root / "etc" / "apt"
        d = etc / "sources.list.d"
        files = [etc / "sources.list"] + (sorted(d.glob("*.list")) if d.is_dir() else [])
        for f in files:
            if f.is_file():
                out += parse_sources_list(f.read_text(encoding="utf-8", errors="replace"), str(f))
        if d.is_dir():
            for f in sorted(d.glob("*.sources")):
                out += parse_deb822_sources(f.read_text(encoding="utf-8", errors="replace"), str(f))
        return out

    def last_refresh(self) -> datetime | None:
        stamp = self._root / "var/lib/apt/periodic/update-success-stamp"
        lists = self._root / "var/lib/apt/lists"
        mt = None
        if stamp.is_file():
            mt = stamp.stat().st_mtime
        elif lists.is_dir():
            times = [p.stat().st_mtime for p in lists.iterdir() if p.is_file() and not p.name.startswith("lock")]
            mt = max(times) if times else None
        return datetime.fromtimestamp(mt, timezone.utc) if mt else None

    # ---- queries
    def upgradable(self) -> list[PkgChange]:
        r = self._run_cmd(["apt", "list", "--upgradable"], 60)
        return parse_upgradable(r.stdout) if r.ok else []

    def plan(self, kind: str, packages: list[str] | None = None) -> Transaction:
        """Simulate a transaction (no root, no changes) and return exactly what APT proposes."""
        names = [validate_package_name(p) for p in (packages or [])]
        verbs = {"upgrade": ["upgrade"], "dist-upgrade": ["dist-upgrade"], "install": ["install", "--"],
                 "remove": ["remove", "--"], "autoremove": ["autoremove"], "purge": ["purge", "--"],
                 "reinstall": ["install", "--reinstall", "--"], "download": ["install", "--download-only", "--"],
                 "fix-broken": ["install", "-f"]}
        if kind not in verbs:
            raise ValueError(f"unknown transaction kind: {kind}")
        if kind in ("install", "remove", "purge", "reinstall", "download") and not names:
            raise ValueError("choose at least one package")
        if not self.available():
            return Transaction(kind, ok=False, error="apt-get is not available on this system")
        argv = ["apt-get", "-s", "-o", "Debug::NoLocking=true", *verbs[kind], *names]
        r = self._run_cmd(argv, 120)
        tx = parse_transaction(kind, r.stdout, r.stderr)
        if not r.ok and tx.ok:
            tx.ok, tx.error = False, (r.stderr.strip().splitlines() or [r.error or "apt-get failed"])[-1]
        return tx

    def sources_summary(self) -> dict:
        repos = self.repositories()
        return {"repositories": repos, "active": sum(1 for r in repos if r.enabled and r.kind == "deb"),
                "refreshed": self.last_refresh()}
