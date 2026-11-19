"""Read-only package inspection for the Package Manager: files, dependencies (forward, reverse, tree), changelog, installed-file
verification, broken-package detection, leftover configuration, orphans and the download cache. Nothing here needs root or changes
the system; anything that does goes through the confirmed APT workflow and the privileged helper."""
from __future__ import annotations

import gzip
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..privileged.protocol import validate_package_name
from ..security.input_validation import ValidationError
from .apt_service import AptService, Transaction
from .package_service import PackageRow
from .process_runner import find_executable, run_command

DEP_KINDS = ("PreDepends", "Depends", "Recommends", "Suggests", "Conflicts", "Breaks", "Replaces", "Enhances")
MAX_TEXT = 400_000


@dataclass
class Dependency:
    kind: str
    name: str
    alternative: bool = False       # one of several alternatives ("a | b")
    virtual: bool = False           # a virtual package name (<name>)


@dataclass
class VerifyIssue:
    path: str
    flags: str                      # dpkg's nine-character verification string, or "missing"
    config: bool
    meaning: str


@dataclass
class CacheInfo:
    path: str
    files: int
    total_bytes: int
    largest: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class TreeNode:
    name: str
    kind: str = ""
    installed: bool | None = None
    children: list["TreeNode"] = field(default_factory=list)
    repeated: bool = False          # already shown higher up: not expanded again


# ------------------------------------------------------------------ pure parsers
def parse_files(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.startswith("/") and ln != "/."]


VERIFY_FLAGS = {0: "file size", 1: "mode", 2: "checksum", 3: "device number", 4: "symlink target", 5: "owner", 6: "group",
                7: "modification time", 8: "capabilities"}


def parse_verify(text: str) -> list[VerifyIssue]:
    """`dpkg --verify` lines: `??5?????? c /etc/x` (checksum differs, config file) or `missing c /path`."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^(missing\s{0,5}|[.?a-zA-Z0-9]{9})\s+(c )?(/.*)$", line.rstrip())
        if not m:
            continue
        flags, is_conf, path = m.group(1).strip(), bool(m.group(2)), m.group(3)
        if flags == "missing":
            meaning = "the file is missing"
        else:
            changed = [VERIFY_FLAGS[i] for i, ch in enumerate(flags[:9]) if ch not in (".", "?")]
            meaning = "changed: " + ", ".join(changed) if changed else "could not be fully checked"
        out.append(VerifyIssue(path, flags, is_conf, meaning))
    return out


def parse_depends(text: str) -> list[Dependency]:
    out = []
    for line in text.splitlines()[1:]:
        m = re.match(r"^\s*(\|?)(\w+): (<?)([^\s>]+)(>?)", line)
        if m and m.group(2) in DEP_KINDS:
            out.append(Dependency(m.group(2), m.group(4), bool(m.group(1)), bool(m.group(3))))
    return out


def parse_rdepends(text: str) -> list[str]:
    names, seen_header = [], False
    for line in text.splitlines():
        if line.startswith("Reverse Depends:"):
            seen_header = True
            continue
        if seen_header and line.startswith(" "):
            n = line.strip().lstrip("|").split()[0] if line.strip() else ""
            if n and n not in names:
                names.append(n)
    return names


def parse_audit(text: str) -> list[str]:
    """`dpkg --audit` lists packages in an inconsistent state, one per indented line (name then a description)."""
    return [ln.split()[0] for ln in text.splitlines() if ln.startswith(" ") and ln.strip()]


def parse_removed(text: str) -> list[PackageRow]:
    rows = []
    for line in text.splitlines():
        parts = line.split("|", 4)
        if len(parts) >= 3 and parts[0].strip() == "rc":
            size = int(parts[3]) if len(parts) > 3 and parts[3].strip().isdigit() else 0
            rows.append(PackageRow(parts[1], parts[2], "config-files", size, parts[4].strip() if len(parts) > 4 else ""))
    return rows


def read_doc(path: Path, limit: int = MAX_TEXT) -> str:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as f:                                     # type: ignore[operator]
        data = f.read(limit + 1)
    return data[:limit].decode("utf-8", errors="replace") + ("\n\n[… truncated]" if len(data) > limit else "")


# ------------------------------------------------------------------ service
class PackageTools:
    def __init__(self, apt: AptService, run: Callable | None = None, doc_root: Path = Path("/usr/share/doc"),
                 cache_dir: Path = Path("/var/cache/apt/archives"), which: Callable[[str], str | None] = find_executable) -> None:
        self._apt = apt
        self._run = run or (lambda argv, t: run_command(argv, timeout=t))
        self._doc_root = doc_root
        self._cache = cache_dir
        self._which = which

    def _out(self, argv: list[str], timeout: float = 30) -> tuple[str, bool]:
        if not self._which(argv[0]):
            return "", False
        r = self._run(argv, timeout)
        return (r.stdout or ""), bool(getattr(r, "ok", False))

    @staticmethod
    def _name(name: str) -> str:
        return validate_package_name(name)

    # ---- per package
    def files(self, name: str) -> list[str]:
        out, ok = self._out(["dpkg", "-L", "--", self._name(name)])
        return parse_files(out) if ok else []

    def dependencies(self, name: str) -> list[Dependency]:
        out, _ = self._out(["apt-cache", "depends", "--", self._name(name)])
        return parse_depends(out)

    def reverse_dependencies(self, name: str, installed_only: bool = True) -> list[str]:
        argv = ["apt-cache", "rdepends"] + (["--installed"] if installed_only else []) + ["--", self._name(name)]
        out, _ = self._out(argv)
        return parse_rdepends(out)

    def changelog_local(self, name: str) -> str | None:
        """The changelog shipped with the package (offline). None if the package ships none."""
        name = self._name(name)
        for fn in ("changelog.Debian.gz", "changelog.Debian", "changelog.gz", "changelog", "NEWS.Debian.gz"):
            p = self._doc_root / name / fn
            if p.is_file():
                try:
                    return read_doc(p)
                except OSError:
                    continue
        return None

    def changelog_remote(self, name: str) -> str:
        """`apt-get changelog`: downloads from the repository. Only called when the user asks."""
        out, ok = self._out(["apt-get", "changelog", "--", self._name(name)], 60)
        if not ok or not out.strip():
            raise ValidationError("the repository did not provide a changelog (or the network is unavailable)")
        return out[:MAX_TEXT]

    def verify(self, name: str) -> list[VerifyIssue]:
        """Compare installed files with the package's recorded checksums (`dpkg --verify`). Files only root can read are skipped by dpkg."""
        out, _ = self._out(["dpkg", "--verify", self._name(name)], 120)
        return parse_verify(out)

    def installed_flag(self, name: str) -> bool:
        out, _ = self._out(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}", "--", self._name(name)])
        return out.strip().startswith("ii")

    def dependency_tree(self, name: str, depth: int = 2, max_nodes: int = 120, kinds: tuple[str, ...] = ("PreDepends", "Depends")) -> TreeNode:
        budget = [max_nodes]
        seen: set[str] = set()

        def build(n: str, kind: str, level: int) -> TreeNode:
            node = TreeNode(n, kind, self.installed_flag(n) if budget[0] > 0 else None)
            budget[0] -= 1
            if n in seen:
                node.repeated = True
                return node
            seen.add(n)
            if level >= depth or budget[0] <= 0:
                return node
            for d in self.dependencies(n):
                if d.kind in kinds and not d.virtual and budget[0] > 0:
                    node.children.append(build(d.name, d.kind, level + 1))
            return node
        return build(self._name(name), "", 0)

    # ---- system-wide
    def removed(self) -> list[PackageRow]:
        out, ok = self._out(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}|${Package}|${Version}|${Installed-Size}|${binary:Summary}\\n"], 60)
        return parse_removed(out) if ok else []

    def upgradable(self) -> Transaction:
        return self._apt.plan("upgrade")

    def broken(self) -> tuple[list[str], Transaction | None]:
        """(packages dpkg reports as half-installed/unconfigured, APT's simulated repair or None). Both are read-only."""
        out, _ = self._out(["dpkg", "--audit"])
        audit = parse_audit(out)
        try:
            fix = self._apt.plan("fix-broken")
        except Exception:
            fix = None
        return audit, fix

    def orphans(self) -> Transaction:
        return self._apt.plan("autoremove")

    def cache_info(self) -> CacheInfo:
        files, total, sizes = 0, 0, []
        try:
            with os.scandir(self._cache) as it:
                for e in it:
                    if e.name.endswith(".deb") and e.is_file():
                        s = e.stat().st_size
                        files, total = files + 1, total + s
                        sizes.append((e.name, s))
        except OSError:
            pass
        return CacheInfo(str(self._cache), files, total, sorted(sizes, key=lambda t: -t[1])[:15])
