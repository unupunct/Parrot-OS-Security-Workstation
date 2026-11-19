"""Package queries (installed, available, details, policy). Read-only; installs/removals are proposals first."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..security.input_validation import ValidationError
from .apt_service import AptService
from .privileged_service import validate_package_name

SEARCH_RE = re.compile(r"^[A-Za-z0-9+._:\-]{1,80}$")


@dataclass
class PackageRow:
    name: str
    version: str = ""
    status: str = ""            # installed | config-files | not-installed
    size_kb: int = 0
    summary: str = ""
    upgradable: bool = False


@dataclass
class PackageDetails:
    name: str
    fields: dict[str, str] = field(default_factory=dict)
    installed: str = ""
    candidate: str = ""
    origins: list[str] = field(default_factory=list)       # "priority uri suite/component arch"
    depends: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.installed or self.installed == "(none)":
            return "not installed"
        return "upgradable" if self.candidate and self.candidate != self.installed else "installed"


STATUS = {"ii": "installed", "rc": "config-files", "iU": "unpacked", "iF": "half-configured", "hi": "installed (held)"}


def parse_dpkg_query(text: str) -> list[PackageRow]:
    """Output of: dpkg-query -W -f '${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${Installed-Size}\\t${binary:Summary}\\n'"""
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        abbrev = parts[0].strip()
        try:
            size = int(parts[3])
        except ValueError:
            size = 0
        out.append(PackageRow(parts[1], parts[2], STATUS.get(abbrev, abbrev or "unknown"), size,
                              parts[4] if len(parts) > 4 else ""))
    return out


def parse_apt_cache_search(text: str) -> list[PackageRow]:
    out = []
    for line in text.splitlines():
        if " - " in line:
            name, summary = line.split(" - ", 1)
            out.append(PackageRow(name.strip(), summary=summary.strip(), status="not-installed"))
    return out


def parse_policy(text: str) -> tuple[str, str, list[str]]:
    installed = candidate = ""
    origins: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Installed:"):
            installed = s.split(":", 1)[1].strip()
        elif s.startswith("Candidate:"):
            candidate = s.split(":", 1)[1].strip()
        else:
            m = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+Packages$", s)
            if m:
                origins.append(f"{m.group(2)} {m.group(3)} {m.group(4)} (priority {m.group(1)})")
    return installed, candidate, list(dict.fromkeys(origins))


def parse_show(text: str) -> dict[str, str]:
    """First stanza of `apt-cache show` (deb822 style, continuation lines start with a space)."""
    fields: dict[str, str] = {}
    key = ""
    for line in text.split("\n\n", 1)[0].splitlines():
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line.strip()
        elif ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            fields[key] = val.strip()
    return fields


class PackageService:
    def __init__(self, apt: AptService) -> None:
        self.apt = apt

    def _run(self, argv: list[str], timeout: float = 30):
        return self.apt._run_cmd(argv, timeout)    # same runner as the APT service (injectable in tests)

    @staticmethod
    def validate_query(query: str) -> str:
        q = query.strip()
        if not SEARCH_RE.match(q):
            raise ValidationError("search with letters, digits and + . _ : - only (max 80 characters)")
        return q

    def installed(self, query: str = "", limit: int = 2000) -> list[PackageRow]:
        r = self._run(["dpkg-query", "-W", "-f",
                       "${db:Status-Abbrev}\t${Package}\t${Version}\t${Installed-Size}\t${binary:Summary}\n"], 60)
        rows = parse_dpkg_query(r.stdout) if r.ok else []
        rows = [p for p in rows if p.status.startswith("installed")]
        q = query.strip().lower()
        if q:
            rows = [p for p in rows if q in p.name.lower() or q in p.summary.lower()]
        up = {c.name for c in self.apt.upgradable()} if rows else set()
        for p in rows:
            p.upgradable = p.name in up
        return rows[:limit]

    def search_available(self, query: str, limit: int = 500) -> list[PackageRow]:
        q = self.validate_query(query)
        r = self._run(["apt-cache", "search", "--names-only", "--", re.escape(q)], 30)
        rows = parse_apt_cache_search(r.stdout) if r.ok else []
        installed = {p.name for p in self.installed()}
        for p in rows:
            p.status = "installed" if p.name in installed else "not-installed"
        return rows[:limit]

    def details(self, name: str) -> PackageDetails:
        n = validate_package_name(name)
        d = PackageDetails(n)
        show = self._run(["apt-cache", "show", "--", n], 30)
        if show.ok:
            d.fields = parse_show(show.stdout)
            d.depends = [x.strip() for x in d.fields.get("Depends", "").split(",") if x.strip()]
        pol = self._run(["apt-cache", "policy", "--", n], 30)
        if pol.ok:
            d.installed, d.candidate, d.origins = parse_policy(pol.stdout)
        return d
