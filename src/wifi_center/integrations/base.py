"""Plugin architecture for external tools.

A tool is described declaratively by a `ToolProfile`. The `ToolIntegration` class implements the
standard interface on top of a profile; tools that need special behaviour (services, containers,
git checkouts) subclass it. Everything that touches the system goes through a `SystemProbe`, so
integrations can be tested without the real tools installed.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from ..services.process_runner import CommandResult, run_command


class LaunchMethod(str, Enum):
    DESKTOP = "desktop"      # GUI application started detached
    CLI = "cli"              # captured, with live output in the operation monitor
    SERVICE = "service"      # managed system service (status only in this application)
    CONTAINER = "container"  # Docker based


class Health(str, Enum):
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    MISSING = "missing"      # tool not installed


@dataclass(frozen=True)
class Dependency:
    kind: str               # executable | package | python_module | docker
    name: str
    purpose: str = ""
    optional: bool = False


@dataclass(frozen=True)
class DependencyStatus:
    dependency: Dependency
    satisfied: bool
    detail: str = ""


@dataclass(frozen=True)
class Operation:
    """A supported, non-attack operation. Only operations listed here can ever be launched."""
    id: str
    title: str
    description: str
    method: LaunchMethod
    args: tuple[str, ...] = ()       # appended after the executable
    timeout: float = 30.0
    dynamic: bool = False            # needs validated parameters; never launched by a bare button/palette entry
    validator: Callable[[tuple[str, ...]], None] | None = None  # raises PolicyViolation for a bad command line


@dataclass(frozen=True)
class ToolProfile:
    id: str
    name: str
    description: str
    category: str
    executables: tuple[str, ...]
    docs_url: str
    source_url: str
    install_hint: str
    apt_packages: tuple[str, ...] = ()
    dependencies: tuple[Dependency, ...] = ()
    capabilities: tuple[str, ...] = ()
    operations: tuple[Operation, ...] = ()
    version_args: tuple[str, ...] | None = None   # executed (read-only) to obtain a version
    version_regex: str | None = None
    entry_files: tuple[str, ...] = ()             # for git checkouts: file proving the install dir is valid
    license: str = ""
    compatibility: str = "Parrot OS / Debian"
    restricted: bool = False                      # primary purpose includes attack operations
    restriction_note: str = ""

    @property
    def launch_methods(self) -> tuple[LaunchMethod, ...]:
        return tuple(dict.fromkeys(op.method for op in self.operations))


@dataclass(frozen=True)
class Detection:
    installed: bool
    path: str | None = None
    via: str = ""          # path | package | config | docker


@dataclass(frozen=True)
class HealthStatus:
    level: Health
    detail: str


@dataclass(frozen=True)
class LaunchRequest:
    tool_id: str
    operation_id: str
    argv: tuple[str, ...]
    method: LaunchMethod
    timeout: float
    cwd: str | None = None


@dataclass
class ParsedResult:
    line_count: int
    summary: str
    data: dict[str, Any] = field(default_factory=dict)


class SystemProbe:
    """All system inspection used by integrations. Replaced by a fake in tests."""

    EXTRA_DIRS = ("/usr/sbin", "/sbin", "/opt/bin", "/usr/local/sbin", "/snap/bin")

    def which(self, name: str) -> str | None:
        found = shutil.which(name)
        if found:
            return found
        for d in self.EXTRA_DIRS:
            p = Path(d) / name
            if p.is_file() and p.stat().st_mode & 0o111:
                return str(p)
        return None

    def dpkg_version(self, package: str) -> str | None:
        if shutil.which("dpkg-query") is None:
            return None
        r = run_command(["dpkg-query", "-W", "-f=${Status}|${Version}", package], timeout=10)
        if r.ok and r.stdout.startswith("install ok installed|"):
            return r.stdout.split("|", 1)[1].strip() or None
        return None

    def python_module(self, module: str) -> bool:
        import importlib.util
        try:
            return importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            return False

    def run(self, argv: list[str], timeout: float = 10.0) -> CommandResult:
        return run_command(argv, timeout=timeout)

    def path_exists(self, path: str) -> bool:
        return Path(path).exists()


_GENERIC_VERSION = re.compile(r"(\d+(?:\.\d+)+[A-Za-z0-9._+~-]*)")


def parse_version(text: str, regex: str | None = None) -> str | None:
    """Extract a version string from command output (first match)."""
    if not text:
        return None
    pattern = re.compile(regex) if regex else _GENERIC_VERSION
    m = pattern.search(text)
    if not m:
        return None
    return (m.group(1) if m.groups() else m.group(0)).strip()


class ToolIntegration:
    """Standard integration interface, implemented generically from the profile."""

    def __init__(self, profile: ToolProfile, probe: SystemProbe | None = None,
                 config: Mapping[str, Any] | None = None) -> None:
        self.profile = profile
        self.probe = probe or SystemProbe()
        self.config: dict[str, Any] = dict(config or {})

    # -- detection --
    def _configured_executable(self) -> str | None:
        override = self.config.get("executable_override")
        if override and self.probe.path_exists(override):
            return override
        return None

    def detect_installation(self) -> Detection:
        exe = self._configured_executable()
        if exe:
            return Detection(True, exe, "config")
        install_path = self.config.get("install_path")
        if install_path and self.profile.entry_files:
            for entry in self.profile.entry_files:
                candidate = str(Path(install_path) / entry)
                if self.probe.path_exists(candidate):
                    return Detection(True, candidate, "config")
        for name in self.profile.executables:
            found = self.probe.which(name)
            if found:
                return Detection(True, found, "path")
        for pkg in self.profile.apt_packages:
            if self.probe.dpkg_version(pkg):
                return Detection(True, None, "package")
        return Detection(False)

    def get_version(self) -> str | None:
        det = self.detect_installation()
        if not det.installed:
            return None
        p = self.profile
        if p.version_args is not None and det.path and det.via in ("path", "config") \
                and not det.path.endswith(".py"):
            r = self.probe.run([det.path, *p.version_args], timeout=10)
            v = parse_version((r.stdout or "") + "\n" + (r.stderr or ""), p.version_regex)
            if v:
                return v
        for pkg in p.apt_packages:
            v = self.probe.dpkg_version(pkg)
            if v:
                return v
        git_dir = self.config.get("install_path")
        if git_dir and self.probe.path_exists(str(Path(git_dir) / ".git")):
            r = self.probe.run(["git", "-C", str(git_dir), "describe", "--tags", "--always"], timeout=10)
            if r.ok and r.stdout.strip():
                return r.stdout.strip()
        return None

    # -- capabilities / dependencies / configuration --
    def get_capabilities(self) -> list[str]:
        caps = list(self.profile.capabilities)
        if self.profile.restricted:
            caps.append("Restricted: detection, version, dependency diagnostics and documentation only")
        return caps

    def check_dependencies(self) -> list[DependencyStatus]:
        return [self._check_dep(d) for d in self.profile.dependencies]

    def _check_dep(self, dep: Dependency) -> DependencyStatus:
        if dep.kind == "executable":
            path = self.probe.which(dep.name)
            return DependencyStatus(dep, bool(path), path or "not found in PATH")
        if dep.kind == "package":
            v = self.probe.dpkg_version(dep.name)
            return DependencyStatus(dep, bool(v), f"version {v}" if v else "package not installed")
        if dep.kind == "python_module":
            ok = self.probe.python_module(dep.name)
            return DependencyStatus(dep, ok, "importable" if ok else "module not available")
        if dep.kind == "docker":
            return self._check_docker(dep)
        return DependencyStatus(dep, False, f"unknown dependency kind {dep.kind}")

    def _check_docker(self, dep: Dependency) -> DependencyStatus:
        if not self.probe.which("docker"):
            return DependencyStatus(dep, False, "docker not installed")
        r = self.probe.run(["docker", "compose", "version"], timeout=10)
        if not r.ok:
            return DependencyStatus(dep, False, "docker installed but the compose plugin is missing")
        return DependencyStatus(dep, True, r.stdout.strip().splitlines()[0] if r.stdout.strip() else "ok")

    def validate_configuration(self) -> list[str]:
        problems = []
        ov = self.config.get("executable_override")
        if ov and not self.probe.path_exists(ov):
            problems.append(f"Configured executable does not exist: {ov}")
        ip = self.config.get("install_path")
        if ip:
            if not self.probe.path_exists(ip):
                problems.append(f"Configured install path does not exist: {ip}")
            elif self.profile.entry_files and not any(
                    self.probe.path_exists(str(Path(ip) / e)) for e in self.profile.entry_files):
                problems.append(f"{ip} does not contain {' or '.join(self.profile.entry_files)}")
        return problems

    def get_health_status(self) -> HealthStatus:
        det = self.detect_installation()
        if not det.installed:
            return HealthStatus(Health.MISSING, "Not installed")
        missing = [s for s in self.check_dependencies() if not s.satisfied and not s.dependency.optional]
        if missing:
            names = ", ".join(s.dependency.name for s in missing)
            return HealthStatus(Health.ERROR, f"Missing required dependencies: {names}")
        problems = self.validate_configuration()
        if problems:
            return HealthStatus(Health.WARNING, "; ".join(problems))
        optional = [s for s in self.check_dependencies() if not s.satisfied]
        if optional:
            return HealthStatus(Health.WARNING, "Optional dependencies missing: "
                                + ", ".join(s.dependency.name for s in optional))
        return HealthStatus(Health.OK, "Installed and healthy")

    # -- operations --
    def launch_supported_operation(self, operation: str, options: Mapping[str, Any] | None = None) -> LaunchRequest:
        """Build a launch request for a *declared* operation. Free-form options are not accepted."""
        if options:
            raise ValueError("this operation accepts no options")
        op = next((o for o in self.profile.operations if o.id == operation), None)
        if op is None:
            raise ValueError(f"{self.profile.name} has no supported operation '{operation}'")
        det = self.detect_installation()
        if not det.installed or not det.path:
            raise ValueError(f"{self.profile.name} is not installed (no executable found)")
        return LaunchRequest(self.profile.id, op.id, (det.path, *op.args), op.method, op.timeout)

    def parse_results(self, result: str) -> ParsedResult:
        lines = [l for l in result.splitlines() if l.strip()]
        return ParsedResult(len(lines), f"{len(lines)} non-empty lines of output")

    def export_results(self, result: str) -> dict[str, Any]:
        parsed = self.parse_results(result)
        return {"tool": self.profile.id, "summary": parsed.summary, "lines": parsed.line_count,
                "output": result}
