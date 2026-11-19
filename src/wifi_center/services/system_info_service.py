"""Detailed system information for the Parrot OS manager (read-only, no privileges)."""
from __future__ import annotations

import os
import platform
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import psutil

from .apt_service import AptService, Repository, repository_notes
from .process_runner import CommandResult, run_command
from .system_service import OsInfo, SystemService, parse_os_release

Runner = Callable[[list[str], float], CommandResult]


@dataclass
class DiskUsage:
    mount: str
    device: str
    fstype: str
    total: int
    used: int
    percent: float


@dataclass
class ServiceUnit:
    name: str
    active: str
    sub: str
    description: str


@dataclass
class SystemReport:
    os_pretty: str = ""
    codename: str = ""
    is_parrot: bool = False
    kernel: str = ""
    hostname: str = ""
    arch: str = ""
    cpu_model: str = ""
    cpu_physical: int = 0
    cpu_logical: int = 0
    mem_total: int = 0
    mem_used: int = 0
    swap_total: int = 0
    swap_used: int = 0
    disks: list[DiskUsage] = field(default_factory=list)
    interfaces: list[tuple[str, bool, tuple[str, ...]]] = field(default_factory=list)
    running: list[ServiceUnit] = field(default_factory=list)
    failed: list[ServiceUnit] = field(default_factory=list)
    services_note: str = ""
    boot_time: datetime | None = None
    uptime_seconds: float = 0.0
    boot_analysis: str = ""
    desktop: str = ""
    repositories: list[Repository] = field(default_factory=list)
    repo_notes: list[str] = field(default_factory=list)


def parse_cpuinfo(text: str) -> str:
    for line in text.splitlines():
        if line.lower().startswith(("model name", "hardware", "cpu model")) and ":" in line:
            return line.split(":", 1)[1].strip()
    return ""


def parse_systemctl_units(text: str) -> list[ServiceUnit]:
    """`systemctl list-units --type=service --no-legend --plain`: UNIT LOAD ACTIVE SUB DESCRIPTION..."""
    out = []
    for line in text.splitlines():
        line = line.lstrip("●* \t")
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            out.append(ServiceUnit(parts[0], parts[2], parts[3], parts[4] if len(parts) > 4 else ""))
    return out


def detect_desktop(env: dict[str, str]) -> str:
    de = env.get("XDG_CURRENT_DESKTOP") or env.get("DESKTOP_SESSION") or ""
    session = env.get("XDG_SESSION_TYPE", "")
    return f"{de} ({session})" if de and session else de or session or "unknown (no desktop session variables)"


class SystemInfoService:
    def __init__(self, system: SystemService, apt: AptService, runner: Runner | None = None,
                 os_release: Path = Path("/etc/os-release"), cpuinfo: Path = Path("/proc/cpuinfo"),
                 env: dict[str, str] | None = None) -> None:
        self._sys, self._apt = system, apt
        self._run = runner or (lambda argv, t: run_command(argv, timeout=t))
        self._os_release, self._cpuinfo = os_release, cpuinfo
        self._env = env if env is not None else dict(os.environ)

    def collect(self) -> SystemReport:
        r = SystemReport()
        info: OsInfo = self._sys.os_info()
        r.os_pretty, r.kernel, r.hostname, r.is_parrot = info.pretty_name, info.kernel, info.hostname, info.is_parrot
        try:
            r.codename = parse_os_release(self._os_release.read_text(encoding="utf-8")).get("VERSION_CODENAME", "")
        except OSError:
            pass
        r.arch = platform.machine()
        try:
            r.cpu_model = parse_cpuinfo(self._cpuinfo.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
        r.cpu_model = r.cpu_model or platform.processor() or "unknown"
        r.cpu_physical, r.cpu_logical = psutil.cpu_count(logical=False) or 0, psutil.cpu_count() or 0
        vm, sw = psutil.virtual_memory(), psutil.swap_memory()
        r.mem_total, r.mem_used, r.swap_total, r.swap_used = vm.total, vm.used, sw.total, sw.used
        for part in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            r.disks.append(DiskUsage(part.mountpoint, part.device, part.fstype, u.total, u.used, u.percent))
        r.interfaces = [(i.name, i.is_up, i.addresses) for i in self._sys.interfaces()]
        if shutil.which("systemctl"):
            run = self._run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain",
                             "--no-pager"], 15)
            fail = self._run(["systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--plain",
                              "--no-pager"], 15)
            r.running, r.failed = parse_systemctl_units(run.stdout), parse_systemctl_units(fail.stdout)
            if not run.ok:
                r.services_note = "systemctl could not list services (is systemd running?)"
        else:
            r.services_note = "systemctl is not available on this system"
        r.boot_time = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
        r.uptime_seconds = self._sys.uptime_seconds()
        if shutil.which("systemd-analyze"):
            res = self._run(["systemd-analyze", "time"], 15)
            r.boot_analysis = res.stdout.strip() if res.ok else ""
        r.desktop = detect_desktop(self._env)
        r.repositories = self._apt.repositories()
        r.repo_notes = repository_notes(r.repositories, r.codename or None)
        return r
