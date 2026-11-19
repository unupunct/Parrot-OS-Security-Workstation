"""BloodHound CE status: Docker availability, container health, resource usage and a service check.

Read-only. Nothing is deployed, started, stopped or exposed; the service check only runs when requested and
only against a loopback URL.
"""
from __future__ import annotations

import json
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .kismet_service import validate_loopback_url
from .process_runner import run_command

DEFAULT_URL = "http://127.0.0.1:8080"


@dataclass
class Container:
    name: str
    image: str
    status: str
    ports: str = ""
    cpu: str = ""
    memory: str = ""

    @property
    def healthy(self) -> bool:
        return self.status.lower().startswith("up") and "unhealthy" not in self.status.lower()


@dataclass
class BloodHoundStatus:
    docker_installed: bool = False
    daemon_reachable: bool = False
    compose_available: bool = False
    containers: list[Container] = field(default_factory=list)
    message: str = ""


def parse_docker_ps(text: str) -> list[Container]:
    out = []
    for line in text.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        name, image = d.get("Names", ""), d.get("Image", "")
        if "bloodhound" in name.lower() or "bloodhound" in image.lower() or "specterops" in image.lower():
            out.append(Container(name, image, d.get("Status", ""), d.get("Ports", "")))
    return out


def parse_docker_stats(text: str) -> dict[str, tuple[str, str]]:
    stats = {}
    for line in text.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        stats[d.get("Name", "")] = (d.get("CPUPerc", ""), d.get("MemUsage", ""))
    return stats


class BloodHoundService:
    def status(self) -> BloodHoundStatus:
        st = BloodHoundStatus()
        if not shutil.which("docker"):
            st.message = "Docker is not installed."
            return st
        st.docker_installed = True
        st.compose_available = run_command(["docker", "compose", "version"], timeout=10).ok
        ps = run_command(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=15)
        if not ps.ok:
            st.message = ("The Docker daemon is not reachable (is it running, and are you in the docker group?). "
                          + (ps.stderr.strip().splitlines() or [""])[-1])
            return st
        st.daemon_reachable = True
        st.containers = parse_docker_ps(ps.stdout)
        if st.containers:
            stats = run_command(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=20)
            usage = parse_docker_stats(stats.stdout) if stats.ok else {}
            for c in st.containers:
                c.cpu, c.memory = usage.get(c.name, ("", ""))
        else:
            st.message = "No BloodHound containers found. WIFI Center never deploys it for you."
        return st

    @staticmethod
    def check_service(url: str = DEFAULT_URL, timeout: float = 5.0) -> str:
        """Ask a loopback BloodHound for its version (explicit user action)."""
        base = validate_loopback_url(url)
        req = urllib.request.Request(base + "/api/version", headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            return f"Service answered with HTTP {e.code}"
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            return f"Service not reachable at {base}: {getattr(e, 'reason', e)}"
        except json.JSONDecodeError:
            return "Service answered, but not with JSON"
        version = (data.get("data") or {}).get("server_version") if isinstance(data, dict) else None
        return f"Service reachable at {base}" + (f" (server version {version})" if version else "")
