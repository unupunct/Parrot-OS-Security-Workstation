"""BloodHound CE is an independent Docker based service: detect the CLI or local images only."""
from __future__ import annotations

from .base import Detection, Health, HealthStatus, ToolIntegration


class BloodHoundIntegration(ToolIntegration):
    def detect_installation(self) -> Detection:
        det = super().detect_installation()
        if det.installed:
            return det
        if self.probe.which("docker"):
            r = self.probe.run(["docker", "image", "ls", "--format", "{{.Repository}}"], timeout=10)
            if r.ok and any("bloodhound" in line.lower() for line in r.stdout.splitlines()):
                return Detection(True, None, "docker")
        return Detection(False)

    def get_health_status(self) -> HealthStatus:
        base = super().get_health_status()
        if base.level in (Health.MISSING, Health.ERROR):
            return base
        # plain `docker info`: the --format field names differ between Docker and Podman (podman-docker), the exit status does not
        r = self.probe.run(["docker", "info"], timeout=10)
        if not r.ok:
            return HealthStatus(Health.WARNING, "The container runtime is not reachable (is Docker/Podman available to your user?)")
        ps = self.probe.run(["docker", "ps", "--format", "{{.Names}}"], timeout=10)
        names = [n for n in (ps.stdout.splitlines() if ps.ok else []) if "bloodhound" in n.lower()]
        if names:
            return HealthStatus(Health.OK, f"BloodHound CE is running ({len(names)} container(s)); the web UI is on its configured local address.")
        return HealthStatus(base.level, "Container runtime reachable; no BloodHound container is running. Start it with its compose file.")             if base.level == Health.OK else base
