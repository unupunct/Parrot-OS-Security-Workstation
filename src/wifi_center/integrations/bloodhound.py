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
        r = self.probe.run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=10)
        if not r.ok:
            return HealthStatus(Health.WARNING, "Docker daemon is not reachable (is it running, and are you in the docker group?)")
        return base
