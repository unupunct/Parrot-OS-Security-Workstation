"""Builds integrations from the catalog; special tools can register their own class."""
from __future__ import annotations

from typing import Any, Mapping

from .base import SystemProbe, ToolIntegration
from .bloodhound import BloodHoundIntegration
from .catalog import PROFILES

SPECIAL: dict[str, type[ToolIntegration]] = {
    "bloodhound-ce": BloodHoundIntegration,
}


def build_integration(profile_id: str, probe: SystemProbe | None = None,
                      config: Mapping[str, Any] | None = None) -> ToolIntegration:
    profile = next(p for p in PROFILES if p.id == profile_id)
    cls = SPECIAL.get(profile.id, ToolIntegration)
    return cls(profile, probe, config)


def build_all(probe: SystemProbe | None = None,
              configs: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, ToolIntegration]:
    probe = probe or SystemProbe()
    configs = configs or {}
    return {p.id: build_integration(p.id, probe, configs.get(p.id)) for p in PROFILES}
