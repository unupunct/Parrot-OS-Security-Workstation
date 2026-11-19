"""Nmap integration: standard interface plus the one parameterised, validated `scan` operation."""
from __future__ import annotations

from typing import Any, Mapping

from .base import LaunchMethod, LaunchRequest, ToolIntegration
from .nmap_args import build_args, validate_args


class NmapIntegration(ToolIntegration):
    SCAN_TIMEOUT = 900.0

    def launch_supported_operation(self, operation: str, options: Mapping[str, Any] | None = None) -> LaunchRequest:
        if operation != "scan":
            return super().launch_supported_operation(operation, options)
        det = self.detect_installation()
        if not det.installed or not det.path:
            raise ValueError("Nmap is not installed (no executable found)")
        opts = dict(options or {})
        try:
            args = build_args(opts["profile"], list(opts["targets"]), str(opts["xml_path"]))
        except KeyError as e:
            raise ValueError(f"missing scan option {e}") from None
        validate_args(args)  # raises PolicyViolation before anything is started
        return LaunchRequest(self.profile.id, "scan", (det.path, *args), LaunchMethod.CLI, self.SCAN_TIMEOUT)
