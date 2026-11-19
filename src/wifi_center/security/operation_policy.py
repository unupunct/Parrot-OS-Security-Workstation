"""Central policy: what the unified launcher may ever run.

Defence in depth. (1) Only operations declared in a tool profile can be built into a launch
request. (2) Restricted tools declare none. (3) This module re-checks every request and refuses
known attack-oriented executables even if a profile were edited by mistake.
"""
from __future__ import annotations

from pathlib import Path

from ..integrations.base import LaunchRequest, ToolProfile


class PolicyViolation(PermissionError):
    pass


# Executables WIFI Center will never start through the launcher.
FORBIDDEN_EXECUTABLES = frozenset({
    "aireplay-ng", "airbase-ng", "airdecap-ng", "aircrack-ng", "wifite", "fern-wifi-cracker",
    "pixiewps", "reaver", "bully", "mdk3", "mdk4", "hashcat", "hydra", "medusa", "sqlmap",
    "msfconsole", "msfvenom", "msfrpcd", "mimikatz", "spooftooph", "bluemaho", "pskracker",
    "wifi_audit.py", "sudo", "su", "pkexec", "sh", "bash", "dash", "zsh",
})


def authorize(profile: ToolProfile, request: LaunchRequest) -> None:
    if request.tool_id != profile.id:
        raise PolicyViolation("request does not belong to this tool profile")
    if profile.restricted:
        raise PolicyViolation(f"{profile.name} is restricted: {profile.restriction_note}")
    op = next((o for o in profile.operations if o.id == request.operation_id), None)
    if op is None:
        raise PolicyViolation(f"operation '{request.operation_id}' is not a supported operation of {profile.name}")
    if not request.argv:
        raise PolicyViolation("empty command")
    exe = Path(request.argv[0]).name.lower()
    if exe in FORBIDDEN_EXECUTABLES:
        raise PolicyViolation(f"executable '{exe}' is not permitted through the launcher")
    if tuple(request.argv[1:]) != tuple(op.args):
        raise PolicyViolation("arguments differ from the declared operation")
    if request.method != op.method:
        raise PolicyViolation("launch method differs from the declared operation")
