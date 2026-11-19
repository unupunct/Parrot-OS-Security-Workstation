"""Interface between the unprivileged application and the (Phase 8) privileged helper.

The GUI never runs commands as root. Every privileged action is a typed `PrivilegedOp` with validated arguments;
the backend that executes it (a Polkit-authorised helper, added in Phase 8) is the only code allowed to touch the
system. Until that backend exists, `UnavailableBackend` reports honestly that nothing can be applied.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from ..security.input_validation import ValidationError

KINDS = ("apt_update", "apt_upgrade", "apt_dist_upgrade", "apt_install", "apt_remove", "apt_autoremove",
         "apt_clean", "purge_residual_configs", "remove_system_files")
PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]{1,100}(:[a-z0-9\-]+)?$")


def validate_package_name(name: str) -> str:
    n = name.strip()
    if not PKG_RE.match(n):
        raise ValidationError(f"invalid package name: {name!r}")
    return n


@dataclass(frozen=True)
class PrivilegedOp:
    kind: str
    packages: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValidationError(f"unknown privileged operation: {self.kind}")
        for p in self.packages:
            validate_package_name(p)
        if self.kind in ("apt_install", "apt_remove", "purge_residual_configs") and not self.packages:
            raise ValidationError(f"{self.kind} needs at least one package")
        if self.kind == "remove_system_files" and not self.paths:
            raise ValidationError("remove_system_files needs paths")


@dataclass
class ExecutionResult:
    executed: bool
    ok: bool
    message: str
    output: list[str] = field(default_factory=list)


class PrivilegedBackend(Protocol):
    name: str

    def available(self) -> bool: ...

    def explain_unavailable(self) -> str: ...

    def execute(self, op: PrivilegedOp) -> ExecutionResult: ...


class UnavailableBackend:
    """Placeholder until the Polkit helper (Phase 8) is installed: executes nothing, says why."""

    name = "unavailable"

    def available(self) -> bool:
        return False

    def explain_unavailable(self) -> str:
        return ("Applying system changes needs the privileged helper, which is not installed yet (it arrives with the "
                "Root Access Manager in Phase 8). Nothing was changed. You can review the proposed transaction here "
                "and run the equivalent command yourself in a terminal.")

    def execute(self, op: PrivilegedOp) -> ExecutionResult:
        return ExecutionResult(False, False, self.explain_unavailable())
