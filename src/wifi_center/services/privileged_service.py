"""Interface between the unprivileged application and the privileged helper.

The GUI never runs commands as root. Every privileged action is a typed `PrivilegedOp` (see `privileged.protocol`)
that the Polkit-authorised helper re-validates and executes; `HelperBackend` talks to it over D-Bus. Where no helper is
installed, `UnavailableBackend` reports honestly that nothing can be applied.

Backends are asynchronous: `start(op, on_output, on_done)` returns immediately and reports through the callbacks (for
`HelperBackend` on the GUI thread). Simple synchronous backends (the placeholder and test doubles) may implement
`execute(op)` instead; `run_privileged` adapts both.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from ..privileged.protocol import (KINDS, Manifest, PrivilegedOp, ProtocolError, action_for,  # noqa: F401  (re-exports)
                                   validate_package_name)

OutputCb = Callable[[str], None]


@dataclass
class ExecutionResult:
    executed: bool
    ok: bool
    message: str
    output: list[str] = field(default_factory=list)


DoneCb = Callable[[ExecutionResult], None]


class PrivilegedBackend(Protocol):
    name: str

    def available(self) -> bool: ...

    def explain_unavailable(self) -> str: ...


class UnavailableBackend:
    """Used until the helper is installed: executes nothing, says why."""

    name = "unavailable"

    def available(self) -> bool:
        return False

    def explain_unavailable(self) -> str:
        return ("Applying system changes needs the privileged helper, which is not installed (see "
                "privileged-helper/README.md; the Root Access Manager shows its status). Nothing was changed. You can "
                "review the proposed transaction here and run the equivalent command yourself in a terminal.")

    def execute(self, op: PrivilegedOp) -> ExecutionResult:
        return ExecutionResult(False, False, self.explain_unavailable())


def run_privileged(backend, op: PrivilegedOp, on_output: OutputCb, on_done: DoneCb) -> None:
    """Start `op` on any backend. For synchronous backends `on_done` is called before this returns."""
    if hasattr(backend, "start"):
        backend.start(op, on_output, on_done)
        return
    res = backend.execute(op)
    for line in res.output:
        on_output(line)
    on_done(res)


def build_op(kind: str, packages: list[str] | None = None, tx=None) -> PrivilegedOp:
    """Operation for an APT transaction kind, carrying the manifest of what the user approved."""
    mapping = {"update": "apt_update", "upgrade": "apt_upgrade", "dist-upgrade": "apt_dist_upgrade",
               "install": "apt_install", "remove": "apt_remove", "autoremove": "apt_autoremove",
               "purge": "purge_residual_configs", "clean": "apt_clean", "reinstall": "apt_reinstall", "download": "apt_download",
               "fix-broken": "apt_fix_broken", "configure": "dpkg_configure"}
    manifest = None
    if tx is not None:
        manifest = Manifest(tuple(c.name for c in tx.installs), tuple(c.name for c in tx.upgrades),
                            tuple(c.name for c in tx.removes))
    return PrivilegedOp(mapping[kind], tuple(packages or ()), manifest=manifest)
