"""Shared pieces of the Parrot OS manager: transaction confirmation + application flow."""
from __future__ import annotations

import html

from PySide6.QtWidgets import QWidget

from ...application.app_controller import AppController
from ...services.apt_service import Transaction, risk_flags
from ...services.privileged_service import PrivilegedOp, build_op, run_privileged
from ..design.tokens import T
from .netsec_common import confirm_dialog

esc = html.escape
OP_FOR_KIND = {"upgrade": "apt_upgrade", "dist-upgrade": "apt_dist_upgrade", "install": "apt_install",
               "remove": "apt_remove", "autoremove": "apt_autoremove"}
TITLES = {"upgrade": "Upgrade installed packages", "dist-upgrade": "Full system upgrade", "install": "Install packages",
          "remove": "Remove packages", "autoremove": "Remove unused dependencies", "update": "Update package lists"}


def equivalent_command(kind: str, packages: list[str] | None = None) -> str:
    verbs = {"upgrade": "apt-get upgrade", "dist-upgrade": "apt-get dist-upgrade", "install": "apt-get install",
             "remove": "apt-get remove", "autoremove": "apt-get autoremove", "update": "apt-get update"}
    return "sudo " + verbs[kind] + (" " + " ".join(packages) if packages else "")


def proposal_html(tx: Transaction, limit: int = 14) -> str:
    def rows(changes, label, color):
        if not changes:
            return ""
        lines = "".join(f"<li>{esc(c.name)} <span style='color:{T.text_secondary}'>{esc(c.old)}"
                        f"{' → ' if c.old and c.new else ''}{esc(c.new)}</span></li>" for c in changes[:limit])
        more = f"<li>… and {len(changes) - limit} more</li>" if len(changes) > limit else ""
        return f"<p style='color:{color}'><b>{label} ({len(changes)})</b></p><ul>{lines}{more}</ul>"
    body = (rows(tx.removes, "Remove", T.danger) + rows(tx.installs, "Install (new)", T.info) +
            rows(tx.upgrades, "Upgrade", T.success))
    size = []
    if tx.download:
        size.append(f"download {esc(tx.download)}")
    if tx.disk_change:
        size.append(f"disk space {esc(tx.disk_change)}")
    return body + (f"<p style='color:{T.text_secondary}'>{', '.join(size)}</p>" if size else "")


def apply_transaction(parent: QWidget, app: AppController, tx: Transaction, kind: str, packages: list[str] | None = None,
                      op: PrivilegedOp | None = None, on_output=None, on_done=None) -> str:
    """The confirmed workflow: show the actual proposal, require explicit approval, refuse while another package
    manager is running, execute through the privileged backend and record the outcome. Returns a status message."""
    title = TITLES.get(kind, kind)
    flags = risk_flags(tx)
    names = tx.package_names()
    started = None
    backend = app.privileged
    if not tx.ok:
        return f"Cannot continue: {tx.error}"
    if tx.is_empty and kind != "update":
        return "There is nothing to do: APT proposes no changes."
    cmd = equivalent_command(kind, packages)
    intro = ("<p>This is exactly what APT proposes. Nothing has been changed.</p>" if backend.available() else
             f"<p style='color:{T.warning}'>{esc(backend.explain_unavailable())}</p>")
    warn = "".join(f"<p style='color:{T.danger}'><b>⚠ {esc(f)}</b></p>" for f in flags)
    text = intro + warn + proposal_html(tx) + f"<p style='color:{T.text_secondary}'>Equivalent command: <code>{esc(cmd)}</code></p>"
    ack = "I have read the list above, including the warnings, and approve these exact changes." if backend.available() else None
    approved = confirm_dialog(parent, title, text, "Apply changes" if backend.available() else "Close",
                              require_checkbox=ack, danger=bool(flags))
    op_type = {"dist-upgrade": "upgrade"}.get(kind, kind)
    if not backend.available():
        app.maintenance.record(title, op_type, "not executed", packages=names,
                               errors="privileged helper unavailable; nothing was changed")
        return backend.explain_unavailable()
    if not approved:
        app.maintenance.record(title, op_type, "cancelled", packages=names)
        return "Cancelled. Nothing was changed."
    holders = app.apt.lock_holders()
    if holders:
        app.maintenance.record(title, op_type, "failed", packages=names, errors="package manager busy: " + ", ".join(holders))
        return ("Another package manager is running (" + ", ".join(holders) + "). Wait for it to finish; WIFI Center never "
                "overrides package-manager locks.")
    if not app.apt.begin_transaction():
        return "A package transaction is already in progress in this application."
    app.audit.record("apt.apply", kind=kind, packages=names[:50])
    try:
        op = op or build_op(kind, packages, tx)      # carries the manifest the helper re-checks as root
    except Exception as e:
        app.apt.end_transaction()
        return f"Cannot continue: {e}"
    result: dict[str, str] = {}

    def finish(res) -> None:
        app.apt.end_transaction()
        status = "success" if res.ok else ("failed" if res.executed else "cancelled")
        app.maintenance.record(title, op_type, status, packages=names, errors="" if res.ok else res.message)
        msg = ("Applied: " if res.ok else ("Failed: " if res.executed else "Not applied: ")) + res.message
        result["msg"] = msg
        if on_done:
            on_done(msg)

    run_privileged(backend, op, on_output or (lambda line: None), finish)
    return result.get("msg", "Started: waiting for authorization and the helper…")
