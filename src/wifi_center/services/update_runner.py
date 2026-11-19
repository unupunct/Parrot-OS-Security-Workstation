"""Runs user-level software updates (Flatpak, pipx, git checkouts, Snap) and streams the output.

Only fixed command shapes are possible: the argv is built here from an allow-list, never from free text. Nothing runs as root
(Flatpak and Snap ask Polkit themselves when a system-wide change needs it), stdin is closed so nothing can wait for input, and
the environment is minimal. APT goes through the privileged helper (System Updates), AppImages are never run.
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Callable

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,80}$")


class UpdateError(ValueError):
    pass


@dataclass(frozen=True)
class UpdateCommand:
    key: str
    argv: tuple[str, ...]
    title: str
    contacts: str            # what the command talks to, shown before it runs

    @property
    def display(self) -> str:
        return " ".join(self.argv)


def plan_update(key: str, item: str = "", checkouts: dict[str, str] | None = None) -> UpdateCommand:
    """The exact command for updating one source (or one item of it)."""
    if key == "flatpak":
        return UpdateCommand(key, ("flatpak", "update", "--noninteractive", "-y"), "Update Flatpak applications",
                             "your Flatpak remotes (for example flathub.org)")
    if key == "pipx":
        if not item:
            return UpdateCommand(key, ("pipx", "upgrade-all"), "Update all pipx applications", "PyPI (pypi.org)")
        if not NAME_RE.match(item):
            raise UpdateError("invalid application name")
        return UpdateCommand(key, ("pipx", "upgrade", item), f"Update {item} (pipx)", "PyPI (pypi.org)")
    if key == "git":
        paths = {v: k for k, v in (checkouts or {}).items()}
        if item not in paths:
            raise UpdateError("choose one of your configured tool checkouts")
        return UpdateCommand(key, ("git", "-C", item, "pull", "--ff-only"), f"Update {paths[item]} (git pull)",
                             "the checkout's git remote; fast-forward only, so local changes are never overwritten")
    if key == "snap":
        return UpdateCommand(key, ("snap", "refresh"), "Refresh Snap packages", "the Snap Store (snapd asks Polkit if needed)")
    raise UpdateError("this source is not updated from here (APT: use System Updates; AppImages: use their own updater)")


def clean_env() -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LC_ALL": "C.UTF-8", "TERM": "dumb",
           "NO_COLOR": "1", "GIT_TERMINAL_PROMPT": "0", "PIP_NO_INPUT": "1"}
    for k in ("HOME", "USER", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_DATA_DIRS", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
              "PIPX_HOME", "PIPX_BIN_DIR", "WAYLAND_DISPLAY", "DISPLAY"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def run_streaming(cmd: UpdateCommand, on_line: Callable[[str], None], cancel: threading.Event | None = None,
                  timeout: float = 3600.0, spawn=subprocess.Popen) -> tuple[int | None, str]:
    """Run `cmd`, streaming merged stdout/stderr lines. Returns (exit code, 'succeeded'|'failed'|'cancelled'|'timeout'|'missing')."""
    try:
        proc = spawn(list(cmd.argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                     errors="replace", env=clean_env(), bufsize=1)
    except FileNotFoundError:
        on_line(f"{cmd.argv[0]} is not installed.")
        return None, "missing"
    except OSError as e:
        on_line(f"Could not start {cmd.argv[0]}: {e}")
        return None, "failed"
    state = {"why": ""}

    def watchdog() -> None:
        waited = 0.0
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                state["why"] = "cancelled"
                break
            if waited >= timeout:
                state["why"] = "timeout"
                break
            threading.Event().wait(0.25)
            waited += 0.25
        if proc.poll() is None:
            proc.terminate()
            threading.Event().wait(3)
            if proc.poll() is None:
                proc.kill()

    t = threading.Thread(target=watchdog, daemon=True)
    t.start()
    try:
        for line in proc.stdout:                           # type: ignore[union-attr]
            on_line(line.rstrip("\r\n"))
    finally:
        code = proc.wait()
    if state["why"]:
        return code, state["why"]
    return code, "succeeded" if code == 0 else "failed"
