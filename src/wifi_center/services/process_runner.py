"""Safe subprocess wrapper: argument lists only, timeouts, explicit cwd, no shell."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


SBIN_DIRS = ("/usr/local/sbin", "/usr/sbin", "/sbin")      # not on a normal user's PATH: iw, ethtool, rfkill, ... live here


def find_executable(name: str) -> str | None:
    """Like shutil.which, but also looks in the sbin directories that ordinary users do not have on PATH."""
    found = shutil.which(name)
    if found or os.sep in name:
        return found
    for d in SBIN_DIRS:
        cand = shutil.which(f"{d}/{name}")
        if cand:
            return cand
    return None


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int | None  # None => could not run / timed out
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_command(
    args: Sequence[str],
    timeout: float = 15.0,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    if isinstance(args, (str, bytes)) or not args or not all(isinstance(a, str) for a in args):
        raise TypeError("args must be a non-empty sequence of strings")
    if any("\x00" in a for a in args):
        raise ValueError("NUL byte in argument")
    argv = tuple(args)
    exe = argv[0] if os.sep in argv[0] else (find_executable(argv[0]) or argv[0])    # run /usr/sbin tools by full path
    try:
        p = subprocess.run(
            [exe, *argv[1:]],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else str(Path.home()),
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
        return CommandResult(argv, p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return CommandResult(argv, None, out, "", timed_out=True, error=f"timed out after {timeout}s")
    except (OSError, ValueError) as e:
        return CommandResult(argv, None, "", "", error=str(e))
