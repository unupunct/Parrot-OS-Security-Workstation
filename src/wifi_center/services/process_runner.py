"""Safe subprocess wrapper: argument lists only, timeouts, explicit cwd, no shell."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


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
    try:
        p = subprocess.run(
            list(argv),
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
