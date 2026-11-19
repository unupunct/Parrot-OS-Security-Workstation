"""Execution engine of the privileged helper (no D-Bus, no Polkit: pure logic, injectable I/O).

Rules enforced here, independently of whatever the GUI says:
* Only the operations in `protocol.KINDS`, each mapped to fixed command lines with absolute executables and a clean
  environment: nothing the caller sends is ever interpreted by a shell or becomes an option.
* Package transactions are re-simulated as root and compared with the transaction the user approved (the manifest):
  anything extra (a surprise removal, an unexpected new package) makes the helper refuse.
* A running package manager is never overridden; one privileged operation runs at a time.
* File removals are re-validated against strict roots, ages and name patterns, performed without following symlinks.
"""
from __future__ import annotations

import json
import os
import re
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Protocol

from ..services.apt_service import APT_PROCESSES, Transaction, parse_transaction
from .protocol import (APT_TRANSACTION_KINDS, REMOVAL_RULES, ExecResult, Manifest, PrivilegedOp, ProtocolError,
                       normalise_removal_path)

Emit = Callable[[str, str], None]          # (stream, line)
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
APT_GET = ("/usr/bin/apt-get",)
EXE_CANDIDATES = {
    "apt-get": ("/usr/bin/apt-get",), "journalctl": ("/usr/bin/journalctl", "/bin/journalctl"),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"), "ip": ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"),
    "iw": ("/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw"), "nmcli": ("/usr/bin/nmcli",),
    "dpkg-query": ("/usr/bin/dpkg-query",), "dpkg": ("/usr/bin/dpkg",),
}
TIMEOUTS = {"apt": 7200.0, "diag": 60.0, "files": 600.0, "iface": 60.0}
STATE_DIR = "/run/wifi-center"
DPKG_STATE_FORMAT = "${db:Status-Abbrev}" + chr(9) + "${Package}" + chr(10)


def clean_env() -> dict[str, str]:
    return {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive",
            "APT_LISTCHANGES_FRONTEND": "none", "NEEDRESTART_SUSPEND": "1", "HOME": "/root"}


def find_exe(name: str, exists: Callable[[str], bool] = os.path.exists) -> str | None:
    return next((p for p in EXE_CANDIDATES[name] if exists(p)), None)


# ---------------------------------------------------------------------------------------------- processes
class Proc(Protocol):
    def lines(self) -> Iterator[str]: ...
    def wait(self, timeout: float | None = None) -> int: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...


class Spawner(Protocol):
    def spawn(self, argv: list[str], env: dict[str, str]) -> Proc: ...


class PopenSpawner:
    """Real process creation: new session (so the whole group can be killed), stdin closed, stderr merged."""

    def spawn(self, argv: list[str], env: dict[str, str]) -> Proc:
        import signal
        import subprocess
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                             text=True, errors="replace", shell=False, cwd="/",
                             **({"start_new_session": True} if os.name == "posix" else {}))

        class _P:
            def lines(self_inner):
                assert p.stdout is not None
                for line in p.stdout:
                    yield line.rstrip("\n")

            def wait(self_inner, timeout=None):
                return p.wait(timeout)

            def terminate(self_inner):
                try:
                    os.killpg(p.pid, signal.SIGTERM) if os.name == "posix" else p.terminate()
                except (ProcessLookupError, OSError):
                    pass

            def kill(self_inner):
                try:
                    os.killpg(p.pid, signal.SIGKILL) if os.name == "posix" else p.kill()
                except (ProcessLookupError, OSError):
                    pass
        return _P()


def stream_command(spawner: Spawner, argv: list[str], emit: Emit, timeout: float, cancel: threading.Event,
                   env: dict[str, str] | None = None, ok_codes: tuple[int, ...] = (0,)) -> tuple[int | None, str]:
    """Run one command, streaming its output. Returns (exit code, status)."""
    emit("info", "$ " + " ".join(argv))
    proc = spawner.spawn(argv, env or clean_env())
    state = {"why": ""}
    done = threading.Event()

    def watchdog() -> None:
        started = time.monotonic()
        while not done.wait(0.25):
            if cancel.is_set():
                state["why"] = "cancelled"
            elif time.monotonic() - started > timeout:
                state["why"] = "timeout"
            if state["why"]:
                proc.terminate()
                if not done.wait(5.0):
                    proc.kill()
                return

    t = threading.Thread(target=watchdog, daemon=True)
    t.start()
    try:
        for line in proc.lines():
            emit("stdout", line)
        code = proc.wait()
    finally:
        done.set()
        t.join(timeout=1.0)
    if state["why"]:
        return code, state["why"]
    return code, "succeeded" if code in ok_codes else "failed"


# ---------------------------------------------------------------------------------------------- planning
@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    timeout: float
    ok_codes: tuple[int, ...] = (0,)


APT_FLAGS = ("-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold")


def apt_simulation_args(op: PrivilegedOp) -> tuple[str, list[str]] | None:
    """(verb, args) of the matching `apt-get -s` simulation for transaction-type operations."""
    return {"apt_upgrade": ("upgrade", []), "apt_dist_upgrade": ("dist-upgrade", []),
            "apt_install": ("install", ["--", *op.packages]), "apt_remove": ("remove", ["--", *op.packages]),
            "apt_autoremove": ("autoremove", []), "purge_residual_configs": ("purge", ["--", *op.packages]),
            "apt_reinstall": ("install", ["--reinstall", "--", *op.packages]),
            "apt_download": ("install", ["--download-only", "--", *op.packages]),
            "apt_fix_broken": ("install", ["-f"])}.get(op.kind)


def plan_commands(op: PrivilegedOp, exists: Callable[[str], bool] = os.path.exists) -> list[Command]:
    """The exact command lines for an operation (apt, diagnostics). File and interface operations are separate."""
    apt = find_exe("apt-get", exists) or "/usr/bin/apt-get"
    if op.kind == "apt_update":
        return [Command((apt, "update"), TIMEOUTS["apt"])]
    if op.kind == "apt_clean":
        return [Command((apt, "clean"), TIMEOUTS["apt"])]
    sim = apt_simulation_args(op)
    if sim:
        verb, args = sim
        return [Command((apt, *APT_FLAGS, verb, *args), TIMEOUTS["apt"])]
    if op.kind == "dpkg_configure":      # finish an interrupted installation: configure packages that were unpacked but not set up
        dp = find_exe("dpkg", exists) or "/usr/bin/dpkg"
        return [Command((dp, "--configure", "-a", "--force-confold"), TIMEOUTS["apt"])]
    if op.kind == "diag_journal":
        jc = find_exe("journalctl", exists)
        if not jc:
            raise ProtocolError("journalctl is not available")
        return [Command((jc, "-p", "warning", "-b", "--no-pager", "-n", "300"), TIMEOUTS["diag"])]
    if op.kind == "diag_unit_status":
        sc = find_exe("systemctl", exists)
        if not sc:
            raise ProtocolError("systemctl is not available")
        return [Command((sc, "status", "--no-pager", "-l", op.unit), TIMEOUTS["diag"], (0, 1, 2, 3, 4))]
    raise ProtocolError(f"no command plan for {op.kind}")


# ---------------------------------------------------------------------------------------------- manifest
def check_manifest(op: PrivilegedOp, actual: Transaction) -> list[str]:
    """Reasons to refuse: anything in the real transaction that the user did not approve."""
    if op.manifest is None:
        return ["the request carries no approved transaction (manifest)"]
    problems = []
    approved = {"remove": set(op.manifest.removes), "install": set(op.manifest.installs),
                "upgrade": set(op.manifest.upgrades)}
    for label, changes in (("removal", actual.removes), ("new package", actual.installs), ("upgrade", actual.upgrades)):
        key = {"removal": "remove", "new package": "install", "upgrade": "upgrade"}[label]
        extra = sorted({c.name for c in changes} - approved[key])
        if extra:
            problems.append(f"unapproved {label}: " + ", ".join(extra[:10]) + (" …" if len(extra) > 10 else ""))
    return problems


def apt_busy(proc_root: str = "/proc") -> list[str]:
    found = []
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return found
    for pid in entries:
        if pid.isdigit():
            try:
                name = Path(proc_root, pid, "comm").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if name.lower() in APT_PROCESSES:
                found.append(f"{name} (pid {pid})")
    return found


# ---------------------------------------------------------------------------------------------- safe file removal
class PosixSafeFs:
    """Removal without following symlinks at any level (openat chain with O_NOFOLLOW). POSIX only."""

    def remove(self, root: str, rel_parts: list[str], min_age_days: int, now: float) -> tuple[bool, str]:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            return False, "unsupported platform"
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        try:
            fd = os.open(root, flags)
            for part in rel_parts[:-1]:
                nfd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = nfd
            name = rel_parts[-1]
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                return False, "not a regular file"
            if st.st_nlink != 1:
                return False, "has several hard links"
            if now - st.st_mtime < min_age_days * 86400:
                return False, "modified too recently"
            os.unlink(name, dir_fd=fd)
            return True, "removed"
        except FileNotFoundError:
            return False, "already gone"
        except OSError as e:
            return False, f"skipped ({e.strerror or e})"
        finally:
            if fd >= 0:
                os.close(fd)


class SafeFs(Protocol):
    def remove(self, root: str, rel_parts: list[str], min_age_days: int, now: float) -> tuple[bool, str]: ...


def remove_files(op: PrivilegedOp, emit: Emit, fs: SafeFs, now: float, cancel: threading.Event) -> ExecResult:
    rule = REMOVAL_RULES[op.category]
    removed = skipped = 0
    for raw in op.paths:
        if cancel.is_set():
            return ExecResult(False, "cancelled", f"cancelled after removing {removed} file(s)")
        try:
            norm = normalise_removal_path(raw, op.category)
        except ProtocolError as e:
            skipped += 1
            emit("stderr", f"refused: {e}")
            continue
        parts = norm[len(rule.root) + 1:].split("/")
        ok, why = fs.remove(rule.root, parts, rule.min_age_days, now)
        removed += ok
        skipped += not ok
        if not ok and why != "already gone":
            emit("stderr", f"{norm}: {why}")
    emit("info", f"removed {removed} file(s), skipped {skipped}")
    return ExecResult(True, "succeeded", f"Removed {removed} file(s); {skipped} skipped by the safety checks.")


# ---------------------------------------------------------------------------------------------- interfaces
def parse_iw_type(text: str) -> str:
    m = re.search(r"^\s*type\s+(\w+)", text, re.M)
    return m.group(1) if m else ""


def parse_link_up(text: str) -> bool:
    m = re.search(r"<([^>]*)>", text)
    return bool(m and "UP" in m.group(1).split(","))


def parse_nm_managed(text: str, iface: str) -> bool | None:
    """`nmcli -t -f DEVICE,STATE device status` -> managed? (None when the device is not listed)."""
    for line in text.splitlines():
        dev, _, state = line.partition(":")
        if dev == iface:
            return state.strip() != "unmanaged"
    return None


class InterfaceManager:
    """Monitor mode with a persistent saved state, so the previous mode can always be restored."""

    def __init__(self, spawner: Spawner, state_dir: str = STATE_DIR, exists: Callable[[str], bool] = os.path.exists) -> None:
        self._sp, self._dir, self._exists = spawner, state_dir, exists

    def _run(self, argv: list[str], emit: Emit, cancel: threading.Event, ok=(0,)) -> tuple[int | None, list[str]]:
        lines: list[str] = []
        code, status = stream_command(self._sp, argv, lambda s, l: (lines.append(l), emit(s, l)), TIMEOUTS["iface"], cancel,
                                      ok_codes=ok)
        return (code if status != "failed" or code is not None else None), lines

    def _capture(self, argv: list[str]) -> str:
        out: list[str] = []
        stream_command(self._sp, argv, lambda s, l: out.append(l) if s == "stdout" else None, 15.0, threading.Event(),
                       ok_codes=(0, 1))
        return "\n".join(out)

    def _state_path(self, iface: str) -> str:
        return os.path.join(self._dir, f"iface-{iface}.json")

    def saved(self, iface: str) -> dict | None:
        try:
            return json.loads(Path(self._state_path(iface)).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _exe(self, name: str) -> str:
        p = find_exe(name, self._exists)
        if not p:
            raise ProtocolError(f"{name} is not installed")
        return p

    def _check_wireless(self, iface: str) -> None:
        if not (self._exists(f"/sys/class/net/{iface}/wireless") or self._exists(f"/sys/class/net/{iface}/phy80211")):
            raise ProtocolError(f"{iface} is not a wireless interface")

    def monitor(self, iface: str, emit: Emit, cancel: threading.Event) -> ExecResult:
        self._check_wireless(iface)
        ip, iw = self._exe("ip"), self._exe("iw")
        nmcli = find_exe("nmcli", self._exists)
        if self.saved(iface):
            return ExecResult(False, "refused", f"{iface} is already switched by WIFI Center; restore it first.")
        mode = parse_iw_type(self._capture([iw, "dev", iface, "info"])) or "managed"
        up = parse_link_up(self._capture([ip, "link", "show", iface]))
        managed = parse_nm_managed(self._capture([nmcli, "-t", "-f", "DEVICE,STATE", "device", "status"]), iface) if nmcli else None
        state = {"mode": mode, "up": up, "nm_managed": managed}
        os.makedirs(self._dir, mode=0o700, exist_ok=True)
        Path(self._state_path(iface)).write_text(json.dumps(state), encoding="utf-8")
        emit("info", f"saved previous state: {state}")
        steps = ([[nmcli, "device", "set", iface, "managed", "no"]] if nmcli and managed else []) + [
            [ip, "link", "set", iface, "down"], [iw, "dev", iface, "set", "type", "monitor"], [ip, "link", "set", iface, "up"]]
        for argv in steps:
            code, _ = self._run(argv, emit, cancel)
            if code != 0 or cancel.is_set():
                emit("stderr", "a step failed or was cancelled: rolling back to the saved state")
                self.restore(iface, emit, threading.Event())
                return ExecResult(False, "cancelled" if cancel.is_set() else "failed",
                                  "Could not switch to monitor mode; the previous state was restored.")
        return ExecResult(True, "succeeded", f"{iface} is now in monitor mode (previous mode: {mode}). Restore it when you are done.")

    def restore(self, iface: str, emit: Emit, cancel: threading.Event) -> ExecResult:
        self._check_wireless(iface)
        ip, iw = self._exe("ip"), self._exe("iw")
        nmcli = find_exe("nmcli", self._exists)
        state = self.saved(iface)
        if not state:
            return ExecResult(False, "refused", f"No saved state for {iface}: nothing to restore.")
        mode = state.get("mode") if state.get("mode") in ("managed", "ap", "station", "monitor", "ibss") else "managed"
        steps = [[ip, "link", "set", iface, "down"], [iw, "dev", iface, "set", "type", "managed" if mode in ("managed", "station") else mode]]
        if state.get("up"):
            steps.append([ip, "link", "set", iface, "up"])
        if nmcli and state.get("nm_managed"):
            steps.append([nmcli, "device", "set", iface, "managed", "yes"])
        failed = False
        for argv in steps:
            code, _ = self._run(argv, emit, threading.Event())
            failed = failed or code != 0
        if not failed:
            try:
                os.remove(self._state_path(iface))
            except OSError:
                pass
        return ExecResult(not failed, "succeeded" if not failed else "failed",
                          f"{iface} restored to {mode}." if not failed else "Some restore steps failed; the saved state was kept so you can retry.")


# ---------------------------------------------------------------------------------------------- the engine
class HelperCore:
    def __init__(self, spawner: Spawner | None = None, fs: SafeFs | None = None, now: Callable[[], float] = time.time,
                 exists: Callable[[str], bool] = os.path.exists, proc_root: str = "/proc", state_dir: str = STATE_DIR) -> None:
        self.spawner = spawner or PopenSpawner()
        self.fs = fs or PosixSafeFs()
        self.now, self.exists, self.proc_root = now, exists, proc_root
        self.interfaces = InterfaceManager(self.spawner, state_dir, exists)
        self._lock = threading.Lock()
        self.current: str | None = None

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    def execute(self, op: PrivilegedOp, emit: Emit, cancel: threading.Event) -> ExecResult:
        if not self._lock.acquire(blocking=False):
            return ExecResult(False, "refused", "Another privileged operation is already running.")
        self.current = op.summary()
        try:
            return self._run(op, emit, cancel)
        except ProtocolError as e:
            return ExecResult(False, "refused", str(e))
        finally:
            self.current = None
            self._lock.release()

    def _run(self, op: PrivilegedOp, emit: Emit, cancel: threading.Event) -> ExecResult:
        if op.kind == "remove_system_files":
            return remove_files(op, emit, self.fs, self.now(), cancel)
        if op.kind == "iface_monitor":
            return self.interfaces.monitor(op.iface, emit, cancel)
        if op.kind == "iface_restore":
            return self.interfaces.restore(op.iface, emit, cancel)
        if op.kind.startswith("apt_") or op.kind in ("purge_residual_configs", "dpkg_configure"):
            holders = apt_busy(self.proc_root)
            if holders:
                return ExecResult(False, "refused", "A package manager is running (" + ", ".join(holders) + "). "
                                  "The helper never overrides package-manager locks.")
            if op.kind in APT_TRANSACTION_KINDS:
                verdict = self._verify_transaction(op, emit, cancel)
                if verdict:
                    return verdict
        status, code, msg = "succeeded", 0, ""
        for cmd in plan_commands(op, self.exists):
            code, status = stream_command(self.spawner, list(cmd.argv), emit, cmd.timeout, cancel, ok_codes=cmd.ok_codes)
            if status != "succeeded":
                break
        ok = status == "succeeded"
        return ExecResult(ok, status, {"succeeded": "Completed.", "failed": f"The command failed (exit code {code}).",
                                       "cancelled": "Cancelled.", "timeout": "Timed out and was stopped."}[status], code)

    def _verify_transaction(self, op: PrivilegedOp, emit: Emit, cancel: threading.Event) -> ExecResult | None:
        verb, args = apt_simulation_args(op)  # type: ignore[misc]
        apt = find_exe("apt-get", self.exists) or "/usr/bin/apt-get"
        lines: list[str] = []
        code, status = stream_command(self.spawner, [apt, "-s", "-o", "Debug::NoLocking=true", verb, *args],
                                      lambda s, l: lines.append(l) if s == "stdout" else None, 300.0, cancel)
        if status != "succeeded":
            return ExecResult(False, "refused", "Could not re-check the transaction before applying it; nothing was changed.")
        actual = parse_transaction(verb, "\n".join(lines))
        problems = check_manifest(op, actual)
        if not actual.ok:
            problems.append(actual.error)
        if problems:
            emit("stderr", "refusing: " + "; ".join(problems))
            return ExecResult(False, "refused", "The transaction no longer matches what you approved ("
                              + "; ".join(problems) + "). Nothing was changed.")
        if op.kind == "purge_residual_configs":
            why = self._check_residual(op, cancel)
            if why:
                emit("stderr", "refusing: " + why)
                return ExecResult(False, "refused", why + " Nothing was changed.")
        emit("info", "transaction matches the approved manifest")
        return None

    def _check_residual(self, op: PrivilegedOp, cancel: threading.Event) -> str | None:
        """A config purge may only touch packages that are already removed (dpkg state 'rc'): never installed software."""
        exe = find_exe("dpkg-query", self.exists) or "/usr/bin/dpkg-query"
        lines: list[str] = []
        code, status = stream_command(self.spawner, [exe, "-W", "-f=" + DPKG_STATE_FORMAT, "--", *op.packages],
                                      lambda s, l: lines.append(l) if s == "stdout" else None, 60.0, cancel)
        if status != "succeeded":
            return "Could not verify the package states."
        state: dict[str, str] = {}
        for line in lines:
            abbrev, _, name = line.partition(chr(9))
            state[name.strip().split(":")[0]] = abbrev.strip()
        bad = [p.split(":")[0] for p in op.packages if not state.get(p.split(":")[0], "").startswith("rc")]
        if bad:
            return "Not leftover configuration (still installed or unknown): " + ", ".join(bad[:10]) + "."
        return None
