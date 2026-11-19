"""Runs approved operations, streams their output, supports cancellation and records everything.

Every start passes through `operation_policy.authorize`; every transition is audit-logged.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, QTimer, Signal

from ..database.repository import Database
from ..integrations.base import LaunchMethod, LaunchRequest, ToolProfile
from ..security.audit_log import AuditLog
from ..security.operation_policy import PolicyViolation, authorize

log = logging.getLogger(__name__)
MAX_LINES = 20000


@dataclass
class OperationState:
    id: int
    name: str
    tool_id: str | None
    argv: tuple[str, ...]
    started_monotonic: float
    started_at: str
    status: str = "running"        # running | succeeded | failed | cancelled | timeout | launched | interrupted
    exit_code: int | None = None
    finished_at: str | None = None
    lines: list[tuple[str, str]] = field(default_factory=list)  # (stream, text)
    runtime: float = 0.0

    @property
    def active(self) -> bool:
        return self.status == "running"


class OperationManager(QObject):
    started = Signal(int)
    output = Signal(int, str, str)       # op id, stream (stdout|stderr|info), line
    finished = Signal(int, str)          # op id, final status
    changed = Signal()

    def __init__(self, db: Database, audit: AuditLog, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._db = db
        self._audit = audit
        self._ops: dict[int, OperationState] = {}
        self._procs: dict[int, QProcess] = {}
        self._timers: dict[int, QTimer] = {}
        self._partial: dict[tuple[int, str], str] = {}
        self._pending_flags: dict[int, str] = {}
        self._log_buffer: list[tuple[int, str, str]] = []
        self._flush = QTimer(self)
        self._flush.setInterval(500)
        self._flush.timeout.connect(self._flush_logs)
        self._flush.start()
        # An earlier crash can leave rows marked running.
        self._db.execute("UPDATE operations SET status='interrupted', finished_at=datetime('now') "
                         "WHERE status='running'")

    # ---- queries ----
    def get(self, op_id: int) -> OperationState | None:
        return self._ops.get(op_id)

    def operations(self) -> list[OperationState]:
        for op in self._ops.values():
            if op.active:
                op.runtime = time.monotonic() - op.started_monotonic
        return sorted(self._ops.values(), key=lambda o: o.id, reverse=True)

    def active_operations(self) -> list[OperationState]:
        return [o for o in self.operations() if o.active]

    # ---- start ----
    def start(self, profile: ToolProfile, request: LaunchRequest, title: str | None = None) -> int:
        try:
            authorize(profile, request)
        except PolicyViolation as e:
            self._audit.record("policy.denied", tool=request.tool_id, operation=request.operation_id, reason=str(e))
            raise
        name = title or f"{profile.name}: {request.operation_id}"
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        op_id = self._db.execute(
            "INSERT INTO operations(name, tool_id, op_type, status, privileged, started_at) VALUES (?,?,?,?,0,?)",
            (name, request.tool_id, request.method.value, "running", now))
        op = OperationState(op_id, name, request.tool_id, request.argv, time.monotonic(), now)
        self._ops[op_id] = op
        self._audit.record("operation.start", id=op_id, tool=request.tool_id, operation=request.operation_id,
                           argv=list(request.argv), method=request.method.value)
        self.started.emit(op_id)
        self._emit(op_id, "info", "$ " + " ".join(request.argv))

        if request.method == LaunchMethod.DESKTOP:
            ok, _pid = QProcess.startDetached(request.argv[0], list(request.argv[1:]), str(Path.home()))
            if ok:
                self._finish(op_id, "launched", None)
            else:
                self._emit(op_id, "stderr", "failed to start application")
                self._finish(op_id, "failed", None)
            return op_id

        proc = QProcess(self)
        proc.setProgram(request.argv[0])
        proc.setArguments(list(request.argv[1:]))
        proc.setWorkingDirectory(request.cwd or str(Path.home()))
        env = QProcessEnvironment.systemEnvironment()
        env.insert("LC_ALL", "C")
        proc.setProcessEnvironment(env)
        proc.readyReadStandardOutput.connect(lambda: self._read(op_id, proc, "stdout"))
        proc.readyReadStandardError.connect(lambda: self._read(op_id, proc, "stderr"))
        proc.finished.connect(lambda code, st: self._on_finished(op_id, code, st))
        proc.errorOccurred.connect(lambda err: self._on_error(op_id, err))
        self._procs[op_id] = proc
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: self._on_timeout(op_id))
        timer.start(int(request.timeout * 1000))
        self._timers[op_id] = timer
        proc.start()
        self.changed.emit()
        return op_id

    # ---- control ----
    def cancel(self, op_id: int) -> None:
        proc = self._procs.get(op_id)
        op = self._ops.get(op_id)
        if not proc or not op or not op.active:
            return
        self._pending_flags[op_id] = "cancelled"
        self._audit.record("operation.cancel", id=op_id)
        self._emit(op_id, "info", "cancellation requested")
        proc.terminate()
        QTimer.singleShot(3000, lambda: proc.kill() if proc.state() != QProcess.ProcessState.NotRunning else None)

    def shutdown(self) -> None:
        for op_id in list(self._procs):
            proc = self._procs[op_id]
            if proc.state() != QProcess.ProcessState.NotRunning:
                self._pending_flags[op_id] = "cancelled"
                proc.kill()
                proc.waitForFinished(1000)
        self._flush_logs()

    # ---- internals ----
    def _read(self, op_id: int, proc: QProcess, stream: str) -> None:
        data = proc.readAllStandardOutput() if stream == "stdout" else proc.readAllStandardError()
        text = bytes(data).decode("utf-8", errors="replace")
        key = (op_id, stream)
        buf = self._partial.get(key, "") + text
        *lines, rest = buf.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self._partial[key] = rest
        for line in lines:
            self._emit(op_id, stream, line)

    def _emit(self, op_id: int, stream: str, line: str) -> None:
        op = self._ops[op_id]
        if len(op.lines) < MAX_LINES:
            op.lines.append((stream, line))
        self._log_buffer.append((op_id, stream, line))
        self.output.emit(op_id, stream, line)

    def _flush_logs(self) -> None:
        if not self._log_buffer:
            return
        buf, self._log_buffer = self._log_buffer, []
        try:
            with self._db.transaction() as c:
                c.executemany("INSERT INTO operation_logs(operation_id, stream, line) VALUES (?,?,?)", buf)
        except Exception:
            log.exception("failed to persist operation logs")

    def _on_finished(self, op_id: int, code: int, status: QProcess.ExitStatus) -> None:
        proc = self._procs.get(op_id)
        if proc is not None:  # drain remaining output
            self._read(op_id, proc, "stdout")
            self._read(op_id, proc, "stderr")
        for stream in ("stdout", "stderr"):
            rest = self._partial.pop((op_id, stream), "")
            if rest:
                self._emit(op_id, stream, rest)
        flag = self._pending_flags.pop(op_id, None)
        if flag:
            final = flag
        elif status == QProcess.ExitStatus.CrashExit:
            final = "failed"
        else:
            final = "succeeded" if code == 0 else "failed"
        self._finish(op_id, final, code)

    def _on_error(self, op_id: int, err: QProcess.ProcessError) -> None:
        if err == QProcess.ProcessError.FailedToStart:
            self._emit(op_id, "stderr", "failed to start process (is the executable present and runnable?)")
            self._finish(op_id, "failed", None)

    def _on_timeout(self, op_id: int) -> None:
        proc = self._procs.get(op_id)
        if proc and self._ops[op_id].active:
            self._pending_flags[op_id] = "timeout"
            self._emit(op_id, "info", "timed out; terminating")
            proc.kill()

    def _finish(self, op_id: int, status: str, code: int | None) -> None:
        op = self._ops[op_id]
        if not op.active:
            return
        op.status, op.exit_code = status, code
        op.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        op.runtime = time.monotonic() - op.started_monotonic
        timer = self._timers.pop(op_id, None)
        if timer:
            timer.stop()
        self._procs.pop(op_id, None)
        self._emit(op_id, "info", f"finished: {status}" + (f" (exit code {code})" if code is not None else ""))
        self._flush_logs()
        self._db.execute("UPDATE operations SET status=?, exit_code=?, finished_at=? WHERE id=?",
                         (status, code, op.finished_at, op_id))
        self._audit.record("operation.finish", id=op_id, status=status, exit_code=code)
        self.finished.emit(op_id, status)
        self.changed.emit()
