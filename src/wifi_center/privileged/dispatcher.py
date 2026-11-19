"""Request handling of the privileged helper: authentication, authorization, ownership, auditing.

Independent of D-Bus (the bus glue calls into this class), so it can be tested with a fake authority.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Protocol

from ..security.audit_log import AuditLog
from .helper_core import HelperCore
from .protocol import ACTIONS, PROTOCOL_VERSION, ExecResult, PrivilegedOp, ProtocolError, op_from_json

StartThread = Callable[[Callable[[], None]], None]
Signal = Callable[..., None]


@dataclass(frozen=True)
class Caller:
    bus_name: str
    uid: int
    pid: int


@dataclass
class AuthResult:
    is_authorized: bool
    is_challenge: bool = False
    message: str = ""


class Authority(Protocol):
    def check(self, bus_name: str, action_id: str, details: dict[str, str], interactive: bool) -> AuthResult: ...
    def revoke(self, bus_name: str) -> bool: ...


class HelperError(Exception):
    """`code` becomes the D-Bus error name suffix (org.wificenter.Helper1.Error.<code>)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


@dataclass
class OpRecord:
    op_id: str
    owner_uid: int
    owner_bus: str
    op: PrivilegedOp
    cancel: threading.Event = field(default_factory=threading.Event)
    finished: bool = False


def default_start(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True).start()


class HelperDispatcher:
    def __init__(self, core: HelperCore, authority: Authority, audit: AuditLog, signal: Signal,
                 start_thread: StartThread = default_start, now: Callable[[], float] = time.time) -> None:
        self.core, self.authority, self.audit, self._signal = core, authority, audit, signal
        self._start, self._now = start_thread, now
        self._ops: dict[str, OpRecord] = {}
        self._lock = threading.Lock()
        self.last_activity = now()
        self.session_started: dict[int, float] = {}

    # ------------------------------------------------------------------ helpers
    def _touch(self) -> None:
        self.last_activity = self._now()

    def _details(self, op: PrivilegedOp) -> dict[str, str]:
        return {"operation": op.kind, "summary": op.summary()[:200]}

    def idle_seconds(self) -> float:
        return self._now() - self.last_activity

    def has_running(self) -> bool:
        with self._lock:
            return any(not r.finished for r in self._ops.values())

    # ------------------------------------------------------------------ execute
    def execute(self, caller: Caller, op_json: str, on_started: Callable[[str], None],
                on_error: Callable[[HelperError], None]) -> None:
        """Validate now, authenticate and run on a worker thread. Exactly one of the callbacks is invoked."""
        self._touch()
        try:
            op = op_from_json(op_json)
        except ProtocolError as e:
            self.audit.record("request.invalid", caller_uid=caller.uid, caller_pid=caller.pid, reason=str(e))
            on_error(HelperError("InvalidArgs", str(e)))
            return
        if self.core.busy:
            on_error(HelperError("Busy", "Another privileged operation is already running."))
            return

        def work() -> None:
            try:
                auth = self.authority.check(caller.bus_name, op.action_id, self._details(op), interactive=True)
            except Exception as e:  # authority unreachable: fail closed
                self.audit.record("auth.error", caller_uid=caller.uid, action=op.action_id, error=str(e))
                on_error(HelperError("AuthorityUnavailable", f"Polkit could not be reached: {e}"))
                return
            if not auth.is_authorized:
                self.audit.record("auth.denied", caller_uid=caller.uid, caller_pid=caller.pid, action=op.action_id,
                                  operation=op.kind, challenge=auth.is_challenge)
                on_error(HelperError("NotAuthorized", "Authorization was denied or cancelled."))
                return
            self.session_started.setdefault(caller.uid, self._now())
            rec = OpRecord(uuid.uuid4().hex[:12], caller.uid, caller.bus_name, op)
            with self._lock:
                self._ops[rec.op_id] = rec
            self.audit.record("op.start", op_id=rec.op_id, caller_uid=caller.uid, caller_pid=caller.pid,
                              action=op.action_id, summary=op.summary())
            on_started(rec.op_id)

            def emit(stream: str, line: str) -> None:
                self._touch()
                self._signal(caller.bus_name, "Output", rec.op_id, stream, line)

            try:
                result = self.core.execute(op, emit, rec.cancel)
            except Exception as e:  # never leave a client hanging
                result = ExecResult(False, "failed", f"Internal error: {e}")
            rec.finished = True
            self.audit.record("op.finish", op_id=rec.op_id, caller_uid=caller.uid, status=result.status,
                              exit_code=result.exit_code, summary=op.summary(), message=result.message[:300])
            self._signal(caller.bus_name, "Finished", rec.op_id, result.exit_code if result.exit_code is not None else -1,
                         result.status, result.message)
            self._touch()
        self._start(work)

    # ------------------------------------------------------------------ cancel / queries
    def cancel(self, caller: Caller, op_id: str) -> bool:
        self._touch()
        rec = self._ops.get(op_id)
        if rec is None or rec.finished:
            return False
        if caller.uid not in (0, rec.owner_uid):
            self.audit.record("cancel.denied", caller_uid=caller.uid, op_id=op_id)
            raise HelperError("NotAuthorized", "Only the user who started an operation can cancel it.")
        rec.cancel.set()
        self.audit.record("op.cancel", op_id=op_id, caller_uid=caller.uid)
        return True

    def status(self, caller: Caller) -> dict:
        """No prompts: asks Polkit for the *current* authorization state of each action."""
        self._touch()
        auth: dict[str, bool] = {}
        for a in ACTIONS:
            try:
                auth[a.id] = self.authority.check(caller.bus_name, a.id, {}, interactive=False).is_authorized
            except Exception:
                auth[a.id] = False
        return {"protocol": PROTOCOL_VERSION, "busy": self.core.busy, "current": self.core.current or "",
                "authorized": auth, "session_started": self.session_started.get(caller.uid, 0.0)}

    def request_authorization(self, caller: Caller, action_id: str) -> bool:
        """Let the user authenticate ahead of time (interactive Polkit prompt)."""
        self._touch()
        if action_id not in {a.id for a in ACTIONS}:
            raise HelperError("InvalidArgs", f"unknown action: {action_id}")
        res = self.authority.check(caller.bus_name, action_id, {"operation": "authorize"}, interactive=True)
        self.audit.record("auth.request", caller_uid=caller.uid, action=action_id, granted=res.is_authorized)
        if res.is_authorized:
            self.session_started.setdefault(caller.uid, self._now())
        return res.is_authorized

    def end_session(self, caller: Caller) -> bool:
        self._touch()
        ok = False
        try:
            ok = self.authority.revoke(caller.bus_name)
        except Exception:
            ok = False
        self.audit.record("session.end", caller_uid=caller.uid, revoked=ok)
        if ok:
            self.session_started.pop(caller.uid, None)
        return ok

    def recent(self, caller: Caller, count: int = 30) -> list[dict]:
        """Operations of the calling user only (root sees all)."""
        self._touch()
        out = []
        for e in reversed(self.audit.tail(2000)):
            if e.get("event") in ("op.finish", "auth.denied", "session.end", "auth.request") and \
                    (caller.uid == 0 or e.get("caller_uid") == caller.uid):
                out.append({"ts": e["ts"], "event": e["event"], "summary": e.get("summary") or e.get("action", ""),
                            "status": e.get("status", ""), "message": e.get("message", "")})
                if len(out) >= max(1, min(int(count), 200)):
                    break
        return out
