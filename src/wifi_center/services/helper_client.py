"""GUI client for the privileged helper (org.wificenter.Helper1 on the system bus).

`HelperBackend` holds all the logic (request building, output routing, error mapping, session queries) and talks to the
bus only through a small `HelperTransport`; `QtDBusTransport` is the real one, tests use a fake. Nothing here ever runs
as root or asks for a password: Polkit shows its own authentication dialog, and a denied/cancelled one is a normal result.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable, Protocol

from ..privileged.protocol import BUS_NAME, ERROR_PREFIX, INTERFACE, OBJECT_PATH, PrivilegedOp, ProtocolError, op_to_json
from .privileged_service import DoneCb, ExecutionResult, OutputCb

log = logging.getLogger(__name__)

ErrorCb = Callable[[str, str], None]          # (error name, message)

FRIENDLY = {
    "NotAuthorized": "Authorization was denied or cancelled, so nothing was changed.",
    "Busy": "The helper is already running another privileged operation. Wait for it to finish.",
    "AuthorityUnavailable": "Polkit could not be reached, so the helper refused to act (it never runs without it).",
    "InvalidArgs": "The helper refused the request as invalid.",
}


class HelperTransport(Protocol):
    def available(self) -> bool: ...

    def call(self, method: str, args: list[Any], on_reply: Callable[[Any], None], on_error: ErrorCb,
             timeout_ms: int = 60000) -> None: ...

    def subscribe(self, on_output: Callable[[str, str, str], None],
                  on_finished: Callable[[str, int, str, str], None]) -> None: ...


def friendly_error(name: str, message: str) -> str:
    code = name[len(ERROR_PREFIX):] if name.startswith(ERROR_PREFIX) else ""
    if code in FRIENDLY:
        return FRIENDLY[code] + ("" if code in ("NotAuthorized", "Busy") else f" ({message})")
    if name.endswith(("ServiceUnknown", "NameHasNoOwner")) or "not provided by any .service" in message:
        return ("The privileged helper is not installed (see privileged-helper/README.md); nothing was changed.")
    if name.endswith("AccessDenied"):
        return "The system bus refused the connection to the helper (its policy does not allow this user)."
    return message or name


class HelperBackend:
    """Async privileged backend: `start(op, on_output, on_done)`; `on_done` always gets exactly one ExecutionResult."""

    name = "polkit-helper"

    def __init__(self, transport: HelperTransport) -> None:
        self._t = transport
        self._active: dict[str, tuple[OutputCb, DoneCb]] = {}
        self._early: list[tuple] = []                 # events that arrive before Execute's reply names the operation
        self._starting = 0
        self._subscribed = False

    # ------------------------------------------------------------------ availability
    def available(self) -> bool:
        try:
            return bool(self._t.available())
        except Exception:
            return False

    def explain_unavailable(self) -> str:
        return ("The privileged helper is not installed or not reachable. Install it with "
                "'sudo ./privileged-helper/install.sh' (see privileged-helper/README.md); until then "
                "nothing is applied. Nothing was changed; every proposed command is only shown for you to review.")

    # ------------------------------------------------------------------ running operations
    def _subscribe(self) -> None:
        if not self._subscribed:
            self._t.subscribe(self._on_output, self._on_finished)
            self._subscribed = True

    def start(self, op: PrivilegedOp, on_output: OutputCb, on_done: DoneCb) -> None:
        try:
            payload = op_to_json(op)
        except ProtocolError as e:
            on_done(ExecutionResult(False, False, f"Invalid request: {e}"))
            return
        if not self.available():
            on_done(ExecutionResult(False, False, self.explain_unavailable()))
            return
        self._subscribe()
        self._starting += 1

        def replied(op_id: Any) -> None:
            self._starting -= 1
            oid = str(op_id)
            self._active[oid] = (on_output, on_done)
            pending, self._early = self._early, []
            for ev in pending:
                if ev[0] == "out":
                    self._on_output(ev[1], ev[2], ev[3])
                else:
                    self._on_finished(ev[1], ev[2], ev[3], ev[4])
            # replay events that belonged to other operations back into the buffer
            self._early = [e for e in self._early if e[1] != oid]

        def failed(name: str, message: str) -> None:
            self._starting -= 1
            on_done(ExecutionResult(False, False, friendly_error(name, message)))

        self._t.call("Execute", [payload], replied, failed, timeout_ms=3_600_000)

    def _on_output(self, op_id: str, stream: str, line: str) -> None:
        cb = self._active.get(str(op_id))
        if cb is None:
            if self._starting:
                self._early.append(("out", str(op_id), stream, line))
            return
        cb[0](line if stream == "stdout" else f"[{stream}] {line}")

    def _on_finished(self, op_id: str, exit_code: int, status: str, message: str) -> None:
        cb = self._active.pop(str(op_id), None)
        if cb is None:
            if self._starting:
                self._early.append(("fin", str(op_id), exit_code, status, message))
            return
        ok = status == "succeeded"
        cb[1](ExecutionResult(status in ("succeeded", "failed", "cancelled", "timeout"), ok, message))

    def cancel(self, op_id: str) -> None:
        self._t.call("Cancel", [op_id], lambda _r: None, lambda n, m: log.warning("cancel failed: %s %s", n, m))

    # ------------------------------------------------------------------ session / status
    def get_status(self, on_done: Callable[[dict | None, str], None]) -> None:
        """Non-interactive: never shows a dialog. `on_done(status_dict_or_None, error_text)`."""
        def ok(r: Any) -> None:
            try:
                on_done(json.loads(str(r)), "")
            except ValueError:
                on_done(None, "The helper returned an unreadable status.")
        self._t.call("GetStatus", [], ok, lambda n, m: on_done(None, friendly_error(n, m)), timeout_ms=8000)

    def request_authorization(self, action_id: str, on_done: Callable[[bool, str], None]) -> None:
        self._t.call("RequestAuthorization", [action_id], lambda r: on_done(bool(r), ""),
                     lambda n, m: on_done(False, friendly_error(n, m)), timeout_ms=600_000)

    def end_session(self, on_done: Callable[[bool, str], None]) -> None:
        self._t.call("EndSession", [], lambda r: on_done(bool(r), ""),
                     lambda n, m: on_done(False, friendly_error(n, m)), timeout_ms=10_000)

    def recent(self, count: int, on_done: Callable[[list[dict], str], None]) -> None:
        def ok(r: Any) -> None:
            try:
                on_done(list(json.loads(str(r))), "")
            except ValueError:
                on_done([], "The helper returned an unreadable list.")
        self._t.call("GetRecentOperations", [int(count)], ok, lambda n, m: on_done([], friendly_error(n, m)), timeout_ms=8000)


# ====================================================================== real transport (QtDBus)
class QtDBusTransport:
    """System-bus transport on QtDBus (PySide6.QtDBus). Needs the Linux build of Qt with D-Bus support."""

    def __init__(self) -> None:
        from PySide6.QtDBus import QDBusConnection
        self._bus = QDBusConnection.systemBus()
        self._watchers: list = []
        self._receiver = None

    def available(self) -> bool:
        from PySide6.QtDBus import QDBusConnectionInterface
        if not self._bus.isConnected():
            return False
        ci = self._bus.interface()
        if ci.isServiceRegistered(BUS_NAME).value():
            return True
        names = ci.activatableServiceNames().value() if hasattr(ci, "activatableServiceNames") else []
        return BUS_NAME in (names or [])

    def call(self, method, args, on_reply, on_error, timeout_ms: int = 60000) -> None:
        from PySide6.QtDBus import QDBusInterface, QDBusMessage, QDBusPendingCallWatcher
        iface = QDBusInterface(BUS_NAME, OBJECT_PATH, INTERFACE, self._bus)
        if not iface.isValid():
            on_error("org.freedesktop.DBus.Error.ServiceUnknown", iface.lastError().message() or "helper not available")
            return
        iface.setTimeout(int(timeout_ms))
        pending = iface.asyncCallWithArgumentList(method, list(args))
        watcher = QDBusPendingCallWatcher(pending)
        self._watchers.append(watcher)

        def done(w) -> None:
            reply = w.reply()
            self._watchers.remove(w)
            if reply.type() == QDBusMessage.MessageType.ErrorMessage:
                on_error(reply.errorName(), reply.errorMessage())
            else:
                a = reply.arguments()
                on_reply(a[0] if a else None)
            w.deleteLater()
        watcher.finished.connect(done)

    def subscribe(self, on_output, on_finished) -> None:
        from PySide6.QtCore import QObject, Slot

        class Receiver(QObject):
            @Slot(str, str, str)
            def Output(self, op_id, stream, line):  # noqa: N802
                on_output(op_id, stream, line)

            @Slot(str, int, str, str)
            def Finished(self, op_id, exit_code, status, message):  # noqa: N802
                on_finished(op_id, exit_code, status, message)

        self._receiver = Receiver()
        self._bus.connect(BUS_NAME, OBJECT_PATH, INTERFACE, "Output", "sss", self._receiver, "Output(QString,QString,QString)")
        self._bus.connect(BUS_NAME, OBJECT_PATH, INTERFACE, "Finished", "siss", self._receiver,
                          "Finished(QString,int,QString,QString)")


class DBusPythonTransport:
    """System-bus transport on dbus-python (python3-dbus), for Qt builds without QtDBus (Parrot ships it separately).

    A private connection runs its own GLib main loop in a daemon thread; every result is handed back to the GUI
    thread through a queued Qt signal, so callers never see the thread."""

    def __init__(self) -> None:
        import threading

        import dbus
        import dbus.mainloop.glib
        from gi.repository import GLib
        from PySide6.QtCore import QObject, Signal

        class Bridge(QObject):
            fire = Signal(object)

        self._dbus, self._GLib = dbus, GLib
        self._bridge = Bridge()
        self._bridge.fire.connect(lambda fn: fn())            # queued: runs on the thread that owns the bridge
        dbus.mainloop.glib.threads_init()
        self._loop = GLib.MainLoop()
        ready = threading.Event()
        holder: dict = {}

        def run() -> None:
            try:
                dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
                holder["bus"] = dbus.SystemBus(private=True)
            except Exception as e:
                holder["error"] = e
            ready.set()
            if "bus" in holder:
                self._loop.run()

        self._thread = threading.Thread(target=run, name="helper-dbus", daemon=True)
        self._thread.start()
        ready.wait(5)
        if "bus" not in holder:
            raise RuntimeError(f"cannot connect to the system bus: {holder.get('error')}")
        self._bus = holder["bus"]

    def _to_gui(self, fn) -> None:
        self._bridge.fire.emit(fn)

    def available(self) -> bool:
        try:
            names = set(map(str, self._bus.list_names())) | set(map(str, self._bus.list_activatable_names()))
            return BUS_NAME in names
        except Exception:
            return False

    def call(self, method, args, on_reply, on_error, timeout_ms: int = 60000) -> None:
        dbus = self._dbus

        def go() -> bool:
            try:
                obj = self._bus.get_object(BUS_NAME, OBJECT_PATH)
                iface = dbus.Interface(obj, INTERFACE)
                getattr(iface, method)(*args,
                                       reply_handler=lambda r: self._to_gui(lambda: on_reply(_plain(r))),
                                       error_handler=lambda e: self._to_gui(
                                           lambda: on_error(e.get_dbus_name() or "", e.get_dbus_message() or str(e))),
                                       timeout=timeout_ms / 1000.0)
            except Exception as e:
                name = e.get_dbus_name() if hasattr(e, "get_dbus_name") else "org.freedesktop.DBus.Error.Failed"
                msg = e.get_dbus_message() if hasattr(e, "get_dbus_message") else str(e)
                self._to_gui(lambda: on_error(name or "", msg))
            return False
        self._GLib.idle_add(go)

    def subscribe(self, on_output, on_finished) -> None:
        def go() -> bool:
            self._bus.add_signal_receiver(
                lambda i, st, line: self._to_gui(lambda: on_output(str(i), str(st), str(line))),
                "Output", INTERFACE, BUS_NAME, OBJECT_PATH)
            self._bus.add_signal_receiver(
                lambda i, code, st, msg: self._to_gui(lambda: on_finished(str(i), int(code), str(st), str(msg))),
                "Finished", INTERFACE, BUS_NAME, OBJECT_PATH)
            return False
        self._GLib.idle_add(go)


def _plain(v: Any) -> Any:
    """dbus-python wraps values in dbus.* types; hand the GUI plain Python ones."""
    if isinstance(v, bool):
        return bool(v)
    if isinstance(v, int):
        return int(v)
    return str(v) if v is not None else None


def make_backend():
    """The real backend when a D-Bus transport is usable on this machine; otherwise None (the caller keeps
    UnavailableBackend and the app stays read-only)."""
    for factory in (QtDBusTransport, DBusPythonTransport):
        try:
            return HelperBackend(factory())
        except Exception as e:
            log.info("privileged helper transport %s unavailable: %s", factory.__name__, e)
    return None
