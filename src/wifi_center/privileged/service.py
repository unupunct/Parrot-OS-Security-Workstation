"""D-Bus glue of the privileged helper (system bus, service org.wificenter.Helper1).

Thin on purpose: every decision lives in `dispatcher` / `helper_core`, which are unit-tested. This module needs
`python3-dbus` and `python3-gi` (GLib main loop) and can only run on a Linux system with a system bus and Polkit.
It is bus-activated and exits by itself after a minute of inactivity.

NOT verified on a live system in this repository's development environment (Windows): follow
privileged-helper/README.md to test it on Parrot OS.
"""
from __future__ import annotations

import json
import os
import sys

from ..security.audit_log import AuditLog
from .dispatcher import AuthResult, Caller, HelperDispatcher, HelperError
from .helper_core import HelperCore
from .protocol import BUS_NAME, ERROR_PREFIX, INTERFACE, OBJECT_PATH, PROTOCOL_VERSION

AUDIT_PATH = "/var/log/wifi-center/helper-audit.log"
IDLE_EXIT_SECONDS = 60
POLKIT = ("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority", "org.freedesktop.PolicyKit1.Authority")


class PolkitAuthority:
    """Asks Polkit about the *calling bus name*, so `auth_admin_keep` retains the authorization for that client."""

    def __init__(self, bus) -> None:
        import dbus
        self._dbus, self._bus = dbus, bus
        self._iface = dbus.Interface(bus.get_object(POLKIT[0], POLKIT[1]), POLKIT[2])

    def _subject(self, bus_name: str):
        d = self._dbus
        return ("system-bus-name", d.Dictionary({"name": d.String(bus_name)}, signature="sv"))

    def check(self, bus_name: str, action_id: str, details: dict[str, str], interactive: bool) -> AuthResult:
        d = self._dbus
        is_auth, is_challenge, _ = self._iface.CheckAuthorization(
            self._subject(bus_name), action_id, d.Dictionary(details, signature="ss"),
            d.UInt32(1 if interactive else 0), "", timeout=600)
        return AuthResult(bool(is_auth), bool(is_challenge))

    def revoke(self, bus_name: str) -> bool:
        self._iface.RevokeTemporaryAuthorizations(self._subject(bus_name))
        return True


def main() -> int:
    if os.geteuid() != 0:
        print("wifi-center-helper must run as root (it is started by the system bus).", file=sys.stderr)
        return 2
    import dbus
    import dbus.lowlevel
    import dbus.mainloop.glib
    import dbus.service
    from gi.repository import GLib

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(BUS_NAME, bus)
    loop = GLib.MainLoop()
    os.makedirs(os.path.dirname(AUDIT_PATH), mode=0o750, exist_ok=True)
    audit = AuditLog(__import__("pathlib").Path(AUDIT_PATH))
    dbus_iface = dbus.Interface(bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus"), "org.freedesktop.DBus")

    def caller_of(sender: str) -> Caller:
        return Caller(sender, int(dbus_iface.GetConnectionUnixUser(sender)),
                      int(dbus_iface.GetConnectionUnixProcessID(sender)))

    def send(dest: str, signal_name: str, *args) -> None:
        msg = dbus.lowlevel.SignalMessage(OBJECT_PATH, INTERFACE, signal_name)
        msg.set_destination(dest)                       # unicast: other users never see this output
        sig = {"Output": "sss", "Finished": "siss"}[signal_name]
        msg.append(*args, signature=sig)
        bus.send_message(msg)

    dispatcher = HelperDispatcher(HelperCore(), PolkitAuthority(bus), audit, send)

    def wrap_error(e: HelperError):
        return dbus.exceptions.DBusException(ERROR_PREFIX + e.code + ": " + e.message, name=ERROR_PREFIX + e.code)

    class Helper(dbus.service.Object):
        @dbus.service.method(INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender",
                             async_callbacks=("reply", "error"))
        def Execute(self, op_json, sender=None, reply=None, error=None):
            dispatcher.execute(caller_of(sender), str(op_json), lambda op_id: reply(op_id),
                               lambda e: error(wrap_error(e)))

        @dbus.service.method(INTERFACE, in_signature="s", out_signature="b", sender_keyword="sender")
        def Cancel(self, op_id, sender=None):
            try:
                return dispatcher.cancel(caller_of(sender), str(op_id))
            except HelperError as e:
                raise wrap_error(e)

        @dbus.service.method(INTERFACE, in_signature="", out_signature="s", sender_keyword="sender")
        def GetStatus(self, sender=None):
            return json.dumps(dispatcher.status(caller_of(sender)))

        @dbus.service.method(INTERFACE, in_signature="s", out_signature="b", sender_keyword="sender",
                             async_callbacks=("reply", "error"))
        def RequestAuthorization(self, action_id, sender=None, reply=None, error=None):
            import threading

            def work():
                try:
                    reply(bool(dispatcher.request_authorization(caller_of(sender), str(action_id))))
                except HelperError as e:
                    error(wrap_error(e))
                except Exception as e:
                    error(dbus.exceptions.DBusException(str(e)))
            threading.Thread(target=work, daemon=True).start()

        @dbus.service.method(INTERFACE, in_signature="", out_signature="b", sender_keyword="sender")
        def EndSession(self, sender=None):
            return dispatcher.end_session(caller_of(sender))

        @dbus.service.method(INTERFACE, in_signature="u", out_signature="s", sender_keyword="sender")
        def GetRecentOperations(self, count, sender=None):
            return json.dumps(dispatcher.recent(caller_of(sender), int(count)))

        @dbus.service.method(INTERFACE, in_signature="", out_signature="u")
        def GetProtocolVersion(self):
            return dbus.UInt32(PROTOCOL_VERSION)

    Helper(bus, OBJECT_PATH)

    def idle_check() -> bool:
        if not dispatcher.has_running() and dispatcher.idle_seconds() > IDLE_EXIT_SECONDS:
            loop.quit()
            return False
        return True
    GLib.timeout_add_seconds(10, idle_check)
    audit.record("helper.start", pid=os.getpid())
    loop.run()
    audit.record("helper.stop")
    del name
    return 0


if __name__ == "__main__":
    sys.exit(main())
