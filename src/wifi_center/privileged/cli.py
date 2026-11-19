"""Command-line client for the privileged helper (for testing it without the GUI).

    python3 -m wifi_center.privileged.cli status
    python3 -m wifi_center.privileged.cli authorize maintenance
    python3 -m wifi_center.privileged.cli run diag_journal
    python3 -m wifi_center.privileged.cli run diag_unit_status --unit ssh.service
    python3 -m wifi_center.privileged.cli run apt_update
    python3 -m wifi_center.privileged.cli recent
    python3 -m wifi_center.privileged.cli end-session

Needs python3-dbus and python3-gi. It prints exactly what the helper reports and what Polkit decided.
"""
from __future__ import annotations

import argparse
import json
import sys

from .protocol import ACTIONS, BUS_NAME, INTERFACE, KINDS, OBJECT_PATH, Manifest, PrivilegedOp, ProtocolError, op_to_json


def _bus():
    import dbus
    import dbus.mainloop.glib
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    return dbus, dbus.SystemBus()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wifi-center-helper-cli", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    a = sub.add_parser("authorize")
    a.add_argument("action", help="short name (maintenance, cleanup-files, network-interface, bluetooth-capture, diagnostics) or full id")
    r = sub.add_parser("run")
    r.add_argument("kind", choices=KINDS)
    r.add_argument("--package", action="append", default=[])
    r.add_argument("--iface", default="")
    r.add_argument("--unit", default="")
    r.add_argument("--category", default="")
    r.add_argument("--path", action="append", default=[])
    r.add_argument("--approve-upgrades", action="append", default=[], help="package names the manifest approves to upgrade")
    r.add_argument("--approve-installs", action="append", default=[])
    r.add_argument("--approve-removes", action="append", default=[])
    sub.add_parser("recent")
    sub.add_parser("end-session")
    args = ap.parse_args(argv)

    try:
        dbus, bus = _bus()
        helper = dbus.Interface(bus.get_object(BUS_NAME, OBJECT_PATH), INTERFACE)
    except Exception as e:
        print(f"Cannot reach {BUS_NAME}: {e}\nIs the helper installed? (sudo ./privileged-helper/install.sh)", file=sys.stderr)
        return 3

    try:
        if args.cmd == "status":
            print(json.dumps(json.loads(str(helper.GetStatus())), indent=2))
        elif args.cmd == "recent":
            for e in json.loads(str(helper.GetRecentOperations(dbus.UInt32(30)))):
                print(e["ts"], e["event"], e["status"], e["summary"])
        elif args.cmd == "end-session":
            print("revoked" if helper.EndSession() else "could not revoke (it will expire on its own)")
        elif args.cmd == "authorize":
            action = args.action if args.action.startswith("org.") else f"org.wificenter.helper.{args.action}"
            print("authorized" if helper.RequestAuthorization(action, timeout=600) else "NOT authorized")
        elif args.cmd == "run":
            manifest = None
            if args.approve_upgrades or args.approve_installs or args.approve_removes:
                manifest = Manifest(tuple(args.approve_installs), tuple(args.approve_upgrades), tuple(args.approve_removes))
            op = PrivilegedOp(args.kind, tuple(args.package), tuple(args.path), args.category, args.iface, args.unit, manifest)
            return _run(dbus, bus, helper, op)
    except ProtocolError as e:
        print(f"Invalid request: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def _run(dbus, bus, helper, op: PrivilegedOp) -> int:
    from gi.repository import GLib
    loop = GLib.MainLoop()
    result = {"code": 1}
    state = {"op_id": None}

    def on_output(op_id, stream, line):
        if op_id == state["op_id"] or state["op_id"] is None:
            print(f"[{stream}] {line}")

    def on_finished(op_id, exit_code, status, message):
        if op_id == state["op_id"] or state["op_id"] is None:
            print(f"== {status}: {message} (exit code {exit_code})")
            result["code"] = 0 if status == "succeeded" else 1
            loop.quit()

    bus.add_signal_receiver(on_output, "Output", INTERFACE, BUS_NAME, OBJECT_PATH)
    bus.add_signal_receiver(on_finished, "Finished", INTERFACE, BUS_NAME, OBJECT_PATH)

    def started(op_id):
        state["op_id"] = str(op_id)
        print(f"started operation {op_id}")

    def failed(err):
        print(f"Refused: {err}", file=sys.stderr)
        result["code"] = 4
        loop.quit()

    helper.Execute(op_to_json(op), reply_handler=started, error_handler=failed, timeout=3600)
    try:
        loop.run()
    except KeyboardInterrupt:
        if state["op_id"]:
            helper.Cancel(state["op_id"])
            print("cancel requested")
    return result["code"]


if __name__ == "__main__":
    sys.exit(main())
