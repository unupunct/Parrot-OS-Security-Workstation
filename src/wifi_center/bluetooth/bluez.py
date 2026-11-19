"""BlueZ over D-Bus: a small, generic client (`BluezAPI`) that the Bluetooth modules build on.

Primitives only (objects, properties, method calls), so every higher-level module can be tested against the in-memory fake in
`fake.py`. The real client talks to the system bus with dbus-python from whatever thread calls it (calls are serialised with a
lock) and converts every value to plain Python. Pairing keys are never read, stored or logged by this layer."""
from __future__ import annotations

import threading
from typing import Any, Protocol

from .models import BluetoothError

BLUEZ = "org.bluez"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
PROPS = "org.freedesktop.DBus.Properties"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
GATT_SERVICE = "org.bluez.GattService1"
GATT_CHAR = "org.bluez.GattCharacteristic1"
GATT_DESC = "org.bluez.GattDescriptor1"
BATTERY = "org.bluez.Battery1"


class BluezAPI(Protocol):
    def available(self) -> bool: ...

    def objects(self) -> dict[str, dict[str, dict[str, Any]]]:
        """path -> interface -> {property: value} for everything BlueZ exports."""

    def get_prop(self, path: str, iface: str, name: str) -> Any: ...

    def set_prop(self, path: str, iface: str, name: str, value: Any) -> None: ...

    def call(self, path: str, iface: str, method: str, args: tuple = (), timeout: float = 30.0) -> Any: ...

    def watch(self, path_prefix: str, callback) -> Any:
        """Call callback(path, interface, changed_properties) for every BlueZ property change under path_prefix. Returns a token."""

    def unwatch(self, token: Any) -> None: ...

    def register_agent(self, handler, capability: str = "KeyboardDisplay") -> Any:
        """Export a pairing agent (see AgentHandler) and make it the default agent. Returns a token for unregister_agent."""

    def unregister_agent(self, token: Any) -> None: ...


class AgentHandler(Protocol):
    """What the pairing agent asks the user. Every method may block (it runs on BlueZ's request thread) and must answer within the
    pairing timeout; returning None / False refuses. Keys and PINs are never stored or logged by this layer."""

    def request_confirmation(self, address: str, passkey: int) -> bool: ...

    def request_pin(self, address: str) -> str | None: ...

    def request_passkey(self, address: str) -> int | None: ...

    def display_passkey(self, address: str, passkey: int) -> None: ...

    def display_pin(self, address: str, pin: str) -> None: ...

    def authorize_service(self, address: str, uuid: str) -> bool: ...

    def cancel(self) -> None: ...


AGENT_PATH = "/org/wificenter/agent"
AGENT_IFACE = "org.bluez.Agent1"


def address_from_path(path: str) -> str:
    """/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF -> AA:BB:CC:DD:EE:FF"""
    tail = path.rsplit("/", 1)[-1]
    return tail[4:].replace("_", ":") if tail.startswith("dev_") else ""


def to_py(v: Any) -> Any:
    """dbus-python values -> plain Python (byte arrays become bytes)."""
    import dbus
    if isinstance(v, dbus.Boolean):
        return bool(v)
    if isinstance(v, (dbus.Byte, dbus.Int16, dbus.Int32, dbus.Int64, dbus.UInt16, dbus.UInt32, dbus.UInt64)):
        return int(v)
    if isinstance(v, (dbus.String, dbus.ObjectPath, dbus.Signature)):
        return str(v)
    if isinstance(v, dbus.Double):
        return float(v)
    if isinstance(v, dbus.ByteArray):
        return bytes(v)
    if isinstance(v, dbus.Array):
        if v.signature == "y":
            return bytes(v)
        return [to_py(x) for x in v]
    if isinstance(v, dbus.Dictionary):
        return {to_py(k): to_py(x) for k, x in v.items()}
    if isinstance(v, (dbus.Struct, tuple)):
        return tuple(to_py(x) for x in v)
    return v


def to_dbus(v: Any) -> Any:
    """Plain Python -> dbus types for the simple shapes BlueZ methods take (bool, int, str, bytes, list, dict of those)."""
    import dbus
    if isinstance(v, bool):
        return dbus.Boolean(v)
    if isinstance(v, int):
        return dbus.Int32(v)
    if isinstance(v, str):
        return dbus.String(v)
    if isinstance(v, (bytes, bytearray)):
        return dbus.Array([dbus.Byte(b) for b in v], signature="y")
    if isinstance(v, (list, tuple)):
        return dbus.Array([to_dbus(x) for x in v], signature="v") if v and not all(isinstance(x, str) for x in v) else dbus.Array([dbus.String(x) for x in v], signature="s")
    if isinstance(v, dict):
        return dbus.Dictionary({dbus.String(k): to_dbus(x) for k, x in v.items()}, signature="sv")
    return v


def friendly_error(name: str, message: str) -> str:
    """Turn a BlueZ / D-Bus error into text the user can act on."""
    short = name.rsplit(".", 1)[-1]
    table = {
        "NotReady": "The Bluetooth adapter is not ready (is it powered on?).",
        "NotAvailable": "That is not available right now.",
        "InProgress": "Another Bluetooth operation is already in progress; try again in a moment.",
        "AlreadyExists": "That already exists (for example the device is already paired).",
        "AlreadyConnected": "The device is already connected.",
        "NotConnected": "The device is not connected.",
        "NotPermitted": "The device or the adapter refused the request (permission or authentication is required).",
        "AuthenticationFailed": "Authentication failed (wrong PIN, a rejected passkey, or the other device refused).",
        "AuthenticationCanceled": "Authentication was cancelled.",
        "AuthenticationRejected": "The other device rejected the pairing.",
        "AuthenticationTimeout": "Pairing timed out: the other device did not answer in time.",
        "ConnectionAttemptFailed": "The connection attempt failed (the device may be out of range, off, or not connectable).",
        "Failed": message or "The operation failed.",
        "DoesNotExist": "That device is no longer known to BlueZ.",
        "NotSupported": "This operation is not supported by the adapter or the device.",
        "InvalidArguments": "BlueZ rejected the request as invalid.",
        "ServiceUnknown": "The Bluetooth service (bluetoothd) is not running.",
        "NoReply": "BlueZ did not answer in time.",
        "AccessDenied": "The system bus refused access to Bluetooth for your user (are you in the 'bluetooth' group?).",
        "UnknownObject": "That Bluetooth object no longer exists.",
        "UnknownMethod": "This BlueZ version does not support that method.",
    }
    return table.get(short, message or name or "Bluetooth operation failed")


class DBusBluez:
    """The real client."""

    def __init__(self) -> None:
        import dbus  # noqa: F401  (fail early where dbus-python is missing)
        self._bus = None
        self._lock = threading.RLock()

    def _connect(self):
        import dbus
        if self._bus is None:
            self._bus = dbus.SystemBus(private=True)
        return self._bus

    def available(self) -> bool:
        try:
            bus = self._connect()
            return BLUEZ in {str(n) for n in bus.list_names()}
        except Exception:
            self._bus = None
            return False

    # ---- watchers and the pairing agent run on a private connection with its own GLib main loop in a daemon thread
    def _loop(self):
        import dbus
        import dbus.mainloop.glib
        from gi.repository import GLib
        if getattr(self, "_glib", None) is None:
            holder: dict = {}
            ready = threading.Event()

            def run() -> None:
                try:
                    dbus.mainloop.glib.threads_init()
                    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
                    holder["bus"] = dbus.SystemBus(private=True)
                    holder["loop"] = GLib.MainLoop()
                except Exception as e:
                    holder["error"] = e
                ready.set()
                if "loop" in holder:
                    holder["loop"].run()
            threading.Thread(target=run, name="bluez-glib", daemon=True).start()
            ready.wait(5)
            if "bus" not in holder:
                raise BluetoothError(f"cannot start the Bluetooth event loop: {holder.get('error')}")
            self._glib = holder
        return self._glib

    def watch(self, path_prefix: str, callback) -> Any:
        glib = self._loop()

        def on_change(iface, changed, invalidated, path=None):
            if str(path).startswith(path_prefix):
                callback(str(path), str(iface), {str(k): to_py(v) for k, v in changed.items()})
        return glib["bus"].add_signal_receiver(on_change, "PropertiesChanged", PROPS, BLUEZ, path_keyword="path")

    def unwatch(self, token: Any) -> None:
        try:
            token.remove()
        except Exception:
            pass

    def register_agent(self, handler, capability: str = "KeyboardDisplay") -> Any:
        import dbus
        import dbus.service
        glib = self._loop()
        bus = glib["bus"]

        class Rejected(dbus.DBusException):
            _dbus_error_name = "org.bluez.Error.Rejected"

        class Agent(dbus.service.Object):
            @dbus.service.method(AGENT_IFACE, in_signature="", out_signature="")
            def Release(self):                                           # noqa: N802
                handler.cancel()

            @dbus.service.method(AGENT_IFACE, in_signature="o", out_signature="s")
            def RequestPinCode(self, device):                            # noqa: N802
                pin = handler.request_pin(address_from_path(str(device)))
                if pin is None:
                    raise Rejected("rejected")
                return pin

            @dbus.service.method(AGENT_IFACE, in_signature="os", out_signature="")
            def DisplayPinCode(self, device, pincode):                   # noqa: N802
                handler.display_pin(address_from_path(str(device)), str(pincode))

            @dbus.service.method(AGENT_IFACE, in_signature="o", out_signature="u")
            def RequestPasskey(self, device):                            # noqa: N802
                v = handler.request_passkey(address_from_path(str(device)))
                if v is None:
                    raise Rejected("rejected")
                return dbus.UInt32(v)

            @dbus.service.method(AGENT_IFACE, in_signature="ouq", out_signature="")
            def DisplayPasskey(self, device, passkey, entered):          # noqa: N802
                handler.display_passkey(address_from_path(str(device)), int(passkey))

            @dbus.service.method(AGENT_IFACE, in_signature="ou", out_signature="")
            def RequestConfirmation(self, device, passkey):              # noqa: N802
                if not handler.request_confirmation(address_from_path(str(device)), int(passkey)):
                    raise Rejected("rejected")

            @dbus.service.method(AGENT_IFACE, in_signature="o", out_signature="")
            def RequestAuthorization(self, device):                      # noqa: N802
                if not handler.request_confirmation(address_from_path(str(device)), 0):
                    raise Rejected("rejected")

            @dbus.service.method(AGENT_IFACE, in_signature="os", out_signature="")
            def AuthorizeService(self, device, uuid):                    # noqa: N802
                if not handler.authorize_service(address_from_path(str(device)), str(uuid)):
                    raise Rejected("rejected")

            @dbus.service.method(AGENT_IFACE, in_signature="", out_signature="")
            def Cancel(self):                                            # noqa: N802
                handler.cancel()

        agent = Agent(bus, AGENT_PATH)
        mgr = dbus.Interface(bus.get_object(BLUEZ, "/org/bluez"), "org.bluez.AgentManager1")
        try:
            mgr.RegisterAgent(dbus.ObjectPath(AGENT_PATH), capability)
            mgr.RequestDefaultAgent(dbus.ObjectPath(AGENT_PATH))
        except dbus.DBusException as e:
            agent.remove_from_connection()
            raise self._error(e) from None
        return (agent, mgr)

    def unregister_agent(self, token: Any) -> None:
        import dbus
        agent, mgr = token
        try:
            mgr.UnregisterAgent(dbus.ObjectPath(AGENT_PATH))
        except Exception:
            pass
        try:
            agent.remove_from_connection()
        except Exception:
            pass

    def _error(self, e: Exception) -> BluetoothError:
        name = e.get_dbus_name() if hasattr(e, "get_dbus_name") else ""
        msg = e.get_dbus_message() if hasattr(e, "get_dbus_message") else str(e)
        return BluetoothError(friendly_error(name or "", msg or ""))

    def objects(self) -> dict[str, dict[str, dict[str, Any]]]:
        import dbus
        with self._lock:
            try:
                bus = self._connect()
                mgr = dbus.Interface(bus.get_object(BLUEZ, "/"), OBJECT_MANAGER)
                return {str(p): {str(i): {str(k): to_py(v) for k, v in props.items()} for i, props in ifs.items()}
                        for p, ifs in mgr.GetManagedObjects(timeout=15).items()}
            except dbus.DBusException as e:
                self._bus = None
                raise self._error(e) from None

    def get_prop(self, path: str, iface: str, name: str) -> Any:
        import dbus
        with self._lock:
            try:
                props = dbus.Interface(self._connect().get_object(BLUEZ, path), PROPS)
                return to_py(props.Get(iface, name))
            except dbus.DBusException as e:
                raise self._error(e) from None

    def set_prop(self, path: str, iface: str, name: str, value: Any) -> None:
        import dbus
        with self._lock:
            try:
                props = dbus.Interface(self._connect().get_object(BLUEZ, path), PROPS)
                props.Set(iface, name, to_dbus(value))
            except dbus.DBusException as e:
                raise self._error(e) from None

    def call(self, path: str, iface: str, method: str, args: tuple = (), timeout: float = 30.0) -> Any:
        import dbus
        with self._lock:
            try:
                obj = dbus.Interface(self._connect().get_object(BLUEZ, path), iface)
                return to_py(getattr(obj, method)(*[to_dbus(a) for a in args], timeout=timeout))
            except dbus.DBusException as e:
                raise self._error(e) from None


class UnavailableBluez:
    """Stands in when BlueZ cannot be reached (no dbus-python, or bluetoothd is not running): every call explains why."""

    def available(self) -> bool:
        return False

    def objects(self):
        raise BluetoothError("The Bluetooth service (bluetoothd) is not running or not reachable.")

    def get_prop(self, *a, **k):
        return self.objects()

    set_prop = call = get_prop

    def watch(self, *a, **k):
        return self.objects()

    unwatch = unregister_agent = lambda self, *a, **k: None
    register_agent = watch


def make_api() -> BluezAPI | None:
    """The real D-Bus client when dbus-python is installed, else None (the Lab then falls back to the bluetoothctl scanner)."""
    try:
        return DBusBluez()
    except Exception:
        return None
