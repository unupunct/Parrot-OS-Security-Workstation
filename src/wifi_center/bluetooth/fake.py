"""An in-memory BlueZ for tests and demos of the Bluetooth modules: adapters, devices that appear while discovery runs, RSSI that
changes, and the common Adapter1 / Device1 methods. It is deliberately simple and follows BlueZ's observable behaviour only."""
from __future__ import annotations

from typing import Any, Callable

from .bluez import ADAPTER, DEVICE, GATT_CHAR, GATT_DESC, GATT_SERVICE
from .models import BluetoothError


def dev_path(adapter: str, address: str) -> str:
    return f"{adapter}/dev_{address.replace(':', '_')}"


class FakeBluez:
    def __init__(self) -> None:
        self.adapters: dict[str, dict[str, Any]] = {}
        self.devices: dict[str, dict[str, Any]] = {}
        self.gatt: dict[str, dict[str, dict[str, Any]]] = {}        # extra objects (services / characteristics / descriptors)
        self.calls: list[tuple] = []
        self.up = True
        self.fail: dict[tuple[str, str], str] = {}                  # (path-or-iface, method) -> error message
        self.reveal: list[tuple[int, str, dict]] = []               # (tick when it appears, adapter path, device props)
        self.rssi_script: dict[str, Callable[[int], int | None]] = {}   # address -> tick -> rssi (None removes the property)
        self.tick = 0
        self.values: dict[str, bytes] = {}
        self.watchers: list[tuple] = []
        self.agent = None
        self.pair_script: Callable[[str, Any], None] | None = None     # runs during Pair(): drive the agent like BlueZ would                          # characteristic path -> value

    # ---- building the scene
    def add_adapter(self, name: str = "hci0", address: str = "AA:00:00:00:00:01", powered: bool = True, **extra) -> str:
        path = f"/org/bluez/{name}"
        self.adapters[path] = {"Address": address, "Alias": "test-host", "Name": "test-host", "Powered": powered, "Discoverable": False,
                               "Pairable": True, "Discovering": False, "Modalias": "usb:v1D6Bp0246d0552", "Roles": ["central", "peripheral"],
                               "UUIDs": ["0000110a-0000-1000-8000-00805f9b34fb"], **extra}
        return path

    def add_device(self, adapter: str, address: str, **props) -> str:
        p = dev_path(adapter, address)
        self.devices[p] = {"Address": address, "Adapter": adapter, "Alias": address.replace(":", "-"), "Paired": False, "Bonded": False,
                           "Trusted": False, "Connected": False, "Blocked": False, "ServicesResolved": False, "UUIDs": [], **props}
        return p

    # ---- BluezAPI
    def available(self) -> bool:
        return self.up

    def _check(self) -> None:
        if not self.up:
            raise BluetoothError("The Bluetooth service (bluetoothd) is not running.")

    def objects(self) -> dict[str, dict[str, dict[str, Any]]]:
        self._check()
        if any(a.get("Discovering") for a in self.adapters.values()):
            self.tick += 1
            for when, adapter, props in list(self.reveal):
                if when <= self.tick:
                    self.reveal.remove((when, adapter, props))
                    self.add_device(adapter, props["Address"], **{k: v for k, v in props.items() if k != "Address"})
            for p, d in self.devices.items():
                fn = self.rssi_script.get(d["Address"])
                if fn:
                    v = fn(self.tick)
                    if v is None:
                        d.pop("RSSI", None)
                    else:
                        d["RSSI"] = v
        out: dict[str, dict[str, dict[str, Any]]] = {p: {ADAPTER: dict(a)} for p, a in self.adapters.items()}
        out.update({p: {DEVICE: dict(d)} for p, d in self.devices.items()})
        for p, ifs in self.gatt.items():
            out.setdefault(p, {}).update({i: dict(v) for i, v in ifs.items()})      # extra interfaces (Battery1...) on an existing object
        return out

    def get_prop(self, path: str, iface: str, name: str) -> Any:
        self._check()
        table = self.adapters if path in self.adapters else self.devices
        if path not in table or name not in table[path]:
            raise BluetoothError("That Bluetooth object no longer exists.")
        return table[path][name]

    def set_prop(self, path: str, iface: str, name: str, value: Any) -> None:
        self._check()
        self.calls.append(("set", path, iface, name, value))
        key = (path, f"set:{name}")
        if key in self.fail:
            raise BluetoothError(self.fail[key])
        table = self.adapters if path in self.adapters else self.devices
        table[path][name] = value

    def call(self, path: str, iface: str, method: str, args: tuple = (), timeout: float = 30.0) -> Any:
        self._check()
        self.calls.append((path, iface, method, args))
        for key in ((path, method), (iface, method)):
            if key in self.fail:
                raise BluetoothError(self.fail[key])
        if iface == ADAPTER:
            a = self.adapters[path]
            if method == "StartDiscovery":
                if not a["Powered"]:
                    raise BluetoothError("The Bluetooth adapter is not ready (is it powered on?).")
                a["Discovering"] = True
            elif method == "StopDiscovery":
                a["Discovering"] = False
            elif method == "SetDiscoveryFilter":
                a["_filter"] = dict(args[0]) if args else {}
            elif method == "RemoveDevice":
                self.devices.pop(args[0], None)
            return None
        if iface == DEVICE:
            d = self.devices[path]
            if method == "Pair":
                if self.pair_script:
                    self.pair_script(path, self.agent)           # may raise BluetoothError to simulate a rejection or timeout
                d["Paired"] = d["Bonded"] = True
            elif method == "Connect":
                d["Connected"] = True
                d["ServicesResolved"] = True
            elif method == "Disconnect":
                d["Connected"] = False
                d["ServicesResolved"] = False
            return None
        if iface == GATT_CHAR:
            if method == "ReadValue":
                return self.values.get(path, b"")
            if method == "WriteValue":
                self.values[path] = bytes(args[0])
                return None
            if method in ("StartNotify", "StopNotify"):
                return None
        if iface == GATT_DESC and method == "ReadValue":
            return self.values.get(path, b"")
        return None

    # ---- watchers and agent
    def watch(self, path_prefix: str, callback) -> Any:
        token = (path_prefix, callback)
        self.watchers.append(token)
        return token

    def unwatch(self, token: Any) -> None:
        if token in self.watchers:
            self.watchers.remove(token)

    def emit(self, path: str, iface: str, changed: dict) -> None:
        for prefix, cb in list(self.watchers):
            if path.startswith(prefix):
                cb(path, iface, dict(changed))

    def push_value(self, char_path: str, value: bytes) -> None:
        """A notification arriving from the device."""
        self.values[char_path] = value
        self.emit(char_path, GATT_CHAR, {"Value": value})

    def register_agent(self, handler, capability: str = "KeyboardDisplay") -> Any:
        self.agent = handler
        self.calls.append(("agent", "register", capability))
        return ("agent", handler)

    def unregister_agent(self, token: Any) -> None:
        self.agent = None
        self.calls.append(("agent", "unregister"))

    # ---- GATT scene helper
    def add_gatt(self, device: str, services: dict[str, dict[str, dict]]) -> None:
        """services = {service_uuid: {char_uuid: {"flags": [...], "value": b""}}}"""
        for si, (suuid, chars) in enumerate(services.items()):
            sp = f"{device}/service{si:04x}"
            self.gatt[sp] = {GATT_SERVICE: {"UUID": suuid, "Primary": True, "Device": device}}
            for ci, (cuuid, spec) in enumerate(chars.items()):
                cp = f"{sp}/char{ci:04x}"
                self.gatt[cp] = {GATT_CHAR: {"UUID": cuuid, "Service": sp, "Flags": list(spec.get("flags", [])), "Notifying": False}}
                self.values[cp] = spec.get("value", b"")
                for di, (duuid, dval) in enumerate(spec.get("descriptors", {}).items()):
                    dp = f"{cp}/desc{di:04x}"
                    self.gatt[dp] = {GATT_DESC: {"UUID": duuid, "Characteristic": cp, "Flags": ["read"]}}
                    self.values[dp] = dval
