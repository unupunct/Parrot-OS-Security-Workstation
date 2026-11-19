"""BluetoothDeviceManager: pair, connect, disconnect, trust, untrust and remove devices through BlueZ.

Every state-changing call needs `confirmed=True` (the UI asks the user first) and nothing runs automatically. Pairing uses a temporary
agent so the user answers confirmation / PIN / passkey requests in the UI; keys and PINs are never read, stored or logged -- BlueZ
keeps the bond. "Remove pairing" only calls BlueZ's RemoveDevice; it never touches files. Results are recorded in the inventory's
connection history (address, event, result: no secrets).

Tested against the in-memory BlueZ (fake.py). Not yet exercised against real devices."""
from __future__ import annotations

from typing import Callable

from .bluez import ADAPTER, DEVICE, AgentHandler, BluezAPI
from .models import BluetoothError, DeviceInfo, OpResult, device_from_props, validate_address

PAIR_TIMEOUT = 60.0
CONNECT_TIMEOUT = 30.0


class BluetoothDeviceManager:
    def __init__(self, api: BluezAPI, inventory=None, audit: Callable[..., None] | None = None) -> None:
        self.api, self.inventory, self._audit = api, inventory, audit

    # ------------------------------------------------------------------ reading
    def known(self) -> list[DeviceInfo]:
        """Devices BlueZ knows about (paired, trusted or recently seen), straight from BlueZ."""
        out = []
        for path, ifs in self.api.objects().items():
            if DEVICE in ifs:
                out.append(device_from_props(path, ifs[DEVICE]))
        return sorted(out, key=lambda d: (not d.connected, not d.paired, d.display_name.lower() or "~", d.address))

    def get(self, address: str) -> DeviceInfo:
        address = validate_address(address)
        for d in self.known():
            if d.address == address:
                return d
        raise BluetoothError("BlueZ does not know this device (anymore). Run a scan so it appears again.")

    def refresh(self, address: str) -> DeviceInfo:
        """Re-read the device's properties from BlueZ. It does not contact the device."""
        return self.get(address)

    # ------------------------------------------------------------------ actions
    def _note(self, address: str, event: str, result: str, detail: str = "") -> None:
        if self.inventory is not None:
            try:
                self.inventory.log_event(address, event, result, detail)
            except Exception:                              # history must never break the operation itself
                pass
        if self._audit:
            self._audit(f"bluetooth.{event}", address=address, result=result)

    def _need(self, confirmed: bool, what: str) -> None:
        if not confirmed:
            raise BluetoothError(f"{what} needs your confirmation first.")

    def _run(self, address: str, event: str, ok_message: str, fn: Callable[[DeviceInfo], None], confirmed: bool, label: str) -> OpResult:
        self._need(confirmed, label)
        dev = self.get(address)
        try:
            fn(dev)
        except BluetoothError as e:
            self._note(dev.address, event, "failed", str(e))
            return OpResult(False, f"{label} failed: {e}", str(e))
        self._note(dev.address, event, "ok")
        return OpResult(True, ok_message, data=self.get(dev.address) if event != "remove" else None)

    def pair(self, address: str, confirmed: bool, handler: AgentHandler | None = None, timeout: float = PAIR_TIMEOUT) -> OpResult:
        """Pair with a device. `handler` answers the pairing prompts (see bluez.AgentHandler); with no handler BlueZ's own agent, if any,
        is used. The agent is removed again whatever the outcome."""
        self._need(confirmed, "Pairing")
        dev = self.get(address)
        if dev.paired:
            return OpResult(True, f"{dev.address} is already paired.")
        token = None
        if handler is not None:
            token = self.api.register_agent(handler)
        try:
            self.api.call(dev.path, DEVICE, "Pair", (), timeout)
        except BluetoothError as e:
            self._note(dev.address, "pair", "failed", str(e))
            return OpResult(False, f"Pairing failed: {e}", str(e))
        finally:
            if token is not None:
                self.api.unregister_agent(token)
        self._note(dev.address, "pair", "ok")
        return OpResult(True, f"Paired with {dev.display_name or dev.address}.", data=self.get(dev.address))

    def connect(self, address: str, confirmed: bool) -> OpResult:
        return self._run(address, "connect", "Connected.", lambda d: self.api.call(d.path, DEVICE, "Connect", (), CONNECT_TIMEOUT), confirmed, "Connecting")

    def disconnect(self, address: str, confirmed: bool) -> OpResult:
        return self._run(address, "disconnect", "Disconnected.", lambda d: self.api.call(d.path, DEVICE, "Disconnect", (), CONNECT_TIMEOUT),
                         confirmed, "Disconnecting")

    def set_trusted(self, address: str, trusted: bool, confirmed: bool) -> OpResult:
        """A trusted device may reconnect on its own without asking -- that is why this needs confirmation."""
        return self._run(address, "trust" if trusted else "untrust", "Trusted: it may now reconnect by itself." if trusted else "No longer trusted.",
                         lambda d: self.api.set_prop(d.path, DEVICE, "Trusted", bool(trusted)), confirmed, "Changing trust")

    def remove_pairing(self, address: str, confirmed: bool) -> OpResult:
        """Ask BlueZ to forget the device (its bond and cached data). Refused while connected: disconnect first."""
        self._need(confirmed, "Removing a pairing")
        dev = self.get(address)
        if dev.connected:
            return OpResult(False, "Disconnect the device first; BlueZ would drop the link as it removes the pairing.")
        return self._run(address, "remove", "Pairing removed. The device can be paired again later.",
                         lambda d: self.api.call(d.adapter or d.path.rsplit("/", 1)[0], ADAPTER, "RemoveDevice", (d.path,)), True, "Removing the pairing")
