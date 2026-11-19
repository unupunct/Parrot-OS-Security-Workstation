"""BLEExplorer: browse a connected device's GATT services, characteristics and descriptors; read values; subscribe to notifications.

Safety model
* Read-only by default. Browsing and reading never change anything on the device.
* Nothing connects automatically: the device must already be connected (use the Device Manager, which asks first).
* Writing needs ALL of: an explicitly selected characteristic, a device marked "mine / authorised" in the inventory, `confirmed=True`
  (the UI shows the target and the exact bytes first), a characteristic that declares write support, valid hex data of at most 512
  bytes, and a characteristic that is not on the deny-list (firmware update / bootloader / security-key services).
* Values of sensitive standard characteristics (serial number, personal data) are labelled so the UI can warn before showing them.

Tested against the in-memory BlueZ (fake.py). Not yet exercised against real devices."""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Callable

from . import registry as reg
from .bluez import DEVICE, GATT_CHAR, GATT_DESC, GATT_SERVICE, BluezAPI
from .models import BluetoothError, OpResult, validate_address

MAX_WRITE = 512
# Firmware update / bootloader style services and characteristics; writing to these can brick a device, so they are never offered.
DENY_UUIDS = {
    "8ec90001-f315-4f60-9fb8-838830daea50": "Nordic secure DFU", "00001530-1212-efde-1523-785feabcd123": "Nordic legacy DFU",
    "0000fe59-0000-1000-8000-00805f9b34fb": "Nordic DFU service", "00060000-f8ce-11e4-abf4-0002a5d5c51b": "Cypress OTA",
    "f000ffc0-0451-4000-b000-000000000000": "TI over-the-air download", "0000fd6f-0000-1000-8000-00805f9b34fb": "Exposure notification",
}
FLAG_TEXT = {"broadcast": "broadcast", "read": "read", "write-without-response": "write (no response)", "write": "write", "notify": "notify",
             "indicate": "indicate", "authenticated-signed-writes": "signed writes", "extended-properties": "extended", "reliable-write": "reliable write",
             "writable-auxiliaries": "writable aux", "encrypt-read": "read needs encryption", "encrypt-write": "write needs encryption",
             "encrypt-authenticated-read": "read needs authenticated pairing", "encrypt-authenticated-write": "write needs authenticated pairing",
             "secure-read": "read needs secure connection", "secure-write": "write needs secure connection", "authorize": "needs authorisation"}


@dataclass
class GattDescriptor:
    path: str
    uuid: str
    name: str


@dataclass
class GattCharacteristic:
    path: str
    uuid: str
    name: str
    flags: list[str]
    standard: bool
    sensitive: str = ""                  # reason, when the standard characteristic carries identifying/personal data
    descriptors: list[GattDescriptor] = field(default_factory=list)
    notifying: bool = False
    service_uuid: str = ""               # the owning service: a characteristic inherits its service's deny-list entry

    @property
    def readable(self) -> bool:
        return "read" in self.flags or any(f in self.flags for f in ("encrypt-read", "encrypt-authenticated-read", "secure-read"))

    @property
    def writable(self) -> bool:
        return any(f in self.flags for f in ("write", "write-without-response", "authenticated-signed-writes"))

    @property
    def can_notify(self) -> bool:
        return "notify" in self.flags or "indicate" in self.flags

    @property
    def protected(self) -> bool:
        """Needs encryption/authentication to access -- BlueZ will refuse or trigger pairing if the link is not secure."""
        return any(f.startswith(("encrypt-", "secure-")) or f == "authorize" for f in self.flags)

    @property
    def denied(self) -> str:
        return DENY_UUIDS.get(self.uuid, "") or DENY_UUIDS.get(self.service_uuid, "")

    def flag_text(self) -> str:
        return ", ".join(FLAG_TEXT.get(f, f) for f in self.flags) or "none declared"


@dataclass
class GattService:
    path: str
    uuid: str
    name: str
    standard: bool
    primary: bool
    characteristics: list[GattCharacteristic] = field(default_factory=list)

    @property
    def denied(self) -> str:
        return DENY_UUIDS.get(self.uuid, "")


# ------------------------------------------------------------------ value decoding (pure)
def hex_dump(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def parse_hex(text: str) -> bytes:
    """'01 02 0A', '0x01,0x02' or '01020a' -> bytes. Raises ValueError with a message the UI can show."""
    cleaned = re.sub(r"0x|[\s,:-]", "", (text or "").strip(), flags=re.I)
    if not cleaned:
        raise ValueError("enter at least one byte in hexadecimal, for example 01 0A FF")
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ValueError("only hexadecimal digits (0-9, A-F) are allowed")
    if len(cleaned) % 2:
        raise ValueError("odd number of hex digits: every byte needs two")
    data = bytes.fromhex(cleaned)
    if len(data) > MAX_WRITE:
        raise ValueError(f"at most {MAX_WRITE} bytes")
    return data


def decode_value(uuid: str, data: bytes) -> str:
    """A human reading for well-known characteristics; empty when there is no safe interpretation (the hex dump is always shown)."""
    code = reg.uuid16(uuid)
    try:
        if code in (0x2A00, 0x2A24, 0x2A25, 0x2A26, 0x2A27, 0x2A28, 0x2A29, 0x2A87):          # UTF-8 strings (name, model, serial, revisions, maker)
            text = data.decode("utf-8")
            return text if text.isprintable() else ""
        if code == 0x2A19 and len(data) == 1:
            return f"{data[0]} %"
        if code == 0x2A01 and len(data) == 2:
            v = struct.unpack("<H", data)[0]
            return f"appearance {v}: {reg.appearance_name(v >> 6) or 'unknown'}"
        if code == 0x2A04 and len(data) == 8:
            lo, hi, lat, to = struct.unpack("<HHHH", data)
            return f"connection interval {lo * 1.25:g}–{hi * 1.25:g} ms, latency {lat}, supervision timeout {to * 10} ms"
        if code == 0x2A50 and len(data) == 7:
            src, vid, pid, ver = struct.unpack("<BHHH", data)
            return f"{'Bluetooth SIG' if src == 1 else 'USB-IF' if src == 2 else 'unknown'} vendor {vid:04X}, product {pid:04X}, version {ver:04X}"
        if code == 0x2A6E and len(data) == 2:
            return f"{struct.unpack('<h', data)[0] / 100:.2f} °C"
    except (UnicodeDecodeError, struct.error):
        return ""
    return ""


class BLEExplorer:
    def __init__(self, api: BluezAPI, inventory=None, audit: Callable[..., None] | None = None) -> None:
        self.api, self.inventory, self._audit = api, inventory, audit
        self._subs: dict[str, object] = {}

    # ------------------------------------------------------------------ browsing
    def _device_path(self, objs: dict, address: str) -> str:
        for p, ifs in objs.items():
            if DEVICE in ifs and str(ifs[DEVICE].get("Address", "")).upper() == address:
                return p
        raise BluetoothError("BlueZ does not know this device. Scan first.")

    def tree(self, address: str) -> list[GattService]:
        """The device's GATT database as BlueZ has it. Needs a connected device with resolved services; never connects by itself."""
        address = validate_address(address)
        objs = self.api.objects()
        dp = self._device_path(objs, address)
        dev = objs[dp][DEVICE]
        if not dev.get("Connected") and not dev.get("ServicesResolved"):
            raise BluetoothError("The device is not connected. Connect it in the Device Manager (BLE devices only expose GATT while connected).")
        services: dict[str, GattService] = {}
        for p, ifs in sorted(objs.items()):
            if not p.startswith(dp + "/") or GATT_SERVICE not in ifs:
                continue
            u = str(ifs[GATT_SERVICE].get("UUID", "")).lower()
            services[p] = GattService(p, u, reg.service_name(u), reg.is_standard(u), bool(ifs[GATT_SERVICE].get("Primary", True)))
        chars: dict[str, GattCharacteristic] = {}
        for p, ifs in sorted(objs.items()):
            if GATT_CHAR in ifs and str(ifs[GATT_CHAR].get("Service", "")) in services:
                c = ifs[GATT_CHAR]
                u = str(c.get("UUID", "")).lower()
                code = reg.uuid16(u)
                ch = GattCharacteristic(p, u, reg.characteristic_name(u), [str(f) for f in c.get("Flags", [])], reg.is_standard(u),
                                        reg.SENSITIVE_CHARACTERISTICS.get(code, "") if code is not None else "", notifying=bool(c.get("Notifying", False)),
                                        service_uuid=services[str(c["Service"])].uuid)
                chars[p] = ch
                services[str(c["Service"])].characteristics.append(ch)
        for p, ifs in sorted(objs.items()):
            if GATT_DESC in ifs and str(ifs[GATT_DESC].get("Characteristic", "")) in chars:
                u = str(ifs[GATT_DESC].get("UUID", "")).lower()
                chars[str(ifs[GATT_DESC]["Characteristic"])].descriptors.append(GattDescriptor(p, u, reg.descriptor_name(u)))
        return list(services.values())

    # ------------------------------------------------------------------ reading
    def read(self, char: GattCharacteristic) -> bytes:
        """Read one characteristic (a GATT read request; it does not change the device)."""
        if not char.readable:
            raise BluetoothError("This characteristic does not declare read support.")
        try:
            return bytes(self.api.call(char.path, GATT_CHAR, "ReadValue", ({},), 15.0) or b"")
        except BluetoothError as e:
            raise BluetoothError(f"Read failed: {e}") from None

    def read_descriptor(self, desc: GattDescriptor) -> bytes:
        return bytes(self.api.call(desc.path, GATT_DESC, "ReadValue", ({},), 15.0) or b"")

    # ------------------------------------------------------------------ notifications
    def subscribe(self, char: GattCharacteristic, on_value: Callable[[bytes], None]) -> None:
        if not char.can_notify:
            raise BluetoothError("This characteristic does not declare notify or indicate.")
        if char.path in self._subs:
            return
        want = char.path
        # watch() matches by path prefix; deliver only this characteristic's own value changes
        token = self.api.watch(want, lambda path, iface, changed: on_value(bytes(changed["Value"])) if path == want and "Value" in changed else None)
        try:
            self.api.call(char.path, GATT_CHAR, "StartNotify", (), 15.0)
        except BluetoothError:
            self.api.unwatch(token)
            raise
        self._subs[char.path] = token

    def is_subscribed(self, char: GattCharacteristic) -> bool:
        return char.path in self._subs

    def unsubscribe(self, char: GattCharacteristic) -> None:
        token = self._subs.pop(char.path, None)
        if token is None:
            return
        self.api.unwatch(token)
        try:
            self.api.call(char.path, GATT_CHAR, "StopNotify", (), 15.0)
        except BluetoothError:
            pass

    def unsubscribe_all(self) -> None:
        for path in list(self._subs):
            self.unsubscribe(GattCharacteristic(path, "", "", [], False))

    # ------------------------------------------------------------------ writing (guarded)
    def write_blockers(self, address: str, char: GattCharacteristic) -> list[str]:
        """Reasons a write would be refused right now; empty means allowed (still needs confirmation)."""
        why = []
        if not char.writable:
            why.append("the characteristic does not declare write support")
        if char.denied:
            why.append(f"it belongs to {char.denied} (firmware update / security), which this tool never writes to")
        row = self.inventory.device(address) if self.inventory else None
        if not row or not row["authorized"]:
            why.append("the device is not marked as yours / authorised in the Device Inventory")
        return why

    def write(self, address: str, char: GattCharacteristic, data: bytes, confirmed: bool, response: bool = True) -> OpResult:
        address = validate_address(address)
        why = self.write_blockers(address, char)
        if why:
            return OpResult(False, "Write refused: " + "; ".join(why) + ".")
        if not confirmed:
            return OpResult(False, "Write refused: it needs your confirmation first.")
        if not data or len(data) > MAX_WRITE:
            return OpResult(False, f"Write refused: 1 to {MAX_WRITE} bytes are allowed.")
        mode = "request" if response and "write" in char.flags else "command"
        detail = f"{char.uuid} <- {len(data)} byte(s) ({mode})"                  # the value is not stored: it may be a secret
        try:
            self.api.call(char.path, GATT_CHAR, "WriteValue", (data, {"type": mode}), 15.0)
        except BluetoothError as e:
            self._note(address, "gatt-write", "failed", detail + f": {e}")
            return OpResult(False, f"Write failed: {e}", str(e))
        self._note(address, "gatt-write", "ok", detail)
        return OpResult(True, f"Wrote {len(data)} byte(s) to {char.name}.")

    def _note(self, address: str, event: str, result: str, detail: str) -> None:
        if self.inventory is not None:
            try:
                self.inventory.log_event(address, event, result, detail)
            except Exception:
                pass
        if self._audit:
            self._audit(f"bluetooth.{event.replace('-', '_')}", address=address, result=result)
