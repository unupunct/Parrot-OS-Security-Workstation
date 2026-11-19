"""BluetoothDeviceInspector: everything BlueZ and the inventory know about one device, in one structure.

Read-only: it never connects. Services are what BlueZ cached from earlier connections or from the advertisement; if the device has
not been connected, the list may be empty and the result says so rather than guessing."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import registry as reg
from .bluez import BATTERY, DEVICE, GATT_SERVICE, BluezAPI
from .models import DeviceInfo, device_from_props, validate_address

_MODALIAS = re.compile(r"^(usb|bluetooth):v([0-9A-Fa-f]{4})p([0-9A-Fa-f]{4})d([0-9A-Fa-f]{4})$")
SOURCES = {"usb": "USB Implementers Forum", "bluetooth": "Bluetooth SIG"}


def parse_modalias(text: str) -> dict | None:
    """usb:v1D6Bp0246d0552 -> {source, vendor_id, product_id, version}. Vendor names are resolved only for Bluetooth SIG ids."""
    m = _MODALIAS.match((text or "").strip())
    if not m:
        return None
    src, v, p, d = m.groups()
    vendor = int(v, 16)
    return {"source": src, "source_name": SOURCES[src], "vendor_id": f"{vendor:04X}", "product_id": p.upper(), "version": d.upper(),
            "vendor": reg.company_name(vendor) if src == "bluetooth" else ""}


@dataclass
class Inspection:
    device: DeviceInfo
    inventory: dict | None = None
    modalias: dict | None = None
    profiles: list[str] = field(default_factory=list)          # from the UUID list (Classic profiles and advertised services)
    gatt_services: list[dict] = field(default_factory=list)    # resolved GATT services (uuid, name, standard, primary)
    battery: int | None = None
    history: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)             # what could not be determined, and why

    def properties(self) -> list[tuple[str, str]]:
        d = self.device
        yes = lambda b: "yes" if b else "no"                   # noqa: E731
        rows = [("Name", d.display_name or "(unnamed)"), ("Address", d.address), ("Address type", f"{d.address_type or 'unknown'} ({d.address_privacy})"),
                ("Technology", f"{d.technology} (inferred)"), ("Device type", d.device_type), ("Manufacturer", d.manufacturer or "not advertised"),
                ("Signal", "not available" if d.rssi is None else f"{d.rssi} dBm ({d.signal_quality})"),
                ("TX power", "not advertised" if d.tx_power is None else f"{d.tx_power} dBm"),
                ("Paired", yes(d.paired)), ("Bonded", yes(d.bonded)), ("Trusted", yes(d.trusted)), ("Connected", yes(d.connected)),
                ("Blocked", yes(d.blocked)), ("Services resolved", yes(d.services_resolved)),
                ("Legacy pairing", "not reported" if d.legacy_pairing is None else yes(d.legacy_pairing)),
                ("Battery", "not reported" if self.battery is None else f"{self.battery} %")]
        if self.modalias:
            m = self.modalias
            rows.append(("Device ID", f"{m['source_name']} vendor {m['vendor_id']}" + (f" ({m['vendor']})" if m["vendor"] else "") +
                         f", product {m['product_id']}, version {m['version']}"))
        return rows


class BluetoothDeviceInspector:
    def __init__(self, api: BluezAPI, inventory=None) -> None:
        self.api, self.inventory = api, inventory

    def inspect(self, address: str) -> Inspection:
        address = validate_address(address)
        objs = self.api.objects()
        dev_path = next((p for p, i in objs.items() if DEVICE in i and str(i[DEVICE].get("Address", "")).upper() == address), None)
        if dev_path is None:
            known = self.inventory.device(address) if self.inventory else None
            stub = DeviceInfo(path="", address=address, name=(known or {}).get("name", ""))
            ins = Inspection(stub, inventory=known)
            ins.notes.append("BlueZ does not know this device right now, so live properties are unavailable. Scan to bring it back.")
            if self.inventory:
                ins.history = self.inventory.events(address, 50)
            return ins
        dev = device_from_props(dev_path, objs[dev_path][DEVICE])
        ins = Inspection(dev, modalias=parse_modalias(dev.modalias))
        ins.inventory = self.inventory.device(address) if self.inventory else None
        ins.profiles = dev.uuid_labels
        bat = objs.get(dev_path, {}).get(BATTERY, {}).get("Percentage")
        ins.battery = int(bat) if bat is not None else None
        for p, ifs in objs.items():
            if p.startswith(dev_path + "/") and GATT_SERVICE in ifs:
                u = str(ifs[GATT_SERVICE].get("UUID", "")).lower()
                ins.gatt_services.append({"uuid": u, "name": reg.service_name(u), "standard": reg.is_standard(u), "primary": bool(ifs[GATT_SERVICE].get("Primary", True)),
                                          "path": p})
        if not dev.services_resolved:
            ins.notes.append("Services are not resolved: the device is not connected (or BlueZ has not finished discovering them). The profile list "
                             "comes from the advertisement and earlier connections only.")
        if dev.rssi is None:
            ins.notes.append("No signal reading: BlueZ only has one while the device is being discovered.")
        if self.inventory:
            ins.history = self.inventory.events(address, 100)
        return ins
