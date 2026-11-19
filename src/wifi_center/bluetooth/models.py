"""Data models shared by the Bluetooth modules."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import registry as reg

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class BluetoothError(RuntimeError):
    """A Bluetooth operation failed or is not supported; the message is meant for the user."""


def validate_address(address: str) -> str:
    a = (address or "").strip().upper()
    if not MAC_RE.match(a):
        raise ValueError("invalid Bluetooth address (expected AA:BB:CC:DD:EE:FF)")
    return a


def address_kind(address: str, address_type: str | None) -> str:
    """public | random-static | resolvable-private | non-resolvable-private | unknown. For random addresses the top two bits
    of the first byte say which kind it is; a public address never changes, which is what makes a device trackable."""
    if address_type == "public":
        return "public"
    try:
        top = int(address.split(":")[0], 16) & 0xC0
    except ValueError:
        return "unknown"
    if address_type == "random":
        return {0xC0: "random-static", 0x40: "resolvable-private", 0x00: "non-resolvable-private"}.get(top, "random")
    return "unknown"


@dataclass
class AdapterInfo:
    path: str                     # /org/bluez/hci1
    name: str                     # hci1
    address: str = ""
    alias: str = ""
    powered: bool = False
    discoverable: bool = False
    pairable: bool = False
    discovering: bool = False
    modalias: str = ""
    roles: list[str] = field(default_factory=list)
    uuids: list[str] = field(default_factory=list)
    # from btmgmt / sysfs / hciconfig (filled by the adapter manager)
    manufacturer: str = ""
    hci_version: str = ""
    driver: str = ""
    bus: str = ""
    usb_id: str = ""
    usb_name: str = ""
    supported_settings: list[str] = field(default_factory=list)
    current_settings: list[str] = field(default_factory=list)
    lmp_features: list[str] = field(default_factory=list)
    hci_revision: str = ""
    lmp_subversion: str = ""
    rfkill: str = ""

    @property
    def firmware(self) -> str:
        """The kernel does not report a firmware version; the controller's own revision numbers are the closest identifier."""
        return f"HCI revision {self.hci_revision}, LMP subversion {self.lmp_subversion}" if self.hci_revision else "not reported by the controller"

    @property
    def classic(self) -> bool | None:
        s = self.supported_settings
        return ("br/edr" in s) if s else None

    @property
    def ble(self) -> bool | None:
        s = self.supported_settings
        return ("le" in s) if s else None


@dataclass
class DeviceInfo:
    path: str
    address: str
    adapter: str = ""
    name: str = ""
    alias: str = ""
    address_type: str = ""
    icon: str = ""
    cod: int | None = None
    appearance: int | None = None
    rssi: int | None = None
    tx_power: int | None = None
    paired: bool = False
    bonded: bool = False
    trusted: bool = False
    connected: bool = False
    blocked: bool = False
    legacy_pairing: bool | None = None
    services_resolved: bool = False
    uuids: list[str] = field(default_factory=list)
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    service_data: dict[str, bytes] = field(default_factory=dict)
    advertising_flags: bytes = b""
    modalias: str = ""
    battery: int | None = None
    last_update: float | None = None      # monotonic time the RSSI last changed, as seen by the scanner

    @property
    def display_name(self) -> str:
        n = (self.alias or self.name or "").strip()
        return "" if n.replace("-", ":").upper() == self.address.upper() else n

    @property
    def manufacturer(self) -> str:
        return ", ".join(reg.company_name(c) for c in sorted(self.manufacturer_data)) if self.manufacturer_data else ""

    @property
    def technology(self) -> str:
        """Classic / BLE / Dual Mode, inferred from what BlueZ reports (BlueZ has no explicit transport field)."""
        classic = self.cod is not None
        ble = bool(self.manufacturer_data or self.service_data or self.advertising_flags or self.appearance is not None
                   or self.address_type == "random")
        if classic and ble:
            return "Dual Mode"
        if classic:
            return "Classic"
        if ble:
            return "BLE"
        return "Unknown"

    @property
    def device_type(self) -> str:
        return (reg.class_of_device(self.cod) or reg.appearance_name(self.appearance) or self.icon or "Unknown").strip()

    @property
    def address_privacy(self) -> str:
        return address_kind(self.address, self.address_type)

    @property
    def signal_quality(self) -> str:
        r = self.rssi
        return "unknown" if r is None else "good" if r >= -60 else "fair" if r >= -75 else "weak"

    @property
    def uuid_labels(self) -> list[str]:
        return reg.uuid_labels(self.uuids)

    def adv_fingerprint(self) -> str:
        """A stable summary of what the device advertises (used to notice changes between scans)."""
        md = ";".join(f"{k:04x}:{v.hex()}" for k, v in sorted(self.manufacturer_data.items()))
        sd = ";".join(f"{k}:{v.hex()}" for k, v in sorted(self.service_data.items()))
        return f"{self.display_name}|{','.join(sorted(self.uuids))}|{md}|{sd}"


def _plain_bytes(v) -> bytes:
    return bytes(v) if not isinstance(v, (bytes, bytearray)) else bytes(v)


def device_from_props(path: str, props: dict, adapter: str = "") -> DeviceInfo:
    g = props.get
    return DeviceInfo(
        path=path, address=str(g("Address", "")).upper(), adapter=adapter or str(g("Adapter", "")), name=str(g("Name", "") or ""),
        alias=str(g("Alias", "") or ""), address_type=str(g("AddressType", "") or ""), icon=str(g("Icon", "") or ""),
        cod=g("Class"), appearance=g("Appearance"), rssi=g("RSSI"), tx_power=g("TxPower"), paired=bool(g("Paired", False)),
        bonded=bool(g("Bonded", False)), trusted=bool(g("Trusted", False)), connected=bool(g("Connected", False)),
        blocked=bool(g("Blocked", False)), legacy_pairing=g("LegacyPairing"), services_resolved=bool(g("ServicesResolved", False)),
        uuids=[str(u).lower() for u in (g("UUIDs") or [])],
        manufacturer_data={int(k): _plain_bytes(v) for k, v in (g("ManufacturerData") or {}).items()},
        service_data={str(k).lower(): _plain_bytes(v) for k, v in (g("ServiceData") or {}).items()},
        advertising_flags=_plain_bytes(g("AdvertisingFlags") or b""), modalias=str(g("Modalias", "") or ""))


@dataclass
class OpResult:
    ok: bool
    message: str
    detail: str = ""
    data: object = None

    def __bool__(self) -> bool:
        return self.ok


SEVERITIES = ("informational", "low", "medium", "high", "critical")
STATUSES = ("confirmed", "observation", "unknown")


@dataclass
class Finding:
    title: str
    severity: str                 # SEVERITIES
    status: str                   # confirmed (verified here), observation (declared/advertised), unknown (could not be determined)
    device: str                   # address
    evidence: str
    explanation: str
    remediation: str
    timestamp: str = field(default_factory=utcnow)
    check: str = ""
    id: int | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
