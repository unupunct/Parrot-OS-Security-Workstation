"""Device classification that never overstates what is known.

`confirmed` means the operating system itself says so (the default route names the gateway; an interface address names this computer).
`inferred` means a hint (vendor name, host name, private MAC address): the reason is always returned so it can be shown and judged.
No port scans, banners or fingerprinting are used."""
from __future__ import annotations

from dataclasses import dataclass

CONFIRMED, INFERRED, UNKNOWN = "confirmed", "inferred", "unknown"

# vendor keyword (lower case) -> device type. Only vendors whose products are overwhelmingly one kind are listed.
VENDOR_RULES: list[tuple[tuple[str, ...], str]] = [
    (("canon", "epson", "brother", "xerox", "lexmark", "kyocera", "ricoh", "konica", "oki data", "zebra tech"), "Printer"),
    (("tp-link", "tp link", "netgear", "d-link", "ubiquiti", "mikrotik", "zyxel", "tenda", "arris", "fiberhome", "technicolor", "linksys",
      "aruba", "ruckus", "cisco", "juniper", "sagemcom", "zte corporation", "huawei technologies"), "Network equipment"),
    (("espressif", "tuya", "shelly", "sonoff", "itead", "xiaomi communications"), "Smart-home / IoT device"),
    (("dahua", "hikvision", "reolink", "axis communications", "amcrest"), "IP camera"),
    (("synology", "qnap", "western digital", "wd my"), "Storage / NAS"),
    (("roku", "vizio", "sonos", "amazon technologies", "chromecast"), "Media / TV device"),
    (("lg electronics", "samsung electronics", "tcl", "hisense", "sony visual"), "TV / appliance"),
    (("raspberry pi",), "Single-board computer"),
    (("intel corporate", "dell", "lenovo", "micro-star", "gigabyte", "asrock", "giga-byte", "hon hai", "realtek", "microsoft"), "Computer"),
    (("xiaomi", "oneplus", "oppo", "vivo", "realme", "motorola mobility", "huawei device", "honor"), "Phone / tablet"),
]
HOSTNAME_RULES: list[tuple[tuple[str, ...], str]] = [
    (("iphone", "ipad", "android", "galaxy", "pixel", "redmi", "oneplus"), "Phone / tablet"),
    (("printer", "laserjet", "deskjet", "officejet", "mfp", "epson", "canon", "brother"), "Printer"),
    (("webos", "bravia", "roku", "firetv", "appletv", "chromecast", "smarttv", "-tv", "tv-"), "TV / media device"),
    (("router", "gateway", "modem", "access-point", "ap-"), "Network equipment"),
    (("nas", "synology", "diskstation"), "Storage / NAS"),
    (("desktop", "laptop", "macbook", "imac", "workstation", "-pc", "pc-"), "Computer"),
    (("camera", "cam-", "ipcam"), "IP camera"),
]


@dataclass(frozen=True)
class Classification:
    device_type: str
    basis: str                  # confirmed | inferred | unknown
    reason: str


def is_private_mac(mac: str | None) -> bool:
    """The locally-administered bit is set: the address was chosen by the device (privacy randomisation), not assigned by a vendor."""
    try:
        return bool(int((mac or "").split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def classify(ip: str, mac: str | None, vendor: str | None, hostname: str | None, *, is_self: bool = False,
             is_gateway: bool = False) -> Classification:
    if is_self:
        return Classification("This computer", CONFIRMED, "the address belongs to one of this computer's interfaces")
    if is_gateway:
        return Classification("Gateway / router", CONFIRMED, "it is the next hop of the default route")
    host = (hostname or "").lower()
    for words, kind in HOSTNAME_RULES:
        hit = next((w for w in words if w in host), None)
        if hit:
            return Classification(kind, INFERRED, f"host name contains “{hit}”")
    v = (vendor or "").lower()
    for words, kind in VENDOR_RULES:
        hit = next((w for w in words if w in v), None)
        if hit:
            return Classification(kind, INFERRED, f"manufacturer “{vendor}” mostly makes this kind of device")
    if is_private_mac(mac):
        return Classification("Private-MAC device", INFERRED,
                              "the MAC address is randomised (typical of phones, tablets and laptops that hide their identity)")
    if vendor:
        return Classification("Unknown", UNKNOWN, f"manufacturer “{vendor}” makes many kinds of device")
    return Classification("Unknown", UNKNOWN, "no manufacturer or host name evidence")
