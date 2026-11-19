"""Bluetooth SIG name registries (a compact built-in subset): services, classic profiles, characteristics, descriptors,
company identifiers, appearance and Class-of-Device decoding. Unknown values are reported as unknown, never guessed."""
from __future__ import annotations

BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"

SERVICES = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute", 0x1802: "Immediate Alert", 0x1803: "Link Loss", 0x1804: "Tx Power",
    0x1805: "Current Time", 0x1808: "Glucose", 0x1809: "Health Thermometer", 0x180A: "Device Information", 0x180D: "Heart Rate",
    0x180F: "Battery", 0x1810: "Blood Pressure", 0x1812: "Human Interface Device", 0x1814: "Running Speed and Cadence",
    0x1816: "Cycling Speed and Cadence", 0x1818: "Cycling Power", 0x1819: "Location and Navigation", 0x181A: "Environmental Sensing",
    0x181C: "User Data", 0x181D: "Weight Scale", 0x1820: "Internet Protocol Support", 0x1821: "Indoor Positioning",
    0x1822: "Pulse Oximeter", 0x1826: "Fitness Machine", 0x1827: "Mesh Provisioning", 0x1828: "Mesh Proxy",
    0x183A: "Insulin Delivery", 0xFE59: "Nordic DFU (firmware update)",
}
PROFILES = {
    0x1101: "Serial Port (SPP)", 0x1103: "Dial-up Networking", 0x1105: "OBEX Object Push", 0x1106: "OBEX File Transfer",
    0x1108: "Headset", 0x110A: "Audio Source (A2DP)", 0x110B: "Audio Sink (A2DP)", 0x110C: "A/V Remote Control Target",
    0x110D: "Advanced Audio Distribution", 0x110E: "A/V Remote Control", 0x1112: "Headset Audio Gateway", 0x1115: "PAN User",
    0x1116: "Network Access Point", 0x1117: "Group Ad-hoc Network", 0x111E: "Hands-Free", 0x111F: "Hands-Free Audio Gateway",
    0x1124: "Human Interface Device", 0x112D: "SIM Access", 0x112F: "Phonebook Access Server", 0x1130: "Phonebook Access Client",
    0x1132: "Message Access Server", 0x1133: "Message Notification Server", 0x1134: "Message Access Profile",
    0x1200: "PnP Information", 0x1800: "Generic Access", 0x1801: "Generic Attribute",
}
CHARACTERISTICS = {
    0x2A00: "Device Name", 0x2A01: "Appearance", 0x2A02: "Peripheral Privacy Flag", 0x2A03: "Reconnection Address",
    0x2A04: "Peripheral Preferred Connection Parameters", 0x2A05: "Service Changed", 0x2A06: "Alert Level", 0x2A07: "Tx Power Level",
    0x2A19: "Battery Level", 0x2A23: "System ID", 0x2A24: "Model Number String", 0x2A25: "Serial Number String",
    0x2A26: "Firmware Revision String", 0x2A27: "Hardware Revision String", 0x2A28: "Software Revision String",
    0x2A29: "Manufacturer Name String", 0x2A2B: "Current Time", 0x2A37: "Heart Rate Measurement", 0x2A38: "Body Sensor Location",
    0x2A39: "Heart Rate Control Point", 0x2A4A: "HID Information", 0x2A4B: "Report Map", 0x2A4C: "HID Control Point",
    0x2A4D: "Report", 0x2A4E: "Protocol Mode", 0x2A50: "PnP ID", 0x2A6D: "Pressure", 0x2A6E: "Temperature", 0x2A6F: "Humidity",
    0x2A9F: "User Control Point",
}
DESCRIPTORS = {
    0x2900: "Characteristic Extended Properties", 0x2901: "Characteristic User Description", 0x2902: "Client Characteristic Configuration",
    0x2903: "Server Characteristic Configuration", 0x2904: "Characteristic Presentation Format", 0x2908: "Report Reference",
}
# Characteristics that hold identifying or personal data: reading them without authentication is worth flagging.
SENSITIVE_CHARACTERISTICS = {0x2A25: "serial number", 0x2A23: "system ID", 0x2A3C: "date of birth", 0x2A8A: "first name",
                             0x2A90: "last name", 0x2A87: "email address", 0x2A6B: "location", 0x2A67: "location and speed",
                             0x2A37: "heart rate", 0x2A4D: "HID input report", 0x2A4B: "HID report map"}
COMPANIES = {
    0x0000: "Ericsson Technology Licensing", 0x0001: "Nokia Mobile Phones", 0x0002: "Intel Corp.", 0x0003: "IBM Corp.",
    0x0006: "Microsoft", 0x0008: "Motorola", 0x0009: "Infineon Technologies", 0x000D: "Texas Instruments", 0x000F: "Broadcom",
    0x001D: "Qualcomm", 0x0030: "STMicroelectronics", 0x0046: "MediaTek", 0x004C: "Apple, Inc.", 0x0059: "Nordic Semiconductor",
    0x005D: "Realtek Semiconductor", 0x0075: "Samsung Electronics", 0x0087: "Garmin International", 0x00D2: "Dialog Semiconductor",
    0x00E0: "Google", 0x012D: "Sony Corporation", 0x0157: "Anhui Huami Information Technology", 0x0171: "Amazon.com Services",
    0x02E5: "Espressif Incorporated", 0x038F: "Xiaomi Inc.",
}
APPEARANCE = {1: "Phone", 2: "Computer", 3: "Watch", 4: "Clock", 5: "Display", 6: "Remote control", 7: "Smart glasses", 8: "Tag",
              9: "Keyring", 10: "Media player", 11: "Barcode scanner", 12: "Thermometer", 13: "Heart rate sensor",
              14: "Blood pressure monitor", 15: "Input device (HID)", 16: "Glucose meter", 17: "Running/walking sensor",
              18: "Cycling sensor", 49: "Pulse oximeter", 50: "Weight scale", 51: "Personal mobility device",
              52: "Continuous glucose monitor", 53: "Insulin pump", 54: "Medication delivery", 81: "Outdoor sports device"}
HCI_VERSIONS = {0: "1.0b", 1: "1.1", 2: "1.2", 3: "2.0+EDR", 4: "2.1+EDR", 5: "3.0+HS", 6: "4.0", 7: "4.1", 8: "4.2", 9: "5.0",
                10: "5.1", 11: "5.2", 12: "5.3", 13: "5.4", 14: "6.0"}
_MAJOR = {0: "Miscellaneous", 1: "Computer", 2: "Phone", 3: "Network access point", 4: "Audio/Video", 5: "Peripheral", 6: "Imaging",
          7: "Wearable", 8: "Toy", 9: "Health"}
_AV_MINOR = {1: "Wearable headset", 2: "Hands-free", 4: "Microphone", 5: "Loudspeaker", 6: "Headphones", 7: "Portable audio",
             8: "Car audio", 9: "Set-top box", 10: "HiFi audio", 11: "VCR", 12: "Video camera", 13: "Camcorder", 14: "Video monitor",
             15: "Video display and loudspeaker", 16: "Video conferencing", 18: "Gaming/toy"}
_PHONE_MINOR = {1: "Cellular", 2: "Cordless", 3: "Smartphone", 4: "Wired modem", 5: "ISDN"}
_COMPUTER_MINOR = {1: "Desktop", 2: "Server", 3: "Laptop", 4: "Handheld PC/PDA", 5: "Palm-size PC/PDA", 6: "Wearable computer"}


def uuid16(uuid: str) -> int | None:
    """The 16-bit value of a Bluetooth-base UUID (0000XXXX-0000-1000-8000-00805f9b34fb), else None (a 128-bit custom UUID)."""
    u = uuid.lower()
    if u.endswith(BASE_UUID_SUFFIX) and u.startswith("0000") and len(u) == 36:
        try:
            return int(u[4:8], 16)
        except ValueError:
            return None
    return None


def short_uuid(uuid: str) -> str:
    v = uuid16(uuid)
    return f"0x{v:04X}" if v is not None else uuid


def _name(table: dict[int, str], uuid: str) -> str | None:
    v = uuid16(uuid)
    return table.get(v) if v is not None else None


def service_name(uuid: str) -> str:
    n = _name(SERVICES, uuid) or _name(PROFILES, uuid)
    if n:
        return n
    return "Unknown standard UUID" if uuid16(uuid) is not None else "Custom (vendor-specific) UUID"


def characteristic_name(uuid: str) -> str:
    n = _name(CHARACTERISTICS, uuid)
    return n or ("Unknown standard characteristic" if uuid16(uuid) is not None else "Custom (vendor-specific) characteristic")


def descriptor_name(uuid: str) -> str:
    return _name(DESCRIPTORS, uuid) or ("Unknown descriptor" if uuid16(uuid) is not None else "Custom descriptor")


def is_standard(uuid: str) -> bool:
    return uuid16(uuid) is not None


def company_name(company_id: int) -> str:
    return COMPANIES.get(company_id, f"company 0x{company_id:04X}")


def appearance_name(value: int | None) -> str | None:
    if value is None:
        return None
    return APPEARANCE.get(value >> 6)


def class_of_device(cod: int | None) -> str | None:
    """Major / minor device class from the Class of Device value (Classic Bluetooth only)."""
    if not cod:
        return None
    major = (cod >> 8) & 0x1F
    minor = (cod >> 2) & 0x3F
    name = _MAJOR.get(major, f"class {major}")
    sub = None
    if major == 4:
        sub = _AV_MINOR.get(minor)
    elif major == 2:
        sub = _PHONE_MINOR.get(minor)
    elif major == 1:
        sub = _COMPUTER_MINOR.get(minor)
    elif major == 5:
        sub = {1: "Keyboard", 2: "Pointing device", 3: "Keyboard and pointing device"}.get((cod >> 6) & 3)
    return f"{name} / {sub}" if sub else name


def uuid_labels(uuids: list[str]) -> list[str]:
    return [f"{short_uuid(u)} {service_name(u)}" if uuid16(u) is not None else f"{u} ({service_name(u)})" for u in uuids]


def hci_version(code: int | None) -> str:
    return HCI_VERSIONS.get(code, f"unknown (HCI version {code})") if code is not None else "unknown"
