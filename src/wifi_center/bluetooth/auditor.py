"""BluetoothSecurityAuditor: evidence-based findings about a Bluetooth device you own or are authorised to assess.

What a finding means
* confirmed   -- verified here: BlueZ reported the property, or a read this tool performed on your explicit request succeeded.
* observation -- the device advertises or declares it (for example a service UUID or a characteristic flag); nothing was tested.
* unknown     -- it could not be determined from this computer, and the finding says why.
Severities run informational, low, medium, high, critical. "critical" is never assigned from advertised data alone.

Rules enforced in code, not only in the UI
* Only devices marked "mine / authorised" in the Device Inventory can be audited.
* The standard audit is passive: it reads properties BlueZ already holds. It sends nothing to the device.
* The deep audit needs `deep=True` AND `confirmed=True`, a connected device, and only performs GATT *reads* of characteristics that
  are readable. It never writes, never pairs, never tries keys, PINs or password guesses, and never attacks encryption.
* Findings are stored locally (bt_audits / bt_findings) until you clear them.

Tested against the in-memory BlueZ (fake.py). Not yet exercised against real devices."""
from __future__ import annotations

from typing import Callable

from ..database.repository import Database
from . import registry as reg
from .ble import DENY_UUIDS, BLEExplorer
from .bluez import BluezAPI
from .devices import BluetoothDeviceManager
from .models import SEVERITIES, BluetoothError, DeviceInfo, Finding, utcnow, validate_address

# service UUID (16-bit) -> (what it is, severity, why it matters)
EXPOSED = {
    0x1101: ("Serial Port Profile (SPP)", "low", "A serial channel is a general-purpose data pipe; devices that expose it without authentication let nearby hosts talk to whatever "
                                                 "is behind it."),
    0x1105: ("OBEX Object Push", "low", "Lets a peer push files to the device; historically a vector for unsolicited content."),
    0x1106: ("OBEX File Transfer", "medium", "Exposes a file-transfer service; without pairing and authorisation it can expose files."),
    0x1115: ("Personal Area Networking (PANU)", "low", "Network access over Bluetooth enlarges the attack surface of the host."),
    0x1116: ("Network Access Point (NAP)", "medium", "The device offers network access over Bluetooth."),
    0x1124: ("Human Interface Device (HID)", "low", "An input device profile: a rogue peer able to pair could inject keystrokes."),
    0x1812: ("HID over GATT", "low", "An input device profile: a rogue peer able to pair could inject keystrokes."),
    0x111F: ("Handsfree Audio Gateway", "low", "Call control and audio; relevant for devices that handle phone calls."),
}


def _f(check: str, title: str, severity: str, status: str, device: str, evidence: str, explanation: str, remediation: str) -> Finding:
    return Finding(title=title, severity=severity, status=status, device=device, evidence=evidence, explanation=explanation,
                   remediation=remediation, check=check)


def passive_findings(dev: DeviceInfo) -> list[Finding]:
    """Checks that use only what BlueZ already knows. Pure: no I/O."""
    a, out = dev.address, []
    # --- address privacy (BLE only: Classic devices always use a public address)
    if dev.technology in ("BLE", "Dual Mode") and dev.address_type:
        kind = dev.address_privacy
        if kind == "public":
            out.append(_f("address-privacy", "Device uses a fixed public address", "low", "confirmed", a,
                          f"BlueZ reports AddressType=public; the address {a} never changes.",
                          "A fixed address lets anyone in radio range recognise this device across places and days (tracking).",
                          "If the device supports LE privacy, enable it so it rotates a resolvable private address; otherwise treat its presence as observable."))
        elif kind in ("resolvable-private", "non-resolvable-private"):
            out.append(_f("address-privacy", "Device uses a rotating private address", "informational", "confirmed", a,
                          f"AddressType=random, kind {kind}.", "Rotating addresses make passive tracking harder.", "None needed."))
    # --- pairing / bonding / trust (host-side facts BlueZ reports about this computer's relationship with the device)
    if dev.paired and not dev.bonded:
        out.append(_f("bond", "Paired but not bonded", "low", "confirmed", a, "Paired=yes, Bonded=no.",
                      "Without a stored bond the keys are not kept, so the device must pair again after a restart and may fall back to weaker handling.",
                      "Pair again and make sure the pairing completes with bonding."))
    if dev.trusted and not dev.paired:
        out.append(_f("trust", "Trusted without being paired", "medium", "confirmed", a, "Trusted=yes, Paired=no.",
                      "Trust lets a device connect without asking, but there is no bond (no shared key) to authenticate it.",
                      "Remove the trust, or pair the device first."))
    elif dev.trusted:
        out.append(_f("trust", "Device is trusted (may reconnect automatically)", "informational", "confirmed", a, "Trusted=yes.",
                      "A trusted device connects without a prompt; only appropriate for devices you control.", "Untrust devices you no longer use."))
    if dev.connected and not dev.paired:
        out.append(_f("unpaired-link", "Connected without pairing", "medium", "confirmed", a, "Connected=yes, Paired=no.",
                      "A link without pairing has no authenticated keys; data on it is not protected by a bond.",
                      "Pair the device if it should be trusted, or disconnect it."))
    if dev.legacy_pairing is True:
        out.append(_f("legacy-pairing", "Legacy (PIN) pairing in use", "medium", "confirmed", a, "BlueZ reports LegacyPairing=yes.",
                      "Pre-2.1 PIN pairing is weak: a short PIN can be recovered from a recording of the pairing exchange.",
                      "Use Secure Simple Pairing or LE Secure Connections where the device supports it; replace devices that cannot."))
    if dev.connected:
        out.append(_f("encryption", "Link encryption state cannot be read from this computer", "informational", "unknown", a,
                      "BlueZ does not expose whether the current link is encrypted or which key strength is used.",
                      "Pairing normally enables encryption, but this tool cannot verify it. It does not claim the link is or is not encrypted.",
                      "Use a controller-level capture (Packet Analyzer, with the right hardware) if you need to verify encryption."))
    # --- advertised services that widen the attack surface (declared, not tested)
    for code, (label, sev, why) in EXPOSED.items():
        if any(reg.uuid16(u) == code for u in dev.uuids):
            out.append(_f(f"service-{code:04x}", f"Advertises {label}", sev, "observation", a, f"UUID 0x{code:04X} is in the device's service list.",
                          why + " This is what the device declares; it has not been tested.",
                          "Disable the service on the device if unused, and require pairing with authentication."))
    for u in dev.uuids:
        if u in DENY_UUIDS:
            out.append(_f("service-dfu", f"Advertises a firmware-update service ({DENY_UUIDS[u]})", "medium", "observation", a, f"UUID {u} is in the service list.",
                          "A firmware update interface that accepts unauthenticated images lets a nearby attacker replace the firmware. Whether this one "
                          "requires authentication is unknown: it was not tested and this tool never writes to it.",
                          "Check the vendor's documentation for signed-update support and keep the firmware current."))
    if not dev.uuids:
        out.append(_f("services", "No service list available", "informational", "unknown", a, "BlueZ has no UUIDs for this device.",
                      "Without a service list, exposed services cannot be judged.", "Connect the device (or scan it again) so BlueZ learns its services."))
    return out


class BluetoothSecurityAuditor:
    def __init__(self, api: BluezAPI, db: Database, inventory, devices: BluetoothDeviceManager, explorer: BLEExplorer,
                 audit: Callable[..., None] | None = None) -> None:
        self.api, self.db, self.inventory, self.devices, self.explorer, self._audit = api, db, inventory, devices, explorer, audit

    def authorised(self, address: str) -> bool:
        row = self.inventory.device(validate_address(address))
        return bool(row and row["authorized"])

    def audit_device(self, address: str, deep: bool = False, confirmed: bool = False) -> tuple[int, list[Finding]]:
        """Run the audit and store the findings. Returns (audit id, findings)."""
        address = validate_address(address)
        if not self.authorised(address):
            raise BluetoothError("Only devices marked as yours / authorised in the Device Inventory can be audited. Mark it there first.")
        dev = self.devices.get(address)
        findings = passive_findings(dev)
        checks = 9
        note = ""
        if deep:
            if not confirmed:
                raise BluetoothError("The deep audit reads characteristics from the device and needs your confirmation first.")
            if not dev.connected:
                raise BluetoothError("The deep audit needs the device connected (use the Device Manager). Nothing was read.")
            deep_f, n_read = self._deep(dev)
            findings += deep_f
            checks += 3
            note = f"{n_read} characteristic(s) read"
        findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.title))
        with self.db.transaction() as c:
            aid = c.execute("INSERT INTO bt_audits(address, started_at, deep, checks_run, note) VALUES (?,?,?,?,?)", (address, utcnow(), int(deep), checks, note)).lastrowid
            for f in findings:
                f.id = c.execute("INSERT INTO bt_findings(audit_id, address, ts, check_id, severity, status, title, evidence, explanation, remediation) "
                                 "VALUES (?,?,?,?,?,?,?,?,?,?)", (aid, address, f.timestamp, f.check, f.severity, f.status, f.title, f.evidence, f.explanation, f.remediation)).lastrowid
        self.inventory.log_event(address, "audit-deep" if deep else "audit", "ok", f"{len(findings)} finding(s)")
        if self._audit:
            self._audit("bluetooth.audit", address=address, deep=deep, findings=len(findings))
        return int(aid), findings

    def _deep(self, dev: DeviceInfo) -> tuple[list[Finding], int]:
        """GATT reads only. Reports what was actually readable from this host."""
        a, out, reads = dev.address, [], 0
        try:
            tree = self.explorer.tree(a)
        except BluetoothError as e:
            return [_f("gatt", "GATT database could not be listed", "informational", "unknown", a, str(e), "The deep checks need the GATT database.",
                       "Reconnect the device and run the audit again.")], 0
        open_reads, writable_open, sensitive_open = [], [], []
        for svc in tree:
            for ch in svc.characteristics:
                if ch.writable and not ch.protected:
                    writable_open.append(ch)
                if not ch.readable or ch.protected:
                    continue
                try:
                    self.explorer.read(ch)                      # the value itself is not kept or shown here
                except BluetoothError:
                    continue
                reads += 1
                open_reads.append(ch)
                if ch.sensitive:
                    sensitive_open.append(ch)
        if sensitive_open:
            names = ", ".join(f"{c.name} ({c.sensitive})" for c in sensitive_open)
            sev, ev = ("high" if not dev.paired else "medium"), f"Read succeeded for: {names}; the device is {'not ' if not dev.paired else ''}paired."
            out.append(_f("gatt-sensitive", "Identifying data is readable" + ("" if dev.paired else " without pairing"), sev, "confirmed", a, ev,
                          "Serial numbers, system IDs and personal-data characteristics let anyone who can connect identify or profile the device (and owner).",
                          "Require encryption/authentication for these characteristics in the firmware, or disable them."))
        if open_reads:
            out.append(_f("gatt-open-read", f"{len(open_reads)} characteristic(s) readable without declaring encryption", "informational", "confirmed", a,
                          f"{len(open_reads)} read(s) succeeded on characteristics with no encrypt/secure flag.",
                          "Public data such as the device name is normal; this is a count of what a connected, " + ("paired" if dev.paired else "unpaired") + " host can read.",
                          "Review whether each of these should require encryption."))
        if writable_open:
            names = ", ".join(c.name for c in writable_open[:8])
            out.append(_f("gatt-open-write", f"{len(writable_open)} characteristic(s) declare write access without an encryption requirement", "low", "observation", a,
                          f"Declared flags only (not tested): {names}.",
                          "A characteristic that can be written without encryption may accept commands from any nearby host. Whether the device really "
                          "accepts them was not tested: this tool never writes during an audit.",
                          "Require encryption (and authentication) on writable characteristics; test writes yourself only with the BLE Explorer, on your own device."))
        if not out:
            out.append(_f("gatt", "No readable data exposed without protection", "informational", "confirmed", a, "Every read attempted on an unprotected characteristic "
                          "failed or none exist.", "Nothing identifying was readable from this connection.", "None needed."))
        return out, reads

    # ------------------------------------------------------------------ stored results
    def audits(self, address: str | None = None, limit: int = 50) -> list[dict]:
        if address:
            return [dict(r) for r in self.db.query("SELECT * FROM bt_audits WHERE address = ? ORDER BY id DESC LIMIT ?", (validate_address(address), limit))]
        return [dict(r) for r in self.db.query("SELECT * FROM bt_audits ORDER BY id DESC LIMIT ?", (limit,))]

    def findings(self, audit_id: int) -> list[Finding]:
        rows = self.db.query("SELECT * FROM bt_findings WHERE audit_id = ?", (audit_id,))
        out = [Finding(title=r["title"], severity=r["severity"], status=r["status"], device=r["address"], evidence=r["evidence"], explanation=r["explanation"],
                       remediation=r["remediation"], timestamp=r["ts"], check=r["check_id"], id=r["id"]) for r in rows]
        return sorted(out, key=lambda f: (-SEVERITIES.index(f.severity), f.title))

    def clear(self, address: str) -> None:
        """Delete stored audits for one device. Only on explicit user action."""
        address = validate_address(address)
        self.db.execute("DELETE FROM bt_findings WHERE address = ?", (address,))
        self.db.execute("DELETE FROM bt_audits WHERE address = ?", (address,))

    @staticmethod
    def summary(findings: list[Finding]) -> dict[str, int]:
        return {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
