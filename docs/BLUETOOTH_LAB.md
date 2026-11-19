# Bluetooth Lab

A Bluetooth diagnostics and device-management workstation built on BlueZ's D-Bus API. It replaces the original "scan and list"
page; the original `bluetoothctl` scanner is kept and is used automatically when BlueZ cannot be reached over D-Bus.

## Dependencies

| Needed for | Package | Install |
|---|---|---|
| Everything (BlueZ client) | `bluez`, `python3-dbus` | `sudo apt install bluez python3-dbus` |
| Chipset and capability details | `bluez` tools (`btmgmt`, `hciconfig`), `rfkill`, `usbutils` | `sudo apt install bluez rfkill usbutils` |
| Packet Analyzer (later stage) | `tshark` | `sudo apt install tshark` |

Your user should be in the `bluetooth` group (Parrot does this by default). No root is needed for any section built so far.

## Sections

| Section | State |
|---|---|
| Dashboard | Done: adapter, chipset, Bluetooth version, Classic / BLE availability, firmware revision numbers, scan status, counts, scan controls |
| Device Scanner | Done: Classic / BLE / both scans, live table, search, filters, known-to-BlueZ list |
| Signal Monitor | Done: live RSSI graph, min / max / average / fluctuation, presence history, configurable interval |
| Adapter Diagnostics | Done: controllers, service and rfkill state, findings, log export, guarded power and reset |
| Device Inventory | Done: persistent devices, names, notes, categories, tags, advertisement changes, duplicate hints, scan comparison, CSV / JSON export |
| Device Manager | Built, **not yet tried on real devices**: pair (with a pairing prompt dialog), connect, disconnect, trust, untrust, remove pairing, refresh; every action asks first and is logged |
| Device Inspector | Built, not yet tried on real devices: properties, profiles, resolved GATT services, battery, device ID, connection history |
| BLE Explorer | Built, not yet tried on real devices: GATT tree, flags, reads, notifications; writes locked unless every safety condition holds |
| Security Auditor | Built, not yet tried on real devices: passive and deep (read-only) audits with stored, evidence-based findings |
| Packet Analyzer, Reports | Later stage |

## What it does and does not claim

* **Scanning only listens.** It never connects, pairs or sends anything to a device. Discovery is bounded, always stopped afterwards,
  and recorded in the audit log.
* **Capabilities are read, not assumed.** Classic / BLE support comes from `btmgmt` (or the controller's LMP feature bits when
  `btmgmt` is unavailable). Buttons for unsupported modes are disabled and say why; unknown stays "unknown".
* **Technology (Classic / BLE / Dual Mode) and device type are inferred** from what a device advertises (class of device, appearance,
  address type, manufacturer data); the UI labels them as inferred. Manufacturers come from Bluetooth SIG company identifiers.
* **RSSI is signal strength, not distance.** Also, BlueZ only publishes a new RSSI when it moves by several dB, so a stationary
  device can look perfectly steady in the Signal Monitor; finer sampling needs an HCI capture. A device with no reading is shown as
  unavailable, and a value that stops changing is flagged as possibly stale.
* **Nothing leaves your computer.** The inventory (`bt_devices`, `bt_sightings`, `bt_adv_changes`, `bt_events`) is local SQLite.
  Records are removed only when you press "Forget device"; this never touches pairing data in BlueZ.
* **Adapter power and reset** need confirmation and are refused while a device is connected through the adapter.
* **Pairing keys** are never read, stored or written to logs.

## Device actions and the safety rules behind them

* **Every state-changing action asks first** (the dialog names the device and the action) and is recorded in that device's connection
  history. The history stores the event and result, never keys, PINs, passkeys or written values.
* **Pairing** uses a temporary BlueZ agent; confirmation codes, PIN and passkey prompts appear as dialogs and the agent is removed
  afterwards whatever the outcome. **Remove pairing** only asks BlueZ to forget the device and is refused while it is connected.
* **BLE Explorer** never connects by itself. Reading is the default. Writing needs *all* of: a device marked "mine / authorised" in
  the Inventory, an explicitly selected characteristic that declares write support, valid hex data (at most 512 bytes), a
  confirmation showing the target and the exact bytes, and a characteristic that is not part of a firmware-update / bootloader
  service (those are never written). Notifications stop when you leave the section.
* **Security Auditor** only runs on devices marked authorised. Findings carry a severity (informational, low, medium, high,
  critical) and a status: **confirmed** (verified from this computer), **observation** (the device declares or advertises it; not
  tested) or **unknown** (cannot be determined here, with the reason). The standard audit reads only what BlueZ already holds. The
  deep audit needs a connected device and your confirmation, and only *reads* characteristics. Nothing writes, guesses PINs or keys,
  or attacks encryption. Link encryption cannot be read from BlueZ, so the auditor reports it as unknown rather than guessing.

## Verification status

Stage 2 is covered by automated tests against an in-memory BlueZ, which checks the logic, the confirmations and the refusals. It has
not been run against real devices: pairing, GATT reads and notifications on actual hardware are untested, and results from them
should be treated as unverified until they are.

## Architecture

`wifi_center/bluetooth/`: `bluez.py` (D-Bus client and error translation), `fake.py` (in-memory BlueZ for tests), `adapter.py`
(BluetoothAdapterManager), `scanner.py` (BluetoothScanner), `signal_monitor.py` (BluetoothSignalMonitor), `diagnostics.py`
(BluetoothDiagnostics), `inventory.py` (BluetoothInventory), `devices.py` (BluetoothDeviceManager), `inspector.py` (BluetoothDeviceInspector), `ble.py`
(BLEExplorer), `auditor.py` (BluetoothSecurityAuditor), `models.py`, `registry.py` (Bluetooth SIG names). The UI is
`ui/pages/bluetooth_lab.py`, `bluetooth_lab_tools.py` and `bluetooth_lab_stage2.py`.
