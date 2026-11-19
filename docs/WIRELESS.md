# Wireless workspace

| Page | What it does | Needs |
|---|---|---|
| Wi-Fi Center | Adapter inventory (driver, bands, monitor-mode capability, state) and read-only driver diagnostics | Linux; `iw`, `ethtool`, `rfkill`, `nmcli` for the full picture |
| Wireless Discovery | Standard Wi-Fi scans, stored history per access point, search/filter/sort, CSV/JSON export | NetworkManager (`nmcli`) or `iw`; vendor names need the `ieee-data` package |
| Kismet Monitor | Service status, REST data (loopback only), `.kismet` log import and management | Kismet |
| Spectrum Analyzer | Channel distribution, channel overlap and historical signal charts from stored scans | A scan in Wireless Discovery |
| Bluetooth Lab | Adapter detection, BlueZ discovery, known devices, CSV import | BlueZ (`bluetoothctl`) |
| Packet Analysis | Offline statistics of existing PCAP/PCAPNG files | TShark (`capinfos` optional) |

## Limits worth knowing

* **Scan data is not RF spectrum.** The Spectrum Analyzer plots what access points announce. An ordinary
  Wi-Fi adapter cannot measure non-Wi-Fi interference, and no spectrum-analysis hardware is supported.
* **Signal from NetworkManager is a quality percentage**, converted to an approximate dBm value
  (-100 dBm = 0 %, -50 dBm = 100 %). `iw` reports real dBm.
* **Interface changes are not implemented.** Monitor mode and up/down need root and will arrive with the
  privileged helper (Phase 8), with confirmation and state restore.
* **Kismet:** only loopback servers are accepted, credentials are kept in memory only, nothing is contacted until
  you press Connect. Endpoint paths follow the Kismet documentation; the JSON field names are read tolerantly
  and have not yet been verified against a live Kismet server.
* **Packet analysis never captures traffic** and only reads files you open.
* **Bluetooth:** discovery asks for confirmation first; no pairing, connecting or spoofing is implemented.
* All exports neutralise spreadsheet formula injection from attacker-controlled SSIDs.
