"""BluetoothInventory: the persistent local record of every device the Lab has seen: names, notes, categories, tags, sightings
(signal over time), advertisement changes and connection events. It never contacts a device and never uploads anything; records
are only deleted when the user asks (`forget`)."""
from __future__ import annotations

import csv
import io
import json

from ..database.repository import Database
from .models import DeviceInfo, utcnow, validate_address
from .scanner import ScanResult

CATEGORIES = ("", "My device", "Audio", "Wearable", "Input device", "Smart home", "Phone / tablet", "Computer", "Vehicle", "Medical",
              "Beacon / tag", "Unknown / not mine")
MAX_NAME, MAX_NOTES, MAX_TAG = 60, 2000, 24


def _clean_tags(tags) -> str:
    out = []
    for t in (tags if isinstance(tags, (list, tuple)) else str(tags or "").split(",")):
        t = str(t).strip().lower()[:MAX_TAG]
        if t and all(c.isalnum() or c in "-_ ." for c in t) and t not in out:
            out.append(t)
    return ",".join(out[:12])


def adv_summary(old: str, new: str) -> str:
    """What changed between two advertisement fingerprints (`name|uuids|mfr|service`)."""
    labels = ("name", "service UUIDs", "manufacturer data", "service data")
    a, b = (old.split("|") + [""] * 4)[:4], (new.split("|") + [""] * 4)[:4]
    diff = [lbl for lbl, x, y in zip(labels, a, b) if x != y]
    return "changed: " + ", ".join(diff) if diff else "advertisement changed"


class BluetoothInventory:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------ recording
    def record_scan(self, result: ScanResult) -> int:
        now = utcnow()
        with self._db.transaction() as c:
            sid = c.execute("INSERT INTO bt_scans(started_at, duration_s, adapter, mode, devices_found, cancelled) VALUES (?,?,?,?,?,?)",
                            (result.started_at, round(result.duration_s, 2), result.adapter, result.mode, len(result.devices), int(result.cancelled))).lastrowid
            for d in result.devices:
                fp = d.adv_fingerprint()
                row = c.execute("SELECT adv_fingerprint FROM bt_devices WHERE address = ?", (d.address,)).fetchone()
                if row is None:
                    c.execute("INSERT INTO bt_devices(address, name, technology, device_type, address_type, manufacturer, first_seen, last_seen, "
                              "last_rssi, adv_fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (d.address, d.display_name, d.technology, d.device_type, d.address_type, d.manufacturer, now, now, d.rssi, fp))
                else:
                    if row["adv_fingerprint"] and row["adv_fingerprint"] != fp:
                        c.execute("INSERT INTO bt_adv_changes(address, ts, summary) VALUES (?,?,?)", (d.address, now, adv_summary(row["adv_fingerprint"], fp)))
                    c.execute("UPDATE bt_devices SET name = COALESCE(NULLIF(?, ''), name), technology = ?, device_type = ?, address_type = COALESCE(NULLIF(?, ''), address_type), "
                              "manufacturer = COALESCE(NULLIF(?, ''), manufacturer), last_seen = ?, last_rssi = COALESCE(?, last_rssi), adv_fingerprint = ? WHERE address = ?",
                              (d.display_name, d.technology, d.device_type, d.address_type, d.manufacturer, now, d.rssi, fp, d.address))
                c.execute("INSERT INTO bt_sightings(scan_id, address, ts, rssi, name, technology, uuids, mfr_data, adv_fingerprint, paired, connected) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                          (sid, d.address, now, d.rssi, d.display_name, d.technology, ",".join(d.uuids),
                           ";".join(f"{k:04x}:{v.hex()}" for k, v in sorted(d.manufacturer_data.items())), fp, int(d.paired), int(d.connected)))
        return int(sid)

    def log_event(self, address: str, event: str, result: str, detail: str = "") -> None:
        """Connection / pairing history. Never receives keys or secrets."""
        self._db.execute("INSERT INTO bt_events(address, ts, event, result, detail) VALUES (?,?,?,?,?)",
                         (validate_address(address), utcnow(), event, result, detail[:500]))

    # ------------------------------------------------------------------ reading
    def devices(self, search: str = "", technology: str = "", category: str = "", tag: str = "", authorized: bool | None = None,
                sort: str = "last_seen") -> list[dict]:
        sql, params = "SELECT * FROM bt_devices WHERE 1=1", []
        q = search.strip().lower()
        if q:
            sql += " AND (lower(address) LIKE ? OR lower(name) LIKE ? OR lower(custom_name) LIKE ? OR lower(manufacturer) LIKE ? OR lower(notes) LIKE ? OR lower(tags) LIKE ?)"
            params += [f"%{q}%"] * 6
        if technology:
            sql, params = sql + " AND technology = ?", params + [technology]
        if category:
            sql, params = sql + " AND category = ?", params + [category]
        if tag:
            sql, params = sql + " AND (',' || tags || ',') LIKE ?", params + [f"%,{tag.strip().lower()},%"]
        if authorized is not None:
            sql, params = sql + " AND authorized = ?", params + [int(authorized)]
        order = {"last_seen": "last_seen DESC", "first_seen": "first_seen DESC", "name": "lower(COALESCE(NULLIF(custom_name,''), name)) ASC",
                 "rssi": "last_rssi IS NULL, last_rssi DESC", "address": "address ASC"}.get(sort, "last_seen DESC")
        return [dict(r) for r in self._db.query(sql + f" ORDER BY {order}", params)]

    def device(self, address: str) -> dict | None:
        r = self._db.query_one("SELECT * FROM bt_devices WHERE address = ?", (validate_address(address),))
        return dict(r) if r else None

    def sightings(self, address: str, limit: int = 500) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM bt_sightings WHERE address = ? ORDER BY ts DESC LIMIT ?", (validate_address(address), limit))][::-1]

    def adv_changes(self, address: str) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM bt_adv_changes WHERE address = ? ORDER BY ts DESC", (validate_address(address),))]

    def events(self, address: str, limit: int = 200) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM bt_events WHERE address = ? ORDER BY id DESC LIMIT ?", (validate_address(address), limit))]

    def scans(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM bt_scans ORDER BY id DESC LIMIT ?", (limit,))]

    def scan_devices(self, scan_id: int) -> list[dict]:
        return [dict(r) for r in self._db.query("SELECT * FROM bt_sightings WHERE scan_id = ? ORDER BY rssi IS NULL, rssi DESC", (scan_id,))]

    # ------------------------------------------------------------------ user data
    def set_info(self, address: str, custom_name: str | None = None, notes: str | None = None, category: str | None = None,
                 tags=None, authorized: bool | None = None) -> None:
        address = validate_address(address)
        if self.device(address) is None:
            raise ValueError("this device is not in the inventory yet (scan first)")
        if category is not None and category not in CATEGORIES:
            raise ValueError("unknown category")
        fields, params = [], []
        if custom_name is not None:
            fields, params = fields + ["custom_name = ?"], params + [custom_name.strip()[:MAX_NAME]]
        if notes is not None:
            fields, params = fields + ["notes = ?"], params + [notes[:MAX_NOTES]]
        if category is not None:
            fields, params = fields + ["category = ?"], params + [category]
        if tags is not None:
            fields, params = fields + ["tags = ?"], params + [_clean_tags(tags)]
        if authorized is not None:
            fields, params = fields + ["authorized = ?"], params + [int(authorized)]
        if fields:
            self._db.execute(f"UPDATE bt_devices SET {', '.join(fields)} WHERE address = ?", (*params, address))

    def forget(self, address: str) -> None:
        """Remove a device from the INVENTORY (its sightings and events too). Pairing data in BlueZ is not touched."""
        address = validate_address(address)
        for table in ("bt_sightings", "bt_adv_changes", "bt_events"):
            self._db.execute(f"DELETE FROM {table} WHERE address = ?", (address,))
        self._db.execute("DELETE FROM bt_devices WHERE address = ?", (address,))

    # ------------------------------------------------------------------ analysis
    def duplicates(self) -> list[list[dict]]:
        """Groups of devices that may be the same physical device: the same name and manufacturer seen under several RANDOM addresses
        (phones and trackers rotate their private address). A hint, not proof."""
        groups: dict[tuple[str, str], list[dict]] = {}
        for d in self.devices():
            if d["address_type"] == "random" and (d["name"] or d["custom_name"]):
                groups.setdefault(((d["custom_name"] or d["name"]).lower(), d["manufacturer"]), []).append(d)
        return [g for g in groups.values() if len(g) > 1]

    def compare(self, older_id: int, newer_id: int) -> dict[str, list]:
        """What changed between two scans: new devices, devices not seen again (NOT proof they are gone), and signal / advertisement changes."""
        a = {r["address"]: r for r in self.scan_devices(older_id)}
        b = {r["address"]: r for r in self.scan_devices(newer_id)}
        changed = []
        for addr in a.keys() & b.keys():
            x, y = a[addr], b[addr]
            notes = []
            if x["adv_fingerprint"] != y["adv_fingerprint"]:
                notes.append(adv_summary(x["adv_fingerprint"] or "", y["adv_fingerprint"] or ""))
            if x["rssi"] is not None and y["rssi"] is not None and abs(x["rssi"] - y["rssi"]) >= 10:
                notes.append(f"signal {x['rssi']} → {y['rssi']} dBm")
            if notes:
                changed.append((y, "; ".join(notes)))
        return {"new": [b[k] for k in sorted(b.keys() - a.keys())], "not_seen": [a[k] for k in sorted(a.keys() - b.keys())], "changed": changed}

    # ------------------------------------------------------------------ export
    COLUMNS = ("address", "name", "custom_name", "category", "tags", "notes", "technology", "device_type", "address_type", "manufacturer",
               "first_seen", "last_seen", "last_rssi", "authorized")

    def export_csv(self, rows: list[dict] | None = None) -> str:
        rows = self.devices() if rows is None else rows
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(self.COLUMNS)
        for r in rows:
            w.writerow(["'" + str(v) if isinstance(v, str) and v[:1] in "=+-@" else ("" if v is None else v) for v in (r[c] for c in self.COLUMNS)])
        return buf.getvalue()

    def export_json(self, rows: list[dict] | None = None) -> str:
        rows = self.devices() if rows is None else rows
        return json.dumps([{c: r[c] for c in self.COLUMNS} for r in rows], indent=2)
