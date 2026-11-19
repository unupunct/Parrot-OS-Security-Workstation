"""Wi-Fi scan observations: NetworkManager (nmcli) first, cached `iw scan dump` as fallback.

Scans only report what the adapter and driver return. Nothing here injects, deauthenticates or
changes interface state.
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

from ..database.repository import Database
from .oui import OuiLookup
from .process_runner import run_command


class ScanError(RuntimeError):
    pass


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    channel: int | None
    frequency_mhz: int | None
    signal_dbm: float | None
    signal_pct: float | None
    encryption: str
    auth: str = ""
    vendor: str | None = None

    @property
    def band(self) -> str:
        return band_of(self.frequency_mhz)


def band_of(freq: int | None) -> str:
    if not freq:
        return "?"
    return "2.4 GHz" if freq < 3000 else "5 GHz" if freq < 5925 else "6 GHz"


def freq_to_channel(freq: int | None) -> int | None:
    if not freq:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq < 5925:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return None


def pct_to_dbm(pct: float) -> float:
    """Rough NetworkManager quality -> dBm mapping (-100 dBm = 0 %, -50 dBm = 100 %)."""
    return round(min(max(pct, 0), 100) / 2 - 100, 1)


def split_terse(line: str) -> list[str]:
    """Split an `nmcli -t` line on unescaped colons and unescape `\\:` and `\\\\`."""
    fields, cur, i = [], [], 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if c == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    fields.append("".join(cur))
    return fields


NMCLI_FIELDS = "BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY"


def parse_nmcli(text: str) -> list[AccessPoint]:
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        f = split_terse(line)
        if len(f) < 6:
            continue
        bssid, ssid, chan, freq, sig, sec = f[:6]
        freq_m = re.match(r"(\d+)", freq)
        freq_i = int(freq_m.group(1)) if freq_m else None
        try:
            pct = float(sig)
        except ValueError:
            pct = None
        sec = sec.strip()
        out.append(AccessPoint(
            bssid=bssid.upper(), ssid=ssid, channel=int(chan) if chan.isdigit() else freq_to_channel(freq_i),
            frequency_mhz=freq_i, signal_dbm=pct_to_dbm(pct) if pct is not None else None, signal_pct=pct,
            encryption="Open" if sec in ("", "--") else sec, auth="802.1X" if "802.1X" in sec else
            ("SAE" if "WPA3" in sec else ("PSK" if "WPA" in sec else ""))))
    return out


def parse_iw_scan_dump(text: str) -> list[AccessPoint]:
    out: list[AccessPoint] = []
    cur: dict | None = None

    def flush() -> None:
        if cur is None:
            return
        enc = "WPA3" if cur["sae"] else "WPA2" if cur["rsn"] else "WPA" if cur["wpa"] else \
            "WEP" if cur["privacy"] else "Open"
        auth = "802.1X" if cur["eap"] else "SAE" if cur["sae"] else "PSK" if (cur["rsn"] or cur["wpa"]) else ""
        freq = cur["freq"]
        out.append(AccessPoint(cur["bssid"], cur["ssid"], cur["channel"] or freq_to_channel(freq), freq,
                               cur["signal"], None, enc, auth))

    for raw in text.splitlines():
        m = re.match(r"^BSS ([0-9A-Fa-f:]{17})", raw)
        if m:
            flush()
            cur = {"bssid": m.group(1).upper(), "ssid": "", "freq": None, "signal": None, "channel": None,
                   "privacy": False, "rsn": False, "wpa": False, "sae": False, "eap": False}
            continue
        if cur is None:
            continue
        s = raw.strip()
        if s.startswith("freq:"):
            cur["freq"] = int(float(s.split(":", 1)[1]))
        elif s.startswith("signal:"):
            mm = re.search(r"(-?\d+(?:\.\d+)?)", s)
            cur["signal"] = float(mm.group(1)) if mm else None
        elif s.startswith("SSID:"):
            cur["ssid"] = s.split(":", 1)[1].strip()
        elif s.startswith("capability:") and "Privacy" in s:
            cur["privacy"] = True
        elif s.startswith("DS Parameter set: channel"):
            cur["channel"] = int(s.rsplit(" ", 1)[1])
        elif s.startswith("RSN:"):
            cur["rsn"] = True
        elif s.startswith("WPA:"):
            cur["wpa"] = True
        elif "Authentication suites:" in s:
            cur["sae"] = cur["sae"] or "SAE" in s
            cur["eap"] = cur["eap"] or "802.1X" in s or "EAP" in s
    flush()
    return out


class WirelessService:
    def __init__(self, db: Database, oui: OuiLookup | None = None) -> None:
        self._db = db
        self.oui = oui or OuiLookup()

    # ---- scanning ----
    def capabilities(self) -> dict[str, bool]:
        return {"nmcli": shutil.which("nmcli") is not None, "iw": shutil.which("iw") is not None}

    def scan(self, interface: str | None = None, rescan: bool = True) -> list[AccessPoint]:
        """Run one scan. Raises ScanError with a user-readable message when impossible."""
        caps = self.capabilities()
        if caps["nmcli"]:
            argv = ["nmcli", "-t", "-f", NMCLI_FIELDS, "dev", "wifi", "list"]
            if interface:
                argv += ["ifname", interface]
            argv += ["--rescan", "yes" if rescan else "no"]
            r = run_command(argv, timeout=30)
            if r.ok:
                return self._finish(parse_nmcli(r.stdout))
            err = (r.stderr or r.error or "").strip()
            if not caps["iw"] or not interface:
                raise ScanError(f"nmcli scan failed: {err or 'unknown error'}")
        if caps["iw"] and interface:
            r = run_command(["iw", "dev", interface, "scan", "dump"], timeout=20)
            if r.ok:
                return self._finish(parse_iw_scan_dump(r.stdout))
            raise ScanError(f"iw scan dump failed: {(r.stderr or r.error or '').strip()}")
        raise ScanError("No scan method available: install NetworkManager (nmcli) or iw, "
                        "and make sure a wireless adapter is present.")

    def _finish(self, aps: list[AccessPoint]) -> list[AccessPoint]:
        for ap in aps:
            ap.vendor = self.oui.vendor(ap.bssid)
        return aps

    # ---- persistence ----
    def record(self, aps: Iterable[AccessPoint], source: str = "wifi-scan", project_id: int | None = None) -> int:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        n = 0
        with self._db.transaction() as c:
            for ap in aps:
                c.execute(
                    "INSERT INTO wireless_observations(project_id, ssid, bssid, channel, frequency_mhz, signal_dbm, "
                    "signal_pct, encryption, auth, vendor, source, first_seen, last_seen, band) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(bssid, COALESCE(ssid,''), source) DO UPDATE SET channel=excluded.channel, "
                    "frequency_mhz=excluded.frequency_mhz, signal_dbm=excluded.signal_dbm, "
                    "signal_pct=excluded.signal_pct, encryption=excluded.encryption, auth=excluded.auth, "
                    "vendor=COALESCE(excluded.vendor, vendor), last_seen=excluded.last_seen, band=excluded.band",
                    (project_id, ap.ssid, ap.bssid, ap.channel, ap.frequency_mhz, ap.signal_dbm, ap.signal_pct,
                     ap.encryption, ap.auth, ap.vendor, source, now, now, ap.band))
                oid = c.execute("SELECT id FROM wireless_observations WHERE bssid=? AND COALESCE(ssid,'')=? "
                                "AND source=?", (ap.bssid, ap.ssid, source)).fetchone()[0]
                c.execute("INSERT INTO wireless_samples(observation_id, ts, signal_dbm, signal_pct, channel, "
                          "frequency_mhz) VALUES (?,?,?,?,?,?)",
                          (oid, now, ap.signal_dbm, ap.signal_pct, ap.channel, ap.frequency_mhz))
                n += 1
        return n

    def observations(self) -> list[dict]:
        return [dict(r) for r in self._db.query(
            "SELECT * FROM wireless_observations ORDER BY last_seen DESC, signal_dbm DESC")]

    def history(self, observation_id: int, limit: int = 500) -> list[dict]:
        return [dict(r) for r in self._db.query(
            "SELECT ts, signal_dbm, signal_pct, channel FROM wireless_samples WHERE observation_id=? "
            "ORDER BY ts DESC LIMIT ?", (observation_id, limit))][::-1]

    def scan_timeline(self, limit: int = 60) -> list[tuple[str, int]]:
        """(scan timestamp, access points seen) for the most recent scans, oldest first."""
        rows = self._db.query("SELECT ts, COUNT(*) n FROM wireless_samples GROUP BY ts ORDER BY ts DESC LIMIT ?",
                              (limit,))
        return [(r["ts"], r["n"]) for r in rows][::-1]

    def latest_scan_ts(self) -> str | None:
        r = self._db.query_one("SELECT MAX(ts) t FROM wireless_samples")
        return r["t"] if r else None

    # ---- export ----
    COLUMNS = ("ssid", "bssid", "channel", "frequency_mhz", "signal_dbm", "signal_pct", "encryption", "auth",
               "vendor", "source", "first_seen", "last_seen")

    def export(self, rows: list[dict], fmt: str) -> str:
        if fmt == "json":
            return json.dumps([{k: r.get(k) for k in self.COLUMNS} for r in rows], indent=2)
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(self.COLUMNS)
            for r in rows:
                w.writerow([_csv_safe(r.get(k)) for k in self.COLUMNS])
            return buf.getvalue()
        raise ValueError("format must be 'csv' or 'json'")


def _csv_safe(v):
    """Neutralise spreadsheet formula injection from attacker-controlled SSIDs."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v
