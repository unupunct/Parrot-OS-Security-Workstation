"""Kismet integration: REST client (loopback only), read-only `.kismet` log import and log listing.

Endpoints are the documented ones (/system/status.json, /devices/last-time/<ts>/devices.json,
/alerts/all_alerts.json). The JSON field names below follow Kismet's device record and are read
defensively (several candidate keys per value) because the official docs do not enumerate them;
they have not been verified against a live Kismet server in this project yet.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import sqlite3
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..security.input_validation import ValidationError, validate_within
from .process_runner import run_command
from .wireless_service import AccessPoint, band_of, freq_to_channel

DEFAULT_URL = "http://127.0.0.1:2501"
LOG_SUFFIXES = (".kismet", ".pcapng", ".pcap", ".netxml", ".nettxt")


class KismetError(RuntimeError):
    pass


def validate_loopback_url(url: str) -> str:
    """Only loopback HTTP(S) endpoints: WIFI Center makes no hidden or remote network connections."""
    from urllib.parse import urlparse
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValidationError("URL must be http(s)://host:port")
    host = u.hostname
    if host != "localhost":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            raise ValidationError("only localhost, 127.0.0.1 and ::1 are supported (loopback only)") from None
        if not loopback:
            raise ValidationError("only loopback Kismet servers are supported")
    return f"{u.scheme}://{u.netloc}"


@dataclass
class KismetDevice:
    mac: str
    name: str
    dev_type: str
    phy: str
    channel: str
    frequency_mhz: int | None
    signal_dbm: float | None
    crypt: str
    first_time: int | None
    last_time: int | None
    manufacturer: str

    @property
    def is_wifi_ap(self) -> bool:
        return self.dev_type.lower() in ("wi-fi ap", "wifi ap")


@dataclass
class KismetAlert:
    header: str
    text: str
    severity: int | None
    timestamp: float | None
    source_mac: str


def _g(d: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def parse_device(d: dict) -> KismetDevice | None:
    mac = _g(d, "kismet.device.base.macaddr", "macaddr")
    if not mac:
        return None
    sig = _g(d, "kismet.device.base.signal", default={})
    last_sig = _g(sig, "kismet.common.signal.last_signal", default=None) if isinstance(sig, dict) else None
    freq = _g(d, "kismet.device.base.frequency", default=None)
    freq_i = int(freq / 1000) if isinstance(freq, (int, float)) and freq > 100000 else \
        (int(freq) if isinstance(freq, (int, float)) and freq else None)
    return KismetDevice(
        mac=str(mac).upper(),
        name=str(_g(d, "kismet.device.base.name", "kismet.device.base.commonname", default="")),
        dev_type=str(_g(d, "kismet.device.base.type", default="unknown")),
        phy=str(_g(d, "kismet.device.base.phyname", default="")),
        channel=str(_g(d, "kismet.device.base.channel", default="")),
        frequency_mhz=freq_i,
        signal_dbm=float(last_sig) if isinstance(last_sig, (int, float)) else None,
        crypt=str(_g(d, "kismet.device.base.crypt", default="")),
        first_time=_g(d, "kismet.device.base.first_time"),
        last_time=_g(d, "kismet.device.base.last_time"),
        manufacturer=str(_g(d, "kismet.device.base.manuf", default="")),
    )


def parse_devices(payload: Any) -> list[KismetDevice]:
    items = payload if isinstance(payload, list) else payload.get("devices", []) if isinstance(payload, dict) else []
    return [dv for dv in (parse_device(i) for i in items if isinstance(i, dict)) if dv]


def parse_alerts(payload: Any) -> list[KismetAlert]:
    items = payload if isinstance(payload, list) else payload.get("kismet.alert.list", []) \
        if isinstance(payload, dict) else []
    out = []
    for a in items:
        if isinstance(a, dict):
            out.append(KismetAlert(str(_g(a, "kismet.alert.header", default="")),
                                   str(_g(a, "kismet.alert.text", default="")),
                                   _g(a, "kismet.alert.severity"), _g(a, "kismet.alert.timestamp"),
                                   str(_g(a, "kismet.alert.transmitter_mac", "kismet.alert.source_mac", default=""))))
    return out


def to_access_point(dev: KismetDevice) -> AccessPoint:
    crypt = dev.crypt or "Unknown"
    chan = int(dev.channel) if dev.channel.isdigit() else freq_to_channel(dev.frequency_mhz)
    return AccessPoint(dev.mac, dev.name, chan, dev.frequency_mhz, dev.signal_dbm, None,
                       "Open" if crypt.lower() in ("none", "open") else crypt, "", dev.manufacturer or None)


class KismetClient:
    """Minimal REST client. Credentials live only in memory for the session."""

    def __init__(self, base_url: str = DEFAULT_URL, username: str = "", password: str = "") -> None:
        self.base_url = validate_loopback_url(base_url)
        self._auth = None
        if username:
            self._auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    def _get(self, path: str, timeout: float = 5.0) -> Any:
        req = urllib.request.Request(self.base_url + path, headers={"Accept": "application/json"})
        if self._auth:
            req.add_header("Authorization", self._auth)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise KismetError("Kismet rejected the credentials (HTTP %d)" % e.code) from None
            raise KismetError(f"Kismet returned HTTP {e.code} for {path}") from None
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise KismetError(f"cannot reach Kismet at {self.base_url}: {getattr(e, 'reason', e)}") from None
        except json.JSONDecodeError:
            raise KismetError("Kismet returned a response that is not JSON") from None

    def status(self) -> dict:
        return self._get("/system/status.json")

    def devices(self, window_seconds: int = 300) -> list[KismetDevice]:
        since = -abs(int(window_seconds))
        return parse_devices(self._get(f"/devices/last-time/{since}/devices.json", timeout=20))

    def alerts(self) -> list[KismetAlert]:
        return parse_alerts(self._get("/alerts/all_alerts.json", timeout=20))


# ---------------- service status (no network) ----------------
def service_state(unit: str = "kismet") -> str:
    r = run_command(["systemctl", "is-active", unit], timeout=5)
    if r.error:
        return "unknown (systemctl unavailable)"
    return r.stdout.strip() or "unknown"


# ---------------- log files ----------------
def default_log_dirs() -> list[Path]:
    home = Path.home()
    return [home / ".kismet", home / "kismet", Path.cwd()]


def list_logs(directory: Path) -> list[dict]:
    if not directory.is_dir():
        return []
    out = []
    for p in sorted(directory.iterdir()):
        if p.is_file() and p.suffix.lower() in LOG_SUFFIXES:
            st = p.stat()
            out.append({"path": str(p), "name": p.name, "size": st.st_size,
                        "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec="seconds")})
    return out


def delete_log(directory: Path, name: str) -> None:
    """Delete one log inside `directory`. The caller must have obtained explicit user confirmation."""
    target = validate_within(directory, name)
    if target.parent != directory.resolve() or target.suffix.lower() not in LOG_SUFFIXES:
        raise ValidationError("not a Kismet log file in the log directory")
    target.unlink()


def read_kismet_log(path: Path) -> list[KismetDevice]:
    """Read devices from a `.kismet` SQLite log, strictly read-only."""
    if path.suffix.lower() != ".kismet":
        raise KismetError("not a .kismet log")
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as e:
        raise KismetError(f"cannot open log: {e}") from None
    try:
        rows = conn.execute("SELECT device FROM devices").fetchall()
    except sqlite3.Error as e:
        raise KismetError(f"not a Kismet log (no devices table): {e}") from None
    finally:
        conn.close()
    devices = []
    for (blob,) in rows:
        try:
            raw = blob.decode("utf-8", errors="replace") if isinstance(blob, (bytes, bytearray)) else blob
            d = parse_device(json.loads(raw))
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue
        if d:
            devices.append(d)
    return devices
