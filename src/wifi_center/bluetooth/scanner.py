"""BluetoothScanner: discovery through BlueZ's own D-Bus API (StartDiscovery with a transport filter), for Classic, BLE or both.

Discovery is a standard inquiry/advertisement scan, started by the user for a bounded time and always stopped afterwards (even on
errors or cancellation). It only listens; it never connects, pairs or sends anything to a device."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .bluez import ADAPTER, DEVICE, BluezAPI
from .models import BluetoothError, DeviceInfo, device_from_props, utcnow

TRANSPORT = {"both": "auto", "classic": "bredr", "ble": "le"}
MODE_LABEL = {"both": "Classic + BLE", "classic": "Classic (BR/EDR)", "ble": "BLE"}
STALE_AFTER_S = 20.0           # an RSSI value that has not changed for this long may be stale


@dataclass
class ScanResult:
    adapter: str
    mode: str
    started_at: str
    duration_s: float
    devices: list[DeviceInfo]
    seen: set[str] = field(default_factory=set)       # addresses that reported a signal during THIS scan
    cancelled: bool = False

    @property
    def found(self) -> int:
        return len(self.seen) if self.seen else len(self.devices)


class RssiTracker:
    """Remembers when each device's RSSI last changed, so a value that stopped updating can be flagged as possibly stale."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._last: dict[str, tuple[int | None, float]] = {}

    def update(self, d: DeviceInfo) -> None:
        now = self._clock()
        prev = self._last.get(d.address)
        if prev is None or prev[0] != d.rssi:
            self._last[d.address] = (d.rssi, now)
        d.last_update = self._last[d.address][1]

    def age(self, d: DeviceInfo) -> float | None:
        return None if d.rssi is None or d.last_update is None else self._clock() - d.last_update

    def is_stale(self, d: DeviceInfo) -> bool:
        a = self.age(d)
        return a is not None and a > STALE_AFTER_S


class BluetoothScanner:
    def __init__(self, api: BluezAPI, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        self._api = api
        self._clock, self._sleep = clock, sleep
        self.tracker = RssiTracker(clock)

    # ---- snapshots
    def devices(self, adapter_path: str | None = None) -> list[DeviceInfo]:
        out = []
        for path, ifs in self._api.objects().items():
            props = ifs.get(DEVICE)
            if props is None:
                continue
            if adapter_path and props.get("Adapter") != adapter_path and not path.startswith(adapter_path + "/"):
                continue
            d = device_from_props(path, props, props.get("Adapter", adapter_path or ""))
            self.tracker.update(d)
            out.append(d)
        return sorted(out, key=lambda x: (x.rssi is None, -(x.rssi or 0), x.address))

    def adapter_props(self, adapter_path: str) -> dict:
        return self._api.objects().get(adapter_path, {}).get(ADAPTER, {})

    # ---- discovery control
    def start(self, adapter_path: str, mode: str = "both", supports_classic: bool | None = None, supports_ble: bool | None = None,
              duplicate_data: bool = True) -> None:
        if mode not in TRANSPORT:
            raise BluetoothError("unknown scan mode")
        if mode == "classic" and supports_classic is False:
            raise BluetoothError("This adapter does not support Classic Bluetooth (BR/EDR).")
        if mode == "ble" and supports_ble is False:
            raise BluetoothError("This adapter does not support Bluetooth Low Energy.")
        props = self.adapter_props(adapter_path)
        if not props:
            raise BluetoothError("That Bluetooth adapter no longer exists.")
        if not props.get("Powered"):
            raise BluetoothError("The adapter is powered off. Power it on first (Adapter Diagnostics or the dashboard).")
        if props.get("Discovering"):
            raise BluetoothError("A scan is already running on this adapter.")
        try:
            self._api.call(adapter_path, ADAPTER, "SetDiscoveryFilter", ({"Transport": TRANSPORT[mode], "DuplicateData": bool(duplicate_data)},))
        except BluetoothError:
            if mode != "both":                       # an unsupported transport filter: say so instead of silently scanning something else
                raise
        self._api.call(adapter_path, ADAPTER, "StartDiscovery")

    def stop(self, adapter_path: str) -> None:
        try:
            self._api.call(adapter_path, ADAPTER, "StopDiscovery")
        except BluetoothError:
            pass                                      # already stopped (for example the adapter powered off)

    def scan(self, adapter_path: str, mode: str = "both", seconds: float = 10.0, on_update: Callable[[list[DeviceInfo]], None] | None = None,
             cancel: threading.Event | None = None, interval: float = 1.0, supports_classic: bool | None = None,
             supports_ble: bool | None = None) -> ScanResult:
        seconds = max(2.0, min(float(seconds), 120.0))
        started_at, t0 = utcnow(), self._clock()
        self.start(adapter_path, mode, supports_classic, supports_ble)
        seen: set[str] = set()
        cancelled = False
        devices: list[DeviceInfo] = []
        try:
            while True:
                devices = self.devices(adapter_path)
                seen |= {d.address for d in devices if d.rssi is not None}
                if on_update:
                    on_update(devices)
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    break
                if self._clock() - t0 >= seconds:
                    break
                self._sleep(interval)
        finally:
            self.stop(adapter_path)
        # BlueZ clears every device's RSSI the moment discovery stops and keeps devices from earlier scans in its cache, so the result
        # is the last snapshot taken WHILE scanning, limited to the devices that actually reported a signal during this scan.
        reported = [d for d in devices if d.address in seen]
        return ScanResult(adapter_path.rsplit("/", 1)[-1], mode, started_at, self._clock() - t0, reported, seen, cancelled)
