"""BluetoothSignalMonitor: live RSSI sampling of nearby devices with history, statistics and presence tracking.

RSSI is a received-signal-strength reading, not a distance: walls, bodies, antennas, transmit power and interference change it a
lot, so nothing here converts it to metres. A device that reports no RSSI is shown as unavailable, and a value that stopped
changing is flagged as possibly stale."""
from __future__ import annotations

import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from .models import DeviceInfo
from .scanner import STALE_AFTER_S, BluetoothScanner

MAX_SAMPLES = 1500
NOTE = "RSSI is a signal strength reading, not a distance: walls, bodies, antennas and interference change it."
GRANULARITY_NOTE = ("BlueZ only publishes a new RSSI when the value moves by several dB, so a stationary device can look perfectly steady here "
                    "even though its real signal fluctuates. Finer sampling needs an HCI capture (Packet Analyzer).")


@dataclass
class Sample:
    t: float                    # wall-clock time (seconds since the epoch)
    rssi: int | None            # None = no reading (unavailable)


@dataclass
class SignalStats:
    current: int | None
    minimum: int | None
    maximum: int | None
    average: float | None
    fluctuation: float | None   # standard deviation in dB
    samples: int
    readings: int
    unavailable: int
    stale: bool

    @property
    def stability(self) -> str:
        if self.fluctuation is None:
            return "unknown"
        return "steady" if self.fluctuation < 3 else "variable" if self.fluctuation < 7 else "erratic"


@dataclass
class Presence:
    start: float
    end: float | None = None    # None = still present

    @property
    def open(self) -> bool:
        return self.end is None


@dataclass
class Series:
    address: str
    name: str = ""
    samples: deque = field(default_factory=lambda: deque(maxlen=MAX_SAMPLES))
    presence: list[Presence] = field(default_factory=list)
    last_change: float | None = None
    last_rssi: int | None = None


class BluetoothSignalMonitor:
    def __init__(self, scanner: BluetoothScanner, clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._sc = scanner
        self._clock, self._wall, self._sleep = clock, wall, sleep
        self.series: dict[str, Series] = {}
        self.adapter: str | None = None
        self.interval = 1.0
        self.watch: set[str] | None = None
        self.running = False

    # ---- control
    def start(self, adapter_path: str, interval: float = 1.0, addresses: list[str] | None = None, mode: str = "both",
              supports_classic: bool | None = None, supports_ble: bool | None = None) -> None:
        if self.running:
            return
        self.interval = max(0.5, min(float(interval), 60.0))
        self.watch = {a.upper() for a in addresses} if addresses else None
        self._sc.start(adapter_path, mode, supports_classic, supports_ble, duplicate_data=True)
        self.adapter, self.running = adapter_path, True

    def stop(self) -> None:
        if self.running and self.adapter:
            self._sc.stop(self.adapter)
        self.running = False

    def run(self, cancel: threading.Event, on_update: Callable[[], None] | None = None) -> None:
        """Poll until cancelled (meant for a worker thread). Discovery is always stopped when this returns."""
        try:
            while not cancel.is_set() and self.running:
                self.poll()
                if on_update:
                    on_update()
                self._sleep(self.interval)
        finally:
            self.stop()

    # ---- sampling
    def poll(self) -> list[DeviceInfo]:
        if not self.adapter:
            return []
        now_wall, now = self._wall(), self._clock()
        devices = self._sc.devices(self.adapter)
        present = set()
        for d in devices:
            if self.watch is not None and d.address not in self.watch:
                continue
            s = self.series.setdefault(d.address, Series(d.address))
            s.name = d.display_name or s.name
            s.samples.append(Sample(now_wall, d.rssi))
            if d.rssi is not None:
                present.add(d.address)
                if d.rssi != s.last_rssi:
                    s.last_rssi, s.last_change = d.rssi, now
                if not s.presence or not s.presence[-1].open:
                    s.presence.append(Presence(now_wall))
        grace = max(self.interval * 3, 5.0)
        for addr, s in self.series.items():
            if addr not in present and s.presence and s.presence[-1].open:
                last_reading = next((x.t for x in reversed(s.samples) if x.rssi is not None), now_wall)
                if now_wall - last_reading > grace:
                    s.presence[-1].end = last_reading
        return devices

    # ---- statistics
    def stats(self, address: str) -> SignalStats | None:
        s = self.series.get(address.upper())
        if not s or not s.samples:
            return None
        vals = [x.rssi for x in s.samples if x.rssi is not None]
        stale = bool(s.last_rssi is not None and s.last_change is not None and self._clock() - s.last_change > STALE_AFTER_S)
        if not vals:
            return SignalStats(None, None, None, None, None, len(s.samples), 0, len(s.samples), False)
        return SignalStats(s.samples[-1].rssi, min(vals), max(vals), sum(vals) / len(vals),
                           statistics.pstdev(vals) if len(vals) > 1 else 0.0, len(s.samples), len(vals), len(s.samples) - len(vals), stale)

    def history(self, address: str, since: float | None = None) -> list[Sample]:
        s = self.series.get(address.upper())
        return [x for x in s.samples if since is None or x.t >= since] if s else []

    def presence(self, address: str) -> list[Presence]:
        s = self.series.get(address.upper())
        return list(s.presence) if s else []

    def ranked(self) -> list[Series]:
        """Series ordered by their latest reading, strongest first; devices without a reading last."""
        def key(s: Series):
            last = s.samples[-1].rssi if s.samples else None
            return (last is None, -(last or 0), s.address)
        return sorted(self.series.values(), key=key)

    def clear(self) -> None:
        self.series.clear()
