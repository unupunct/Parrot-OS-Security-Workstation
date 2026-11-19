"""Analytics over REAL stored Wi-Fi scans: per-scan network sets, activity events (appearances, disappearances, signal
changes), signal statistics and channel occupancy with interference levels. Pure functions: nothing here invents data; with no
scans every function returns an empty result and the UI shows an empty state."""
from __future__ import annotations

from dataclasses import dataclass, field

CHANGE_DB = 6.0           # a signal move of at least this many dB between two scans counts as a change
BANDS = ("2.4 GHz", "5 GHz", "6 GHz")


@dataclass
class ScanEvent:
    ts: str
    kind: str                 # appeared | disappeared | changed
    ssid: str
    bssid: str
    band: str
    detail: str = ""


@dataclass
class ScanSummary:
    ts: str
    counts: dict[str, int] = field(default_factory=dict)          # band -> networks seen in this scan
    events: list[ScanEvent] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def band_of_freq(freq: int | None) -> str:
    if not freq:
        return "unknown"
    return "2.4 GHz" if freq < 3000 else "5 GHz" if freq < 5925 else "6 GHz"


def summarize_scans(scans: list[dict]) -> list[ScanSummary]:
    """`scans` = [{ts, aps: [{id, ssid, bssid, signal_dbm, frequency_mhz}]}] oldest first. The first scan has no events
    (everything is new by definition and would say nothing); later scans are compared with the one before."""
    out: list[ScanSummary] = []
    prev: dict[int, dict] | None = None
    for sc in scans:
        cur = {a["id"]: a for a in sc["aps"]}
        counts: dict[str, int] = {}
        for a in cur.values():
            b = band_of_freq(a.get("frequency_mhz"))
            counts[b] = counts.get(b, 0) + 1
        summ = ScanSummary(sc["ts"], counts)
        if prev is not None:
            for oid, a in cur.items():
                b = band_of_freq(a.get("frequency_mhz"))
                if oid not in prev:
                    summ.events.append(ScanEvent(sc["ts"], "appeared", a.get("ssid") or "<hidden>", a["bssid"], b,
                                                 f"{a['signal_dbm']:.0f} dBm" if a.get("signal_dbm") is not None else ""))
                else:
                    old, new = prev[oid].get("signal_dbm"), a.get("signal_dbm")
                    if old is not None and new is not None and abs(new - old) >= CHANGE_DB:
                        summ.events.append(ScanEvent(sc["ts"], "changed", a.get("ssid") or "<hidden>", a["bssid"], b,
                                                     f"{old:.0f} → {new:.0f} dBm"))
            for oid, a in prev.items():
                if oid not in cur:
                    summ.events.append(ScanEvent(sc["ts"], "disappeared", a.get("ssid") or "<hidden>", a["bssid"],
                                                 band_of_freq(a.get("frequency_mhz")), "not seen in this scan"))
        out.append(summ)
        prev = cur
    return out


@dataclass
class SignalStats:
    current: float
    minimum: float
    maximum: float
    average: float
    samples: int


def signal_stats(values: list[float | None]) -> SignalStats | None:
    v = [x for x in values if x is not None]
    if not v:
        return None
    return SignalStats(v[-1], min(v), max(v), sum(v) / len(v), len(v))


@dataclass
class ChannelStat:
    channel: int
    band: str
    count: int
    percent: float
    neighbours: int            # OTHER networks whose signal overlaps this channel
    level: str                 # low | medium | high


def _overlaps(band: str, a: int, b: int) -> bool:
    """2.4 GHz channels are 5 MHz apart and 20 MHz wide: channels fewer than 5 apart overlap. In 5/6 GHz only the same channel does."""
    return abs(a - b) < 5 if band == "2.4 GHz" else a == b


def channel_occupancy(rows: list[dict]) -> list[ChannelStat]:
    """Networks per channel (from the rows shown), the share of all networks, and how many OTHER networks overlap it."""
    chans: dict[tuple[str, int], int] = {}
    for r in rows:
        if r.get("channel"):
            band = r.get("band") or band_of_freq(r.get("frequency_mhz"))
            chans[(band, r["channel"])] = chans.get((band, r["channel"]), 0) + 1
    total = sum(chans.values())
    out = []
    for (band, ch), n in sorted(chans.items(), key=lambda kv: (BANDS.index(kv[0][0]) if kv[0][0] in BANDS else 9, kv[0][1])):
        nb = sum(m for (b2, c2), m in chans.items() if b2 == band and _overlaps(band, ch, c2)) - n + (n - 1)
        level = "low" if nb <= 1 else "medium" if nb <= 3 else "high"
        out.append(ChannelStat(ch, band, n, 100.0 * n / total if total else 0.0, nb, level))
    return out
