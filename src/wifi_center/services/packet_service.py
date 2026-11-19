"""Offline packet-capture analysis through TShark. Reads existing files only; never captures."""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..security.input_validation import ValidationError, validate_absolute_path
from .process_runner import run_command

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")
FIELDS = ("frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "frame.protocols")


class PacketError(RuntimeError):
    pass


@dataclass
class CaptureMetadata:
    values: dict[str, str] = field(default_factory=dict)


@dataclass
class PacketAnalysis:
    path: str
    packets: int = 0
    total_bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    protocols: Counter = field(default_factory=Counter)          # leaf protocol -> packets
    conversations: dict[tuple[str, str], list[int]] = field(default_factory=dict)  # (a,b) -> [packets, bytes]
    timeline: dict[int, list[int]] = field(default_factory=dict)  # second offset -> [packets, bytes]
    truncated: bool = False

    @property
    def duration(self) -> float:
        return (self.last_ts - self.first_ts) if self.first_ts is not None and self.last_ts is not None else 0.0

    def top_conversations(self, n: int = 20) -> list[tuple[str, str, int, int]]:
        rows = [(a, b, v[0], v[1]) for (a, b), v in self.conversations.items()]
        return sorted(rows, key=lambda r: r[3], reverse=True)[:n]


def validate_capture_path(path: str) -> Path:
    p = validate_absolute_path(path, kind="file")
    if p.suffix.lower() not in CAPTURE_SUFFIXES:
        raise ValidationError("not a capture file (.pcap, .pcapng, .cap)")
    return p


_LEAF_SKIP = {"eth", "ethertype", "sll", "frame", "data"}


def leaf_protocol(protocols: str) -> str:
    parts = [p for p in protocols.split(":") if p]
    for p in reversed(parts):
        if p not in _LEAF_SKIP:
            return p
    return parts[-1] if parts else "unknown"


def analyze_lines(lines, path: str = "", max_packets: int | None = None) -> PacketAnalysis:
    """Aggregate tshark `-T fields` output (tab separated, FIELDS order). Pure and unit-testable."""
    a = PacketAnalysis(path)
    times: list[tuple[float, int]] = []
    for line in lines:
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 2:
            continue
        cols += [""] * (len(FIELDS) - len(cols))
        try:
            ts, size = float(cols[0]), int(cols[1])
        except ValueError:
            continue
        if max_packets is not None and a.packets >= max_packets:
            a.truncated = True
            break
        a.packets += 1
        a.total_bytes += size
        a.first_ts = ts if a.first_ts is None else min(a.first_ts, ts)
        a.last_ts = ts if a.last_ts is None else max(a.last_ts, ts)
        a.protocols[leaf_protocol(cols[6])] += 1
        src = cols[2].split(",")[0] or cols[4].split(",")[0]
        dst = cols[3].split(",")[0] or cols[5].split(",")[0]
        if src and dst:
            key = tuple(sorted((src, dst)))
            conv = a.conversations.setdefault(key, [0, 0])  # type: ignore[arg-type]
            conv[0] += 1
            conv[1] += size
        times.append((ts, size))
    base = a.first_ts or 0.0
    tl: dict[int, list[int]] = defaultdict(lambda: [0, 0])
    for ts, size in times:
        b = tl[int(ts - base)]
        b[0] += 1
        b[1] += size
    a.timeline = dict(tl)
    return a


def parse_capinfos(text: str) -> CaptureMetadata:
    md = CaptureMetadata()
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z][^:]{2,40}):\s+(.+)$", line.strip())
        if m:
            md.values[m.group(1).strip()] = m.group(2).strip()
    return md


class PacketService:
    def available(self) -> bool:
        return shutil.which("tshark") is not None

    def metadata(self, path: str) -> CaptureMetadata:
        p = validate_capture_path(path)
        if not shutil.which("capinfos"):
            return CaptureMetadata()
        r = run_command(["capinfos", str(p)], timeout=60)
        return parse_capinfos(r.stdout) if r.ok else CaptureMetadata()

    def analyze(self, path: str, max_packets: int = 500_000, timeout: float = 180.0,
                cancel: threading.Event | None = None) -> PacketAnalysis:
        p = validate_capture_path(path)
        exe = shutil.which("tshark")
        if not exe:
            raise PacketError("TShark is not installed (sudo apt install tshark)")
        argv = [exe, "-r", str(p), "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
        for f in FIELDS:
            argv += ["-e", f]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
                                stdin=subprocess.DEVNULL, shell=False)
        timer = threading.Timer(timeout, proc.kill)
        timer.start()

        def lines():
            for line in proc.stdout:  # type: ignore[union-attr]
                if cancel is not None and cancel.is_set():
                    proc.kill()
                    return
                yield line

        try:
            result = analyze_lines(lines(), str(p), max_packets)
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
            err = proc.stderr.read() if proc.stderr else ""
            proc.wait()
        if result.packets == 0 and proc.returncode not in (0, None, -9):
            raise PacketError((err.strip().splitlines() or ["tshark failed to read the file"])[-1])
        return result
