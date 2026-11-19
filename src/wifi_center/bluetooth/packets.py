"""BluetoothPacketAnalyzer: read and summarise HCI captures (btmon / btsnoop files).

What a capture is, and is not
* A capture made here is the HCI traffic of THIS computer's Bluetooth controller: commands, events and data exchanged between the
  host and the controller. At that level the data is already decrypted by the controller, so GATT/ATT and SMP packets are readable.
* It does NOT contain other people's Bluetooth conversations. Over-the-air traffic needs a dedicated sniffer, and encrypted air
  traffic cannot be read without the keys. This module never claims to decode traffic it cannot see.
* Key material (link keys, long-term keys, IRKs, PIN replies) is replaced by "[redacted]" in every summary and hex view, and is not
  exported in the CSV/JSON summaries. The raw capture file itself still contains it: it is stored with mode 0600 and the UI says so.

The parser is pure Python (btsnoop file format, monitor and H4 data links); tshark is optional and only adds a full dissection and
PCAPNG conversion.
"""
from __future__ import annotations

import csv
import io
import json
import os
import shutil
import struct
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..services.process_runner import find_executable, run_command
from .models import BluetoothError

BTSNOOP_MAGIC = b"btsnoop\x00"
EPOCH_DELTA_US = 0x00DCDDB30F2F8000          # btsnoop counts microseconds from year 0
MAX_PACKETS = 200_000
MAX_FILE = 256 * 1024 * 1024
DL_H4, DL_MONITOR, DL_HCI_UNENCAPSULATED = 1002, 2001, 1001

MONITOR_OPCODES = {0: "new_index", 1: "del_index", 2: "cmd", 3: "evt", 4: "acl_tx", 5: "acl_rx", 6: "sco_tx", 7: "sco_rx", 8: "open_index",
                   9: "close_index", 10: "index_info", 11: "vendor_diag", 12: "note", 13: "user_logging", 14: "ctrl_open", 15: "ctrl_close",
                   16: "ctrl_cmd", 17: "ctrl_evt", 18: "iso_tx", 19: "iso_rx"}
H4_TYPES = {1: "cmd", 4: "evt"}          # ACL (type 2) direction comes from the flags; SCO and ISO are not decoded

EVENTS = {0x03: "Connection Complete", 0x04: "Connection Request", 0x05: "Disconnection Complete", 0x06: "Authentication Complete",
          0x07: "Remote Name Request Complete", 0x08: "Encryption Change", 0x0E: "Command Complete", 0x0F: "Command Status",
          0x13: "Number of Completed Packets", 0x16: "PIN Code Request", 0x17: "Link Key Request", 0x18: "Link Key Notification",
          0x2F: "Extended Inquiry Result", 0x31: "IO Capability Request", 0x32: "IO Capability Response", 0x33: "User Confirmation Request",
          0x34: "User Passkey Request", 0x36: "Simple Pairing Complete", 0x3E: "LE Meta Event"}
LE_EVENTS = {1: "LE Connection Complete", 2: "LE Advertising Report", 3: "LE Connection Update Complete", 5: "LE Long Term Key Request",
             0x0A: "LE Enhanced Connection Complete", 0x0D: "LE Extended Advertising Report"}
COMMANDS = {0x0401: "Inquiry", 0x0405: "Create Connection", 0x0406: "Disconnect", 0x040B: "Link Key Request Reply", 0x040D: "PIN Code Request Reply",
            0x0419: "Remote Name Request", 0x0C03: "Reset", 0x0C13: "Write Local Name", 0x0C1A: "Write Scan Enable", 0x2005: "LE Set Random Address",
            0x200A: "LE Set Advertising Enable", 0x200B: "LE Set Scan Parameters", 0x200C: "LE Set Scan Enable", 0x200D: "LE Create Connection",
            0x2019: "LE Start Encryption", 0x201A: "LE Long Term Key Request Reply"}
SECRET_COMMANDS = {0x040B, 0x040D, 0x2019, 0x201A}                 # their parameters are keys or PINs
HCI_ERRORS = {0x01: "Unknown HCI Command", 0x02: "Unknown Connection Identifier", 0x04: "Page Timeout", 0x05: "Authentication Failure",
              0x06: "PIN or Key Missing", 0x08: "Connection Timeout", 0x0C: "Command Disallowed", 0x0D: "Rejected, limited resources",
              0x13: "Remote User Terminated", 0x15: "Remote Terminated, power off", 0x16: "Connection Terminated by Local Host",
              0x3D: "MIC Failure", 0x3E: "Connection Failed to be Established"}
ATT = {0x01: "Error Response", 0x02: "Exchange MTU Request", 0x03: "Exchange MTU Response", 0x04: "Find Information Request",
       0x05: "Find Information Response", 0x08: "Read By Type Request", 0x09: "Read By Type Response", 0x0A: "Read Request", 0x0B: "Read Response",
       0x10: "Read By Group Type Request", 0x11: "Read By Group Type Response", 0x12: "Write Request", 0x13: "Write Response",
       0x1B: "Handle Value Notification", 0x1D: "Handle Value Indication", 0x1E: "Handle Value Confirmation", 0x52: "Write Command"}
SMP = {1: "Pairing Request", 2: "Pairing Response", 3: "Pairing Confirm", 4: "Pairing Random", 5: "Pairing Failed", 6: "Encryption Information",
       7: "Central Identification", 8: "Identity Information", 9: "Identity Address Information", 0x0A: "Signing Information", 0x0B: "Security Request",
       0x0C: "Pairing Public Key", 0x0D: "Pairing DHKey Check"}
SECRET_SMP = {6, 7, 8, 0x0A}
IO_CAPS = {0: "DisplayOnly", 1: "DisplayYesNo", 2: "KeyboardOnly", 3: "NoInputNoOutput", 4: "KeyboardDisplay"}
REDACTED = "[redacted]"


@dataclass
class Packet:
    index: int
    ts: float                    # unix seconds
    kind: str                    # cmd | evt | acl_tx | acl_rx | sco | iso | note | other
    direction: str               # "host → controller" | "controller → host" | ""
    summary: str
    layer: str = "HCI"           # HCI | ACL | L2CAP | ATT | SMP | note
    payload: bytes = b""
    handle: int | None = None
    tags: list[str] = field(default_factory=list)
    secret: bool = False         # key material: summary and hex are redacted

    def hex(self, limit: int = 64) -> str:
        if self.secret:
            return REDACTED
        h = " ".join(f"{b:02X}" for b in self.payload[:limit])
        return h + (f" … (+{len(self.payload) - limit} bytes)" if len(self.payload) > limit else "")

    def as_row(self) -> dict:
        return {"no": self.index, "time": time.strftime("%H:%M:%S", time.localtime(self.ts)) + f".{int((self.ts % 1) * 1000):03d}", "layer": self.layer,
                "direction": self.direction, "summary": self.summary, "length": len(self.payload), "tags": ",".join(self.tags)}


@dataclass
class Analysis:
    path: str
    datalink: int
    packets: list[Packet] = field(default_factory=list)
    truncated: bool = False
    counts: Counter = field(default_factory=Counter)
    connections: list[dict] = field(default_factory=list)
    encryption: list[dict] = field(default_factory=list)
    pairings: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    gatt_writes: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return (self.packets[-1].ts - self.packets[0].ts) if len(self.packets) > 1 else 0.0

    def summary_text(self) -> str:
        lines = [f"{len(self.packets)} packet(s) over {self.duration:.1f} s" + (" (capture truncated at the packet limit)" if self.truncated else "")]
        lines += [f"  {k}: {v}" for k, v in sorted(self.counts.items())]
        lines.append(f"{len(self.connections)} connection event(s), {len(self.encryption)} encryption change(s), {len(self.pairings)} pairing exchange(s), "
                     f"{len(self.errors)} error status(es), {self.gatt_writes} GATT write(s)")
        return "\n".join(lines)

    def export_csv(self) -> str:
        out = io.StringIO()
        w = csv.DictWriter(out, ["no", "time", "layer", "direction", "summary", "length", "tags"])
        w.writeheader()
        for p in self.packets:
            w.writerow(p.as_row())
        return out.getvalue()

    def export_json(self) -> str:
        return json.dumps({"file": os.path.basename(self.path), "packets": [p.as_row() for p in self.packets], "connections": self.connections,
                           "encryption": self.encryption, "pairings": self.pairings, "errors": self.errors, "gatt_writes": self.gatt_writes,
                           "notes": self.notes}, indent=2)


# ------------------------------------------------------------------ pure decoding
def _addr(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in reversed(raw))


def _status(code: int) -> str:
    return "success" if code == 0 else f"failed: {HCI_ERRORS.get(code, f'error 0x{code:02X}')}"


def decode_smp(data: bytes) -> tuple[str, list[str], bool, dict | None]:
    """-> (summary, tags, secret, pairing details for Request/Response)."""
    if not data:
        return "SMP (empty)", [], False, None
    code = data[0]
    name = SMP.get(code, f"SMP 0x{code:02X}")
    if code in SECRET_SMP:
        return f"{name} {REDACTED}", ["key-material"], True, None
    if code in (1, 2) and len(data) >= 7:
        io_cap, oob, auth = data[1], data[2], data[3]
        d = {"io": IO_CAPS.get(io_cap, f"0x{io_cap:02X}"), "oob": bool(oob), "bonding": bool(auth & 0x03), "mitm": bool(auth & 0x04),
             "secure_connections": bool(auth & 0x08)}
        return (f"{name}: {d['io']}, {'bonding, ' if d['bonding'] else ''}{'MITM, ' if d['mitm'] else ''}{'Secure Connections' if d['secure_connections'] else 'legacy'}",
                ["pairing"], False, d)
    if code == 5 and len(data) >= 2:
        return f"{name}: reason 0x{data[1]:02X}", ["pairing", "error"], False, None
    return name, ["pairing"] if code in (3, 4, 0x0C, 0x0D, 0x0B) else [], False, None


def decode_att(data: bytes) -> tuple[str, list[str]]:
    if not data:
        return "ATT (empty)", []
    op = data[0]
    name = ATT.get(op, f"ATT 0x{op:02X}")
    tags: list[str] = []
    if op in (0x0A, 0x12, 0x52, 0x1B, 0x1D) and len(data) >= 3:
        handle = struct.unpack("<H", data[1:3])[0]
        name += f" (handle 0x{handle:04X}" + ("" if op == 0x0A else f", {len(data) - 3} byte(s)") + ")"
    if op in (0x12, 0x52):
        tags.append("gatt-write")
    return name, tags


def decode_acl(data: bytes) -> tuple[str, str, int | None, list[str], bool, dict | None]:
    """-> (layer, summary, handle, tags, secret, pairing)."""
    if len(data) < 4:
        return "ACL", "ACL (short)", None, [], False, None
    hf, _total = struct.unpack("<HH", data[:4])
    handle, pb = hf & 0x0FFF, (hf >> 12) & 3
    body = data[4:]
    if pb == 1:
        return "ACL", f"ACL continuation, {len(body)} byte(s)", handle, [], False, None
    if len(body) < 4:
        return "ACL", f"ACL, {len(body)} byte(s)", handle, [], False, None
    l2len, cid = struct.unpack("<HH", body[:4])
    pl = body[4:4 + l2len]
    if cid == 4:
        s, tags = decode_att(pl)
        return "ATT", s, handle, tags, False, None
    if cid == 6:
        s, tags, secret, pairing = decode_smp(pl)
        return "SMP", s, handle, tags, secret, pairing
    names = {1: "L2CAP signalling", 5: "LE signalling"}
    return "L2CAP", f"{names.get(cid, f'channel 0x{cid:04X}')}, {len(pl)} byte(s)", handle, [], False, None


def decode_event(data: bytes) -> tuple[str, list[str], dict | None]:
    if len(data) < 2:
        return "Event (short)", [], None
    code, body = data[0], data[2:]
    name = EVENTS.get(code, f"Event 0x{code:02X}")
    info: dict | None = None
    tags: list[str] = []
    if code == 0x18:
        return f"{name} {REDACTED}", ["key-material"], None
    if code == 0x08 and len(body) >= 4:
        st, handle, en = body[0], struct.unpack("<H", body[1:3])[0], body[3]
        info = {"type": "encryption", "handle": handle, "enabled": bool(en), "status": st}
        name += f": handle 0x{handle:04X} {'enabled' if en else 'disabled'} ({_status(st)})"
    elif code == 0x05 and len(body) >= 4:
        st, handle, reason = body[0], struct.unpack("<H", body[1:3])[0], body[3]
        info = {"type": "disconnect", "handle": handle, "reason": HCI_ERRORS.get(reason, f"0x{reason:02X}")}
        name += f": handle 0x{handle:04X}, reason {info['reason']}"
    elif code == 0x03 and len(body) >= 9:
        st, handle, addr = body[0], struct.unpack("<H", body[1:3])[0], _addr(body[3:9])
        info = {"type": "connect", "handle": handle, "address": addr, "transport": "BR/EDR", "status": st}
        name += f": {addr} handle 0x{handle:04X} ({_status(st)})"
    elif code == 0x3E and body:
        sub = body[0]
        name = LE_EVENTS.get(sub, f"LE Meta 0x{sub:02X}")
        if sub in (1, 0x0A) and len(body) >= 13:
            st, handle, addr = body[1], struct.unpack("<H", body[2:4])[0], _addr(body[6:12])
            info = {"type": "connect", "handle": handle, "address": addr, "transport": "LE", "status": st}
            name += f": {addr} handle 0x{handle:04X} ({_status(st)})"
    elif code == 0x0E and len(body) >= 4:
        op, st = struct.unpack("<H", body[1:3])[0], body[3]
        name += f": {COMMANDS.get(op, f'0x{op:04X}')} {_status(st)}"
        if st:
            info = {"type": "error", "what": COMMANDS.get(op, f"command 0x{op:04X}"), "status": _status(st)}
    elif code == 0x0F and len(body) >= 4:
        st, op = body[0], struct.unpack("<H", body[2:4])[0]
        name += f": {COMMANDS.get(op, f'0x{op:04X}')} {_status(st) if st else 'pending'}"
        if st:
            info = {"type": "error", "what": COMMANDS.get(op, f"command 0x{op:04X}"), "status": _status(st)}
    elif code in (0x06, 0x36) and body:
        name += f": {_status(body[0])}"
        if body[0]:
            info = {"type": "error", "what": EVENTS[code], "status": _status(body[0])}
        tags.append("pairing")
    elif code in (0x16, 0x31, 0x32, 0x33, 0x34):
        tags.append("pairing")
    return name, tags, info


def decode_command(data: bytes) -> tuple[str, bool]:
    if len(data) < 3:
        return "Command (short)", False
    op = struct.unpack("<H", data[:2])[0]
    name = COMMANDS.get(op, f"Command 0x{op:04X}")
    secret = op in SECRET_COMMANDS
    return (f"{name} {REDACTED}" if secret else name), secret


# ------------------------------------------------------------------ file parsing
def parse_btsnoop(path: str | Path, max_packets: int = MAX_PACKETS) -> Analysis:
    p = Path(path)
    if not p.is_file():
        raise BluetoothError("That capture file does not exist.")
    if p.stat().st_size > MAX_FILE:
        raise BluetoothError("The capture is larger than 256 MiB; split it or open it in Wireshark.")
    raw = p.read_bytes()
    if len(raw) < 16 or raw[:8] != BTSNOOP_MAGIC:
        raise BluetoothError("This is not a btsnoop capture (Wireshark's .pcap/.pcapng are opened with tshark or Wireshark instead).")
    version, datalink = struct.unpack(">II", raw[8:16])
    a = Analysis(str(p), datalink)
    if datalink not in (DL_MONITOR, DL_H4, DL_HCI_UNENCAPSULATED):
        a.notes.append(f"Unsupported data link type {datalink}; only HCI captures are decoded.")
        return a
    pos, n = 16, len(raw)
    open_connections: dict[int, dict] = {}
    while pos + 24 <= n:
        orig, incl, flags, _drops, ts = struct.unpack(">IIIIq", raw[pos:pos + 24])
        pos += 24
        if incl > n - pos or incl > 1 << 20:
            a.notes.append("The capture ends with a damaged record; everything before it was read.")
            break
        data = raw[pos:pos + incl]
        pos += incl
        if len(a.packets) >= max_packets:
            a.truncated = True
            break
        t = (ts - EPOCH_DELTA_US) / 1e6
        kind, direction = "other", ""
        if datalink == DL_MONITOR:
            kind = MONITOR_OPCODES.get(flags & 0xFFFF, "other")
        elif datalink == DL_H4 and data:
            t4, data = data[0], data[1:]
            if t4 == 2:
                kind = "acl_rx" if flags & 1 else "acl_tx"
            else:
                kind = H4_TYPES.get(t4) or "other"
        else:
            kind = ("evt" if flags & 1 else "cmd") if flags & 2 else ("acl_rx" if flags & 1 else "acl_tx")
        direction = {"cmd": "host → controller", "acl_tx": "host → controller", "sco_tx": "host → controller", "iso_tx": "host → controller",
                     "evt": "controller → host", "acl_rx": "controller → host", "sco_rx": "controller → host", "iso_rx": "controller → host"}.get(kind, "")
        pkt = Packet(len(a.packets) + 1, t, kind, direction, kind, "HCI", data)
        info = None
        if kind == "cmd":
            pkt.summary, pkt.secret = decode_command(data)
            if pkt.secret:
                pkt.tags.append("key-material")
        elif kind == "evt":
            pkt.summary, pkt.tags, info = decode_event(data)
            pkt.secret = "key-material" in pkt.tags
        elif kind in ("acl_tx", "acl_rx"):
            pkt.layer, pkt.summary, pkt.handle, pkt.tags, pkt.secret, pairing = decode_acl(data)
            if pairing is not None:
                a.pairings.append({"time": t, "direction": direction, **pairing})
            if "gatt-write" in pkt.tags:
                a.gatt_writes += 1
        elif kind == "note":
            pkt.layer, pkt.summary = "note", data.rstrip(b"\x00").decode("utf-8", "replace")[:200]
        elif kind in ("new_index", "index_info"):
            pkt.summary = "Controller added" + (f": {_addr(data[1:7])}" if len(data) >= 7 else "")
        else:
            pkt.summary = kind.replace("_", " ")
        if pkt.secret:
            pkt.payload = b""
        a.packets.append(pkt)
        a.counts[pkt.layer if pkt.layer != "HCI" else kind] += 1
        if info:
            _record(a, info, t, open_connections)
    _conclude(a)
    return a


def _record(a: Analysis, info: dict, t: float, conns: dict[int, dict]) -> None:
    kind = info["type"]
    if kind == "connect":
        row = {"time": t, "address": info["address"], "handle": info["handle"], "transport": info["transport"], "result": _status(info["status"])}
        a.connections.append(row)
        if info["status"] == 0:
            conns[info["handle"]] = row
    elif kind == "disconnect":
        peer = conns.pop(info["handle"], None)
        a.connections.append({"time": t, "address": peer["address"] if peer else "", "handle": info["handle"], "transport": peer["transport"] if peer else "",
                              "result": f"disconnected: {info['reason']}"})
    elif kind == "encryption":
        peer = conns.get(info["handle"])
        a.encryption.append({"time": t, "handle": info["handle"], "address": peer["address"] if peer else "", "enabled": info["enabled"],
                             "result": _status(info["status"])})
    elif kind == "error":
        a.errors.append({"time": t, "what": info["what"], "status": info["status"]})


def _conclude(a: Analysis) -> None:
    """Evidence-based reading of the pairing exchanges: only what the packets show."""
    reqs = [p for p in a.pairings if p["direction"].startswith("host")]
    resps = [p for p in a.pairings if p["direction"].startswith("controller")]
    for pr in a.pairings:
        pr["time_text"] = time.strftime("%H:%M:%S", time.localtime(pr["time"]))
    if reqs and resps:
        sc = reqs[0]["secure_connections"] and resps[0]["secure_connections"]
        mitm = reqs[0]["mitm"] or resps[0]["mitm"]
        a.notes.append(f"LE pairing in this capture: {'LE Secure Connections' if sc else 'legacy LE pairing (at least one side did not set the Secure Connections flag)'}; "
                       f"{'MITM protection requested' if mitm else 'no MITM protection requested (Just Works style association)'}. "
                       "This reads the pairing flags the two sides exchanged; it does not prove the pairing succeeded or the final key strength.")
    elif a.pairings:
        a.notes.append("A pairing request or response is present, but not both: the exchange is incomplete in this capture.")
    if a.encryption:
        on = sum(1 for e in a.encryption if e["enabled"] and e["result"] == "success")
        a.notes.append(f"{on} successful encryption-enable event(s) were seen. Encryption on a link is confirmed only by such events.")
    if a.packets and not a.connections:
        a.notes.append("No connection events: the capture may have started after the links were established.")


# ------------------------------------------------------------------ the analyzer (files, tools)
class BluetoothPacketAnalyzer:
    SCOPE_NOTE = ("A capture here records this computer's own Bluetooth controller (HCI). It shows traffic between this computer and the devices it talks "
                  "to; it does not capture other people's conversations, and over-the-air encrypted traffic cannot be read without keys. Capturing needs "
                  "administrator authentication and can include pairing secrets, so the file is private to you (mode 0600). Capture only your own devices.")

    def __init__(self, directory: Path, run: Callable | None = None, which: Callable[[str], str | None] = find_executable) -> None:
        self.dir = Path(directory)
        self._run = run or (lambda argv, t: run_command(argv, t))
        self._which = which

    def tools(self) -> dict[str, str | None]:
        return {"btmon": self._which("btmon"), "tshark": self._which("tshark")}

    def adopt(self, source: str) -> Path:
        """Copy a capture the helper produced into the application's own folder (private to the user)."""
        src = Path(source)
        if not src.is_file() or src.suffix != ".btsnoop":
            raise BluetoothError("The capture file is missing.")
        self.dir.mkdir(parents=True, exist_ok=True)
        dest = self.dir / src.name
        shutil.copyfile(src, dest)
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        return dest

    def list(self) -> list[dict]:
        if not self.dir.is_dir():
            return []
        rows = [{"path": str(p), "name": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime} for p in self.dir.glob("*.btsnoop")]
        return sorted(rows, key=lambda r: -r["mtime"])

    def delete(self, path: str) -> None:
        p = Path(path)
        if p.parent != self.dir or p.suffix != ".btsnoop":
            raise BluetoothError("Only captures stored by WIFI Center can be deleted here.")
        p.unlink(missing_ok=True)

    def analyze(self, path: str) -> Analysis:
        return parse_btsnoop(path)

    def tshark_decode(self, path: str, display_filter: str = "", limit: int = 400) -> str:
        """Full dissection through tshark (read-only, runs as you). Empty filter = everything up to `limit` packets."""
        exe = self._which("tshark")
        if not exe:
            raise BluetoothError("tshark is not installed (sudo apt install tshark). The built-in analysis above works without it.")
        if len(display_filter) > 300 or any(c in display_filter for c in "\x00\n\r"):
            raise BluetoothError("That display filter is not valid.")
        argv = [exe, "-r", path, "-c", str(max(1, min(limit, 5000)))]
        if display_filter:
            argv += ["-Y", display_filter]
        res = self._run(argv, 90)
        if not res.ok:
            raise BluetoothError("tshark could not read the capture: " + (getattr(res, "stderr", "") or "unknown error")[:200])
        return res.stdout

    def convert_pcapng(self, path: str, dest: str) -> None:
        exe = self._which("tshark")
        if not exe:
            raise BluetoothError("Converting to PCAPNG needs tshark (sudo apt install tshark). The .btsnoop file opens directly in Wireshark.")
        res = self._run([exe, "-r", path, "-F", "pcapng", "-w", dest], 120)
        if not res.ok:
            raise BluetoothError("tshark could not convert the capture.")
