"""Hardware inventory for the System Information page (Speccy-style): CPU, memory, motherboard, graphics, storage,
optical drives, audio, network adapters and USB peripherals, with temperatures and fans where the kernel reports them.

Everything is read without privileges from /sys, /proc, psutil and standard tools (lscpu, lspci, lsblk, lsusb);
details that need root (memory slot type/speed, serial numbers, SMART) are not read and the page says so.
All parsing is pure and tested; the collector takes injectable readers so it can be tested anywhere.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import psutil

from .process_runner import run_command

Runner = Callable[[list[str], float], "object"]


@dataclass
class Item:
    label: str
    value: str

    def __post_init__(self) -> None:
        self.value = "" if self.value is None else str(self.value)


@dataclass
class Group:
    title: str
    items: list[Item] = field(default_factory=list)
    temp: float | None = None            # degrees C for the group's headline sensor
    bar: float | None = None             # 0..100 usage shown as a bar


@dataclass
class Section:
    id: str
    title: str
    icon: str
    headline: str                         # one line for the summary view
    temp: float | None = None
    groups: list[Group] = field(default_factory=list)
    note: str = ""


# ------------------------------------------------------------------ parsers
def parse_lscpu(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def parse_lspci_mm(text: str) -> list[dict[str, str]]:
    """`lspci -mm -k`: slot "class" "vendor" "device" ..."""
    rows = []
    for line in text.splitlines():
        parts = re.findall(r'"([^"]*)"', line)
        slot = line.split(None, 1)[0] if line.strip() else ""
        if len(parts) >= 3 and slot:
            rows.append({"slot": slot, "class": parts[0], "vendor": parts[1], "device": parts[2]})
    return rows


def parse_lsblk_json(text: str) -> list[dict]:
    try:
        return list(json.loads(text).get("blockdevices", []))
    except (ValueError, AttributeError):
        return []


def parse_lsusb(text: str) -> list[tuple[str, str]]:
    """`lsusb` lines -> (vendor:product id, description)."""
    out = []
    for line in text.splitlines():
        m = re.match(r"Bus \d+ Device \d+: ID ([0-9a-fA-F]{4}:[0-9a-fA-F]{4})\s*(.*)", line)
        if m:
            out.append((m.group(1).lower(), m.group(2).strip()))
    return out


def parse_asound_cards(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*\d+\s+\[(\S+)\s*\]:\s*(.*)", line)
        if m:
            out.append(m.group(2).strip())
    return out


def human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def temp_level(t: float | None, warn: float = 70.0, hot: float = 85.0) -> str:
    if t is None:
        return "none"
    return "hot" if t >= hot else "warm" if t >= warn else "ok"


def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


class HardwareInfoService:
    def __init__(self, runner: Runner | None = None, sys_root: str = "/sys", proc_root: str = "/proc",
                 which: Callable[[str], str | None] | None = None) -> None:
        self._run = runner or (lambda argv, t: run_command(argv, timeout=t))
        self._which = which or shutil.which
        self._sys, self._proc = sys_root, proc_root

    # ---------------------------------------------------------------- helpers
    def _out(self, argv: list[str], timeout: float = 10.0) -> str:
        if not self._which(argv[0]):
            return ""
        try:
            r = self._run(argv, timeout)
            return r.stdout if getattr(r, "ok", False) else ""
        except Exception:
            return ""

    def _temps(self) -> dict[str, list[tuple[str, float]]]:
        try:
            return {k: [(s.label or k, float(s.current)) for s in v] for k, v in psutil.sensors_temperatures().items()}
        except (AttributeError, OSError):
            return {}

    def _fans(self) -> list[tuple[str, int]]:
        try:
            return [(s.label or k, int(s.current)) for k, v in psutil.sensors_fans().items() for s in v]
        except (AttributeError, OSError):
            return []

    # ---------------------------------------------------------------- sections
    def collect(self) -> list[Section]:
        temps, fans = self._temps(), self._fans()
        usb = parse_lsusb(self._out(["lsusb"]))
        return [self.cpu(temps), self.memory(), self.motherboard(temps, fans), self.graphics(temps),
                self.storage(temps), self.optical(), self.audio(), self.network(usb), self.peripherals(usb)]

    def cpu(self, temps: dict) -> Section:
        d = parse_lscpu(self._out(["lscpu"]))
        name = d.get("Model name") or d.get("Model") or "Unknown processor"
        cores = [v for k, v in temps.items() if k in ("coretemp", "k10temp", "zenpower", "cpu_thermal")]
        flat = [t for sub in cores for t in sub]
        pkg = next((t for lbl, t in flat if "package" in lbl.lower() or "tdie" in lbl.lower() or "tctl" in lbl.lower()),
                   max((t for _, t in flat), default=None))
        if pkg is None:                                    # e.g. Apple SMC: the CPU proximity/die sensors
            smc = {lbl: t for v in temps.values() for lbl, t in v}
            pkg = next((smc[k] for k in ("TC0P", "TC0D", "TC0c", "TC0C") if k in smc), None)     # proximity, then die
        busy = psutil.cpu_percent(interval=0.25)       # measured over a short window (a first call would read 0)
        g = Group("Processor", [
            Item("Name", name), Item("Vendor", d.get("Vendor ID", "")), Item("Architecture", d.get("Architecture", "")),
            Item("Cores / threads", f"{d.get('Core(s) per socket', psutil.cpu_count(logical=False) or '?')} cores, "
                                    f"{d.get('CPU(s)', psutil.cpu_count() or '?')} threads"),
            Item("Sockets", d.get("Socket(s)", "")),
            Item("Frequency", f"{psutil.cpu_freq().current:.0f} MHz now" if psutil.cpu_freq() else ""),
            Item("Min / max frequency", f"{d.get('CPU min MHz', '?').split(',')[0].split('.')[0]} / "
                                        f"{d.get('CPU max MHz', '?').split(',')[0].split('.')[0]} MHz"),
            Item("Virtualization", d.get("Virtualization", "not reported")),
            Item("Utilization", f"{busy:.0f} %"),
        ], temp=pkg, bar=busy)
        cache = Group("Caches", [Item(k.replace(" cache", ""), v) for k, v in d.items() if k.endswith(" cache")])
        per_core = Group("Core temperatures", [Item(lbl, f"{t:.0f} °C") for lbl, t in flat if lbl.lower().startswith("core")]) \
            if any(lbl.lower().startswith("core") for lbl, _ in flat) else None
        vulns = [Item(k.replace("Vulnerability ", ""), v) for k, v in d.items() if k.startswith("Vulnerability ")]
        groups = [g, cache] + ([per_core] if per_core else []) + ([Group("Security mitigations", vulns)] if vulns else [])
        return Section("cpu", "CPU", "cpu", name, pkg, [x for x in groups if x.items])

    def memory(self) -> Section:
        vm, sw = psutil.virtual_memory(), psutil.swap_memory()
        info = {}
        for line in _read(Path(self._proc) / "meminfo").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k] = v.strip()
        g = Group("Physical memory", [Item("Installed", human(vm.total)), Item("In use", human(vm.used)),
                                      Item("Available", human(vm.available)), Item("Cached", info.get("Cached", "").replace(" kB", " KiB"))],
                  bar=vm.percent)
        s = Group("Swap", [Item("Size", human(sw.total)), Item("In use", human(sw.used))], bar=sw.percent if sw.total else None)
        return Section("memory", "RAM", "ram", f"{human(vm.total)} ({vm.percent:.0f} % in use)", None, [g, s],
                       note="Module type, speed and slots need root (dmidecode) and are not read.")

    def motherboard(self, temps: dict, fans: list) -> Section:
        dmi = Path(self._sys) / "class/dmi/id"
        rd = lambda n: _read(dmi / n)                                                  # noqa: E731
        board = " ".join(x for x in (rd("board_vendor"), rd("board_name")) if x) or "not reported"
        machine = " ".join(x for x in (rd("sys_vendor"), rd("product_name")) if x)
        g = Group("System", [Item("Model", machine or "not reported"), Item("Motherboard", board),
                             Item("Board version", rd("board_version")), Item("Chassis type", rd("chassis_type"))])
        b = Group("BIOS / firmware", [Item("Vendor", rd("bios_vendor")), Item("Version", rd("bios_version")),
                                      Item("Date", rd("bios_date")),
                                      Item("Boot mode", "UEFI" if (Path(self._sys) / "firmware/efi").exists() else "legacy BIOS")])
        groups = [g, b]
        sensor_items = []
        for chip, rows in temps.items():
            if chip in ("coretemp", "k10temp", "amdgpu", "radeon", "nouveau", "nvme", "drivetemp"):
                continue
            for lbl, t in rows[:12]:
                sensor_items.append(Item(f"{chip} {lbl}", f"{t:.0f} °C"))
        if sensor_items:
            groups.append(Group("Temperature sensors", sensor_items))
        if fans:
            groups.append(Group("Fans", [Item(lbl, f"{rpm} RPM") for lbl, rpm in fans]))
        ambient = [t for rows in temps.values() for lbl, t in rows if lbl.upper().startswith("TA0P")]
        return Section("board", "Motherboard", "board", f"{machine or board}", ambient[0] if ambient else None,
                       [x for x in groups if x.items], note="Serial numbers need root and are not read.")

    def graphics(self, temps: dict) -> Section:
        rows = [r for r in parse_lspci_mm(self._out(["lspci", "-mm", "-k"]))
                if r["class"].startswith(("VGA", "3D", "Display"))]
        gpu_t = next((t for k in ("amdgpu", "radeon", "nouveau") for _, t in temps.get(k, [])), None)
        gpu_t = gpu_t if gpu_t is not None else next((t for k, v in temps.items() for lbl, t in v if lbl.upper().startswith("TG0")), None)
        groups = []
        for r in rows:
            slot_dir = Path(self._sys) / "bus/pci/devices" / f"0000:{r['slot']}"
            driver = os.path.basename(os.readlink(slot_dir / "driver")) if (slot_dir / "driver").is_symlink() else "none"
            groups.append(Group(f"{r['vendor']} {r['device']}",
                                [Item("PCI slot", r["slot"]), Item("Kernel driver", driver)], temp=gpu_t))
        mon = []
        drm = Path(self._sys) / "class/drm"
        if drm.is_dir():
            for c in sorted(drm.iterdir()):
                if "-" in c.name and _read(c / "status") == "connected":
                    modes = _read(c / "modes").splitlines()
                    mon.append(Item(c.name.split("-", 1)[1], modes[0] if modes else "connected"))
        if mon:
            groups.append(Group("Connected displays", mon))
        names = [f"{r['vendor'].split('[')[-1].strip(']')} {r['device']}" for r in rows]
        head = " + ".join(names[:2]) if names else "No graphics adapter found"
        return Section("graphics", "Graphics", "gpu", head, gpu_t, groups)

    def storage(self, temps: dict) -> Section:
        devs = parse_lsblk_json(self._out(["lsblk", "-J", "-d", "-b", "-o", "NAME,MODEL,SIZE,ROTA,TRAN,TYPE,RM"]))
        groups, head = [], ""
        drive_t = [t for k, v in temps.items() if k in ("drivetemp", "nvme") for _, t in v]
        for d in devs:
            if d.get("type") != "disk" or not int(d.get("size") or 0):
                continue
            kind = "SSD" if str(d.get("rota")) in ("0", "False", "false") else "HDD"
            if (d.get("tran") or "") == "usb":
                kind = "USB " + kind
            name = (d.get("model") or d.get("name") or "disk").strip()
            head = head or f"{name} ({human(int(d['size']))})"
            groups.append(Group(name, [Item("Device", "/dev/" + d["name"]), Item("Capacity", human(int(d["size"]))),
                                       Item("Type", kind), Item("Interface", d.get("tran") or "unknown")],
                                temp=drive_t[0] if drive_t and not groups else None))
        parts = []
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
            except OSError:
                continue
            parts.append(Group(f"{p.mountpoint}  ({p.fstype})", [Item("Device", p.device), Item("Used", f"{human(u.used)} of {human(u.total)}")],
                               bar=u.percent))
        return Section("storage", "Storage", "disk", head or "No physical disks found", drive_t[0] if drive_t else None,
                       groups + parts, note="SMART health needs root and is not read.")

    def optical(self) -> Section:
        devs = parse_lsblk_json(self._out(["lsblk", "-J", "-d", "-o", "NAME,MODEL,TYPE,SIZE"]))
        rows = [d for d in devs if d.get("type") == "rom"]
        groups = [Group((d.get("model") or d["name"]).strip(), [Item("Device", "/dev/" + d["name"]),
                                                                Item("Media", d.get("size") or "no disc")]) for d in rows]
        return Section("optical", "Optical drives", "disc", (rows[0].get("model") or "optical drive").strip() if rows
                       else "No optical drive", None, groups)

    def audio(self) -> Section:
        cards = parse_asound_cards(_read(Path(self._proc) / "asound/cards"))
        pci = [r for r in parse_lspci_mm(self._out(["lspci", "-mm"])) if r["class"].startswith(("Audio", "Multimedia audio"))]
        groups = [Group("Sound cards", [Item(f"Card {i}", c) for i, c in enumerate(cards)])] if cards else []
        if pci:
            groups.append(Group("Audio controllers", [Item(r["slot"], f"{r['vendor']} {r['device']}") for r in pci]))
        return Section("audio", "Audio", "speaker", cards[0] if cards else "No sound card found", None, groups)

    def network(self, usb: list[tuple[str, str]]) -> Section:
        names = {k: v for k, v in usb}
        groups = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for ifname in sorted(stats):
            if ifname == "lo" or ifname.startswith(("veth", "docker", "br-", "virbr")):
                continue
            base = Path(self._sys) / "class/net" / ifname
            wireless = (base / "wireless").exists() or (base / "phy80211").exists()
            dev = base / "device"
            driver = os.path.basename(os.readlink(dev / "driver")) if (dev / "driver").is_symlink() else ""
            usb_id = ""
            try:
                real = dev.resolve()
                for parent in (real, real.parent):
                    v, p = _read(parent / "idVendor"), _read(parent / "idProduct")
                    if v and p:
                        usb_id = f"{v}:{p}".lower()
                        break
            except OSError:
                pass
            st = stats[ifname]
            ips = ", ".join(a.address for a in addrs.get(ifname, []) if a.family.name == "AF_INET")
            items = [Item("Type", "Wi-Fi" if wireless else "Ethernet"), Item("State", "up" if st.isup else "down"),
                     Item("Driver", driver or "n/a"), Item("IPv4", ips or "none")]
            if usb_id:
                items.append(Item("USB adapter", names.get(usb_id, usb_id)))
            if st.speed:
                items.append(Item("Link speed", f"{st.speed} Mb/s"))
            groups.append(Group(ifname, items))
        wifi = sum(1 for g in groups if g.items[0].value == "Wi-Fi")
        return Section("network", "Network", "network", f"{len(groups)} interface(s), {wifi} wireless", None, groups)

    def peripherals(self, usb: list[tuple[str, str]]) -> Section:
        skip = re.compile(r"root hub|hub\b", re.I)
        items = [Item(i, d) for i, d in usb if not skip.search(d)]
        return Section("peripherals", "Peripherals", "usb", f"{len(items)} USB device(s)", None,
                       [Group("USB devices", items)] if items else [])
