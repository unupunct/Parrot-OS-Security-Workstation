"""MAC vendor lookup from locally installed OUI databases only (no network, nothing bundled)."""
from __future__ import annotations

import re
from pathlib import Path

CANDIDATES = (
    Path("/usr/share/ieee-data/oui.txt"),
    Path("/var/lib/ieee-data/oui.txt"),
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/share/wireshark/manuf"),
)
_HEX_LINE = re.compile(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$")
_NMAP_LINE = re.compile(r"^([0-9A-Fa-f]{6})\s+(.+)$")
_MANUF_LINE = re.compile(r"^([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\s+(\S+)(?:\s+(.+))?$")


def normalise_prefix(mac: str) -> str | None:
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", mac)
    return hexchars[:6].upper() if len(hexchars) >= 6 else None


class OuiLookup:
    def __init__(self, paths: tuple[Path, ...] = CANDIDATES) -> None:
        self._paths = paths
        self._table: dict[str, str] | None = None
        self.source: Path | None = None

    def _load(self) -> dict[str, str]:
        if self._table is not None:
            return self._table
        table: dict[str, str] = {}
        for p in self._paths:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                m = _HEX_LINE.match(line)
                if m:
                    table["".join(m.group(1, 2, 3)).upper()] = m.group(4).strip()
                    continue
                m = _MANUF_LINE.match(line)
                if m:
                    table[m.group(1).replace(":", "").upper()] = (m.group(3) or m.group(2)).strip()
                    continue
                m = _NMAP_LINE.match(line)
                if m and not line.startswith("#") and not m.group(2).startswith("(base 16)"):
                    table[m.group(1).upper()] = m.group(2).strip()
            if table:
                self.source = p
                break
        self._table = table
        return table

    @property
    def available(self) -> bool:
        return bool(self._load())

    def vendor(self, mac: str) -> str | None:
        prefix = normalise_prefix(mac)
        return self._load().get(prefix) if prefix else None
