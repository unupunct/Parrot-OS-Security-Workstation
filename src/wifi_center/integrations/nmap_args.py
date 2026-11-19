"""The only Nmap command lines WIFI Center will ever run, and the validator that enforces it.

No scripts, no OS detection, no spoofing, no decoys, no input lists: just a fixed set of conservative profiles.
Targets must already have passed the authorized-scope check; the validator re-checks their syntax.
"""
from __future__ import annotations

from pathlib import Path

from ..security.input_validation import ValidationError, validate_cidr, validate_hostname, validate_ip
from ..security.operation_policy import PolicyViolation

SCAN_PROFILES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "discovery": ("Host discovery", "Which hosts respond (ping scan, no port scan).", ("-sn",)),
    "ports": ("Top 100 TCP ports", "TCP connect scan of the 100 most common ports.",
              ("-sT", "--top-ports", "100")),
    "services": ("Service inventory", "Top 100 TCP ports plus light service/version detection.",
                 ("-sT", "-sV", "--version-light", "--top-ports", "100")),
}
COMMON = ("-n", "-T3", "--max-retries", "2", "--host-timeout", "5m", "--no-stylesheet")
MAX_TARGETS = 64
MAX_ADDRESSES = 1024
XML_PREFIX, XML_SUFFIX, XML_DIRNAME = "wifi-center-nmap-", ".xml", "scans"


def validate_target(t: str) -> str:
    """Return the normalised target (IP, CIDR or hostname) or raise ValidationError."""
    if not t or t.startswith("-"):
        raise ValidationError(f"invalid target: {t!r}")
    if "/" in t:
        return validate_cidr(t, MAX_ADDRESSES)
    try:
        return validate_ip(t)
    except ValidationError:
        return validate_hostname(t)


def build_args(profile: str, targets: list[str], xml_path: str) -> tuple[str, ...]:
    if profile not in SCAN_PROFILES:
        raise ValidationError(f"unknown scan profile: {profile}")
    return (*SCAN_PROFILES[profile][2], *COMMON, "-oX", xml_path, *targets)


def validate_args(args: tuple[str, ...]) -> None:
    """Raise PolicyViolation unless `args` (everything after the executable) is exactly a planned scan."""
    try:
        idx = args.index("-oX")
    except ValueError:
        raise PolicyViolation("nmap: missing -oX output file") from None
    flags = tuple(args[:idx])
    if flags not in {(*p[2], *COMMON) for p in SCAN_PROFILES.values()}:
        raise PolicyViolation("nmap: options are not one of the approved scan profiles")
    if idx + 2 >= len(args):
        raise PolicyViolation("nmap: no targets")
    xml = Path(args[idx + 1])
    if not (xml.is_absolute() and xml.parent.name == XML_DIRNAME and xml.name.startswith(XML_PREFIX)
            and xml.name.endswith(XML_SUFFIX) and ".." not in xml.parts):
        raise PolicyViolation("nmap: output file must be a WIFI Center scan file")
    targets = args[idx + 2:]
    if len(targets) > MAX_TARGETS:
        raise PolicyViolation("nmap: too many targets")
    for t in targets:
        try:
            validate_target(t)
        except ValidationError as e:
            raise PolicyViolation(f"nmap: {e}") from None
