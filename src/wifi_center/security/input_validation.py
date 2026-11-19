"""Input validation helpers. Reject early, never sanitise-and-hope."""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path


class ValidationError(ValueError):
    pass


_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def validate_absolute_path(value: str, *, must_exist: bool = True, kind: str = "any") -> Path:
    """Return a normalised absolute path; reject NUL, relative paths and `..` components."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("path is empty")
    if "\x00" in value:
        raise ValidationError("path contains a NUL byte")
    p = Path(value)
    if not p.is_absolute():
        raise ValidationError("path must be absolute")
    if ".." in p.parts:
        raise ValidationError("path must not contain '..'")
    if must_exist:
        if not p.exists():
            raise ValidationError(f"path does not exist: {value}")
        if kind == "file" and not p.is_file():
            raise ValidationError("path is not a file")
        if kind == "dir" and not p.is_dir():
            raise ValidationError("path is not a directory")
    return p


def validate_executable(value: str) -> Path:
    p = validate_absolute_path(value, kind="file")
    if os.name == "posix" and not os.access(p, os.X_OK):
        raise ValidationError("file is not executable")
    return p


def validate_within(base: Path, candidate: str | Path) -> Path:
    """Path-traversal guard: `candidate` must resolve inside `base`."""
    base_r = base.resolve()
    cand_r = (base_r / candidate).resolve() if not Path(candidate).is_absolute() else Path(candidate).resolve()
    try:
        cand_r.relative_to(base_r)
    except ValueError:
        raise ValidationError(f"{candidate} escapes {base}") from None
    return cand_r


def validate_hostname(value: str) -> str:
    if not _HOSTNAME.match(value or ""):
        raise ValidationError(f"invalid hostname: {value!r}")
    return value.lower()


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValidationError(f"invalid IP address: {value!r}") from None


def validate_cidr(value: str, max_hosts: int | None = None) -> str:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValidationError(f"invalid network: {value!r}") from None
    if max_hosts is not None and net.num_addresses > max_hosts:
        raise ValidationError(f"network too large ({net.num_addresses} addresses, limit {max_hosts})")
    return str(net)
