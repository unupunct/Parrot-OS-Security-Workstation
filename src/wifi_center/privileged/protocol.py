"""Wire protocol shared by the GUI client and the privileged helper.

The helper never trusts the GUI: it re-validates everything defined here when it receives a request. Keep this
module small and dependency-free (it is part of the root-privileged code path).
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field

BUS_NAME = "org.wificenter.Helper1"
OBJECT_PATH = "/org/wificenter/Helper1"
INTERFACE = "org.wificenter.Helper1"
ERROR_PREFIX = "org.wificenter.Helper1.Error."
POLICY_FILE = "/usr/share/polkit-1/actions/org.wificenter.helper.policy"
PROTOCOL_VERSION = 1

PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]{1,100}(:[a-z0-9\-]+)?$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,15}$")
HCI_RE = re.compile(r"^hci\d{1,3}$")
MAX_CAPTURE_SECONDS = 600
UNIT_RE = re.compile(r"^[A-Za-z0-9@:_.\-]{1,100}\.service$")
MAX_PACKAGES = 2000
MAX_PATHS = 50_000
MAX_PATH_LEN = 1024


from ..security.input_validation import ValidationError


class ProtocolError(ValidationError):
    """Raised for any malformed or disallowed request."""


# ---------------------------------------------------------------------------------------------- actions
@dataclass(frozen=True)
class Action:
    id: str
    title: str
    description: str
    kinds: tuple[str, ...]


ACTIONS: tuple[Action, ...] = (
    Action("org.wificenter.helper.maintenance", "Package maintenance",
           "Refresh package lists; upgrade, install, reinstall, download and remove packages; repair broken dependencies; finish interrupted installations; clean the APT cache.",
           ("apt_update", "apt_upgrade", "apt_dist_upgrade", "apt_install", "apt_remove", "apt_autoremove",
            "apt_clean", "purge_residual_configs", "apt_reinstall", "apt_download", "apt_fix_broken", "dpkg_configure")),
    Action("org.wificenter.helper.cleanup-files", "Remove old system files",
           "Delete old files in /var/tmp and rotated logs in /var/log, individually validated.",
           ("remove_system_files",)),
    Action("org.wificenter.helper.network-interface", "Wireless interface mode",
           "Switch a wireless interface to monitor mode and restore it afterwards.",
           ("iface_monitor", "iface_restore")),
    Action("org.wificenter.helper.bluetooth-capture", "Bluetooth packet capture",
           "Record the HCI traffic of one Bluetooth controller with btmon for a limited time. The capture file is handed to the requesting user.",
           ("bt_capture",)),
    Action("org.wificenter.helper.diagnostics", "System diagnostics",
           "Read the system journal and service status (read-only).", ("diag_journal", "diag_unit_status")),
)
KINDS: tuple[str, ...] = tuple(k for a in ACTIONS for k in a.kinds)
APT_TRANSACTION_KINDS = ("apt_upgrade", "apt_dist_upgrade", "apt_install", "apt_remove", "apt_autoremove",
                         "purge_residual_configs", "apt_reinstall", "apt_download", "apt_fix_broken")
REMOVAL_CATEGORIES = ("var_tmp", "logs_system")


def action_for(kind: str) -> str:
    for a in ACTIONS:
        if kind in a.kinds:
            return a.id
    raise ProtocolError(f"unknown operation: {kind!r}")


def validate_package_name(name: str) -> str:
    n = str(name).strip()
    if not PKG_RE.match(n):
        raise ProtocolError(f"invalid package name: {name!r}")
    return n


# ---------------------------------------------------------------------------------------------- operations
@dataclass(frozen=True)
class Manifest:
    """What the user approved. The helper refuses to run if the real transaction contains anything else."""
    installs: tuple[str, ...] = ()
    upgrades: tuple[str, ...] = ()
    removes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"installs": list(self.installs), "upgrades": list(self.upgrades), "removes": list(self.removes)}


@dataclass(frozen=True)
class PrivilegedOp:
    kind: str
    packages: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    category: str = ""
    iface: str = ""
    unit: str = ""
    manifest: Manifest | None = None
    seconds: int = 0

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ProtocolError(f"unknown privileged operation: {self.kind}")
        if len(self.packages) > MAX_PACKAGES:
            raise ProtocolError("too many packages")
        for p in self.packages:
            validate_package_name(p)
        if self.kind in ("apt_install", "apt_remove", "purge_residual_configs", "apt_reinstall", "apt_download") and not self.packages:
            raise ProtocolError(f"{self.kind} needs at least one package")
        if self.kind == "remove_system_files":
            if self.category not in REMOVAL_CATEGORIES:
                raise ProtocolError(f"category must be one of {REMOVAL_CATEGORIES}")
            if not self.paths or len(self.paths) > MAX_PATHS:
                raise ProtocolError("remove_system_files needs 1..%d paths" % MAX_PATHS)
        if self.kind in ("iface_monitor", "iface_restore") and not IFACE_RE.match(self.iface):
            raise ProtocolError(f"invalid interface name: {self.iface!r}")
        if self.kind == "bt_capture":
            if not HCI_RE.match(self.iface):
                raise ProtocolError(f"invalid Bluetooth controller: {self.iface!r}")
            if not 1 <= self.seconds <= MAX_CAPTURE_SECONDS:
                raise ProtocolError(f"capture length must be 1..{MAX_CAPTURE_SECONDS} seconds")
        if self.kind == "diag_unit_status" and not UNIT_RE.match(self.unit):
            raise ProtocolError(f"invalid service unit: {self.unit!r}")

    @property
    def action_id(self) -> str:
        return action_for(self.kind)

    def summary(self) -> str:
        """Short, log-safe description (never the full path list)."""
        bits = [self.kind]
        if self.packages:
            bits.append(f"{len(self.packages)} package(s): " + ", ".join(self.packages[:5]) + (" …" if len(self.packages) > 5 else ""))
        if self.paths:
            bits.append(f"{len(self.paths)} path(s) in {self.category}")
        if self.iface:
            bits.append(f"interface {self.iface}")
        if self.unit:
            bits.append(self.unit)
        if self.seconds:
            bits.append(f"{self.seconds} s")
        return " · ".join(bits)


def op_to_json(op: PrivilegedOp) -> str:
    d = {"v": PROTOCOL_VERSION, "kind": op.kind, "packages": list(op.packages), "paths": list(op.paths),
         "category": op.category, "iface": op.iface, "unit": op.unit,
         "manifest": op.manifest.to_dict() if op.manifest else None, "seconds": op.seconds}
    return json.dumps(d, separators=(",", ":"))


def _str_list(v, field_name: str, limit: int, item_limit: int = MAX_PATH_LEN) -> tuple[str, ...]:
    if v is None:
        return ()
    if not isinstance(v, list) or len(v) > limit or not all(isinstance(x, str) and len(x) <= item_limit and "\x00" not in x for x in v):
        raise ProtocolError(f"invalid {field_name}")
    return tuple(v)


def op_from_json(text: str) -> PrivilegedOp:
    """Strictly parse a request. Unknown fields, wrong types and oversized input are rejected."""
    if not isinstance(text, str) or len(text) > 8_000_000:
        raise ProtocolError("request too large")
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        raise ProtocolError("request is not valid JSON") from None
    if not isinstance(d, dict):
        raise ProtocolError("request must be an object")
    allowed = {"v", "kind", "packages", "paths", "category", "iface", "unit", "manifest", "seconds"}
    extra = set(d) - allowed
    if extra:
        raise ProtocolError(f"unknown field(s): {sorted(extra)}")
    if d.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    for key in ("kind", "category", "iface", "unit"):
        if key in d and not isinstance(d[key], str):
            raise ProtocolError(f"{key} must be a string")
    seconds = d.get("seconds", 0)
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise ProtocolError("seconds must be an integer")
    manifest = None
    m = d.get("manifest")
    if m is not None:
        if not isinstance(m, dict) or set(m) - {"installs", "upgrades", "removes"}:
            raise ProtocolError("invalid manifest")
        manifest = Manifest(*(tuple(validate_package_name(p) for p in _str_list(m.get(k), k, MAX_PACKAGES, 110))
                              for k in ("installs", "upgrades", "removes")))
    return PrivilegedOp(d.get("kind", ""), tuple(validate_package_name(p) for p in _str_list(d.get("packages"), "packages", MAX_PACKAGES, 110)),
                        _str_list(d.get("paths"), "paths", MAX_PATHS), d.get("category", ""), d.get("iface", ""),
                        d.get("unit", ""), manifest, seconds)


# ---------------------------------------------------------------------------------------------- path rules
@dataclass(frozen=True)
class RemovalRule:
    root: str
    min_age_days: int
    name_regex: str | None = None


REMOVAL_RULES = {
    "var_tmp": RemovalRule("/var/tmp", 30),
    "logs_system": RemovalRule("/var/log", 30, r"(\.\d+(\.gz)?|\.gz|\.old)$"),
}


def normalise_removal_path(path: str, category: str) -> str:
    """Absolute, normalised, strictly inside the category's root. Pure string logic (POSIX semantics)."""
    rule = REMOVAL_RULES[category]
    if not path or "\x00" in path or len(path) > MAX_PATH_LEN or not path.startswith("/"):
        raise ProtocolError(f"not an absolute path: {path[:60]!r}")
    if any(part in ("..", ".") for part in path.split("/")):
        raise ProtocolError("path contains '.' or '..' components")
    norm = posixpath.normpath(path)
    if norm != path.rstrip("/") or not norm.startswith(rule.root + "/"):
        raise ProtocolError(f"{path} is outside {rule.root}")
    if rule.name_regex and not re.search(rule.name_regex, posixpath.basename(norm)):
        raise ProtocolError(f"{posixpath.basename(norm)} is not a rotated log")
    return norm


@dataclass
class ExecResult:
    ok: bool
    status: str                 # succeeded | failed | cancelled | timeout | refused
    message: str
    exit_code: int | None = None
    output: list[str] = field(default_factory=list)
