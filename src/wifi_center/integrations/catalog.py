"""Profiles for every supported tool.

Tools whose primary purpose includes attack operations are `restricted`: WIFI Center only reports
installation, version, dependencies and documentation for them and exposes no launch operations.
"""
from __future__ import annotations

from .base import Dependency, LaunchMethod, Operation, ToolProfile

CATEGORIES = (
    "Wireless monitoring and analysis",
    "Bluetooth",
    "Network discovery",
    "Web security",
    "Security testing",
    "Password auditing",
    "Identity and infrastructure analysis",
    "Additional integration",
)

def _cli(version_args: tuple[str, ...]) -> tuple[Operation, ...]:
    return (Operation("version", "Show version", "Print the tool's version (read-only).",
                      LaunchMethod.CLI, version_args, timeout=15.0),)


def _gui(args: tuple[str, ...] = ()) -> Operation:
    return Operation("launch", "Launch application", "Start the desktop application.",
                     LaunchMethod.DESKTOP, args)


_RESTRICTED_NOTE = ("Integration is limited to installation detection, version reporting, dependency "
                    "diagnostics and documentation. WIFI Center does not launch this tool.")

PROFILES: tuple[ToolProfile, ...] = (
    # ---- Wireless monitoring and analysis ----
    ToolProfile(
        id="aircrack-ng", name="Aircrack-ng", category=CATEGORIES[0],
        description="Wireless network auditing suite (monitoring, capture and analysis utilities).",
        executables=("aircrack-ng", "airodump-ng"), apt_packages=("aircrack-ng",),
        docs_url="https://www.aircrack-ng.org/documentation.html",
        source_url="https://github.com/aircrack-ng/aircrack-ng",
        install_hint="sudo apt install aircrack-ng",
        capabilities=("Installation and version detection", "Documentation"),
        license="GPL-2.0", restricted=True, restriction_note=_RESTRICTED_NOTE),
    ToolProfile(
        id="kismet", name="Kismet", category=CATEGORIES[0],
        description="Wireless network and device detector, sniffer and monitoring system with a web API.",
        executables=("kismet",), apt_packages=("kismet",),
        docs_url="https://www.kismetwireless.net/docs/",
        source_url="https://github.com/kismetwireless/kismet",
        install_hint="sudo apt install kismet",
        dependencies=(Dependency("executable", "iw", "interface and capability queries", optional=True),),
        capabilities=("Version detection", "Service health and data import (Phase 3)"),
        operations=_cli(("--version",)), version_args=("--version",), version_regex=r"Kismet\s+(\S+)",
        license="GPL-2.0"),
    ToolProfile(
        id="wireshark", name="Wireshark", category=CATEGORIES[0],
        description="Graphical network protocol analyzer.",
        executables=("wireshark",), apt_packages=("wireshark",),
        docs_url="https://www.wireshark.org/docs/",
        source_url="https://gitlab.com/wireshark/wireshark",
        install_hint="sudo apt install wireshark",
        dependencies=(Dependency("executable", "tshark", "packet statistics and PCAP import", optional=True),),
        capabilities=("Launch desktop application", "PCAP/PCAPNG analysis through TShark (Phase 3)"),
        operations=(_gui(),) + _cli(("--version",)), version_args=("--version",),
        license="GPL-2.0"),
    ToolProfile(
        id="tshark", name="TShark", category=CATEGORIES[0],
        description="Command-line packet analyzer from the Wireshark project.",
        executables=("tshark",), apt_packages=("tshark",),
        docs_url="https://www.wireshark.org/docs/man-pages/tshark.html",
        source_url="https://gitlab.com/wireshark/wireshark",
        install_hint="sudo apt install tshark",
        capabilities=("Version detection", "Offline PCAP statistics (Phase 3)"),
        operations=_cli(("--version",)), version_args=("--version",), license="GPL-2.0"),
    ToolProfile(
        id="sparrow-wifi", name="Sparrow WiFi", category=CATEGORIES[0],
        description="Graphical Wi-Fi and Bluetooth analyzer for Linux.",
        executables=("sparrow-wifi",), apt_packages=("sparrow-wifi",),
        entry_files=("sparrow-wifi.py",),
        docs_url="https://github.com/ghostop14/sparrow-wifi#readme",
        source_url="https://github.com/ghostop14/sparrow-wifi",
        install_hint="Check 'apt-cache policy sparrow-wifi'; otherwise review the source and clone "
                     "https://github.com/ghostop14/sparrow-wifi, then set its folder in Tool Configuration.",
        dependencies=(Dependency("executable", "iw", "Wi-Fi scanning"),
                      Dependency("python_module", "PyQt5", "graphical interface", optional=True)),
        capabilities=("Launch desktop application",),
        operations=(_gui(),), license="GPL-3.0"),
    ToolProfile(
        id="wifite", name="Wifite", category=CATEGORIES[0],
        description="Automated wireless attack tool.",
        executables=("wifite",), apt_packages=("wifite",),
        docs_url="https://github.com/kimocoder/wifite2#readme",
        source_url="https://github.com/kimocoder/wifite2",
        install_hint="sudo apt install wifite",
        capabilities=("Installation and version detection", "Documentation"),
        license="GPL-2.0", restricted=True, restriction_note=_RESTRICTED_NOTE),
    ToolProfile(
        id="fern-wifi-cracker", name="Fern Wi-Fi Cracker", category=CATEGORIES[0],
        description="Graphical wireless security auditing and attack tool.",
        executables=("fern-wifi-cracker",), apt_packages=("fern-wifi-cracker",),
        docs_url="https://github.com/savio-code/fern-wifi-cracker#readme",
        source_url="https://github.com/savio-code/fern-wifi-cracker",
        install_hint="sudo apt install fern-wifi-cracker",
        capabilities=("Installation and version detection", "Documentation"),
        license="GPL-3.0", restricted=True, restriction_note=_RESTRICTED_NOTE),
    ToolProfile(
        id="pixiewps", name="PixieWPS", category=CATEGORIES[0],
        description="Offline WPS PIN recovery utility.",
        executables=("pixiewps",), apt_packages=("pixiewps",),
        docs_url="https://github.com/wiire-a/pixiewps#readme",
        source_url="https://github.com/wiire-a/pixiewps",
        install_hint="sudo apt install pixiewps",
        capabilities=("Installation and version detection", "Documentation"),
        license="GPL-3.0", restricted=True, restriction_note=_RESTRICTED_NOTE),
    # ---- Bluetooth ----
    ToolProfile(
        id="spooftooph", name="Spooftooph", category=CATEGORIES[1],
        description="Bluetooth device information spoofing and cloning utility.",
        executables=("spooftooph",), apt_packages=("spooftooph",),
        docs_url="https://www.kali.org/tools/spooftooph/",
        source_url="https://gitlab.com/kalilinux/packages/spooftooph",
        install_hint="sudo apt install spooftooph",
        capabilities=("Installation and version detection", "Documentation"),
        license="GPL-2.0", restricted=True, restriction_note=_RESTRICTED_NOTE),
    ToolProfile(
        id="bluemaho", name="BlueMaho", category=CATEGORIES[1],
        description="Bluetooth security testing suite.",
        executables=("bluemaho",), entry_files=("BlueMaho.py", "bluemaho.py"),
        docs_url="https://github.com/zenware/BlueMaho#readme",
        source_url="https://github.com/zenware/BlueMaho",
        install_hint="Not packaged in APT. Review the source, clone it, then set its folder in Tool Configuration.",
        capabilities=("Installation detection", "Documentation"),
        license="See repository", restricted=True, restriction_note=_RESTRICTED_NOTE),
    # ---- Network discovery ----
    ToolProfile(
        id="nmap", name="Nmap", category=CATEGORIES[2],
        description="Network discovery and security auditing utility.",
        executables=("nmap",), apt_packages=("nmap",),
        docs_url="https://nmap.org/docs.html", source_url="https://github.com/nmap/nmap",
        install_hint="sudo apt install nmap",
        capabilities=("Version detection", "Scoped host discovery and result import (Phase 4)"),
        operations=_cli(("--version",)), version_args=("--version",), version_regex=r"Nmap version (\S+)",
        license="Nmap Public Source License"),
    # ---- Web security ----
    ToolProfile(
        id="burpsuite", name="Burp Suite", category=CATEGORIES[3],
        description="Web application security testing platform (desktop).",
        executables=("burpsuite",), apt_packages=("burpsuite",),
        docs_url="https://portswigger.net/burp/documentation",
        source_url="https://portswigger.net/burp",
        install_hint="sudo apt install burpsuite  (or the installer from portswigger.net)",
        dependencies=(Dependency("executable", "java", "Java runtime", optional=True),),
        capabilities=("Launch desktop application", "Report import (Phase 4)"),
        operations=(_gui(),), license="Proprietary (Community edition)"),
    ToolProfile(
        id="nikto", name="Nikto", category=CATEGORIES[3],
        description="Web server scanner.",
        executables=("nikto",), apt_packages=("nikto",),
        docs_url="https://github.com/sullo/nikto/wiki", source_url="https://github.com/sullo/nikto",
        install_hint="sudo apt install nikto",
        capabilities=("Version detection", "Report import (Phase 4)"),
        operations=_cli(("-Version",)), version_args=("-Version",),
        version_regex=r"(?:Nikto|version)\D*(\d+\.\d+(?:\.\d+)*)", license="GPL-2.0"),
    ToolProfile(
        id="sqlmap", name="sqlmap", category=CATEGORIES[3],
        description="Automatic SQL injection and database takeover tool.",
        executables=("sqlmap",), apt_packages=("sqlmap",),
        docs_url="https://github.com/sqlmapproject/sqlmap/wiki",
        source_url="https://github.com/sqlmapproject/sqlmap",
        install_hint="sudo apt install sqlmap",
        capabilities=("Installation and version detection", "Documentation"),
        license="GPL-2.0", restricted=True, restriction_note=_RESTRICTED_NOTE),
    # ---- Security testing ----
    ToolProfile(
        id="metasploit", name="Metasploit Framework", category=CATEGORIES[4],
        description="Penetration testing framework.",
        executables=("msfconsole",), apt_packages=("metasploit-framework",),
        docs_url="https://docs.metasploit.com/", source_url="https://github.com/rapid7/metasploit-framework",
        install_hint="sudo apt install metasploit-framework",
        dependencies=(Dependency("executable", "psql", "database support", optional=True),),
        capabilities=("Installation and version detection", "Documentation", "Authorized lab project organization (Phase 4)"),
        license="BSD-3-Clause", restricted=True, restriction_note=_RESTRICTED_NOTE),
    # ---- Password auditing ----
    ToolProfile(
        id="john", name="John the Ripper", category=CATEGORIES[5],
        description="Password security auditing tool. WIFI Center plans offline password-policy evaluation only.",
        executables=("john",), apt_packages=("john",),
        docs_url="https://www.openwall.com/john/doc/", source_url="https://github.com/openwall/john",
        install_hint="sudo apt install john",
        capabilities=("Version detection", "Offline password-policy audit with approved datasets (Phase 4)"),
        license="GPL-2.0"),
    ToolProfile(
        id="pskracker", name="PSKracker", category=CATEGORIES[5],
        description="WPA/WPA2 default pre-shared key generator.",
        executables=("pskracker",), entry_files=("pskracker",),
        docs_url="https://github.com/soxrok2212/PSKracker#readme",
        source_url="https://github.com/soxrok2212/PSKracker",
        install_hint="Not packaged in APT. Review the source, build it yourself, then set its folder in Tool Configuration.",
        capabilities=("Installation detection", "Documentation"),
        license="See repository", restricted=True, restriction_note=_RESTRICTED_NOTE),
    # ---- Identity and infrastructure ----
    ToolProfile(
        id="bloodhound-ce", name="BloodHound Community Edition", category=CATEGORIES[6],
        description="Active Directory attack-path analysis platform, run as a Docker based service.",
        executables=("bloodhound-cli",),
        docs_url="https://bloodhound.specterops.io/", source_url="https://github.com/SpecterOps/BloodHound",
        install_hint="Follow https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart "
                     "(Docker Compose). WIFI Center never deploys or exposes it automatically.",
        dependencies=(Dependency("docker", "docker compose", "container runtime"),),
        capabilities=("Docker and container status", "Documentation", "Authorized data organization (Phase 4)"),
        license="Apache-2.0"),
    # ---- Additional integration ----
    ToolProfile(
        id="wifi-audit-tool", name="wifi-audit-tool", category=CATEGORIES[7],
        description="Command-line wireless auditing toolkit that wraps the aircrack-ng suite "
                    "(includes handshake capture). Requires root.",
        executables=("wifi_audit.py",), entry_files=("wifi_audit.py",),
        dependencies=(Dependency("executable", "airodump-ng", "capture backend"),
                      Dependency("executable", "aireplay-ng", "injection backend"),
                      Dependency("executable", "iw", "interface control"),
                      Dependency("python_module", "colorama", "terminal colours")),
        docs_url="https://github.com/trmxvibs/wifi-audit-tool#readme",
        source_url="https://github.com/trmxvibs/wifi-audit-tool",
        install_hint="Not packaged. Source reviewed: GPL-3.0, needs root, its install.sh runs sudo and "
                     "pip --break-system-packages, so WIFI Center does not run it. Clone it manually if wanted.",
        capabilities=("Installation detection", "Documentation"),
        license="GPL-3.0", compatibility="Kali Linux (documented); Debian-based",
        restricted=True, restriction_note=_RESTRICTED_NOTE),
)


def profile_by_id(tool_id: str) -> ToolProfile | None:
    return next((p for p in PROFILES if p.id == tool_id), None)
