"""Single source of truth for the sidebar structure.

`phase` is the development phase in which the page becomes functional; pages whose phase
has not shipped are shown with an honest 'not implemented yet' page, never fake data.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NavItem:
    id: str
    title: str
    phase: int
    summary: str = ""


@dataclass(frozen=True)
class NavCategory:
    title: str
    items: tuple[NavItem, ...]


NAVIGATION: tuple[NavCategory, ...] = (
    NavCategory("DASHBOARD", (
        NavItem("overview", "Overview", 1, "Live system, adapter and tool overview."),
        NavItem("activity", "Activity Monitor", 2, "Running operations with live output."),
        NavItem("system_hw", "System & Hardware", 7, "CPU, memory, storage, services and boot details."),
    )),
    NavCategory("WIRELESS", (
        NavItem("wifi_center", "Wi-Fi Center", 3, "Adapter manager and driver diagnostics."),
        NavItem("wireless_discovery", "Wireless Discovery", 3, "Access points seen by your adapter."),
        NavItem("kismet", "Kismet Monitor", 3, "Kismet service health and observations."),
        NavItem("spectrum", "Wi-Fi Analyzer", 3, "Channel graph, signal history, access-point list and channel rating."),
        NavItem("bluetooth", "Bluetooth Lab", 3, "Bluetooth diagnostics, scanning, signal monitor and inventory."),
        NavItem("packets", "Packet Analysis", 3, "PCAP statistics through TShark/Wireshark."),
    )),
    NavCategory("NETWORK SECURITY", (
        NavItem("net_discovery", "Network Discovery", 4, "Authorized-scope host discovery with Nmap."),
        NavItem("lan_scanner", "LAN Scanner", 4, "Find every device on your own network."),
        NavItem("net_mapping", "Network Mapping", 4, "Topology from imported Nmap results."),
        NavItem("assessment", "Security Assessment", 4, "Findings and remediation tracking."),
        NavItem("web_security", "Web Security", 4, "Burp Suite, Nikto and sqlmap status and report import."),
        NavItem("password_audit", "Password Auditing", 4, "Offline password-policy evaluation."),
    )),
    NavCategory("INTELLIGENCE", (
        NavItem("osint", "OSINT Explorer", 5, "Searchable catalog of public research resources."),
        NavItem("osint_user", "Username Search", 5, "Open public username lookups."),
        NavItem("osint_email", "Email Research", 5, "Public email research resources."),
        NavItem("osint_domain", "Domain Research", 5, "Public domain research resources."),
        NavItem("osint_ip", "IP Research", 5, "Public IP research resources."),
    )),
    NavCategory("PARROT OS", (
        NavItem("sys_updates", "System Updates", 7, "APT update workflow with confirmation."),
        NavItem("sw_updates", "Software Updates", 7, "APT, Flatpak, Snap and git sources."),
        NavItem("cleanup", "System Cleanup", 7, "Scan, preview and dry-run cleanup."),
        NavItem("packages", "Package Manager", 7, "Search, inspect, install and remove packages."),
        NavItem("root_access", "Root Access Manager", 8, "Polkit-based scoped privileged session."),
        NavItem("sys_info", "System Information", 7, "OS, kernel, filesystems, services."),
        NavItem("maintenance", "Maintenance History", 7, "Audit trail of maintenance operations."),
    )),
    NavCategory("TOOL MANAGEMENT", (
        NavItem("tools_all", "All Tools", 2, "Catalog of supported security tools."),
        NavItem("tools_installed", "Installed Tools", 2, "Detected installations and versions."),
        NavItem("tools_missing", "Missing Dependencies", 2, "Tools and dependencies that are absent."),
        NavItem("tools_config", "Tool Configuration", 2, "Per-tool configuration."),
        NavItem("terminal", "Integrated Terminal", 2, "Operation output and unprivileged terminal."),
    )),
    NavCategory("RESOURCES", (
        NavItem("wordlists", "Wordlist Library", 6, "Local-first resource library with integrity checks."),
        NavItem("docs", "Documentation", 6, "Official documentation for integrated tools."),
        NavItem("local_resources", "Local Resources", 6, "User-supplied reference files."),
    )),
    NavCategory("PROJECTS", (
        NavItem("reports", "Reports", 9, "PDF, HTML, JSON and CSV reports."),
        NavItem("evidence", "Evidence", 9, "Evidence files referenced from the database."),
        NavItem("project_history", "Project History", 9, "All projects and their activity."),
    )),
    NavCategory("SETTINGS", (
        NavItem("settings_general", "General", 1, "Startup, directories, logging."),
        NavItem("settings_appearance", "Appearance", 1, "Theme and accent colour."),
        NavItem("settings_integrations", "Integrations", 2, "Tool integration options."),
        NavItem("settings_permissions", "Permissions", 8, "Privileged operation policy."),
        NavItem("settings_backup", "Backup & Recovery", 1, "Database backup and restore."),
    )),
)

CURRENT_PHASE = 9


def all_items() -> list[NavItem]:
    return [i for c in NAVIGATION for i in c.items]


def find_item(item_id: str) -> NavItem | None:
    return next((i for i in all_items() if i.id == item_id), None)


def category_of(item_id: str) -> str | None:
    for c in NAVIGATION:
        if any(i.id == item_id for i in c.items):
            return c.title
    return None
