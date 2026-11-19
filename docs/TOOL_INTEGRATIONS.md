# Tool integrations

WIFI Center manages external tools through a plugin-style integration layer
(`src/wifi_center/integrations/`). Each tool has a declarative `ToolProfile` in `catalog.py`;
`ToolIntegration` (in `base.py`) implements the standard interface on top of it:

`detect_installation`, `get_version`, `get_capabilities`, `check_dependencies`,
`validate_configuration`, `get_health_status`, `launch_supported_operation`, `parse_results`,
`export_results`.

Tools needing special handling subclass it and register in `registry.py` (BloodHound CE does:
it is a Docker service, so detection looks at `bloodhound-cli` and local Docker images).

## How detection works

1. A configured executable or git-checkout folder (Tool Configuration page), else
2. an executable found on `PATH` (plus `/usr/sbin`, `/sbin`, ...), else
3. an installed APT package (`dpkg-query`, no execution).

Versions come from a read-only version command where one is known to be safe, otherwise from
package metadata, otherwise from `git describe` for checkouts. Restricted tools are never executed
for version detection.

## Security boundary

Tools whose primary purpose includes attack operations are **restricted**: Aircrack-ng, Wifite,
Fern Wi-Fi Cracker, PixieWPS, Spooftooph, BlueMaho, sqlmap, Metasploit Framework, PSKracker and
wifi-audit-tool. For these WIFI Center reports installation, version (from package data),
dependencies and documentation only. They have no launch operations, and
`security/operation_policy.py` re-checks every launch request against the profile and a denylist.

Launching is limited to operations declared in a profile (`version`, `launch`); free-form options
and arguments are rejected.

## wifi-audit-tool review (trmxvibs/wifi-audit-tool)

Inspected before integrating: GPL-3.0 (no code is copied into this MIT project), actively
maintained (last commit 2026-08-16), pure Python, wraps `aircrack-ng` (`airodump-ng`,
`aireplay-ng`), requires root, includes a handshake-capture module, and its `install.sh` runs
`sudo` and `pip --break-system-packages`. WIFI Center therefore only detects it (user-configured
checkout folder), checks its dependencies and links to its documentation.

## Adding a tool

Add a `ToolProfile` to `PROFILES`. Declare only operations that are safe to run without user-supplied
arguments. Mark the profile `restricted=True` if the tool's main purpose is offensive.
