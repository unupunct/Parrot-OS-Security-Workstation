# Network Security workspace (Phase 4)

## Safety model

* **Projects own the scope.** A project has an authorized scope (IPs, CIDR networks, hostnames). Scans can only target
  things inside it. Hostnames match exactly: nothing is resolved over the network to decide scope.
* **Explicit confirmation.** "Review and start scan" re-validates everything, shows the project, targets and profile, and
  needs the authorization checkbox ticked. The confirmation is written to the audit log.
* **Approved profiles only.** Host discovery (`-sn`), top-100 TCP ports (`-sT`) and a light service inventory
  (`-sT -sV --version-light`), always with `-n`, a host timeout and XML output. There are no scripts, OS fingerprinting,
  decoys, spoofing or input-list options. The command line is checked three times: when it is built, by the integration,
  and by the operation policy, which rejects anything that is not exactly one approved profile (`integrations/nmap_args.py`).
* Targets are limited to 64 entries and networks to 1024 addresses.

## Pages

| Page | What it does |
|---|---|
| Network Discovery | Scope management, scoped scans with live output, import of Nmap XML/normal/grepable files, results with ports and services, history, scan-to-scan comparison (new/gone hosts, opened/closed/changed ports), CSV/JSON export |
| Network Mapping | Topology of the hosts in a chosen scan, with search, details and JSON export |
| Security Assessment | Projects, findings with severity and remediation tracking (status, notes, due date), evidence references with SHA-256 integrity checks, notes, imports, Metasploit and BloodHound status |
| Web Security | Burp Suite / Nikto / sqlmap status, Burp launch, project references (http/https URLs only), report import |
| Password Auditing | Offline password-policy evaluation (see below) |

Imported hosts also appear on the dashboard topology (database inventory), so the live map and the stored results agree.

## Reports that can be imported

Nmap (XML, normal, grepable), Nikto (XML, CSV, JSON), Burp Suite issue export (XML), Metasploit workspace export (XML;
hosts, services and vulnerability records) and a generic findings file (CSV/JSON with `title`, `severity`, `description`,
`location`, `recommendation`) for any other tool. XML containing DOCTYPE/ENTITY declarations is rejected, files over 50 MiB
are refused, importing the same file twice is ignored, and exports neutralise spreadsheet formulas.
The Nikto, Burp and Metasploit layouts follow each tool's documented output; check them against exports from your versions.

## Restricted tools

sqlmap and Metasploit stay detect/version/docs only; their results can be organised through imports. BloodHound CE is an
independent Docker service: WIFI Center reads Docker/container status and resource use and can ask a **loopback** service
for its version when you press the button. It never deploys, starts or exposes it.

## Password auditing

WIFI Center does not crack anything. The page evaluates candidate passwords you supply (use synthetic test data or data you
are authorized to evaluate) against a policy: length, character classes, repeats, sequences, user name, an optional
approved blocklist. John the Ripper is shown as a detected tool but is not run. Results name entries by line or user
name; password text is not stored, logged, exported or put into findings, only aggregate counts.

## Discovery dashboard (Network Discovery, first tab)

An advanced LAN discovery module. The Nmap workflow tabs next to it are unchanged.

* **Identify my network**: reads `ip -j address`, `ip -j route`, `ip -j neigh` and `resolvectl status` (falling back to
  `/etc/resolv.conf`) and shows each active interface with its real prefix length, subnet, gateway (and its MAC), DNS and IPv6
  addresses. The subnet is calculated from the prefix length, never guessed.
* **Scan modes**: Quick Discovery (ARP/ICMP, short timeout), Full Subnet Discovery (every usable address plus a retry pass),
  Neighbor Discovery (reads ARP/IPv6 neighbour tables, sends nothing). Optional IPv6 neighbour discovery sends one all-nodes
  link-local echo and reads the neighbour table. Concurrency and timeout are configurable; scans can be paused, resumed and cancelled,
  and are aborted (and saved) if the interface's address changes mid-scan.
* **Safety, enforced in code**: a project is required and the range must be inside its authorized scope (never widened
  automatically; the dashboard offers a confirmed "Add to authorized scope" action), must be a subnet of a directly attached private
  network and at most 4096 addresses. Only ping, ARP/NDP resolution and neighbour-table reads are used. Every scan needs a
  confirmation that shows the exact range, interface, project and what will be sent, and is written to the audit log.
* **Results**: IP, MAC, host name, manufacturer (local OUI database), device type, response method (icmp / arp / ndp /
  neighbor-cache / local), latency, status (responded / cached), first and last seen, notes (new, ip changed, multiple IPs).
  A missing answer never means a host is offline. Export as CSV, JSON or HTML.
* **Device identification**: *confirmed* (gateway from the default route, this computer from its own addresses) is kept apart from
  *inferred* (manufacturer / host-name hints, private MAC addresses), and every inference shows its reason.
* **Topology**: only evidence the system can show is drawn: Internet to gateway (default route), this computer and every host
  to the local network segment (ARP/NDP on this computer's own Layer-2 segment). Hosts are not linked to the router, because
  sharing a segment with it does not show how they connect to it. Clicking a node lists the evidence for each connection.
* **History**: every scan (project, scope, interface, range, mode, duration, results) is stored in `nd_scans` / `nd_hosts`, device
  history (names, first seen, last IP) in `nd_devices`. Scans can be compared (new, not seen, changed). Nothing is deleted
  unless you delete a scan yourself.

