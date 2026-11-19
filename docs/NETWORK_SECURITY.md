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
