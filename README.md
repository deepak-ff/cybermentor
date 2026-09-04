# CyberMentor (security-audit-tool)

A non-intrusive, **Read-Only** host security auditing tool written in **pure
Python (standard library only — no third-party dependencies)**.

It performs two jobs:

1. **Configuration audit** — runs **33 CIS / MS-SCC Benchmark-aligned checks**
   across SSH, file permissions, authentication policy, firewalls, kernel
   hardening, logging, network settings, and (on Windows) firewall, SMB,
   RDP and password policy. It reports each as **PASS / WARN / FAIL /
   INFO / SKIP** and computes a **0–100 hardening score**.
2. **Multithreaded TCP port scanner** — scans port ranges concurrently using a
   bounded thread pool, which dramatically reduces scan time on real networks
   where most ports are filtered and time out.

It produces up to four reports from a single run so they always agree:
- **Structured JSON** (machine-readable, easy to feed into other tooling)
- **Self-contained HTML dashboard** (single file, inline CSS, human-readable)
- **CSV** (flat table for spreadsheets / SIEM ingestion)
- **SARIF 2.1.0** (for GitHub code scanning, Visual Studio, etc.)

> The tool is intentionally **non-intrusive**: like the well-known open-source
> tool [Lynis](https://github.com/CISOfy/lynis), it only reads configuration and
> permissions and **never modifies the system** it inspects.

---

## Quick start

No dependencies to install:

```bash
python3 -m audit_tool --host 127.0.0.1 --ports 1-1024 --threads 256 --out reports
```

Example output:

```
[*] Running configuration checks ...
[*] Scanning 127.0.0.1:1-1024 (threads=256) ...
[*] Port scan complete in 131 ms; 2 open port(s).

[+] Hardening score: 43/100
[+] Summary: PASS: 8, WARN: 4, FAIL: 6, INFO: 5, SKIP: 1
[+] JSON report : reports/audit_127.0.0.1_20260903_132307.json
[+] HTML report : reports/audit_127.0.0.1_20260903_132307.html
```

### Options

| Flag | Description |
|---|---|
| `--host` | Host to port-scan (default `127.0.0.1`) |
| `--ports` | Port range/list, e.g. `80`, `1-1024`, `80,443`, or `top` (default `1-1024`) |
| `--timeout` | Socket connect timeout in seconds (default `1.0`) |
| `--threads` | Number of scanning threads (default `256`) |
| `--batch-size` | Ports per concurrent batch (default `1024`) |
| `--skip-scan` | Run configuration checks only |
| `--show-speedup` | Compare concurrent vs sequential scanning timings |
| `--out` | Output directory for reports (default `reports`) |
| `--hostname` | Label used in the report (default: the `--host` target) |
| `--formats` | Comma list of report formats to write: `json,html,csv,sarif` (default `json,html`) |
| `--only` | Only run checks in these categories (comma list, case-insensitive) |
| `--exclude` | Exclude checks by id (comma list, case-insensitive) |
| `--list-checks` | Print the registered checks and exit |
| `--fail-exit` | Exit with code 1 if any FAIL results are present (CI-friendly) |
| `-v / -vv` | Increase verbosity |
| `--version` | Show version and exit |

After `pip install .` the same entry points are available as console scripts:
`audit-tool`, `audit-web`, `audit-baseline`.

### Installing on Kali / Debian / Ubuntu

The tool is pure Python stdlib, so on Kali (or any Debian/Ubuntu box) you can
run it straight from a clone, or install it properly:

```bash
git clone https://github.com/deepak-ff/cybermentor.git
cd cybermentor
sudo ./install.sh        # all users: venv in /opt, scripts in /usr/local/bin
# or, without root (installs into ~/.local):
./install.sh

audit-tool --list-checks        # try it
./uninstall.sh                  # removes everything again
```

`install.sh` also installs bash completion for all three commands when the
system completion directory is writable.

### Comparing concurrent vs sequential scanning

```bash
python3 -m audit_tool --host <target> --ports 1-2000 --show-speedup
```

The tool prints both the sequential and concurrent timings. **Where the
speed-up appears:** on networks (or hosts) where closed ports are *filtered and
time out*, sequential scanning waits the full timeout for each port, whereas
the thread pool overlaps those waits. On `localhost` closed ports are *refused
instantly*, so there is little to parallelize and timings can look similar —
that's expected, not a defect. On real targets the improvement scales roughly
with the thread count.

---

## Browser UI & Baseline Diff

A lightweight web UI is included (no extra dependencies) to browse JSON reports
and compare two runs (baseline/diff). Run it from the project root and point
it at your `reports` directory:

```bash
python -m audit_tool.web --reports reports --port 8000
# or, after `pip install .`:
audit-web --reports reports --port 8000
```

Open `http://localhost:8000/` in a browser to view reports and compute diffs
between two saved runs.

#### Running scans from the browser (backend + frontend)

The UI has a **New scan** panel: enter host / ports / threads, hit *Run
scan*, and the tool runs in a background thread on the machine hosting the
server — when it finishes, the new report appears in the list and opens
automatically.

API: `POST /api/scan` with JSON body
`{"host": "10.0.0.5", "ports": "1-1024", "threads": 256, "skip_scan": false,
"formats": ["json", "html"]}` → `202 {"id": "web_…"}`; poll
`GET /api/scan?id=…` until `status` is `done` (or `error`).

**Security:** because a scan can target arbitrary hosts, the scan API is
only enabled when the server is bound to a **loopback address**
(`127.0.0.1`/`::1`). If you bind with `--host 0.0.0.0` (e.g. to browse
reports on a LAN), `POST /api/scan` returns `403` — run scans from the CLI
instead. All other endpoints are read-only.

### Comparing two runs from the command line

To diff two JSON reports without a browser (useful in CI / scripts):

```bash
python -m audit_tool.baseline baseline/baseline.json reports/audit_127.0.0.1_*.json
# or: audit-baseline <base.json> <new.json>
```

This prints a summary of checks that changed level between the two runs.
Capture a new baseline at any time with the helper script:

```bash
python scripts/update_baseline.py reports/my_report.json
```

## Checks included (33)

| ID | Title | Reference |
|---|---|---|
| SSH-001 | PermitRootLogin is disabled | CIS 5.2.8 |
| SSH-002 | Password authentication is disabled | CIS 5.2.9 |
| SSH-003 | PermitEmptyPasswords is disabled | CIS 5.2.10 |
| SSH-004 | SSH config file permissions hardened | CIS 5.2.1 |
| FILE-001 | No world-writable files in /etc | CIS 6.1.11 |
| FILE-002 | World-writable directories checked | CIS 5.1.2 |
| FILE-003 | /etc/passwd permission 644 | CIS 6.1.1 |
| FILE-004 | /etc/shadow permission 640/600 | CIS 6.1.2 |
| FILE-005 | Sticky bit set on world-writable dirs | CIS 1.1.1 |
| FILE-006 | SUID/SGID binaries inventory reviewed | CIS 6.1.13 |
| FILE-007 | /etc/group permission 644 | CIS 6.1.3 |
| AUTH-001 | Password aging configured | CIS 5.4.1.1 |
| AUTH-002 | Umask set to 027 or stricter | CIS 5.4.4 |
| AUTH-003 | Empty password entries absent | CIS 5.4.1 |
| AUTH-004 | Root account is locked or key-based only | CIS 5.3.1 |
| FIRE-001 | Host-based firewall active | CIS 3.5.1 |
| NET-001 | IP forwarding is disabled | CIS 3.2.1 |
| NET-002 | ICMP redirect accept is disabled | CIS 3.2.2 |
| NET-003 | Open listening ports inventoried | — |
| NET-004 | Reverse path filtering enabled | CIS 3.3.4.1 |
| KRNL-001 | Kernel pointers are restricted | CIS 3.3.3 |
| KRNL-002 | Core dumps are disabled | CIS 1.5.1 |
| KRNL-003 | Address space layout randomization (ASLR) enabled | CIS 3.3.4 |
| LOGG-001 | Audit daemon (auditd) present | CIS 4.1 |
| LOGG-002 | Rsyslog is present | CIS 4.2 |
| MISC-001 | /tmp is a separate filesystem | CIS 1.1.2 |
| MISC-002 | sudoers file permission 440 | CIS 5.5.2 |
| WIN-001 | Windows Firewall enabled for all profiles | MS-SCC 2.1.2 |
| WIN-002 | User Account Control (UAC) enabled | MS-SCC 2.2.11 |
| WIN-003 | SMBv1 protocol disabled | MS-SCC 3.14.2 |
| WIN-004 | RDP requires network level authentication | MS-SCC 4.28.1 |
| WIN-005 | Windows Update service is running | MS-SCC 3.3.5 |
| WIN-006 | Local password policy meets minimums | MS-SCC 3.3.6 |

On non-Windows hosts the `WIN-*` checks report `SKIP`, and vice versa — the
same installation is cross-platform. Each check returns a `CheckResult` with
its **CIS / MS-SCC reference** so findings can be traced to the benchmark.

---

## How it works

```
audit_tool/
  cli.py        # argument parsing + orchestration (entry point `audit-tool`)
  checks.py     # check registry + each CIS/MS-SCC-aligned check (all read-only)
  scanner.py    # multithreaded TCP port scanner
  reporter.py   # JSON / HTML / CSV / SARIF report writers
  models.py     # CheckResult / ScanResult dataclasses + scoring
  web.py        # stdlib HTTP report browser + diff API (entry `audit-web`)
  baseline.py   # JSON-vs-JSON report comparison (entry `audit-baseline`)
  report_schema.json  # JSON Schema the JSON reports are validated against
```

- `checks.py` uses a small `@register` decorator so new checks are easy to add.
- `scanner.py` scans ports in **bounded batches** so even `1-65535` does not
  spawn an unbounded number of simultaneous sockets.
- All checks are wrapped so a single failing check never aborts the whole audit.

---

## Development & quality

- **Standard library only** — nothing to install beyond Python itself
  (tests add `pytest`, `ruff`, `black`, `mypy`, `jsonschema`).
- **Test suite**: 249 unit/integration tests, ~99% line coverage.
- **Quality gates in CI**: `ruff check`, `black --check`, `mypy`,
  `coverage run -m pytest`, plus a weekly scheduled baseline-scan workflow.
- **JSON reports are schema-validated** (`audit_tool/report_schema.json`)
  before they are written; a validation failure exits non-zero.

## Roadmap / possible additions

Already delivered (v1.0): `--formats csv,sarif`, category selection
(`--only` / `--exclude`), baseline/diff mode (CLI + web UI), CI-friendly exit
codes (`--fail-exit`).

Still possible:

- Remote host checks over SSH (reusing a user-supplied key)
- More CIS controls (LVM, systemd, PAM, DNS, NTP, …)
- GitHub-App / SARIF annotation integration examples

---

## License

MIT — free to use, modify, and extend.

## CI badges

- Coverage: ![coverage](https://codecov.io/gh/deepak-ff/cybermentor/branch/main/graph/badge.svg)
