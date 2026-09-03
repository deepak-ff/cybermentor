# security-audit-tool

A non-intrusive, **Read-Only** host security auditing tool written in **pure
Python (standard library only — no third-party dependencies)**.

It performs two jobs:

1. **Configuration audit** — runs **24+ CIS Benchmark-aligned checks** across
   SSH, file permissions, authentication policy, firewalls, kernel hardening,
   logging, and network settings. It reports each as **PASS / WARN / FAIL /
   INFO / SKIP** and computes a **0–100 hardening score**.
2. **Multithreaded TCP port scanner** — scans port ranges concurrently using a
   bounded thread pool, which dramatically reduces scan time on real networks
   where most ports are filtered and time out.

It produces two reports from a single run so they always agree:
- **Structured JSON** (machine-readable, easy to feed into other tooling)
- **Self-contained HTML dashboard** (single file, inline CSS, human-readable)

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
| `--ports` | Port range/list, e.g. `80` or `1-1024` (default `1-1024`) |
| `--timeout` | Socket connect timeout in seconds (default `1.0`) |
| `--threads` | Number of scanning threads (default `256`) |
| `--skip-scan` | Run configuration checks only |
| `--show-speedup` | Compare concurrent vs sequential scanning timings |
| `--out` | Output directory for reports (default `reports`) |
| `--hostname` | Label used in the report (default `localhost`) |

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
```

Open `http://localhost:8000/` in a browser to view reports and compute diffs
between two saved runs.


## Checks included (24+)

- **SSH** — `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`,
  `sshd_config` permissions
- **Filesystem** — world-writable files/dirs, `/etc/passwd` & `/etc/shadow`
  modes, sticky bit on `/tmp`/`/var/tmp`, SUID/SGID inventory, `/tmp` filesystem
- **Authentication** — password aging (`PASS_MAX_DAYS`), `UMASK`, empty
  password entries, `sudoers` permissions
- **Firewall / Network** — host firewall active, `ip_forward`, ICMP redirects,
  listening ports inventory
- **Kernel** — `kptr_restrict`, core dumps, ASLR (`randomize_va_space`)
- **Logging** — `auditd`, `rsyslog`

Each check returns a `CheckResult` with its **CIS reference** so findings can be
traced to the relevant benchmark.

---

## How it works

```
audit_tool/
  cli.py        # argument parsing + orchestration
  checks.py     # check registry + each CIS-aligned check (all read-only)
  scanner.py    # multithreaded TCP port scanner
  reporter.py   # JSON + HTML report writers
  models.py     # CheckResult / ScanResult dataclasses + scoring
```

- `checks.py` uses a small `@register` decorator so new checks are easy to add.
- `scanner.py` scans ports in **bounded batches** so even `1-65535` does not
  spawn an unbounded number of simultaneous sockets.
- All checks are wrapped so a single failing check never aborts the whole audit.

---

## Roadmap / possible additions

- `--json` / `--csv` report formats
- Check categories selection (`--only SSH,kernel`)
- Remote host checks over SSH (reusing a user-supplied key)
- Baseline/diff mode to compare two runs
- CI-friendly exit codes (non-zero when `FAIL` present)

---

## License

MIT — free to use, modify, and extend.

## CI badges

- Coverage: ![coverage](https://codecov.io/gh/deepak-ff/cybermentor/branch/main/graph/badge.svg)
