# SecBench

SecBench is a cross-platform desktop application (Windows / macOS / Linux) that
authenticates to an Azure tenant, a Microsoft 365 organisation, or any reachable
host (local, SSH-Linux, SSH-macOS, SSH-Windows) and runs CIS / STIG benchmarks
against them, producing HTML, JSON, CSV, and PDF reports.

The engine ships with **24 benchmarks** and over **2,200 automated controls** out
of ~2,600 total. Sources of truth for the control text remain the official CIS
Benchmark and DISA STIG PDFs; SecBench reproduces only the control identifiers
and short factual titles.

> SecBench is an independent, informational tool. It is **not** affiliated with,
> sponsored by, or endorsed by the Center for Internet Security (CIS) or the
> Defense Information Systems Agency (DISA). Authoritative control text and
> audit guidance live in the official benchmark / STIG documents at
> <https://www.cisecurity.org/cis-benchmarks/> and
> <https://public.cyber.mil/stigs/>. Use this tool as an aid; do not treat its
> output as a certified attestation.

## Bundled benchmarks

The Connect screen groups benchmarks into **Cloud** (Azure / M365) and
**Infrastructure** (host-based). Numbers are *automated controls / total
controls in the catalog*; the rest are flagged as Manual review.

### Cloud (Azure / M365)

| Benchmark | Version | Target | Coverage |
|---|---|---|---:|
| CIS Microsoft Azure Foundations Benchmark | 6.0.0 | `azure` | 143 / 159 |
| CIS Microsoft Azure Compute Services Benchmark | 2.0.0 | `azure` | 13 / 74 |
| CIS Microsoft Azure Database Services Benchmark | 2.0.0 | `azure` | 16 / 62 |
| CIS Microsoft Azure Storage Services Benchmark | 1.0.0 | `azure` | 15 / 40 |
| CIS Microsoft 365 Foundations Benchmark | 6.0.1 | `m365` | 11 / 137 |

### Infrastructure - macOS

| Benchmark | Version | Target | Coverage |
|---|---|---|---:|
| CIS Apple macOS 26 Tahoe Benchmark | 1.0.0 | `macos` | 82 / 97 |

### Infrastructure - Red Hat Enterprise Linux (CIS + STIG)

| Benchmark | Version | Target | Coverage |
|---|---|---|---:|
| CIS Red Hat Enterprise Linux 10 Benchmark | 1.0.1 | `rhel` | 166 / 186 |
| CIS Red Hat Enterprise Linux 9 Benchmark | 2.0.0 | `rhel` | 165 / 196 |
| CIS Red Hat Enterprise Linux 9 STIG Benchmark | 1.0.0 | `rhel` | 123 / 126 |
| CIS Red Hat Enterprise Linux 8 Benchmark | 4.0.0 | `rhel` | 165 / 182 |
| CIS Red Hat Enterprise Linux 8 STIG Benchmark | 2.0.0 | `rhel` | 123 / 125 |

### Infrastructure - Microsoft Windows / Defender / Windows Server

| Benchmark | Version | Target | Coverage |
|---|---|---|---:|
| CIS Microsoft Defender Antivirus Benchmark | 1.0.0 | `windows` | 26 / 39 |
| CIS Microsoft Windows 11 Enterprise Benchmark | 5.0.1 | `windows` | 109 / 119 |
| CIS Microsoft Windows 11 Stand-alone Benchmark | 5.0.0 | `windows` | 95 / 99 |
| CIS Microsoft Azure Compute Microsoft Windows Server 2022 Benchmark | 1.0.0 | `windows` | 93 / 93 |
| CIS Microsoft Azure Compute Microsoft Windows Server 2019 Benchmark | 1.0.0 | `windows` | 93 / 93 |
| CIS Microsoft Windows Server 2025 Benchmark | 2.0.0 | `windows` | 99 / 99 |
| CIS Microsoft Windows Server 2025 Stand-alone Benchmark | 1.0.0 | `windows` | 93 / 93 |
| CIS Microsoft Windows Server 2022 Benchmark | 5.0.0 | `windows` | 99 / 99 |
| CIS Microsoft Windows Server 2022 Stand-alone Benchmark | 2.0.0 | `windows` | 93 / 93 |
| CIS Microsoft Windows Server 2022 STIG Benchmark | 2.0.0 | `windows` | 109 / 109 |
| CIS Microsoft Windows Server 2019 Benchmark | 4.0.0 | `windows` | 99 / 99 |
| CIS Microsoft Windows Server 2019 Stand-alone Benchmark | 3.0.0 | `windows` | 93 / 93 |
| CIS Microsoft Windows Server 2019 STIG Benchmark | 3.0.0 | `windows` | 109 / 109 |

## Quick start (running from source)

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
secbench-gui                        # launch the desktop UI
secbench --list                     # CLI: list benchmarks
```

## Authentication and target setup

The Connect screen is split into two tabs:

### Cloud tab (Azure / M365)

1. **Interactive browser** sign-in (recommended for desktop use).
2. **Device code** flow (useful over SSH / headless).
3. **Service principal** (client ID + secret or certificate).

Required minimum permissions:

- Azure: `Reader` on every subscription you want to evaluate, plus
  `Security Reader` for Defender for Cloud controls.
- Microsoft Graph: `Directory.Read.All`, `Policy.Read.All`,
  `Reports.Read.All`, `SecurityEvents.Read.All`,
  `RoleManagement.Read.Directory`, `Application.Read.All`,
  `AuditLog.Read.All`.

### Infrastructure tab

Configure a single OS target shared by every host-based benchmark
(macOS Tahoe, all RHEL profiles, every Windows profile and
Defender AV):

- **Local computer** - runs commands on the same machine the GUI is on
  (available on macOS, Linux, and Windows hosts).
- **SSH** - connects to a remote macOS / Linux / Windows host with
  optional `sudo` elevation. The "Test target" button auto-detects the
  remote OS via `uname -a` (POSIX) or `cmd /c ver` (Windows).

### Windows elevation

When the GUI runs on Windows **without administrator rights**, a yellow
banner appears at the bottom of the window. Many local Windows checks
(`secedit /export`, `auditpol`, `Get-MpPreference`, BitLocker, privileged
registry keys) require admin rights and will otherwise return MANUAL or
FAIL. The **Restart as administrator** button re-launches SecBench
elevated via a UAC prompt; if anything goes wrong, a diagnostic log is
written to `%TEMP%\secbench_elevation.log`.

## Reports

After a run completes, use the Reports page to export:

- Interactive **HTML** (Jinja2-rendered, self-contained).
- Machine-readable **JSON**.
- Flat **CSV** (one row per control).
- **PDF** (rendered via WeasyPrint where available, falling back to ReportLab).

## Building standalone binaries

The packaging scripts produce real, **standalone** binaries via PyInstaller -
no Python install required on the target machine. PyInstaller cannot
cross-compile, so each script must be run on its target OS.

### Windows

```powershell
# One-folder bundle (default; faster startup):
.\packaging\build_windows.ps1
# Output:  dist\SecBench\SecBench.exe  (+ supporting DLLs / data in same folder)

# Single self-extracting .exe (slower first launch, easiest to ship):
.\packaging\build_windows.ps1 -OneFile
# Output:  dist\SecBench.exe

# Skip pip install if your venv is already set up:
.\packaging\build_windows.ps1 -SkipInstall
```

### macOS

```bash
# One-folder bundle + .app:
./packaging/build_macos.sh
# Outputs:  dist/SecBench/SecBench  and  dist/SecBench.app

# Single Mach-O binary:
SECBENCH_ONEFILE=1 ./packaging/build_macos.sh
# Output:  dist/SecBench

# Skip pip install:
SECBENCH_SKIP_INSTALL=1 ./packaging/build_macos.sh
```

### Linux

```bash
# One-folder bundle:
./packaging/build_linux.sh
# Output:  dist/SecBench/SecBench

# Single ELF binary:
SECBENCH_ONEFILE=1 ./packaging/build_linux.sh
# Output:  dist/SecBench
```

The PyInstaller spec lives at `packaging/pyinstaller-secbench.spec`. Optional
icons can be placed at `packaging/icons/icon.ico` (Windows), `icon.icns`
(macOS); they are picked up automatically when present.

To distribute a build, zip the `dist/SecBench/` folder (one-folder mode) or
ship the single binary (one-file mode). End users do **not** need Python
installed.

## Project layout

```
src/secbench/
  app.py              # GUI entry point (also -m secbench)
  cli.py              # CLI entry point
  elevation.py        # Windows admin-detect + UAC self-relaunch
  config.py           # Settings persistence
  auth/               # Interactive / device-code / service-principal sign-in
  azure_client/       # Azure SDK wrappers + response cache
  benchmarks/         # YAML catalogs + Python checks per benchmark
    _linux_common/    # Shared RHEL helpers (rpm, systemd, sshd, sysctl, ...)
    _windows_common/  # Shared Windows helpers (registry, secedit, auditpol,
                      #   Get-MpPreference, firewall, services, ...)
    azure_*/, m365_*/, macos_*/, rhel_*/, windows_*/, win_server_*/, defender_*
  engine/             # Runner, registry, catalog loader, progress events
  gui/                # PyQt6 pages: Connect / Benchmarks / Run / Results / Reports
  reports/            # HTML / JSON / CSV / PDF generators + Jinja2 templates
  targets/            # LocalTarget, SshTarget abstractions
packaging/            # PyInstaller spec + per-OS build scripts
tests/                # pytest catalog + engine tests
```

## Disclaimer

The CIS Benchmark trademarks are property of the Center for Internet Security.
The DISA STIG documents are produced by the U.S. Defense Information Systems
Agency. SecBench reproduces only short, factual references to control
identifiers and section titles; full audit/remediation prose remains under
the original copyright and is intentionally summarized rather than verbatim.
Always consult the official benchmark / STIG documents for authoritative
guidance.
