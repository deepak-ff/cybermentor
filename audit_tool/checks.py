"""Non-intrusive host security checks, aligned to CIS and MS-SCC baselines.

Design
------
Every check is a read-only probe: it inspects configuration, file permissions
or service state and reports PASS / WARN / FAIL / INFO / SKIP. Nothing on the
target system is ever modified.

Checks are registered with a :class:`CheckSpec` capturing the check id,
title, category, benchmark reference, severity weight and the platforms the
check applies to. On a given platform, checks that do not apply are reported
as SKIP ("not applicable") so a report always shows the full control set.

Checks must be robust to missing files, permission denials and absent
commands (e.g. ``/etc/shadow`` without root, ``ufw`` not installed) and
degrade to SKIP/INFO rather than raise.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import (
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
)

from .models import CheckResult, Level, Platform, Severity

CheckFunc = Callable[[str], CheckResult]


@dataclass(frozen=True)
class CheckSpec:
    """Metadata for a single security check."""

    id: str
    title: str
    category: str
    cis_ref: str
    severity: Severity
    platforms: Tuple[Platform, ...]


CHECK_REGISTRY: Dict[str, CheckSpec] = {}
CHECK_FUNCS: Dict[str, CheckFunc] = {}


def register(
    check_id: str,
    title: str,
    category: str,
    cis_ref: str = "",
    severity: Severity = Severity.MEDIUM,
    platforms: Tuple[Platform, ...] = (Platform.ANY,),
) -> Callable[[CheckFunc], CheckFunc]:
    """Decorator that registers a check function with its metadata."""

    def decorator(func: CheckFunc) -> CheckFunc:
        spec = CheckSpec(check_id, title, category, cis_ref, severity, platforms)
        CHECK_REGISTRY[check_id] = spec
        CHECK_FUNCS[check_id] = func
        return func

    return decorator


def current_platform() -> Platform:
    """Detect the platform this process is running on."""
    return Platform.WINDOWS if sys.platform == "win32" else Platform.LINUX


# ------------------------------------------------------------------ helpers


def _res(
    check_id: str,
    host: str,
    level: Level,
    detail: str,
    recommendation: str = "",
) -> CheckResult:
    """Build a CheckResult from the registered spec of *check_id*."""
    spec = CHECK_REGISTRY[check_id]
    return CheckResult(
        id=spec.id,
        title=spec.title,
        category=spec.category,
        level=level,
        detail=detail,
        recommendation=recommendation,
        cis_ref=spec.cis_ref,
        host=host,
        severity=spec.severity,
    )


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, FileNotFoundError, PermissionError, ValueError):
        return None


def _mode(path: str) -> Optional[int]:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def _fmt_mode(mode: int) -> str:
    return oct(mode)[2:].zfill(4)


def _cmd(args: Sequence[str], timeout: float = 15.0) -> Optional[Tuple[int, str]]:
    """Run an external command; return (returncode, combined output) or None
    when the command is missing or times out."""
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return None


def _reg_dword(hive: str, subkey: str, value: str) -> Optional[int]:
    """Read a DWORD registry value (Windows only); None if unavailable."""
    if sys.platform != "win32":
        return None
    try:
        import winreg  # type: ignore[import-not-found]

        hives = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }
        root = hives.get(hive)
        if root is None:
            return None
        with winreg.OpenKey(root, subkey) as key:
            data, reg_type = winreg.QueryValueEx(key, value)
        if reg_type == winreg.REG_DWORD:
            return int(data)
    except (OSError, ImportError, ValueError, TypeError):
        return None
    return None


# ---------------------------------------------------------------------- SSH


@register(
    "SSH-001",
    "PermitRootLogin is disabled",
    "SSH",
    "CIS 5.2.8",
    Severity.HIGH,
    platforms=(Platform.LINUX,),
)
def check_ssh_permit_root(host: str) -> CheckResult:
    cfg = _read("/etc/ssh/sshd_config")
    if cfg is None:
        return _res("SSH-001", host, Level.SKIP, "sshd_config not readable")
    value = "yes"
    v = re.search(r"^\s*PermitRootLogin\s+(\S+)", cfg, re.MULTILINE)
    if v:
        value = v.group(1).lower()
    ok = value in ("no", "prohibit-password")
    return _res(
        "SSH-001",
        host,
        Level.PASS if ok else Level.FAIL,
        f"PermitRootLogin={value}",
        "Set PermitRootLogin no (or prohibit-password) in sshd_config.",
    )


@register(
    "SSH-002",
    "Password authentication is disabled",
    "SSH",
    "CIS 5.2.9",
    Severity.HIGH,
    platforms=(Platform.LINUX,),
)
def check_ssh_password_auth(host: str) -> CheckResult:
    cfg = _read("/etc/ssh/sshd_config")
    if cfg is None:
        return _res("SSH-002", host, Level.SKIP, "sshd_config not readable")
    v = re.search(r"^\s*PasswordAuthentication\s+(\S+)", cfg, re.MULTILINE)
    value = v.group(1).lower() if v else "yes"
    ok = value == "no"
    return _res(
        "SSH-002",
        host,
        Level.PASS if ok else Level.FAIL,
        f"PasswordAuthentication={value}",
        "Set PasswordAuthentication no and use SSH keys.",
    )


@register(
    "SSH-003",
    "PermitEmptyPasswords is disabled",
    "SSH",
    "CIS 5.2.10",
    Severity.CRITICAL,
    platforms=(Platform.LINUX,),
)
def check_ssh_empty_passwords(host: str) -> CheckResult:
    cfg = _read("/etc/ssh/sshd_config")
    if cfg is None:
        return _res("SSH-003", host, Level.SKIP, "sshd_config not readable")
    v = re.search(r"^\s*PermitEmptyPasswords\s+(\S+)", cfg, re.MULTILINE)
    value = v.group(1).lower() if v else "no"
    ok = value == "no"
    return _res(
        "SSH-003",
        host,
        Level.PASS if ok else Level.FAIL,
        f"PermitEmptyPasswords={value}",
        "Set PermitEmptyPasswords no in sshd_config.",
    )


@register(
    "SSH-004",
    "SSH config file permissions hardened",
    "SSH",
    "CIS 5.2.1",
    Severity.LOW,
    platforms=(Platform.LINUX,),
)
def check_ssh_config_mode(host: str) -> CheckResult:
    mode = _mode("/etc/ssh/sshd_config")
    if mode is None:
        return _res("SSH-004", host, Level.SKIP, "sshd_config not found")
    ok = mode & 0o022 == 0  # not group/world writable
    return _res(
        "SSH-004",
        host,
        Level.PASS if ok else Level.FAIL,
        f"mode {_fmt_mode(mode)}",
        "chmod 600 /etc/ssh/sshd_config (not group/other writable).",
    )


# ---------------------------------------------------------- File permissions


@register(
    "FILE-001",
    "No world-writable files in /etc",
    "Filesystem",
    "CIS 6.1.11",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_world_writable_etc(host: str) -> CheckResult:
    world_writable: List[str] = []
    for root, _dirs, files in os.walk("/etc", topdown=True):
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
                if st.st_mode & stat.S_IWOTH:
                    world_writable.append(path)
            except OSError:
                continue
        if len(world_writable) > 500:  # avoid pathological scans
            break
    if world_writable:
        sample = ", ".join(world_writable[:5])
        detail = f"{len(world_writable)} world-writable file(s), e.g. {sample}"
    else:
        detail = "0 world-writable file(s) found in /etc"
    return _res(
        "FILE-001",
        host,
        Level.PASS if not world_writable else Level.WARN,
        detail,
        "Review and remove world-writable permissions on the listed files.",
    )


@register(
    "FILE-002",
    "World-writable directories checked",
    "Filesystem",
    "CIS 5.1.2",
    Severity.LOW,
    platforms=(Platform.LINUX,),
)
def check_world_writable_dirs(host: str) -> CheckResult:
    dirs: List[str] = []
    # Common sticky dirs are expected; report only unusual ones.
    sticky_writable = {"/tmp", "/var/tmp", "/dev/shm"}
    try:
        entries = os.listdir("/")
    except OSError:
        entries = []
    for name in entries:
        path = f"/{name}"
        if not os.path.isdir(path):
            continue
        try:
            st = os.stat(path)
            if st.st_mode & stat.S_IWOTH and path not in sticky_writable:
                dirs.append(path)
        except OSError:
            continue
    return _res(
        "FILE-002",
        host,
        Level.WARN if dirs else Level.PASS,
        (
            f"unexpected world-writable dirs: {', '.join(dirs)}"
            if dirs
            else "none outside /tmp,/var/tmp,/dev/shm"
        ),
        "Remove world-writable permissions on the listed directories "
        "or add the sticky bit.",
    )


@register(
    "FILE-003",
    "/etc/passwd permission 644",
    "Filesystem",
    "CIS 6.1.1",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_passwd_mode(host: str) -> CheckResult:
    mode = _mode("/etc/passwd")
    if mode is None:
        return _res("FILE-003", host, Level.SKIP, "/etc/passwd not found")
    ok = mode == 0o644
    return _res(
        "FILE-003",
        host,
        Level.PASS if ok else Level.FAIL,
        f"mode {_fmt_mode(mode)}",
        "chmod 644 /etc/passwd.",
    )


@register(
    "FILE-004",
    "/etc/shadow permission 640/600",
    "Filesystem",
    "CIS 6.1.2",
    Severity.HIGH,
    platforms=(Platform.LINUX,),
)
def check_shadow_mode(host: str) -> CheckResult:
    mode = _mode("/etc/shadow")
    if mode is None:
        return _res("FILE-004", host, Level.SKIP, "/etc/shadow not accessible")
    ok = mode in (0o600, 0o640)
    return _res(
        "FILE-004",
        host,
        Level.PASS if ok else Level.FAIL,
        f"mode {_fmt_mode(mode)}",
        "chmod 600 /etc/shadow (root only).",
    )


@register(
    "FILE-005",
    "Sticky bit set on world-writable dirs",
    "Filesystem",
    "CIS 1.1.1",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_sticky_bits(host: str) -> CheckResult:
    bad: List[str] = []
    for path in ("/tmp", "/var/tmp"):
        if not os.path.isdir(path):
            continue
        try:
            st = os.stat(path)
            if not st.st_mode & stat.S_ISVTX:
                bad.append(path)
        except OSError:
            continue
    return _res(
        "FILE-005",
        host,
        Level.PASS if not bad else Level.FAIL,
        (f"missing sticky bit on {', '.join(bad)}" if bad else "sticky bit set"),
        "chmod 1777 /tmp /var/tmp.",
    )


@register(
    "FILE-006",
    "SUID/SGID binaries inventory reviewed",
    "Filesystem",
    "CIS 6.1.13",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_suid_sgid(host: str) -> CheckResult:
    suid: List[str] = []
    scan_roots = (
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    )
    for root in scan_roots:
        if not os.path.isdir(root):
            continue
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            try:
                st = os.stat(path)
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    suid.append(path)
            except OSError:
                continue
    base = os.path.basename
    well_known = {
        "sudo",
        "su",
        "mount",
        "umount",
        "passwd",
        "chsh",
        "ping",
        "gpasswd",
        "newgrp",
        "chfn",
        "logout",
        "pkexec",
    }
    suspicious = [p for p in suid if base(p) not in well_known]
    detail = f"{len(suid)} SUID/SGID binary(ies); {len(suspicious)} non-standard"
    if suspicious:
        detail += f" (e.g. {', '.join(suspicious[:5])})"
    return _res(
        "FILE-006",
        host,
        Level.WARN if suspicious else Level.PASS,
        detail,
        "Remove SUID/SGID bits from binaries that do not require privilege elevation.",
    )


@register(
    "FILE-007",
    "/etc/group permission 644",
    "Filesystem",
    "CIS 6.1.3",
    Severity.LOW,
    platforms=(Platform.LINUX,),
)
def check_group_mode(host: str) -> CheckResult:
    mode = _mode("/etc/group")
    if mode is None:
        return _res("FILE-007", host, Level.SKIP, "/etc/group not found")
    ok = mode == 0o644
    return _res(
        "FILE-007",
        host,
        Level.PASS if ok else Level.FAIL,
        f"mode {_fmt_mode(mode)}",
        "chmod 644 /etc/group.",
    )


# ------------------------------------------------------------ Authentication


@register(
    "AUTH-001",
    "Password aging configured",
    "Authentication",
    "CIS 5.4.1.1",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_password_aging(host: str) -> CheckResult:
    cfg = _read("/etc/login.defs")
    if cfg is None:
        return _res("AUTH-001", host, Level.SKIP, "login.defs not readable")
    max_days = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", cfg, re.MULTILINE)
    min_days = re.search(r"^\s*PASS_MIN_DAYS\s+(\d+)", cfg, re.MULTILINE)
    max_v = int(max_days.group(1)) if max_days else 99999
    min_v = int(min_days.group(1)) if min_days else 0
    ok = max_v <= 365
    return _res(
        "AUTH-001",
        host,
        Level.PASS if ok else Level.FAIL,
        f"PASS_MAX_DAYS={max_v}, PASS_MIN_DAYS={min_v}",
        "Set PASS_MAX_DAYS<=365 and PASS_MIN_DAYS>=1 in /etc/login.defs.",
    )


@register(
    "AUTH-002",
    "Umask set to 027 or stricter",
    "Authentication",
    "CIS 5.4.4",
    Severity.LOW,
    platforms=(Platform.LINUX,),
)
def check_umask(host: str) -> CheckResult:
    cfg = _read("/etc/login.defs")
    if cfg is None:
        return _res("AUTH-002", host, Level.SKIP, "login.defs not readable")
    v = re.search(r"^\s*UMASK\s+(\d+)", cfg, re.MULTILINE)
    if not v:
        return _res(
            "AUTH-002",
            host,
            Level.INFO,
            "UMASK not set in login.defs (defaults to 022)",
            "Set UMASK 027 in /etc/login.defs.",
        )
    umask = int(v.group(1), 8)
    # "027 or stricter": the umask must mask at least the bits of 027
    # (group rwx + other rx), so new files are 640 or tighter.
    ok = (umask & 0o027) == 0o027
    return _res(
        "AUTH-002",
        host,
        Level.PASS if ok else Level.FAIL,
        f"UMASK={v.group(1)}",
        "Set UMASK 027 in /etc/login.defs.",
    )


@register(
    "AUTH-003",
    "Empty password entries absent",
    "Authentication",
    "CIS 5.4.1",
    Severity.CRITICAL,
    platforms=(Platform.LINUX,),
)
def check_empty_passwords(host: str) -> CheckResult:
    shadow = _read("/etc/shadow")
    if shadow is None:
        return _res(
            "AUTH-003",
            host,
            Level.SKIP,
            "/etc/shadow not readable (requires root)",
        )
    # An empty password is field 2 (the hash) being exactly empty.
    empty = []
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "":
            empty.append(parts[0])
    return _res(
        "AUTH-003",
        host,
        Level.PASS if not empty else Level.FAIL,
        (f"accounts with empty password: {', '.join(empty)}" if empty else "none"),
        "Lock or set passwords for accounts with empty password fields.",
    )


@register(
    "AUTH-004",
    "Root account is locked or key-based only",
    "Authentication",
    "CIS 5.3.1",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_root_locked(host: str) -> CheckResult:
    shadow = _read("/etc/shadow")
    if shadow is None:
        return _res(
            "AUTH-004",
            host,
            Level.SKIP,
            "/etc/shadow not readable (requires root)",
        )
    root: Optional[List[str]] = None
    for line in shadow.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "root":
            root = parts
            break
    if root is None or len(root) < 2:
        return _res(
            "AUTH-004",
            host,
            Level.FAIL,
            "root account not found in /etc/shadow",
            "Ensure the root account exists and its password field is locked.",
        )
    field2 = root[1]
    locked = field2.startswith(("!", "*", "!!")) or field2 in ("", "!")
    if field2 == "":
        return _res(
            "AUTH-004",
            host,
            Level.FAIL,
            "root account has an EMPTY password hash",
            "Set a password or lock root: passwd -l root.",
        )
    return _res(
        "AUTH-004",
        host,
        Level.PASS if locked else Level.WARN,
        (
            "root account locked (no password hash)"
            if locked
            else "root account has an active password hash"
        ),
        "Lock the root account (passwd -l root) and use sudo for privileged work.",
    )


# ------------------------------------------------------------ Firewall / network


@register(
    "FIRE-001",
    "Host-based firewall active",
    "Firewall",
    "CIS 3.5.1",
    Severity.HIGH,
    platforms=(Platform.LINUX,),
)
def check_firewall(host: str) -> CheckResult:
    backend = None
    out: Optional[Tuple[int, str]] = None
    if shutil.which("ufw"):
        out = _cmd(["ufw", "status"])
        backend = "ufw"
    elif shutil.which("nft"):
        out = _cmd(["nft", "list", "ruleset"])
        backend = "nftables"
    elif shutil.which("iptables"):
        out = _cmd(["iptables", "-L", "-n"])
        backend = "iptables"
    else:
        return _res(
            "FIRE-001",
            host,
            Level.INFO,
            "no firewall tool found (ufw/nftables/iptables)",
            "Install and enable a host firewall (ufw or nftables).",
        )

    text = (out or (0, ""))[1].strip()
    if backend == "ufw":
        active = "Status: active" in text
        detail = f"backend=ufw; {text.splitlines()[0] if text else 'no status output'}"
    else:
        active = bool(text)
        detail = f"backend={backend}; rules={'present' if text else 'none'}"
    return _res(
        "FIRE-001",
        host,
        Level.PASS if active else Level.FAIL,
        detail,
        "Enable the host firewall and define rules for required services.",
    )


@register(
    "NET-001",
    "IP forwarding is disabled",
    "Network",
    "CIS 3.2.1",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_ip_forwarding(host: str) -> CheckResult:
    val = _read("/proc/sys/net/ipv4/ip_forward")
    if val is None:
        return _res("NET-001", host, Level.SKIP, "procfs not readable")
    ok = val.strip() == "0"
    return _res(
        "NET-001",
        host,
        Level.PASS if ok else Level.FAIL,
        f"net.ipv4.ip_forward={val.strip()}",
        "sysctl -w net.ipv4.ip_forward=0 unless routing is required.",
    )


@register(
    "NET-002",
    "ICMP redirect accept is disabled",
    "Network",
    "CIS 3.2.2",
    Severity.LOW,
    platforms=(Platform.LINUX,),
)
def check_icmp_redirects(host: str) -> CheckResult:
    val = _read("/proc/sys/net/ipv4/conf/all/accept_redirects")
    if val is None:
        return _res("NET-002", host, Level.SKIP, "procfs not readable")
    ok = val.strip() == "0"
    return _res(
        "NET-002",
        host,
        Level.PASS if ok else Level.FAIL,
        f"accept_redirects={val.strip()}",
        "Set net.ipv4.conf.all.accept_redirects=0.",
    )


@register(
    "NET-003",
    "Open listening ports inventoried",
    "Network",
    "",
    Severity.LOW,
    platforms=(Platform.ANY,),
)
def check_listening_ports(host: str) -> CheckResult:
    out = _cmd(["ss", "-tulnp"]) or _cmd(["netstat", "-tulnp"])
    count = 0
    if out is not None:
        ports = re.findall(r":(\d+)\s", out[1])
        count = len(set(ports))
    return _res(
        "NET-003",
        host,
        Level.INFO,
        f"{count} listening port(s) detected (see 'ss -tulnp')",
        "Close or restrict unused listening services.",
    )


@register(
    "NET-004",
    "Reverse path filtering enabled",
    "Network",
    "CIS 3.3.4.1",
    Severity.LOW,
    platforms=(Platform.LINUX,),
)
def check_rp_filter(host: str) -> CheckResult:
    val = _read("/proc/sys/net/ipv4/conf/all/rp_filter")
    if val is None:
        return _res("NET-004", host, Level.SKIP, "procfs not readable")
    ok = val.strip() in ("1", "2")
    return _res(
        "NET-004",
        host,
        Level.PASS if ok else Level.FAIL,
        f"rp_filter={val.strip()}",
        "sysctl -w net.ipv4.conf.all.rp_filter=1.",
    )


# --------------------------------------------------------------------- Kernel / sysctl


@register(
    "KRNL-001",
    "Kernel pointers are restricted",
    "Kernel",
    "CIS 3.3.3",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_kptr_restrict(host: str) -> CheckResult:
    val = _read("/proc/sys/kernel/kptr_restrict")
    if val is None:
        return _res("KRNL-001", host, Level.SKIP, "procfs not readable")
    ok = val.strip() in ("1", "2")
    return _res(
        "KRNL-001",
        host,
        Level.PASS if ok else Level.FAIL,
        f"kernel.kptr_restrict={val.strip()}",
        "sysctl -w kernel.kptr_restrict=2.",
    )


@register(
    "KRNL-002",
    "Core dumps are disabled",
    "Kernel",
    "CIS 1.5.1",
    Severity.LOW,
    platforms=(Platform.LINUX,),
)
def check_core_dumps(host: str) -> CheckResult:
    cfg = _read("/etc/security/limits.conf")
    val = None
    if cfg:
        m = re.search(r"^\s*\*\s+hard\s+core\s+0", cfg, re.MULTILINE)
        if m:
            val = "0"
    return _res(
        "KRNL-002",
        host,
        Level.PASS if val == "0" else Level.INFO,
        (
            f"hard core limit set to {val}"
            if val
            else "hard core limit not set in limits.conf"
        ),
        "Add '* hard core 0' to /etc/security/limits.conf.",
    )


@register(
    "KRNL-003",
    "Address space layout randomization (ASLR) enabled",
    "Kernel",
    "CIS 3.3.4",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_aslr(host: str) -> CheckResult:
    val = _read("/proc/sys/kernel/randomize_va_space")
    if val is None:
        return _res("KRNL-003", host, Level.SKIP, "procfs not readable")
    ok = val.strip() == "2"
    return _res(
        "KRNL-003",
        host,
        Level.PASS if ok else Level.FAIL,
        f"randomize_va_space={val.strip()}",
        "sysctl -w kernel.randomize_va_space=2.",
    )


# ---------------------------------------------------------------- Logging / audit


@register(
    "LOGG-001",
    "Audit daemon (auditd) present",
    "Logging",
    "CIS 4.1",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_auditd(host: str) -> CheckResult:
    present = shutil.which("auditd") is not None
    return _res(
        "LOGG-001",
        host,
        Level.PASS if present else Level.INFO,
        f"auditd {'installed' if present else 'not installed'}",
        "Install auditd (apt install auditd) to enable audit logging.",
    )


@register(
    "LOGG-002",
    "Rsyslog is present",
    "Logging",
    "CIS 4.2",
    Severity.LOW,
    platforms=(Platform.LINUX,),
)
def check_rsyslog(host: str) -> CheckResult:
    present = shutil.which("rsyslogd") is not None
    return _res(
        "LOGG-002",
        host,
        Level.PASS if present else Level.INFO,
        f"rsyslogd {'present' if present else 'not installed'}",
        "Install and enable rsyslog for centralised logging.",
    )


# ------------------------------------------------------------------- Misc


@register(
    "MISC-001",
    "/tmp is a separate filesystem",
    "Filesystem",
    "CIS 1.1.2",
    Severity.MEDIUM,
    platforms=(Platform.LINUX,),
)
def check_tmp_fs(host: str) -> CheckResult:
    fstab = _read("/etc/fstab")
    mounted_raw = _cmd(["mount"])
    mounted = (mounted_raw[1] if mounted_raw else "").lower()
    if fstab is None and not mounted:
        return _res("MISC-001", host, Level.SKIP, "cannot inspect mounts")
    ok = "/tmp" in mounted or bool(fstab and "/tmp" in fstab)
    return _res(
        "MISC-001",
        host,
        Level.PASS if ok else Level.WARN,
        f"/tmp {'mounted separately' if ok else 'not on its own filesystem'}",
        "Mount /tmp as a separate filesystem with nodev,nosuid,noexec.",
    )


@register(
    "MISC-002",
    "sudoers file permission 440",
    "Authentication",
    "CIS 5.5.2",
    Severity.HIGH,
    platforms=(Platform.LINUX,),
)
def check_sudoers_mode(host: str) -> CheckResult:
    mode = _mode("/etc/sudoers")
    if mode is None:
        return _res("MISC-002", host, Level.SKIP, "/etc/sudoers not readable")
    ok = mode in (0o440, 0o400) and mode & 0o022 == 0
    return _res(
        "MISC-002",
        host,
        Level.PASS if ok else Level.FAIL,
        f"mode {_fmt_mode(mode)}",
        "chmod 440 /etc/sudoers.",
    )


# --------------------------------------------------------------------- Windows


@register(
    "WIN-001",
    "Windows Firewall enabled for all profiles",
    "Windows",
    "MS-SCC 2.1.2",
    Severity.HIGH,
    platforms=(Platform.WINDOWS,),
)
def check_win_firewall(host: str) -> CheckResult:
    out = _cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
    if out is None:
        return _res("WIN-001", host, Level.SKIP, "netsh not available")
    _rc, text = out
    states = re.findall(r"firewall state\s*:\s*(\w+)", text, re.IGNORECASE)
    if not states:
        return _res(
            "WIN-001",
            host,
            Level.SKIP,
            f"unrecognized netsh output: {text[:80]!r}",
        )
    off = [s for s in states if s.casefold() != "on"]
    return _res(
        "WIN-001",
        host,
        Level.PASS if not off else Level.FAIL,
        f"firewall states: {', '.join(states)}",
        "netsh advfirewall set allprofiles state on",
    )


@register(
    "WIN-002",
    "User Account Control (UAC) enabled",
    "Windows",
    "MS-SCC 2.2.11",
    Severity.MEDIUM,
    platforms=(Platform.WINDOWS,),
)
def check_win_uac(host: str) -> CheckResult:
    val = _reg_dword(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
    )
    if val is None:
        return _res(
            "WIN-002",
            host,
            Level.SKIP,
            "UAC policy value not readable (requires admin?)",
        )
    ok = val == 2
    return _res(
        "WIN-002",
        host,
        Level.PASS if ok else Level.FAIL,
        f"EnableLUA={val} (2 = always notify)",
        "Set HKLM\\...\\Policies\\System\\EnableLUA = 2.",
    )


@register(
    "WIN-003",
    "SMBv1 protocol disabled",
    "Windows",
    "MS-SCC 3.14.2",
    Severity.HIGH,
    platforms=(Platform.WINDOWS,),
)
def check_win_smb1(host: str) -> CheckResult:
    client = _reg_dword(
        "HKLM",
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "SMB1",
    )
    server = _reg_dword(
        "HKLM",
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1",
    )
    if client is None and server is None:
        return _res(
            "WIN-003",
            host,
            Level.INFO,
            "SMB1 not explicitly configured (OS default applies)",
            "Disable SMB1 explicitly via the registry "
            "or 'Remove-ItemProperty ... SMB1'.",
        )
    enabled = [v for v in (client, server) if v == 0]
    ok = not enabled
    detail = f"client SMB1={client}, server SMB1={server} (2 = disabled)"
    return _res(
        "WIN-003",
        host,
        Level.PASS if ok else Level.FAIL,
        detail,
        "Set SMB1=2 (disabled) under LanmanWorkstation and LanmanServer Parameters.",
    )


@register(
    "WIN-004",
    "RDP requires network level authentication",
    "Windows",
    "MS-SCC 4.28.1",
    Severity.MEDIUM,
    platforms=(Platform.WINDOWS,),
)
def check_win_rdp_nla(host: str) -> CheckResult:
    val = _reg_dword(
        "HKLM",
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication",
    )
    if val is None:
        return _res(
            "WIN-004", host, Level.SKIP, "RDP-Tcp station not found / not readable"
        )
    ok = val == 1
    return _res(
        "WIN-004",
        host,
        Level.PASS if ok else Level.FAIL,
        f"UserAuthentication={val} (1 = NLA required)",
        "Enable 'Require user to log on by using Network Level "
        "Authentication' on the RDP-Tcp station.",
    )


@register(
    "WIN-005",
    "Windows Update service is running",
    "Windows",
    "MS-SCC 3.3.5",
    Severity.LOW,
    platforms=(Platform.WINDOWS,),
)
def check_win_update_service(host: str) -> CheckResult:
    out = _cmd(["sc", "query", "wuauserv"])
    if out is None:
        return _res("WIN-005", host, Level.SKIP, "'sc' not available")
    rc, text = out
    if rc != 0:
        return _res(
            "WIN-005",
            host,
            Level.SKIP,
            "could not query wuauserv (requires admin?)",
        )
    running = re.search(r"STATE\s*:\s*\d+\s*-?\s*RUNNING", text, re.IGNORECASE)
    return _res(
        "WIN-005",
        host,
        Level.PASS if running else Level.FAIL,
        "wuauserv STATE: RUNNING" if running else "wuauserv is not running",
        "Set the Windows Update service (wuauserv) to automatic and start it.",
    )


def _win_password_policy(
    text: str,
) -> Tuple[Optional[List[str]], Optional[List[str]]]:
    """Parse `net accounts` output.

    Returns (issues, detail) where both are None when the output is not
    parseable.
    """
    max_age = re.search(r"Maximum password age\s*:\s*(\d+)", text, re.IGNORECASE)
    min_len = re.search(r"Minimum password length\s*:\s*(\d+)", text, re.IGNORECASE)
    if not max_age and not min_len:
        return None, None
    issues: List[str] = []
    if max_age and int(max_age.group(1)) > 90:
        issues.append(f"max age {max_age.group(1)} days (> 90)")
    if min_len and int(min_len.group(1)) < 8:
        issues.append(f"min length {min_len.group(1)} chars (< 8)")
    detail: List[str] = []
    if max_age:
        detail.append(f"max age {max_age.group(1)} days")
    if min_len:
        detail.append(f"min length {min_len.group(1)} chars")
    return issues, detail


@register(
    "WIN-006",
    "Local password policy meets minimums",
    "Windows",
    "MS-SCC 3.3.6",
    Severity.MEDIUM,
    platforms=(Platform.WINDOWS,),
)
def check_win_password_policy(host: str) -> CheckResult:
    out = _cmd(["net", "accounts"])
    if out is None:
        return _res("WIN-006", host, Level.SKIP, "'net' not available")
    rc, text = out
    if rc != 0:
        return _res(
            "WIN-006",
            host,
            Level.SKIP,
            "could not read password policy (requires admin?)",
        )
    issues, detail = _win_password_policy(text)
    if issues is None or detail is None:
        return _res("WIN-006", host, Level.SKIP, "password policy output not parseable")
    if issues:
        return _res(
            "WIN-006",
            host,
            Level.WARN,
            "password policy issues: " + "; ".join(issues),
            "Set Maximum password age <= 90 days " "and Minimum password length >= 8.",
        )
    return _res("WIN-006", host, Level.PASS, ", ".join(detail))


# ------------------------------------------------------------------- registry


def iter_specs(
    categories: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> Iterator[Tuple[str, CheckSpec]]:
    """Yield (id, spec) for registered checks after filters are applied.

    *categories* is matched case-insensitively against spec.category;
    *exclude* is matched case-insensitively against the check id.
    """
    cats = {c.strip().lower() for c in categories if c.strip()} if categories else None
    excl = {e.strip().upper() for e in exclude if e.strip()} if exclude else set()
    for cid in sorted(CHECK_REGISTRY):
        spec = CHECK_REGISTRY[cid]
        if spec.id.upper() in excl:
            continue
        if cats is not None and spec.category.lower() not in cats:
            continue
        yield cid, spec


def run_all_checks(
    host: str = "localhost",
    categories: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
    platform: Optional[Platform] = None,
) -> List[CheckResult]:
    """Run the selected checks and return ordered results.

    Checks that do not apply to *platform* are reported as SKIP so the report
    always presents the full control set. A check that raises is contained:
    it is reported as INFO with the error, never aborting the whole audit.
    """
    plat = platform or current_platform()
    results: List[CheckResult] = []
    for cid, spec in iter_specs(categories, exclude):
        if Platform.ANY not in spec.platforms and plat not in spec.platforms:
            results.append(
                _res(
                    spec.id,
                    host,
                    Level.SKIP,
                    f"not applicable on {plat.value}",
                )
            )
            continue
        func = CHECK_FUNCS[cid]
        try:
            results.append(func(host))
        except Exception as exc:  # never let one check break the whole audit
            results.append(
                _res(
                    spec.id,
                    host,
                    Level.INFO,
                    f"check error: {exc}",
                    "Review check implementation.",
                )
            )
    # Sort by category then id for a readable report
    results.sort(key=lambda r: (r.category, r.id))
    return results
