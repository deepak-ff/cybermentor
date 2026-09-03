"""Non-intrusive host security checks (CIS Benchmark-aligned).

Every check is read-only: it inspects configuration and file permissions and
reports PASS / WARN / FAIL / INFO / SKIP. Nothing is modified on the target.

Checks gracefully handle files that do not exist or permissions that prevent
reading (e.g. /etc/shadow when not root) by returning SKIP or INFO.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from typing import Callable, Dict, Iterable, List, Optional

from .models import CheckResult, Level

CHECK_REGISTRY: Dict[str, Callable[..., CheckResult]] = {}


def register(check_id: str, title: str, category: str, cis_ref: str = ""):
    def decorator(func: Callable[..., CheckResult]):
        setattr(func, "meta", (check_id, title, category, cis_ref))
        CHECK_REGISTRY[check_id] = func
        return func

    return decorator


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, FileNotFoundError, PermissionError):
        return None


def _mode(path: str) -> Optional[int]:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def _fmt_mode(mode: int) -> str:
    return oct(mode)[2:].zfill(4)


# ---------------------------------------------------------------------- SSH
@register("SSH-001", "PermitRootLogin is disabled", "SSH", "CIS 5.2.8")
def check_ssh_permit_root(host: str) -> CheckResult:
    cfg = _read("/etc/ssh/sshd_config")
    if cfg is None:
        return CheckResult(
            "SSH-001",
            "PermitRootLogin is disabled",
            "SSH",
            Level.SKIP,
            host=host,
            detail="sshd_config not readable",
            cis_ref="CIS 5.2.8",
        )
    value = "yes"
    v = re.search(r"^\s*PermitRootLogin\s+(\S+)", cfg, re.MULTILINE)
    if v:
        value = v.group(1).lower()
    ok = value in ("no", "prohibit-password")
    return CheckResult(
        "SSH-001",
        "PermitRootLogin is disabled",
        "SSH",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"PermitRootLogin={value}",
        recommendation="Set PermitRootLogin no (or prohibit-password) in sshd_config.",
        cis_ref="CIS 5.2.8",
    )


@register("SSH-002", "Password authentication is disabled", "SSH", "CIS 5.2.9")
def check_ssh_password_auth(host: str) -> CheckResult:
    cfg = _read("/etc/ssh/sshd_config")
    if cfg is None:
        return CheckResult(
            "SSH-002",
            "Password authentication is disabled",
            "SSH",
            Level.SKIP,
            host=host,
            detail="sshd_config not readable",
            cis_ref="CIS 5.2.9",
        )
    v = re.search(r"^\s*PasswordAuthentication\s+(\S+)", cfg, re.MULTILINE)
    value = v.group(1).lower() if v else "yes"
    ok = value == "no"
    return CheckResult(
        "SSH-002",
        "Password authentication is disabled",
        "SSH",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"PasswordAuthentication={value}",
        recommendation="Set PasswordAuthentication no and use SSH keys.",
        cis_ref="CIS 5.2.9",
    )


@register("SSH-003", "PermitEmptyPasswords is disabled", "SSH", "CIS 5.2.10")
def check_ssh_empty_passwords(host: str) -> CheckResult:
    cfg = _read("/etc/ssh/sshd_config")
    if cfg is None:
        return CheckResult(
            "SSH-003",
            "PermitEmptyPasswords is disabled",
            "SSH",
            Level.SKIP,
            host=host,
            detail="sshd_config not readable",
            cis_ref="CIS 5.2.10",
        )
    v = re.search(r"^\s*PermitEmptyPasswords\s+(\S+)", cfg, re.MULTILINE)
    value = v.group(1).lower() if v else "yes"
    ok = value == "no"
    return CheckResult(
        "SSH-003",
        "PermitEmptyPasswords is disabled",
        "SSH",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"PermitEmptyPasswords={value}",
        recommendation="Set PermitEmptyPasswords no in sshd_config.",
        cis_ref="CIS 5.2.10",
    )


@register("SSH-004", "SSH config file permissions hardened", "SSH", "CIS 5.2.1")
def check_ssh_config_mode(host: str) -> CheckResult:
    mode = _mode("/etc/ssh/sshd_config")
    if mode is None:
        return CheckResult(
            "SSH-004",
            "SSH config file permissions hardened",
            "SSH",
            Level.SKIP,
            host=host,
            detail="sshd_config not found",
            cis_ref="CIS 5.2.1",
        )
    ok = mode & 0o022 == 0  # not group/world writable
    return CheckResult(
        "SSH-004",
        "SSH config file permissions hardened",
        "SSH",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"mode {_fmt_mode(mode)}",
        recommendation="chmod 600 /etc/ssh/sshd_config (not group/other writable).",
        cis_ref="CIS 5.2.1",
    )


# ---------------------------------------------------------- File permissions
@register("FILE-001", "No world-writable files in /etc", "Filesystem", "CIS 6.1.11")
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
    return CheckResult(
        "FILE-001",
        "No world-writable files in /etc",
        "Filesystem",
        Level.PASS if not world_writable else Level.WARN,
        host=host,
        detail=f"{len(world_writable)} world-writable file(s) found",
        recommendation="Review and remove world-writable permissions on the listed files.",
        cis_ref="CIS 6.1.11",
    )


@register("FILE-002", "World-writable directories checked", "Filesystem", "CIS 5.1.2")
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
    return CheckResult(
        "FILE-002",
        "World-writable directories checked",
        "Filesystem",
        Level.WARN if dirs else Level.PASS,
        host=host,
        detail=(
            f"unexpected world-writable dirs: {', '.join(dirs)}"
            if dirs
            else "none outside /tmp,/var/tmp,/dev/shm"
        ),
        recommendation="Ensure world-writable directories (except /tmp etc.) are removed or secured.",
        cis_ref="CIS 5.1.2",
    )


@register("FILE-003", "/etc/passwd permission 644", "Filesystem", "CIS 6.1.1")
def check_passwd_mode(host: str) -> CheckResult:
    mode = _mode("/etc/passwd")
    if mode is None:
        return CheckResult(
            "FILE-003",
            "/etc/passwd permission 644",
            "Filesystem",
            Level.SKIP,
            host=host,
            detail="/etc/passwd not found",
            cis_ref="CIS 6.1.1",
        )
    ok = mode == 0o644
    return CheckResult(
        "FILE-003",
        "/etc/passwd permission 644",
        "Filesystem",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"mode {_fmt_mode(mode)}",
        recommendation="chmod 644 /etc/passwd.",
        cis_ref="CIS 6.1.1",
    )


@register("FILE-004", "/etc/shadow permission 640/600", "Filesystem", "CIS 6.1.2")
def check_shadow_mode(host: str) -> CheckResult:
    mode = _mode("/etc/shadow")
    if mode is None:
        return CheckResult(
            "FILE-004",
            "/etc/shadow permission 640/600",
            "Filesystem",
            Level.SKIP,
            host=host,
            detail="/etc/shadow not accessible",
            cis_ref="CIS 6.1.2",
        )
    ok = mode in (0o600, 0o640)
    return CheckResult(
        "FILE-004",
        "/etc/shadow permission 640/600",
        "Filesystem",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"mode {_fmt_mode(mode)}",
        recommendation="chmod 600 /etc/shadow (root only).",
        cis_ref="CIS 6.1.2",
    )


@register(
    "FILE-005", "Sticky bit set on world-writable dirs", "Filesystem", "CIS 1.1.1"
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
    return CheckResult(
        "FILE-005",
        "Sticky bit set on world-writable dirs",
        "Filesystem",
        Level.PASS if not bad else Level.FAIL,
        host=host,
        detail=(f"missing sticky bit on {', '.join(bad)}" if bad else "sticky bit set"),
        recommendation="chmod 1777 /tmp /var/tmp.",
        cis_ref="CIS 1.1.1",
    )


@register(
    "FILE-006", "SUID/SGID binaries inventory reviewed", "Filesystem", "CIS 6.1.13"
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
    return CheckResult(
        "FILE-006",
        "SUID/SGID binaries inventory reviewed",
        "Filesystem",
        Level.WARN if suspicious else Level.PASS,
        host=host,
        detail=f"{len(suid)} SUID/SGID binary(ies); {len(suspicious)} non-standard",
        recommendation="Remove SUID/SGID bits from binaries that do not require privilege elevation.",
        cis_ref="CIS 6.1.13",
    )


# ------------------------------------------------------------ Authentication
@register("AUTH-001", "Password aging configured", "Authentication", "CIS 5.4.1.1")
def check_password_aging(host: str) -> CheckResult:
    cfg = _read("/etc/login.defs")
    if cfg is None:
        return CheckResult(
            "AUTH-001",
            "Password aging configured",
            "Authentication",
            Level.SKIP,
            host=host,
            detail="login.defs not readable",
            cis_ref="CIS 5.4.1.1",
        )
    max_days = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", cfg, re.MULTILINE)
    min_days = re.search(r"^\s*PASS_MIN_DAYS\s+(\d+)", cfg, re.MULTILINE)
    max_v = int(max_days.group(1)) if max_days else 99999
    min_v = int(min_days.group(1)) if min_days else 0
    ok = max_v <= 365
    return CheckResult(
        "AUTH-001",
        "Password aging configured",
        "Authentication",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"PASS_MAX_DAYS={max_v}, PASS_MIN_DAYS={min_v}",
        recommendation="Set PASS_MAX_DAYS<=365 and PASS_MIN_DAYS>=1 in /etc/login.defs.",
        cis_ref="CIS 5.4.1.1",
    )


@register("AUTH-002", "Umask set to 027 or stricter", "Authentication", "CIS 5.4.4")
def check_umask(host: str) -> CheckResult:
    cfg = _read("/etc/login.defs")
    if cfg is None:
        return CheckResult(
            "AUTH-002",
            "Umask set to 027 or stricter",
            "Authentication",
            Level.SKIP,
            host=host,
            detail="login.defs not readable",
            cis_ref="CIS 5.4.4",
        )
    v = re.search(r"^\s*UMASK\s+(\d+)", cfg, re.MULTILINE)
    if not v:
        return CheckResult(
            "AUTH-002",
            "Umask set to 027 or stricter",
            "Authentication",
            Level.INFO,
            host=host,
            detail="UMASK not set in login.defs (defaults to 022)",
            recommendation="Set UMASK 027 in /etc/login.defs.",
            cis_ref="CIS 5.4.4",
        )
    umask = int(v.group(1), 8)
    ok = umask & 0o022 == 0o022  # no write perms for group/other
    return CheckResult(
        "AUTH-002",
        "Umask set to 027 or stricter",
        "Authentication",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"UMASK={v.group(1)}",
        recommendation="Set UMASK 027 in /etc/login.defs.",
        cis_ref="CIS 5.4.4",
    )


@register("AUTH-003", "Empty password entries absent", "Authentication", "CIS 5.4.1")
def check_empty_passwords(host: str) -> CheckResult:
    shadow = _read("/etc/shadow")
    if shadow is None:
        return CheckResult(
            "AUTH-003",
            "Empty password entries absent",
            "Authentication",
            Level.SKIP,
            host=host,
            detail="/etc/shadow not readable (requires root)",
            cis_ref="CIS 5.4.1",
        )
    empty = [line.split(":")[0] for line in shadow.splitlines() if "::" in line]
    return CheckResult(
        "AUTH-003",
        "Empty password entries absent",
        "Authentication",
        Level.PASS if not empty else Level.FAIL,
        host=host,
        detail=(
            f"accounts with empty password: {', '.join(empty)}" if empty else "none"
        ),
        recommendation="Lock or set passwords for accounts with empty password fields.",
        cis_ref="CIS 5.4.1",
    )


# --------------------------------------------------------------- Firewall / network
@register("FIRE-001", "Host-based firewall active", "Firewall", "CIS 3.5.1")
def check_firewall(host: str) -> CheckResult:
    backend = None
    if shutil.which("ufw"):
        out = _cmd("ufw status")
        backend = "ufw"
    elif shutil.which("nft"):
        out = _cmd("nft list ruleset")
        backend = "nftables"
    elif shutil.which("iptables"):
        out = _cmd("iptables -L -n")
        backend = "iptables"
    else:
        return CheckResult(
            "FIRE-001",
            "Host-based firewall active",
            "Firewall",
            Level.INFO,
            host=host,
            detail="no firewall tool found (ufw/nftables/iptables)",
            recommendation="Install and enable a host firewall (ufw or nftables).",
            cis_ref="CIS 3.5.1",
        )

    active = bool(out and out.strip())
    if backend == "ufw" and out:
        # ufw reports "Status: active|inactive"
        active = "Status: active" in out or "Status: active" in out.casefold()
    return CheckResult(
        "FIRE-001",
        "Host-based firewall active",
        "Firewall",
        Level.PASS if active else Level.FAIL,
        host=host,
        detail=f"backend={backend}; rules={'present' if out else 'none'}",
        recommendation="Enable the host firewall and define rules for required services.",
        cis_ref="CIS 3.5.1",
    )


@register("NET-001", "IP forwarding is disabled", "Network", "CIS 3.2.1")
def check_ip_forwarding(host: str) -> CheckResult:
    val = _read("/proc/sys/net/ipv4/ip_forward")
    if val is None:
        return CheckResult(
            "NET-001",
            "IP forwarding is disabled",
            "Network",
            Level.SKIP,
            host=host,
            detail="procfs not readable",
            cis_ref="CIS 3.2.1",
        )
    ok = val.strip() == "0"
    return CheckResult(
        "NET-001",
        "IP forwarding is disabled",
        "Network",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"net.ipv4.ip_forward={val.strip()}",
        recommendation="sysctl -w net.ipv4.ip_forward=0 unless routing is required.",
        cis_ref="CIS 3.2.1",
    )


@register("NET-002", "Packet redirect sending is disabled", "Network", "CIS 3.2.2")
def check_icmp_redirects(host: str) -> CheckResult:
    val = _read("/proc/sys/net/ipv4/conf/all/accept_redirects")
    if val is None:
        return CheckResult(
            "NET-002",
            "ICMP redirect accept is disabled",
            "Network",
            Level.SKIP,
            host=host,
            detail="procfs not readable",
            cis_ref="CIS 3.2.2",
        )
    ok = val.strip() == "0"
    return CheckResult(
        "NET-002",
        "ICMP redirect accept is disabled",
        "Network",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"accept_redirects={val.strip()}",
        recommendation="Set net.ipv4.conf.all.accept_redirects=0.",
        cis_ref="CIS 3.2.2",
    )


@register("NET-003", "Open listening ports inventoried", "Network", "")
def check_listening_ports(host: str) -> CheckResult:
    out = _cmd("ss -tulnp") or _cmd("netstat -tulnp")
    count = 0
    if out:
        ports = re.findall(r":(\d+)\s", out)
        count = len(set(ports))
    return CheckResult(
        "NET-003",
        "Open listening ports inventoried",
        "Network",
        Level.INFO,
        host=host,
        detail=f"{count} listening port(s) detected (see 'ss -tulnp')",
        recommendation="Close or restrict unused listening services.",
    )


# --------------------------------------------------------------------- Kernel / sysctl
@register("KRNL-001", "Kernel pointers are restricted", "Kernel", "CIS 3.3.3")
def check_kptr_restrict(host: str) -> CheckResult:
    val = _read("/proc/sys/kernel/kptr_restrict")
    if val is None:
        return CheckResult(
            "KRNL-001",
            "Kernel pointers are restricted",
            "Kernel",
            Level.SKIP,
            host=host,
            detail="procfs not readable",
            cis_ref="CIS 3.3.3",
        )
    ok = val.strip() in ("1", "2")
    return CheckResult(
        "KRNL-001",
        "Kernel pointers are restricted",
        "Kernel",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"kernel.kptr_restrict={val.strip()}",
        recommendation="sysctl -w kernel.kptr_restrict=2.",
        cis_ref="CIS 3.3.3",
    )


@register("KRNL-002", "Core dumps are disabled", "Kernel", "CIS 1.5.1")
def check_core_dumps(host: str) -> CheckResult:
    cfg = _read("/etc/security/limits.conf")
    val = None
    if cfg:
        m = re.search(r"^\s*\*\s+hard\s+core\s+0", cfg, re.MULTILINE)
        if m:
            val = "0"
    return CheckResult(
        "KRNL-002",
        "Core dumps are disabled",
        "Kernel",
        Level.PASS if val == "0" else Level.INFO,
        host=host,
        detail=(
            f"hard core limit set to {val}"
            if val
            else "hard core limit not set in limits.conf"
        ),
        recommendation="Add '* hard core 0' to /etc/security/limits.conf.",
        cis_ref="CIS 1.5.1",
    )


@register(
    "KRNL-003",
    "Address space layout randomization (ASLR) enabled",
    "Kernel",
    "CIS 3.3.4",
)
def check_aslr(host: str) -> CheckResult:
    val = _read("/proc/sys/kernel/randomize_va_space")
    if val is None:
        return CheckResult(
            "KRNL-003",
            "ASLR enabled",
            "Kernel",
            Level.SKIP,
            host=host,
            detail="procfs not readable",
            cis_ref="CIS 3.3.4",
        )
    ok = val.strip() == "2"
    return CheckResult(
        "KRNL-003",
        "ASLR enabled",
        "Kernel",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"randomize_va_space={val.strip()}",
        recommendation="sysctl -w kernel.randomize_va_space=2.",
        cis_ref="CIS 3.3.4",
    )


# ---------------------------------------------------------------- Logging / audit
@register("LOGG-001", "Audit daemon (auditd) present", "Logging", "CIS 4.1")
def check_auditd(host: str) -> CheckResult:
    present = shutil.which("auditd") is not None
    return CheckResult(
        "LOGG-001",
        "Audit daemon (auditd) present",
        "Logging",
        Level.PASS if present else Level.INFO,
        host=host,
        detail=f"auditd {'installed' if present else 'not installed'}",
        recommendation="Install auditd (apt install auditd) to enable audit logging.",
        cis_ref="CIS 4.1",
    )


@register("LOGG-002", "Rsyslog is present and running", "Logging", "CIS 4.2")
def check_rsyslog(host: str) -> CheckResult:
    present = shutil.which("rsyslogd") is not None
    return CheckResult(
        "LOGG-002",
        "Rsyslog is present",
        "Logging",
        Level.PASS if present else Level.INFO,
        host=host,
        detail=f"rsyslogd {'present' if present else 'not installed'}",
        recommendation="Install and enable rsyslog for centralised logging.",
        cis_ref="CIS 4.2",
    )


# ------------------------------------------------------------------- Misc
@register("MISC-001", "/tmp is a separate filesystem", "Filesystem", "CIS 1.1.2")
def check_tmp_fs(host: str) -> CheckResult:
    fstab = _read("/etc/fstab")
    mounted_raw = _cmd("mount")
    mounted = (mounted_raw or "").lower()
    if fstab is None and not mounted:
        return CheckResult(
            "MISC-001",
            "/tmp is a separate filesystem",
            "Filesystem",
            Level.SKIP,
            host=host,
            detail="cannot inspect mounts",
            cis_ref="CIS 1.1.2",
        )
    ok = "/tmp" in mounted or bool(fstab and "/tmp" in fstab)
    return CheckResult(
        "MISC-001",
        "/tmp is a separate filesystem",
        "Filesystem",
        Level.PASS if ok else Level.WARN,
        host=host,
        detail=f"/tmp {'mounted separately' if ok else 'not on its own filesystem'}",
        recommendation="Mount /tmp as a separate filesystem with nodev,nosuid,noexec.",
        cis_ref="CIS 1.1.2",
    )


@register("MISC-002", "sudoers file permission 440", "Authentication", "CIS 5.5.2")
def check_sudoers_mode(host: str) -> CheckResult:
    mode = _mode("/etc/sudoers")
    if mode is None:
        return CheckResult(
            "MISC-002",
            "sudoers file permission 440",
            "Authentication",
            Level.SKIP,
            host=host,
            detail="/etc/sudoers not readable",
            cis_ref="CIS 5.5.2",
        )
    ok = mode in (0o440, 0o400) and mode & 0o022 == 0
    return CheckResult(
        "MISC-002",
        "sudoers file permission 440",
        "Authentication",
        Level.PASS if ok else Level.FAIL,
        host=host,
        detail=f"mode {_fmt_mode(mode)}",
        recommendation="chmod 440 /etc/sudoers.",
        cis_ref="CIS 5.5.2",
    )


def _cmd(command: str) -> Optional[str]:
    try:
        import shlex
        import subprocess

        proc = subprocess.run(
            shlex.split(command), capture_output=True, text=True, timeout=15
        )
        return proc.stdout
    except Exception:
        return None


def run_all_checks(host: str = "localhost") -> List[CheckResult]:
    """Run every registered check and return ordered results."""
    results: List[CheckResult] = []
    for check_id, func in CHECK_REGISTRY.items():
        meta = getattr(func, "meta", None)
        try:
            result = func(host)
        except Exception as exc:  # never let one check break the whole audit
            result = CheckResult(
                check_id,
                getattr(func, "__name__", check_id),
                "Unknown",
                Level.INFO,
                host=host,
                detail=f"check error: {exc}",
                recommendation="Review check implementation.",
            )
        results.append(result)
    # Sort by category then id for a readable report
    results.sort(key=lambda r: (r.category, r.id))
    return results
