"""Reusable RHEL/Linux check implementations.

These helper factories return check functions that can be registered
under different control IDs by each individual benchmark (RHEL 8, 9, 10
and the STIG variants). This avoids duplicating the same logic five
times.
"""

from __future__ import annotations

import re

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from . import (
    auditctl_status,
    file_contains,
    file_perm_check,
    kmod_disabled,
    mount_option_check,
    package_missing,
    package_present,
    require_target,
    rpm_installed,
    run,
    sshd_check,
    sshd_effective,
    stat_mode,
    sysctl_equals,
    sysctl_value,
    unit_active,
    unit_enabled,
)

# ---------------------------------------------------------------- factories

def kmod_check(module: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return kmod_disabled(ctx, control, module)
    return fn


def mount_check(path: str, option: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return mount_option_check(control, ctx, path, option)
    return fn


def separate_partition_check(path: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["findmnt", "-kn", path])
        if res.rc != 0 or not res.stdout.strip():
            return make_result(control, Status.FAIL,
                               f"{path} is not a separate mount point.")
        return make_result(control, Status.PASS,
                           f"{path} is a separate mount.")
    return fn


def package_missing_check(package: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return package_missing(ctx, control, package)
    return fn


def package_present_check(package: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return package_present(ctx, control, package)
    return fn


def service_disabled_check(unit: str, *, also_check_packages: list[str] | None = None):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        if also_check_packages:
            installed = any(rpm_installed(ctx, p) for p in also_check_packages)
            if not installed:
                return make_result(control, Status.PASS,
                                   f"{', '.join(also_check_packages)} not installed.")
        if unit_active(ctx, unit) or unit_enabled(ctx, unit):
            return make_result(control, Status.FAIL,
                               f"{unit} is active or enabled.")
        return make_result(control, Status.PASS, f"{unit} is disabled or absent.")
    return fn


def service_enabled_check(unit: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        en = unit_enabled(ctx, unit)
        ac = unit_active(ctx, unit)
        if en and ac:
            return make_result(control, Status.PASS, f"{unit} is enabled and active.")
        return make_result(control, Status.FAIL,
                           f"{unit} enabled={en}, active={ac}")
    return fn


def sysctl_check(key: str, want: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return sysctl_equals(ctx, control, key, want)
    return fn


def file_perm(path: str, *, max_mode: str = "644",
              owner: str = "root", group: str = "root"):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return file_perm_check(ctx, control, path,
                               max_mode=max_mode, owner=owner, group=group)
    return fn


def sshd_param(key: str, want):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        cfg = sshd_effective(ctx)
        return sshd_check(control, cfg, key, want)
    return fn


def sshd_int_max(key: str, max_val: int):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        cfg = sshd_effective(ctx)
        if not cfg:
            return make_result(control, Status.MANUAL,
                               "Could not read sshd effective config (sshd -T).")
        raw = cfg.get(key.lower(), "")
        try:
            val = int(raw.split()[0])
        except (ValueError, IndexError):
            return make_result(control, Status.MANUAL,
                               f"Could not parse sshd {key}={raw}.")
        if val <= max_val:
            return make_result(control, Status.PASS, f"sshd {key}={val} (<= {max_val}).")
        return make_result(control, Status.FAIL, f"sshd {key}={val} (> {max_val}).")
    return fn


# ---------------------------------------------------------------- selinux

def selinux_installed():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        if rpm_installed(ctx, "libselinux"):
            return make_result(control, Status.PASS, "libselinux is installed.")
        return make_result(control, Status.FAIL, "libselinux is not installed.")
    return fn


def selinux_enforcing():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["getenforce"], timeout=10.0)
        out = (res.stdout or "").strip()
        if out == "Enforcing":
            return make_result(control, Status.PASS, "SELinux is Enforcing.")
        return make_result(control, Status.FAIL, f"getenforce={out or '(no output)'}")
    return fn


def selinux_policy_targeted():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["sestatus"], timeout=10.0)
        if "Loaded policy name" in res.stdout:
            line = next((ln for ln in res.stdout.splitlines()
                         if "Loaded policy name" in ln), "")
            policy = line.split(":", 1)[-1].strip()
            if policy in ("targeted", "mls"):
                return make_result(control, Status.PASS, f"policy={policy}")
            return make_result(control, Status.FAIL, f"policy={policy}")
        return make_result(control, Status.MANUAL, "Could not read sestatus output.")
    return fn


def selinux_not_disabled_in_bootloader():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -E 'selinux=0|enforcing=0' /boot/grub2/grub.cfg "
                        "/boot/grub2/grubenv /etc/default/grub 2>/dev/null"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               "selinux=0 or enforcing=0 present in bootloader configuration.",
                               evidence=[{"output": res.stdout.strip()[:500]}])
        return make_result(control, Status.PASS,
                           "No selinux=0/enforcing=0 in bootloader configuration.")
    return fn


# ---------------------------------------------------------------- crypto policy

def crypto_policy_min(min_policies: tuple[str, ...] = ("FUTURE", "FIPS")):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["update-crypto-policies", "--show"], timeout=10.0)
        out = (res.stdout or "").strip()
        if not out:
            return make_result(control, Status.MANUAL, "Could not read crypto policy.")
        # Some systems return e.g. 'DEFAULT:NO-SHA1'
        head = out.split(":")[0].upper()
        if head in min_policies:
            return make_result(control, Status.PASS, f"crypto-policy={out}")
        return make_result(control, Status.FAIL, f"crypto-policy={out}")
    return fn


def crypto_policy_no_sha1():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["update-crypto-policies", "--show"], timeout=10.0)
        out = (res.stdout or "").strip().upper()
        if "NO-SHA1" in out or "FIPS" in out or "FUTURE" in out:
            return make_result(control, Status.PASS, f"crypto-policy disables SHA-1 ({out}).")
        return make_result(control, Status.FAIL, f"crypto-policy={out}")
    return fn


# ---------------------------------------------------------------- banners

def banner_file_check(path: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        info = stat_mode(ctx, path)
        if info is None:
            return make_result(control, Status.FAIL, f"{path} not present.")
        # Should not contain OS version information leaks (\m, \r, \s, \v).
        res = run(ctx, ["grep", "-Eq", r"(\\v|\\r|\\m|\\s|\\Os|\\os)", path],
                  timeout=10.0)
        if res.rc == 0:
            return make_result(control, Status.FAIL,
                               f"{path} discloses OS information (escape sequences).")
        return make_result(control, Status.PASS, f"{path} present and free of OS info.")
    return fn


# ---------------------------------------------------------------- updates

def updates_installed():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["dnf", "-q", "check-update"], timeout=120.0)
        # rc == 0 => no updates; rc == 100 => updates available.
        if res.rc == 0:
            return make_result(control, Status.PASS,
                               "dnf check-update reports no pending updates.")
        if res.rc == 100:
            count = sum(1 for ln in res.stdout.splitlines()
                        if ln.strip() and not ln.startswith(("Last metadata", "Obsoleting")))
            return make_result(control, Status.FAIL,
                               f"{count} package update(s) pending.")
        return make_result(control, Status.MANUAL,
                           f"dnf check-update rc={res.rc}: {res.stderr.strip()[:300]}")
    return fn


# ---------------------------------------------------------------- gpgcheck

def gpgcheck_global():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        if file_contains(ctx, "/etc/dnf/dnf.conf", r"^\s*gpgcheck\s*=\s*1"):
            return make_result(control, Status.PASS, "gpgcheck=1 in /etc/dnf/dnf.conf.")
        return make_result(control, Status.FAIL,
                           "gpgcheck not set to 1 in /etc/dnf/dnf.conf.")
    return fn


def repo_gpgcheck_global():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        if file_contains(ctx, "/etc/dnf/dnf.conf", r"^\s*repo_gpgcheck\s*=\s*1"):
            return make_result(control, Status.PASS,
                               "repo_gpgcheck=1 in /etc/dnf/dnf.conf.")
        return make_result(control, Status.FAIL,
                           "repo_gpgcheck not enabled.")
    return fn


# ---------------------------------------------------------------- bootloader

def bootloader_password():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -Eq '^GRUB2_PASSWORD|^password_pbkdf2' "
                        "/boot/grub2/user.cfg /boot/grub2/grub.cfg "
                        "/etc/grub.d/* 2>/dev/null"])
        if res.rc == 0:
            return make_result(control, Status.PASS, "GRUB password is set.")
        return make_result(control, Status.FAIL, "No GRUB password is set.")
    return fn


def bootloader_perms():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return file_perm_check(ctx, control, "/boot/grub2/grub.cfg",
                               max_mode="600", owner="root", group="root")
    return fn


# ---------------------------------------------------------------- core dumps

def core_dumps_restricted():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -E '\\* hard core' /etc/security/limits.conf "
                        "/etc/security/limits.d/*.conf 2>/dev/null"])
        kp = sysctl_value(ctx, "fs.suid_dumpable")
        if "* hard core 0" in res.stdout and kp == "0":
            return make_result(control, Status.PASS,
                               "Core dumps restricted (limits + sysctl).")
        return make_result(control, Status.FAIL,
                           f"limits='{res.stdout.strip() or '(none)'}'  sysctl fs.suid_dumpable={kp}")
    return fn


# ---------------------------------------------------------------- auditd

def auditd_installed():
    return package_present_check("audit")


def auditd_enabled():
    return service_enabled_check("auditd")


def audit_grub_arg():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -E '^\\s*GRUB_CMDLINE_LINUX' /etc/default/grub 2>/dev/null"])
        if "audit=1" in res.stdout:
            return make_result(control, Status.PASS,
                               "audit=1 set in GRUB_CMDLINE_LINUX.")
        return make_result(control, Status.FAIL,
                           "audit=1 not set in GRUB_CMDLINE_LINUX.")
    return fn


def audit_backlog_limit():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        st = auditctl_status(ctx)
        if st is None:
            return make_result(control, Status.MANUAL, "auditctl unavailable.")
        try:
            v = int(st.get("backlog_limit", "0"))
        except ValueError:
            v = 0
        if v >= 8192:
            return make_result(control, Status.PASS, f"backlog_limit={v}")
        return make_result(control, Status.FAIL, f"backlog_limit={v} (< 8192)")
    return fn


# ---------------------------------------------------------------- rsyslog

def rsyslog_installed():
    return package_present_check("rsyslog")


def rsyslog_enabled():
    return service_enabled_check("rsyslog")


# ---------------------------------------------------------------- chrony

def chrony_in_use():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        if not rpm_installed(ctx, "chrony"):
            return make_result(control, Status.FAIL, "chrony is not installed.")
        if unit_active(ctx, "chronyd") and unit_enabled(ctx, "chronyd"):
            return make_result(control, Status.PASS,
                               "chronyd is enabled and active.")
        return make_result(control, Status.FAIL,
                           "chronyd is not enabled+active.")
    return fn


# ---------------------------------------------------------------- sudo

def sudo_use_pty():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -REi '^Defaults\\s+(.*\\s)?use_pty' "
                        "/etc/sudoers /etc/sudoers.d 2>/dev/null"])
        if res.stdout.strip():
            return make_result(control, Status.PASS, "Defaults use_pty set.")
        return make_result(control, Status.FAIL, "Defaults use_pty not set.")
    return fn


def sudo_log_file():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -REi '^Defaults\\s+.*logfile=' "
                        "/etc/sudoers /etc/sudoers.d 2>/dev/null"])
        if res.stdout.strip():
            return make_result(control, Status.PASS,
                               "Defaults logfile= configured.")
        return make_result(control, Status.FAIL, "No sudo logfile= directive.")
    return fn


def sudo_no_nopasswd():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -REi '^[^#]*\\bNOPASSWD\\b' "
                        "/etc/sudoers /etc/sudoers.d 2>/dev/null"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               "NOPASSWD directive(s) present.",
                               evidence=[{"output": res.stdout.strip()[:500]}])
        return make_result(control, Status.PASS, "No NOPASSWD directives.")
    return fn


def sudo_no_authenticate_disabled():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -REi '^[^#]*\\b!authenticate\\b' "
                        "/etc/sudoers /etc/sudoers.d 2>/dev/null"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL, "!authenticate present.")
        return make_result(control, Status.PASS, "Re-authentication required.")
    return fn


def sudo_timestamp_timeout():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -RE 'timestamp_timeout' /etc/sudoers /etc/sudoers.d 2>/dev/null"])
        if not res.stdout.strip():
            return make_result(control, Status.FAIL,
                               "timestamp_timeout not configured.")
        m = re.search(r"timestamp_timeout=(-?\d+)", res.stdout)
        if not m:
            return make_result(control, Status.MANUAL,
                               f"Could not parse: {res.stdout.strip()[:200]}")
        v = int(m.group(1))
        if 0 <= v <= 15:
            return make_result(control, Status.PASS, f"timestamp_timeout={v}")
        return make_result(control, Status.FAIL,
                           f"timestamp_timeout={v} (must be 0..15)")
    return fn


def su_restricted():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -E '^auth\\s+required\\s+pam_wheel.so' /etc/pam.d/su"])
        if "use_uid" in res.stdout and "group=" in res.stdout:
            return make_result(control, Status.PASS,
                               "pam_wheel.so use_uid group=... configured.")
        return make_result(control, Status.FAIL,
                           "pam_wheel.so not configured for /etc/pam.d/su.")
    return fn


# ---------------------------------------------------------------- pam

def password_min_length(min_len: int = 14):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -E '^minlen' /etc/security/pwquality.conf "
                        "/etc/security/pwquality.conf.d/*.conf 2>/dev/null"])
        m = re.search(r"minlen\s*=\s*(\d+)", res.stdout)
        if m and int(m.group(1)) >= min_len:
            return make_result(control, Status.PASS, f"minlen={m.group(1)}")
        return make_result(control, Status.FAIL,
                           f"minlen={m.group(1) if m else '(unset)'} (want >= {min_len})")
    return fn


def password_lockout():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -REi 'pam_faillock' /etc/pam.d/system-auth /etc/pam.d/password-auth "
                        "/etc/security/faillock.conf 2>/dev/null"])
        if "deny" in res.stdout and "unlock_time" in res.stdout:
            return make_result(control, Status.PASS, "pam_faillock configured.")
        return make_result(control, Status.FAIL, "pam_faillock not configured.")
    return fn


def password_reuse():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -RE 'pam_(unix|pwhistory).*remember' "
                        "/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/security/pwhistory.conf "
                        "2>/dev/null"])
        m = re.search(r"remember\s*=?\s*(\d+)", res.stdout)
        if m and int(m.group(1)) >= 5:
            return make_result(control, Status.PASS, f"remember={m.group(1)}")
        return make_result(control, Status.FAIL,
                           f"remember={m.group(1) if m else '(unset)'} (want >= 5)")
    return fn


def password_hash_strong():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -REi 'pam_unix.so.*(sha512|yescrypt)' /etc/pam.d/ 2>/dev/null"])
        if res.stdout.strip():
            return make_result(control, Status.PASS,
                               "pam_unix uses sha512 or yescrypt.")
        return make_result(control, Status.FAIL,
                           "pam_unix does not use sha512/yescrypt.")
    return fn


# ---------------------------------------------------------------- /etc/login.defs

def login_defs_value(key: str):
    def get(ctx: Context) -> str | None:
        res = run(ctx, ["/bin/sh", "-c",
                        f"awk '/^{key}\\b/ {{print $2}}' /etc/login.defs"])
        out = (res.stdout or "").strip()
        return out or None
    return get


def password_max_days(max_days: int = 365):
    get = login_defs_value("PASS_MAX_DAYS")

    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        v = get(ctx)
        if v is None:
            return make_result(control, Status.MANUAL, "PASS_MAX_DAYS not set.")
        try:
            iv = int(v)
        except ValueError:
            return make_result(control, Status.MANUAL, f"PASS_MAX_DAYS={v}")
        if iv <= max_days:
            return make_result(control, Status.PASS, f"PASS_MAX_DAYS={iv}")
        return make_result(control, Status.FAIL, f"PASS_MAX_DAYS={iv} (>{max_days})")
    return fn


def password_min_days(min_days: int = 1):
    get = login_defs_value("PASS_MIN_DAYS")

    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        v = get(ctx)
        if v is None:
            return make_result(control, Status.MANUAL, "PASS_MIN_DAYS not set.")
        try:
            iv = int(v)
        except ValueError:
            return make_result(control, Status.MANUAL, f"PASS_MIN_DAYS={v}")
        if iv >= min_days:
            return make_result(control, Status.PASS, f"PASS_MIN_DAYS={iv}")
        return make_result(control, Status.FAIL, f"PASS_MIN_DAYS={iv} (<{min_days})")
    return fn


def password_warn_age(min_warn: int = 7):
    get = login_defs_value("PASS_WARN_AGE")

    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        v = get(ctx)
        if v is None:
            return make_result(control, Status.MANUAL, "PASS_WARN_AGE not set.")
        try:
            iv = int(v)
        except ValueError:
            return make_result(control, Status.MANUAL, f"PASS_WARN_AGE={v}")
        if iv >= min_warn:
            return make_result(control, Status.PASS, f"PASS_WARN_AGE={iv}")
        return make_result(control, Status.FAIL, f"PASS_WARN_AGE={iv} (<{min_warn})")
    return fn


def umask_restrictive(max_umask: str = "027"):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "grep -E '^\\s*UMASK\\s+' /etc/login.defs 2>/dev/null"])
        m = re.search(r"UMASK\s+(\d+)", res.stdout)
        if not m:
            return make_result(control, Status.MANUAL, "UMASK not set in /etc/login.defs.")
        try:
            if int(m.group(1), 8) >= int(max_umask, 8):
                return make_result(control, Status.PASS, f"UMASK={m.group(1)}")
        except ValueError:
            pass
        return make_result(control, Status.FAIL,
                           f"UMASK={m.group(1)} (want >= {max_umask})")
    return fn


def root_only_uid_zero():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "awk -F: '($3 == 0) {print $1}' /etc/passwd"])
        users = [u for u in res.stdout.split() if u]
        if users == ["root"]:
            return make_result(control, Status.PASS, "Only root has UID 0.")
        return make_result(control, Status.FAIL,
                           f"UID 0 accounts: {', '.join(users) or '(none)'}")
    return fn


def shadowed_passwords():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "awk -F: '($2 != \"x\") {print $1\":\"$2}' /etc/passwd"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               "Some accounts in /etc/passwd are not shadowed.",
                               evidence=[{"output": res.stdout[:500]}])
        return make_result(control, Status.PASS,
                           "All accounts use shadowed passwords.")
    return fn


def no_empty_shadow_pw():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               "Accounts with empty password fields found.",
                               evidence=[{"output": res.stdout[:500]}])
        return make_result(control, Status.PASS,
                           "No empty password fields in /etc/shadow.")
    return fn


def no_world_writable():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | "
                        "xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | head -50"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               "World-writable files found.",
                               evidence=[{"paths": res.stdout.strip().splitlines()[:30]}])
        return make_result(control, Status.PASS, "No world-writable files found.")
    return fn


def no_unowned_files():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | "
                        "xargs -I '{}' find '{}' -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -50"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               "Unowned/ungrouped files found.",
                               evidence=[{"paths": res.stdout.strip().splitlines()[:30]}])
        return make_result(control, Status.PASS, "No unowned/ungrouped files found.")
    return fn


def duplicate_uids():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "cut -d: -f3 /etc/passwd | sort | uniq -d"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               f"Duplicate UIDs: {res.stdout.strip()}")
        return make_result(control, Status.PASS, "No duplicate UIDs.")
    return fn


def duplicate_gids():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "cut -d: -f3 /etc/group | sort | uniq -d"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               f"Duplicate GIDs: {res.stdout.strip()}")
        return make_result(control, Status.PASS, "No duplicate GIDs.")
    return fn


def duplicate_user_names():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "cut -d: -f1 /etc/passwd | sort | uniq -d"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               f"Duplicate user names: {res.stdout.strip()}")
        return make_result(control, Status.PASS, "No duplicate user names.")
    return fn


def duplicate_group_names():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "cut -d: -f1 /etc/group | sort | uniq -d"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               f"Duplicate group names: {res.stdout.strip()}")
        return make_result(control, Status.PASS, "No duplicate group names.")
    return fn


def passwd_groups_exist():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["/bin/sh", "-c",
                        "for g in $(cut -d: -f4 /etc/passwd | sort -u); "
                        "do grep -q \"^[^:]*:[^:]*:$g:\" /etc/group || echo missing-gid:$g; done"])
        if res.stdout.strip():
            return make_result(control, Status.FAIL,
                               "Some users reference undefined groups.",
                               evidence=[{"output": res.stdout[:500]}])
        return make_result(control, Status.PASS,
                           "All /etc/passwd primary groups exist in /etc/group.")
    return fn
