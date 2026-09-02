"""Shared helpers for the RHEL CIS / STIG benchmark families.

These helpers all route shell commands through ``ctx.target`` so they work
identically when the app runs on the same host (LocalTarget) or against a
remote Linux machine over SSH (SshTarget).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status

log = logging.getLogger(__name__)


# ---------------------------------------------------------------- target gate

def require_target(ctx: Context, control: Control) -> CheckResult | None:
    """Return an ERROR result if no Linux target is set."""
    if ctx.target is None:
        return make_result(
            control,
            Status.ERROR,
            "No Linux target configured. Set 'Local' or an SSH host on the Connect page.",
        )
    return None


# ---------------------------------------------------------------- run helpers

def run(ctx: Context, argv: list[str], *, timeout: float = 30.0):
    return ctx.target.run(argv, timeout=timeout)


def shell(ctx: Context, command: str, *, timeout: float = 30.0):
    return ctx.target.run_shell(command, timeout=timeout)


# ---------------------------------------------------------------- packages

def rpm_installed(ctx: Context, package: str) -> bool:
    res = run(ctx, ["rpm", "-q", package], timeout=10.0)
    return res.rc == 0 and "is not installed" not in res.stdout


def package_missing(ctx: Context, control: Control, package: str) -> CheckResult:
    if rpm_installed(ctx, package):
        return make_result(control, Status.FAIL, f"{package} is installed.")
    return make_result(control, Status.PASS, f"{package} is not installed.")


def package_present(ctx: Context, control: Control, package: str) -> CheckResult:
    if rpm_installed(ctx, package):
        return make_result(control, Status.PASS, f"{package} is installed.")
    return make_result(control, Status.FAIL, f"{package} is not installed.")


# ---------------------------------------------------------------- systemd

def systemctl(ctx: Context, *args: str) -> tuple[int, str]:
    res = run(ctx, ["systemctl", *args], timeout=15.0)
    return res.rc, (res.stdout or "").strip()


def unit_enabled(ctx: Context, unit: str) -> bool:
    rc, out = systemctl(ctx, "is-enabled", unit)
    return rc == 0 and out.strip() == "enabled"


def unit_active(ctx: Context, unit: str) -> bool:
    rc, out = systemctl(ctx, "is-active", unit)
    return rc == 0 and out.strip() == "active"


def unit_masked(ctx: Context, unit: str) -> bool:
    rc, out = systemctl(ctx, "is-enabled", unit)
    return out.strip() in ("masked", "masked-runtime")


def service_should_be_disabled(ctx: Context, control: Control, unit: str) -> CheckResult:
    if not rpm_provides_unit(ctx, unit):
        return make_result(control, Status.PASS,
                           f"{unit} not installed.")
    if unit_active(ctx, unit) or unit_enabled(ctx, unit):
        return make_result(control, Status.FAIL,
                           f"{unit} is active or enabled.")
    return make_result(control, Status.PASS, f"{unit} is disabled.")


def rpm_provides_unit(ctx: Context, unit: str) -> bool:
    """True if a unit file exists on the target (best-effort)."""
    res = run(ctx, ["systemctl", "list-unit-files", unit], timeout=10.0)
    return unit in (res.stdout or "")


# ---------------------------------------------------------------- mounts

def mount_options(ctx: Context, path: str) -> set[str] | None:
    """Return the active mount options for ``path`` or None if not a mount."""
    res = run(ctx, ["findmnt", "-kn", path], timeout=10.0)
    if res.rc != 0 or not res.stdout.strip():
        return None
    parts = res.stdout.split()
    # findmnt -kn columns: TARGET SOURCE FSTYPE OPTIONS
    if len(parts) < 4:
        return None
    return {o.strip() for o in parts[3].split(",") if o.strip()}


def mount_has_option(ctx: Context, path: str, option: str) -> bool | None:
    opts = mount_options(ctx, path)
    if opts is None:
        return None
    return option in opts


def mount_option_check(control: Control, ctx: Context, path: str, option: str) -> CheckResult:
    val = mount_has_option(ctx, path, option)
    if val is None:
        return make_result(control, Status.NOT_APPLICABLE,
                           f"{path} is not a separate mount point.")
    if val:
        return make_result(control, Status.PASS,
                           f"{path} mounted with {option}.")
    return make_result(control, Status.FAIL,
                       f"{path} mount is missing the '{option}' option.")


# ---------------------------------------------------------------- kernel modules

def kmod_disabled(ctx: Context, control: Control, mod: str) -> CheckResult:
    """Pass if the module is blacklisted/disabled and not currently loaded."""
    res = run(ctx, ["/bin/sh", "-c",
                    f"modprobe -n -v {mod} 2>&1; lsmod | grep -E '^{mod}\\b'"])
    out = (res.stdout or "") + (res.stderr or "")
    loaded = bool(re.search(rf"^{mod}\b", out, re.MULTILINE))
    blacklisted = ("install /bin/false" in out) or ("install /bin/true" in out) or \
                  ("blacklist" in out.lower()) or ("not found" in out.lower())
    if not loaded and blacklisted:
        return make_result(control, Status.PASS,
                           f"{mod} is disabled and not loaded.")
    if loaded:
        return make_result(control, Status.FAIL, f"{mod} is currently loaded.")
    return make_result(control, Status.FAIL,
                       f"{mod} is not blacklisted (modprobe loadable).")


# ---------------------------------------------------------------- sysctl

def sysctl_value(ctx: Context, key: str) -> str | None:
    res = run(ctx, ["sysctl", "-n", key], timeout=10.0)
    if res.rc != 0:
        return None
    return res.stdout.strip()


def sysctl_equals(ctx: Context, control: Control, key: str, want: str) -> CheckResult:
    v = sysctl_value(ctx, key)
    if v is None:
        return make_result(control, Status.MANUAL,
                           f"Could not read sysctl {key}.")
    if v == want:
        return make_result(control, Status.PASS, f"{key} = {v}")
    return make_result(control, Status.FAIL, f"{key} = {v} (want {want})")


# ---------------------------------------------------------------- file modes

def stat_mode(ctx: Context, path: str) -> tuple[str, str, str] | None:
    """Return (octal_mode, owner, group) for ``path`` or None."""
    res = run(ctx, ["stat", "-c", "%a %U %G", path], timeout=10.0)
    if res.rc != 0 or not res.stdout.strip():
        return None
    parts = res.stdout.strip().split()
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


def file_perm_check(ctx: Context, control: Control, path: str,
                    *, max_mode: str = "644",
                    owner: str = "root", group: str = "root") -> CheckResult:
    info = stat_mode(ctx, path)
    if info is None:
        return make_result(control, Status.NOT_APPLICABLE, f"{path} not present.")
    mode, o, g = info
    issues = []
    try:
        if int(mode, 8) > int(max_mode, 8):
            issues.append(f"mode={mode} > {max_mode}")
    except ValueError:
        issues.append(f"unparseable mode {mode}")
    if owner and o != owner:
        issues.append(f"owner={o}!={owner}")
    if group and g != group:
        issues.append(f"group={g}!={group}")
    if issues:
        return make_result(control, Status.FAIL, f"{path}: {', '.join(issues)}")
    return make_result(control, Status.PASS,
                       f"{path}: {mode} {o}:{g}")


# ---------------------------------------------------------------- sshd_config

def sshd_effective(ctx: Context) -> dict[str, str]:
    """Read effective sshd config via `sshd -T`."""
    res = run(ctx, ["sshd", "-T"], timeout=15.0)
    out: dict[str, str] = {}
    if res.rc != 0:
        # Try sudo as a fallback - sshd -T must be run as root.
        res = run(ctx, ["sudo", "sshd", "-T"], timeout=15.0)
    if res.rc != 0:
        return out
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0].lower()] = parts[1].strip()
    return out


def sshd_check(control: Control, cfg: dict[str, str], key: str,
               want: str | Iterable[str], *, case_insensitive: bool = True) -> CheckResult:
    if not cfg:
        return make_result(control, Status.MANUAL,
                           "Could not read sshd effective config (sshd -T).")
    have = cfg.get(key.lower(), "")
    wants: list[str] = [want] if isinstance(want, str) else list(want)
    norm_have = have.lower() if case_insensitive else have
    for w in wants:
        if (w.lower() if case_insensitive else w) == norm_have:
            return make_result(control, Status.PASS, f"sshd {key}={have}")
    return make_result(control, Status.FAIL,
                       f"sshd {key}={have or '(unset)'} (want {' or '.join(wants)})")


# ---------------------------------------------------------------- text files

def file_contains(ctx: Context, path: str, regex: str) -> bool:
    res = run(ctx, ["grep", "-Eq", regex, path], timeout=10.0)
    return res.rc == 0


def first_match(ctx: Context, path: str, regex: str) -> str | None:
    res = run(ctx, ["grep", "-Em1", regex, path], timeout=10.0)
    if res.rc != 0:
        return None
    return res.stdout.strip()


# ---------------------------------------------------------------- audit

def auditctl_status(ctx: Context) -> dict[str, str] | None:
    res = run(ctx, ["auditctl", "-s"], timeout=10.0)
    if res.rc != 0:
        res = run(ctx, ["sudo", "auditctl", "-s"], timeout=10.0)
    if res.rc != 0:
        return None
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            out[parts[0]] = " ".join(parts[1:])
    return out


# ---------------------------------------------------------------- result helpers

def boolean_result(control: Control, value: bool | None, *, want: bool,
                   summary_pass: str, summary_fail: str,
                   na_msg: str | None = None) -> CheckResult:
    if value is None:
        return make_result(control, Status.MANUAL,
                           na_msg or "Could not determine value; verify manually.")
    if value == want:
        return make_result(control, Status.PASS, summary_pass)
    return make_result(control, Status.FAIL, summary_fail)
