"""Section 3 - Logging and Auditing."""

from __future__ import annotations

import re

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check
from ._helpers import require_target, run


@check("CIS-MACOS-3.1")
def auditd_running(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "launchctl", "list"])
    if "com.apple.auditd" in res.stdout:
        return make_result(control, Status.PASS, "com.apple.auditd is loaded.")
    res2 = run(ctx, ["pgrep", "-x", "auditd"])
    if res2.stdout.strip():
        return make_result(control, Status.PASS, "auditd is running.")
    return make_result(control, Status.FAIL, "auditd is not loaded.")


@check("CIS-MACOS-3.2")
def audit_flags(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "cat", "/etc/security/audit_control"])
    if res.rc != 0:
        return make_result(control, Status.MANUAL, res.stderr.strip()[:300])
    flags_line = next((l for l in res.stdout.splitlines() if l.startswith("flags:")), "")
    flags = flags_line.replace("flags:", "").strip()
    required = {"ad", "fd", "fm", "fr", "fw", "lo", "-all"}
    present = {f.strip() for f in flags.split(",") if f.strip()}
    # Accept if the flag string contains "lo" and "ad" at minimum (common CIS guidance).
    if {"lo", "ad", "fd", "fm", "fr", "fw"}.issubset(present):
        return make_result(control, Status.PASS, f"audit_control flags: {flags}")
    return make_result(control, Status.FAIL, f"audit_control flags missing required entries: {flags}")


@check("CIS-MACOS-3.3")
def install_log_retention(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["grep", "-A1", "install.log", "/etc/asl/com.apple.install"], timeout=10.0)
    out = res.stdout
    m = re.search(r"ttl=(\d+)", out)
    if m and int(m.group(1)) >= 365:
        return make_result(control, Status.PASS, f"install.log ttl={m.group(1)}")
    if m:
        return make_result(control, Status.FAIL, f"install.log ttl={m.group(1)} (<365)")
    return make_result(control, Status.MANUAL, "Could not parse com.apple.install asl config.")


@check("CIS-MACOS-3.4")
def audit_retention(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "cat", "/etc/security/audit_control"])
    if res.rc != 0:
        return make_result(control, Status.MANUAL, res.stderr.strip()[:300])
    expire = re.search(r"expire-after:\s*(\S+)", res.stdout)
    if expire:
        return make_result(control, Status.PASS, f"expire-after={expire.group(1)}")
    return make_result(control, Status.FAIL, "expire-after directive not set.")


@check("CIS-MACOS-3.5")
def audit_perms(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "ls", "-le", "/var/audit"])
    if res.rc != 0:
        return make_result(control, Status.MANUAL, res.stderr.strip()[:300])
    issues = []
    for line in res.stdout.splitlines()[1:]:
        # Mode is the first field; expect rw------- or r--------
        parts = line.split()
        if len(parts) < 3:
            continue
        mode = parts[0]
        owner = parts[2]
        if owner != "root":
            issues.append(f"{parts[-1]} owner={owner}")
        if not (mode.startswith("-rw-------") or mode.startswith("-r--------")):
            issues.append(f"{parts[-1]} mode={mode}")
    if issues:
        return make_result(control, Status.FAIL, "; ".join(issues[:10]))
    return make_result(control, Status.PASS, "Audit records are root-owned with restrictive perms.")


@check("CIS-MACOS-3.6")
def firewall_logging(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw",
                    "--getloggingmode"])
    if "on" in res.stdout.lower():
        return make_result(control, Status.PASS, res.stdout.strip())
    if res.rc != 0:
        return make_result(control, Status.MANUAL, res.stderr.strip()[:300])
    return make_result(control, Status.FAIL, res.stdout.strip())
