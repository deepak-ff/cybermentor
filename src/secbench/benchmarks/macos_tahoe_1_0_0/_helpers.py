"""Common helpers for the macOS Tahoe benchmark - all checks route shell
commands through ``ctx.target`` so they work the same locally and over SSH."""

from __future__ import annotations

import logging
import re
from typing import Optional

from ...engine.helpers import error_result, make_result
from ...engine.models import CheckResult, Context, Control, Status

log = logging.getLogger(__name__)


def require_target(ctx: Context, control: Control) -> Optional[CheckResult]:
    """Return an ERROR result if no target is set; helps every check stay short."""
    if ctx.target is None:
        return make_result(
            control,
            Status.ERROR,
            "No macOS target configured. Set 'Local' or an SSH host on the Connect page.",
        )
    return None


def run(ctx: Context, argv: list[str], *, timeout: float = 30.0):
    return ctx.target.run(argv, timeout=timeout)


def shell(ctx: Context, command: str, *, timeout: float = 30.0):
    return ctx.target.run_shell(command, timeout=timeout)


# ---------------------------------------------------------------- defaults

def defaults_read(ctx: Context, domain: str, key: Optional[str] = None,
                  *, host: bool = False, system: bool = False) -> tuple[int, str]:
    argv = ["defaults"]
    if host:
        argv += ["-currentHost"]
    if system:
        argv = ["sudo", "defaults"]
        if host:
            argv += ["-currentHost"]
    argv += ["read", domain]
    if key is not None:
        argv += [key]
    res = run(ctx, argv, timeout=15.0)
    return res.rc, (res.stdout or "").strip()


def defaults_int(ctx: Context, domain: str, key: str, *, host: bool = False) -> Optional[int]:
    rc, out = defaults_read(ctx, domain, key, host=host)
    if rc != 0:
        return None
    try:
        return int(out)
    except (TypeError, ValueError):
        return None


def defaults_bool(ctx: Context, domain: str, key: str, *, host: bool = False) -> Optional[bool]:
    rc, out = defaults_read(ctx, domain, key, host=host)
    if rc != 0:
        return None
    out = out.strip()
    if out in ("1", "true", "TRUE", "True", "YES", "yes"):
        return True
    if out in ("0", "false", "FALSE", "False", "NO", "no"):
        return False
    return None


# ---------------------------------------------------------------- launchctl

def launchd_loaded(ctx: Context, label_pattern: str) -> bool:
    """True if any line of `launchctl list` matches the given pattern."""
    res = run(ctx, ["launchctl", "list"], timeout=15.0)
    if res.rc != 0:
        return False
    rx = re.compile(label_pattern)
    for line in res.stdout.splitlines():
        if rx.search(line):
            return True
    return False


def launchd_disabled(ctx: Context, label: str) -> bool:
    """True if the label is in the system 'disabled' list (`launchctl print-disabled`)."""
    res = run(ctx, ["launchctl", "print-disabled", "system"], timeout=15.0)
    if res.rc != 0:
        return False
    target = f'"{label}"'
    for line in res.stdout.splitlines():
        if target in line and "true" in line.lower():
            return True
    return False


# ----------------------------------------------------------------- pmset

def pmset_g(ctx: Context, scope: str = "") -> dict[str, str]:
    argv = ["pmset", "-g"]
    if scope:
        argv.append(scope)
    res = run(ctx, argv, timeout=15.0)
    out: dict[str, str] = {}
    if res.rc != 0:
        return out
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Battery") or line.startswith("AC Power"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0]] = parts[1].strip()
    return out


# --------------------------------------------------------------- profiles

def profile_value(ctx: Context, payload_type: str, key: str) -> Optional[str]:
    """Try to find a value in a configuration-profile payload of the given type."""
    res = run(ctx, ["profiles", "show", "-output", "stdout"], timeout=20.0)
    if res.rc != 0:
        return None
    # parse plist-ish output line by line for `key = value;`
    in_payload = False
    pattern = re.compile(rf"\b{re.escape(key)}\s*=\s*([^;]+);")
    for line in res.stdout.splitlines():
        if payload_type in line:
            in_payload = True
        if in_payload:
            m = pattern.search(line)
            if m:
                return m.group(1).strip().strip("\"")
    return None


# --------------------------------------------------------- result helpers

def boolean_result(control: Control, value: Optional[bool], *, want: bool, summary_pass: str,
                   summary_fail: str, na_msg: Optional[str] = None) -> CheckResult:
    if value is None:
        return make_result(control, Status.MANUAL,
                           na_msg or "Could not determine value; verify manually.",
                           evidence=[])
    if value == want:
        return make_result(control, Status.PASS, summary_pass)
    return make_result(control, Status.FAIL, summary_fail)


def from_command(ctx: Context, control: Control, argv: list[str], *,
                 ok_predicate, summary_pass: str, summary_fail_fmt: str) -> CheckResult:
    res = run(ctx, argv)
    if res.rc != 0 and not ok_predicate(res):
        return make_result(control, Status.ERROR,
                           f"command failed: {' '.join(argv)} (rc={res.rc}) {res.stderr.strip()[:300]}")
    if ok_predicate(res):
        return make_result(control, Status.PASS, summary_pass)
    return make_result(control, Status.FAIL, summary_fail_fmt.format(out=res.stdout.strip()[:300]))
