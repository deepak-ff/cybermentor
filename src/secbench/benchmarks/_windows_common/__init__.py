"""Shared helpers for the Microsoft Windows / Defender benchmark families.

These helpers all route shell commands through ``ctx.target`` so they
work identically when the app runs on the same Windows host
(LocalTarget) or against a remote Windows machine reached via a
PowerShell-capable transport.
"""

from __future__ import annotations

import logging
import re

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status

log = logging.getLogger(__name__)


# ---------------------------------------------------------------- target gate

def require_target(ctx: Context, control: Control) -> CheckResult | None:
    """Return an ERROR result if no Windows target is set."""
    if ctx.target is None:
        return make_result(
            control,
            Status.ERROR,
            "No Windows target configured. Set 'Local' or a Windows SSH host on the Connect page.",
        )
    return None


# ---------------------------------------------------------------- run helpers

def run(ctx: Context, argv: list[str], *, timeout: float = 30.0):
    return ctx.target.run(argv, timeout=timeout)


def powershell(ctx: Context, script: str, *, timeout: float = 30.0):
    """Run a PowerShell script block through the target."""
    return ctx.target.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script,
        ],
        timeout=timeout,
    )


# ---------------------------------------------------------------- registry

def reg_value(ctx: Context, key: str, name: str) -> str | None:
    """Read a single registry value via ``reg query``.

    ``key`` is in the ``HKLM\\Software\\...`` form. Returns the raw value
    string (without the type prefix) or None if the value is missing.
    """
    res = run(ctx, ["reg", "query", key, "/v", name], timeout=15.0)
    if res.rc != 0:
        return None
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or "REG_" not in line:
            continue
        # Format: <Name>    REG_<TYPE>    <data>
        m = re.match(r"^(\S+)\s+REG_\S+\s+(.*)$", line)
        if not m:
            continue
        if m.group(1).lower() == name.lower():
            return m.group(2).strip()
    return None


def reg_dword(ctx: Context, key: str, name: str) -> int | None:
    raw = reg_value(ctx, key, name)
    if raw is None:
        return None
    raw = raw.strip()
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw)
    except ValueError:
        return None


def reg_dword_equals(control: Control, ctx: Context, key: str, name: str,
                     want: int) -> CheckResult:
    v = reg_dword(ctx, key, name)
    if v is None:
        return make_result(control, Status.FAIL,
                           f"{key}\\{name} not present (want {want}).")
    if v == want:
        return make_result(control, Status.PASS, f"{name}={v}")
    return make_result(control, Status.FAIL, f"{name}={v} (want {want})")


def reg_dword_min(control: Control, ctx: Context, key: str, name: str,
                  min_val: int) -> CheckResult:
    v = reg_dword(ctx, key, name)
    if v is None:
        return make_result(control, Status.FAIL,
                           f"{key}\\{name} not present (want >= {min_val}).")
    if v >= min_val:
        return make_result(control, Status.PASS, f"{name}={v}")
    return make_result(control, Status.FAIL,
                       f"{name}={v} (want >= {min_val})")


def reg_dword_max(control: Control, ctx: Context, key: str, name: str,
                  max_val: int) -> CheckResult:
    v = reg_dword(ctx, key, name)
    if v is None:
        return make_result(control, Status.FAIL,
                           f"{key}\\{name} not present (want <= {max_val}).")
    if v <= max_val:
        return make_result(control, Status.PASS, f"{name}={v}")
    return make_result(control, Status.FAIL,
                       f"{name}={v} (want <= {max_val})")


def reg_string_equals(control: Control, ctx: Context, key: str, name: str,
                      want: str, *, case_insensitive: bool = True) -> CheckResult:
    v = reg_value(ctx, key, name)
    if v is None:
        return make_result(control, Status.FAIL,
                           f"{key}\\{name} not present (want {want}).")
    if (v.lower() == want.lower()) if case_insensitive else (v == want):
        return make_result(control, Status.PASS, f"{name}={v}")
    return make_result(control, Status.FAIL, f"{name}={v} (want {want})")


# ---------------------------------------------------------------- defender

def get_mp_preference(ctx: Context, name: str) -> str | None:
    res = powershell(ctx, f"(Get-MpPreference).{name}", timeout=20.0)
    if res.rc != 0:
        return None
    out = (res.stdout or "").strip()
    return out or None


def mp_pref_int(control: Control, ctx: Context, name: str, want: int) -> CheckResult:
    v = get_mp_preference(ctx, name)
    if v is None:
        return make_result(control, Status.MANUAL,
                           f"Could not read Get-MpPreference.{name}.")
    try:
        iv = int(v.split()[0])
    except (ValueError, IndexError):
        return make_result(control, Status.MANUAL,
                           f"Get-MpPreference.{name}={v} (unparseable).")
    if iv == want:
        return make_result(control, Status.PASS, f"{name}={iv}")
    return make_result(control, Status.FAIL, f"{name}={iv} (want {want})")


def mp_pref_bool(control: Control, ctx: Context, name: str,
                 want: bool) -> CheckResult:
    v = get_mp_preference(ctx, name)
    if v is None:
        return make_result(control, Status.MANUAL,
                           f"Could not read Get-MpPreference.{name}.")
    val = v.strip().lower()
    is_true = val in ("true", "1", "yes", "enabled")
    is_false = val in ("false", "0", "no", "disabled")
    if (want and is_true) or (not want and is_false):
        return make_result(control, Status.PASS, f"{name}={v}")
    if is_true == is_false:  # neither
        return make_result(control, Status.MANUAL, f"{name}={v} (unknown bool)")
    return make_result(control, Status.FAIL,
                       f"{name}={v} (want {'True' if want else 'False'})")


# ---------------------------------------------------------------- mpcomputerstatus

def get_mp_computer_status(ctx: Context, name: str) -> str | None:
    res = powershell(ctx, f"(Get-MpComputerStatus).{name}", timeout=20.0)
    if res.rc != 0:
        return None
    out = (res.stdout or "").strip()
    return out or None


def mp_status_bool(control: Control, ctx: Context, name: str,
                   want: bool) -> CheckResult:
    v = get_mp_computer_status(ctx, name)
    if v is None:
        return make_result(control, Status.MANUAL,
                           f"Could not read Get-MpComputerStatus.{name}.")
    val = v.strip().lower()
    is_true = val in ("true", "1", "yes", "enabled")
    if want == is_true:
        return make_result(control, Status.PASS, f"{name}={v}")
    return make_result(control, Status.FAIL,
                       f"{name}={v} (want {'True' if want else 'False'})")


# ---------------------------------------------------------------- secedit / policy

def secedit_export(ctx: Context) -> dict[str, str] | None:
    """Run ``secedit /export`` and parse the resulting INI-style file."""
    script = (
        "$tmp = [System.IO.Path]::GetTempFileName(); "
        "secedit /export /cfg $tmp /quiet | Out-Null; "
        "Get-Content $tmp; Remove-Item $tmp -ErrorAction SilentlyContinue"
    )
    res = powershell(ctx, script, timeout=30.0)
    if res.rc != 0:
        return None
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if "=" in line and not line.strip().startswith("["):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out or None


def secedit_int(ctx: Context, key: str) -> int | None:
    cfg = secedit_export(ctx)
    if cfg is None:
        return None
    v = cfg.get(key)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def secedit_min(control: Control, ctx: Context, key: str,
                min_val: int) -> CheckResult:
    cfg = secedit_export(ctx)
    if cfg is None:
        return make_result(control, Status.MANUAL,
                           "Could not export local security policy (secedit).")
    raw = cfg.get(key)
    if raw is None:
        return make_result(control, Status.FAIL,
                           f"Policy key '{key}' not present (want >= {min_val}).")
    try:
        iv = int(raw)
    except ValueError:
        return make_result(control, Status.MANUAL, f"{key}={raw}")
    if iv >= min_val:
        return make_result(control, Status.PASS, f"{key}={iv}")
    return make_result(control, Status.FAIL,
                       f"{key}={iv} (want >= {min_val})")


def secedit_max(control: Control, ctx: Context, key: str,
                max_val: int) -> CheckResult:
    cfg = secedit_export(ctx)
    if cfg is None:
        return make_result(control, Status.MANUAL,
                           "Could not export local security policy (secedit).")
    raw = cfg.get(key)
    if raw is None:
        return make_result(control, Status.FAIL,
                           f"Policy key '{key}' not present (want <= {max_val}).")
    try:
        iv = int(raw)
    except ValueError:
        return make_result(control, Status.MANUAL, f"{key}={raw}")
    if iv <= max_val:
        return make_result(control, Status.PASS, f"{key}={iv}")
    return make_result(control, Status.FAIL,
                       f"{key}={iv} (want <= {max_val})")


def secedit_equals(control: Control, ctx: Context, key: str,
                   want: int) -> CheckResult:
    cfg = secedit_export(ctx)
    if cfg is None:
        return make_result(control, Status.MANUAL,
                           "Could not export local security policy (secedit).")
    raw = cfg.get(key)
    if raw is None:
        return make_result(control, Status.FAIL,
                           f"Policy key '{key}' not present (want {want}).")
    try:
        iv = int(raw)
    except ValueError:
        return make_result(control, Status.MANUAL, f"{key}={raw}")
    if iv == want:
        return make_result(control, Status.PASS, f"{key}={iv}")
    return make_result(control, Status.FAIL,
                       f"{key}={iv} (want {want})")


# ---------------------------------------------------------------- audit policy

def auditpol_subcategory(ctx: Context, subcategory: str) -> str | None:
    """Return the audit setting for a given sub-category (Success/Failure/None)."""
    res = run(ctx, ["auditpol", "/get", "/subcategory:" + subcategory], timeout=20.0)
    if res.rc != 0:
        return None
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("System audit policy", "Category", "------")):
            continue
        # Format: "<sub-category>      <setting>"
        parts = re.split(r"\s{2,}", line)
        if len(parts) >= 2 and parts[0].lower().strip() == subcategory.lower():
            return parts[-1].strip()
    return None


def auditpol_check(control: Control, ctx: Context, subcategory: str,
                   want: str = "Success and Failure") -> CheckResult:
    v = auditpol_subcategory(ctx, subcategory)
    if v is None:
        return make_result(control, Status.MANUAL,
                           f"Could not read auditpol for {subcategory}.")
    if v.lower() == want.lower():
        return make_result(control, Status.PASS, f"{subcategory}={v}")
    return make_result(control, Status.FAIL, f"{subcategory}={v} (want {want})")


# ---------------------------------------------------------------- services

def service_status(ctx: Context, service: str) -> tuple[str, str] | None:
    """Return (status, start-type) for a Windows service via Get-Service."""
    res = powershell(
        ctx,
        f"$s = Get-Service -Name '{service}' -ErrorAction SilentlyContinue; "
        f"if ($s) {{ \"$($s.Status)|$($s.StartType)\" }}",
        timeout=15.0,
    )
    if res.rc != 0 or not res.stdout.strip():
        return None
    out = res.stdout.strip()
    if "|" not in out:
        return None
    status, start = out.split("|", 1)
    return status.strip(), start.strip()


def service_disabled(control: Control, ctx: Context, service: str) -> CheckResult:
    info = service_status(ctx, service)
    if info is None:
        return make_result(control, Status.PASS, f"{service} not present.")
    status, start = info
    if start.lower() == "disabled":
        return make_result(control, Status.PASS,
                           f"{service} StartType={start}, Status={status}")
    return make_result(control, Status.FAIL,
                       f"{service} StartType={start} (want Disabled)")


def service_running(control: Control, ctx: Context, service: str) -> CheckResult:
    info = service_status(ctx, service)
    if info is None:
        return make_result(control, Status.FAIL, f"{service} not present.")
    status, start = info
    if status.lower() == "running":
        return make_result(control, Status.PASS,
                           f"{service} Status={status}, StartType={start}")
    return make_result(control, Status.FAIL,
                       f"{service} Status={status} (want Running)")
