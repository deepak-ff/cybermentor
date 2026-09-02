"""Reusable Windows / Defender check factories.

These factories return check functions that can be registered under
different control IDs by each individual benchmark (Defender AV,
Windows 11 Enterprise, Windows 11 Stand-alone). This avoids
duplicating the same logic three times.
"""

from __future__ import annotations

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from . import (
    auditpol_check,
    mp_pref_bool,
    mp_pref_int,
    mp_status_bool,
    reg_dword_equals,
    reg_dword_max,
    reg_dword_min,
    reg_string_equals,
    require_target,
    secedit_equals,
    secedit_max,
    secedit_min,
    service_disabled,
    service_running,
)

# ------------------------------------------------------------- registry

def reg_eq(key: str, name: str, want: int):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return reg_dword_equals(control, ctx, key, name, want)
    return fn


def reg_min(key: str, name: str, min_val: int):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return reg_dword_min(control, ctx, key, name, min_val)
    return fn


def reg_max(key: str, name: str, max_val: int):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return reg_dword_max(control, ctx, key, name, max_val)
    return fn


def reg_string(key: str, name: str, want: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return reg_string_equals(control, ctx, key, name, want)
    return fn


# ------------------------------------------------------------- secedit

def policy_min(key: str, min_val: int):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return secedit_min(control, ctx, key, min_val)
    return fn


def policy_max(key: str, max_val: int):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return secedit_max(control, ctx, key, max_val)
    return fn


def policy_eq(key: str, want: int):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return secedit_equals(control, ctx, key, want)
    return fn


# ------------------------------------------------------------- auditpol

def audit_policy(subcategory: str, want: str = "Success and Failure"):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return auditpol_check(control, ctx, subcategory, want)
    return fn


# ------------------------------------------------------------- services

def service_disabled_check(service: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return service_disabled(control, ctx, service)
    return fn


def service_running_check(service: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return service_running(control, ctx, service)
    return fn


# ------------------------------------------------------------- defender

def defender_pref_int(name: str, want: int):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return mp_pref_int(control, ctx, name, want)
    return fn


def defender_pref_bool(name: str, want: bool):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return mp_pref_bool(control, ctx, name, want)
    return fn


def defender_status_bool(name: str, want: bool):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        return mp_status_bool(control, ctx, name, want)
    return fn


# ------------------------------------------------------------- bitlocker

def bitlocker_enabled():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        from . import powershell as _ps
        res = _ps(ctx,
                  "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus",
                  timeout=20.0)
        out = (res.stdout or "").strip()
        if out == "On":
            return make_result(control, Status.PASS,
                               f"BitLocker on system drive: {out}")
        if out == "Off":
            return make_result(control, Status.FAIL, "BitLocker is off.")
        return make_result(control, Status.MANUAL,
                           f"Could not determine BitLocker state: {out or '(no output)'}")
    return fn


# ------------------------------------------------------------- firewall

def firewall_profile_enabled(profile: str):
    """profile: Domain / Private / Public"""
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        from . import powershell as _ps
        res = _ps(ctx,
                  f"(Get-NetFirewallProfile -Name {profile}).Enabled",
                  timeout=15.0)
        out = (res.stdout or "").strip()
        if out.lower() == "true":
            return make_result(control, Status.PASS,
                               f"{profile} firewall profile enabled.")
        return make_result(control, Status.FAIL,
                           f"{profile} firewall profile not enabled (got {out}).")
    return fn


def firewall_default_inbound(profile: str, want: str = "Block"):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        from . import powershell as _ps
        res = _ps(ctx,
                  f"(Get-NetFirewallProfile -Name {profile}).DefaultInboundAction",
                  timeout=15.0)
        out = (res.stdout or "").strip()
        if out.lower() == want.lower():
            return make_result(control, Status.PASS,
                               f"{profile} DefaultInboundAction={out}")
        return make_result(control, Status.FAIL,
                           f"{profile} DefaultInboundAction={out} (want {want})")
    return fn


# ------------------------------------------------------------- smb / shares

def no_smbv1():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        from . import powershell as _ps
        res = _ps(ctx,
                  "(Get-SmbServerConfiguration).EnableSMB1Protocol",
                  timeout=15.0)
        out = (res.stdout or "").strip().lower()
        if out == "false":
            return make_result(control, Status.PASS, "SMBv1 is disabled.")
        if out == "true":
            return make_result(control, Status.FAIL, "SMBv1 is enabled.")
        return make_result(control, Status.MANUAL,
                           f"Could not read SMB1 state: {out or '(empty)'}")
    return fn


# ------------------------------------------------------------- accounts

def guest_disabled():
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        from . import powershell as _ps
        res = _ps(ctx,
                  "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled",
                  timeout=15.0)
        out = (res.stdout or "").strip().lower()
        if out == "false":
            return make_result(control, Status.PASS, "Guest account disabled.")
        if out == "true":
            return make_result(control, Status.FAIL, "Guest account enabled.")
        return make_result(control, Status.PASS,
                           "Guest account not present.")
    return fn


def administrator_renamed():
    """STIG/CIS recommends renaming the built-in Administrator account."""
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        from . import powershell as _ps
        res = _ps(ctx,
                  "(Get-LocalUser | Where-Object { $_.SID -like '*-500' }).Name",
                  timeout=15.0)
        out = (res.stdout or "").strip()
        if not out:
            return make_result(control, Status.MANUAL,
                               "Could not enumerate local accounts.")
        if out.lower() != "administrator":
            return make_result(control, Status.PASS,
                               f"Built-in Administrator renamed to '{out}'.")
        return make_result(control, Status.FAIL,
                           "Built-in Administrator has not been renamed.")
    return fn
