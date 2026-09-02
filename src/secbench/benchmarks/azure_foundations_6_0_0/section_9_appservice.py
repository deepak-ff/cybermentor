"""Azure Foundations 6.0.0 - Section 9: App Service."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _list_apps(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            apps = cached(
                ctx, "app.list", sub,
                factory=lambda s=sub: list(arm.web(s).web_apps.list()),
            )
        except Exception as exc:
            log.warning("app list failed: %s", exc)
            continue
        for a in apps:
            out.append((sub, a))
    return out


def _rg_of(rid: str) -> str:
    if "/resourceGroups/" not in (rid or ""):
        return ""
    return rid.split("/resourceGroups/")[1].split("/")[0]


@check("CIS-AZ-FND-9.1")
def https_only(ctx: Context, control: Control) -> CheckResult:
    try:
        apps = _list_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, a in apps:
        if not getattr(a, "https_only", False):
            failures.append({"subscription": sub, "app": a.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="All App Services have HTTPS Only enabled.",
        fail_summary=f"{len(failures)} App Service(s) accept HTTP traffic.",
    )


@check("CIS-AZ-FND-9.4")
def latest_tls(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    try:
        apps = _list_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, a in apps:
        rg = _rg_of(a.id)
        if not rg:
            continue
        try:
            cfg = arm.web(sub).web_apps.get_configuration(rg, a.name)
        except Exception as exc:
            failures.append({"subscription": sub, "app": a.name, "error": str(exc)})
            continue
        tls = (getattr(cfg, "min_tls_version", "") or "").strip()
        if tls not in ("1.2", "1.3"):
            failures.append({"subscription": sub, "app": a.name, "min_tls": tls or "unset"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="All App Services enforce TLS 1.2 or higher.",
        fail_summary=f"{len(failures)} App Service(s) allow TLS < 1.2.",
    )


@check("CIS-AZ-FND-9.3")
def ftp_disabled(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    try:
        apps = _list_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, a in apps:
        rg = _rg_of(a.id)
        if not rg:
            continue
        try:
            cfg = arm.web(sub).web_apps.get_configuration(rg, a.name)
        except Exception as exc:
            failures.append({"subscription": sub, "app": a.name, "error": str(exc)})
            continue
        ftp_state = (getattr(cfg, "ftps_state", "") or "").lower()
        if ftp_state not in ("ftpsonly", "disabled"):
            failures.append({"subscription": sub, "app": a.name, "ftps_state": ftp_state or "AllAllowed"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="All App Services have FTP set to FTPS-only or disabled.",
        fail_summary=f"{len(failures)} App Service(s) accept plain FTP.",
    )


@check("CIS-AZ-FND-9.2")
def app_service_authentication(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    try:
        apps = _list_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, a in apps:
        rg = _rg_of(a.id)
        if not rg:
            continue
        try:
            settings = arm.web(sub).web_apps.get_auth_settings(rg, a.name)
        except Exception as exc:
            failures.append({"subscription": sub, "app": a.name, "error": str(exc)})
            continue
        if not getattr(settings, "enabled", False):
            failures.append({"subscription": sub, "app": a.name, "issue": "App Service Authentication disabled"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="App Service Authentication enabled on all apps.",
        fail_summary=f"{len(failures)} App Service(s) have authentication disabled.",
    )


@check("CIS-AZ-FND-9.9")
def http_version_latest(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    try:
        apps = _list_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, a in apps:
        rg = _rg_of(a.id)
        if not rg:
            continue
        try:
            cfg = arm.web(sub).web_apps.get_configuration(rg, a.name)
        except Exception as exc:
            failures.append({"subscription": sub, "app": a.name, "error": str(exc)})
            continue
        if not getattr(cfg, "http20_enabled", False):
            failures.append({"subscription": sub, "app": a.name, "http20_enabled": False})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="All App Services have HTTP/2 enabled.",
        fail_summary=f"{len(failures)} App Service(s) have HTTP/2 disabled.",
    )


@check("CIS-AZ-FND-9.10")
def ftp_deployments_disabled(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    try:
        apps = _list_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, a in apps:
        rg = _rg_of(a.id)
        if not rg:
            continue
        try:
            policy = arm.web(sub).web_apps.get_ftp_allowed(rg, a.name)
        except Exception as exc:
            failures.append({"subscription": sub, "app": a.name, "error": str(exc)})
            continue
        if getattr(policy, "allow", True):
            failures.append({"subscription": sub, "app": a.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="FTP basic-auth deployments disabled on all App Services.",
        fail_summary=f"{len(failures)} App Service(s) still allow FTP basic-auth deployments.",
    )


# 9.6 / 9.7 / 9.8 - runtime version supported. We can't keep an authoritative
# 'currently supported' list in code without going stale, so the check flags
# any runtime explicitly set to an EOL major (PHP <8.x, Python <3.10, Java <11)
# and otherwise reports PASS. Users are encouraged to verify against the live
# Azure runtime support matrix.

_EOL_PREFIXES = {
    "PHP": ("PHP|5", "PHP|7"),
    "PYTHON": ("PYTHON|2", "PYTHON|3.7", "PYTHON|3.8", "PYTHON|3.9"),
    "JAVA": ("JAVA|8", "JAVA|9", "JAVA|10"),
}


def _runtime_version_check(language: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        arm = ArmClient(ctx.credential)
        try:
            apps = _list_apps(ctx)
        except Exception as exc:
            return error_result(control, exc)
        failures: list[dict] = []
        total = 0
        for sub, a in apps:
            rg = _rg_of(a.id)
            if not rg:
                continue
            try:
                cfg = arm.web(sub).web_apps.get_configuration(rg, a.name)
            except Exception:
                continue
            stack = (getattr(cfg, "linux_fx_version", "") or "").upper()
            if not stack:
                stack = (getattr(cfg, "windows_fx_version", "") or "").upper()
            if not stack.startswith(language.upper()):
                continue
            total += 1
            if any(stack.startswith(p) for p in _EOL_PREFIXES.get(language.upper(), ())):
                failures.append({"subscription": sub, "app": a.name, "runtime": stack})
        return fail_or_pass(
            control,
            failures=failures,
            total=total,
            pass_summary=f"No App Services run end-of-life {language} versions (or {language} not in use).",
            fail_summary=f"{len(failures)} App Service(s) run an EOL {language} version.",
            na_summary=f"No App Services use {language}.",
        )
    return fn


check("CIS-AZ-FND-9.6")(_runtime_version_check("PHP"))
check("CIS-AZ-FND-9.7")(_runtime_version_check("PYTHON"))
check("CIS-AZ-FND-9.8")(_runtime_version_check("JAVA"))


@check("CIS-AZ-FND-9.5")
def aad_register(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    try:
        apps = _list_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, a in apps:
        ident = getattr(a, "identity", None)
        if ident is None or not getattr(ident, "principal_id", None):
            failures.append({"subscription": sub, "app": a.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="All App Services have a managed identity registered.",
        fail_summary=f"{len(failures)} App Service(s) lack a managed identity.",
    )
