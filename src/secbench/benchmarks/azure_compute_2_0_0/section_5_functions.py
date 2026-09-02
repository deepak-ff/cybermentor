"""Azure Compute 2.0.0 - Section 5: Azure Functions."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _rg_of(rid: str) -> str:
    if "/resourceGroups/" not in (rid or ""):
        return ""
    return rid.split("/resourceGroups/")[1].split("/")[0]


def _list_function_apps(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            apps = cached(
                ctx, "func.list", sub,
                factory=lambda s=sub: list(arm.web(s).web_apps.list()),
            )
        except Exception as exc:
            log.warning("function apps list failed: %s", exc)
            continue
        for a in apps:
            kind = (getattr(a, "kind", "") or "").lower()
            if "functionapp" in kind:
                out.append((sub, a))
    return out


@check("CIS-AZ-CMP-5.1")
def fn_https_only(ctx: Context, control: Control) -> CheckResult:
    try:
        apps = _list_function_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, a in apps:
        if not getattr(a, "https_only", False):
            failures.append({"subscription": sub, "function_app": a.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="All Function Apps require HTTPS only.",
        fail_summary=f"{len(failures)} Function App(s) accept HTTP.",
    )


@check("CIS-AZ-CMP-5.2")
def fn_min_tls_12(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    try:
        apps = _list_function_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, a in apps:
        rg = _rg_of(a.id)
        if not rg:
            continue
        try:
            cfg = arm.web(sub).web_apps.get_configuration(rg, a.name)
        except Exception as exc:
            failures.append({"subscription": sub, "function_app": a.name, "error": str(exc)})
            continue
        tls = (getattr(cfg, "min_tls_version", "") or "").strip()
        if tls not in ("1.2", "1.3"):
            failures.append({"subscription": sub, "function_app": a.name, "min_tls": tls or "unset"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="All Function Apps enforce TLS 1.2+.",
        fail_summary=f"{len(failures)} Function App(s) allow TLS < 1.2.",
    )


@check("CIS-AZ-CMP-5.7")
def fn_managed_identity(ctx: Context, control: Control) -> CheckResult:
    try:
        apps = _list_function_apps(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, a in apps:
        ident = getattr(a, "identity", None)
        if ident is None or not getattr(ident, "principal_id", None):
            failures.append({"subscription": sub, "function_app": a.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(apps),
        pass_summary="All Function Apps have a managed identity.",
        fail_summary=f"{len(failures)} Function App(s) lack a managed identity.",
    )
