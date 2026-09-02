"""Azure Compute 2.0.0 - Section 3: Azure Container Registry."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _list_registries(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            regs = cached(
                ctx, "acr.list", sub,
                factory=lambda s=sub: list(arm.acr(s).registries.list()),
            )
        except Exception as exc:
            log.warning("acr list failed: %s", exc)
            continue
        for r in regs:
            out.append((sub, r))
    return out


@check("CIS-AZ-CMP-3.2")
def admin_disabled(ctx: Context, control: Control) -> CheckResult:
    try:
        regs = _list_registries(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, r in regs:
        if getattr(r, "admin_user_enabled", False):
            failures.append({"subscription": sub, "registry": r.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(regs),
        pass_summary="No ACR admin users are enabled.",
        fail_summary=f"{len(failures)} ACR(s) have admin user enabled.",
    )


@check("CIS-AZ-CMP-3.4")
def network_restricted(ctx: Context, control: Control) -> CheckResult:
    try:
        regs = _list_registries(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, r in regs:
        public = (getattr(r, "public_network_access", "") or "").lower()
        nrs = getattr(r, "network_rule_set", None)
        default_action = (getattr(nrs, "default_action", "") or "").lower() if nrs else ""
        if public != "disabled" and default_action != "deny":
            failures.append({
                "subscription": sub, "registry": r.name,
                "public_network_access": public, "default_action": default_action,
            })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(regs),
        pass_summary="ACRs restrict network access (private or default-deny).",
        fail_summary=f"{len(failures)} ACR(s) allow public access without restriction.",
    )


@check("CIS-AZ-CMP-3.11")
def public_network_disabled(ctx: Context, control: Control) -> CheckResult:
    try:
        regs = _list_registries(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, r in regs:
        public = (getattr(r, "public_network_access", "") or "").lower()
        if public != "disabled":
            failures.append({"subscription": sub, "registry": r.name, "public_network_access": public})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(regs),
        pass_summary="All ACRs disable public network access.",
        fail_summary=f"{len(failures)} ACR(s) still allow public network access.",
    )
