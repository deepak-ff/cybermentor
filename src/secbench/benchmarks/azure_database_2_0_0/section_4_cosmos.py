"""Azure Database 2.0.0 - Section 4: Cosmos DB."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _list_accounts(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            accs = cached(
                ctx, "cosmos.list", sub,
                factory=lambda s=sub: list(arm.cosmos(s).database_accounts.list()),
            )
        except Exception as exc:
            log.warning("cosmos list failed: %s", exc)
            continue
        for a in accs:
            out.append((sub, a))
    return out


@check("CIS-AZ-DB-4.1")
def vnet_filter(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _list_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, a in accs:
        if not getattr(a, "is_virtual_network_filter_enabled", False):
            failures.append({"subscription": sub, "account": a.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All Cosmos DB accounts have VNet filters enabled.",
        fail_summary=f"{len(failures)} Cosmos DB account(s) lack VNet filters.",
    )


@check("CIS-AZ-DB-4.4")
def disable_local_auth(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _list_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, a in accs:
        if not getattr(a, "disable_local_auth", False):
            failures.append({"subscription": sub, "account": a.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All Cosmos DB accounts disable local key authentication.",
        fail_summary=f"{len(failures)} Cosmos DB account(s) still allow account-key auth.",
    )


@check("CIS-AZ-DB-4.8")
def public_network_disabled(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _list_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, a in accs:
        pna = (getattr(a, "public_network_access", "") or "").lower()
        if pna != "disabled":
            failures.append({"subscription": sub, "account": a.name, "public_network_access": pna})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All Cosmos DB accounts have public network access disabled.",
        fail_summary=f"{len(failures)} Cosmos DB account(s) allow public network access.",
    )
