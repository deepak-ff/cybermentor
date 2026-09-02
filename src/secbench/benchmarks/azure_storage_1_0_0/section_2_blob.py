"""Azure Storage 1.0.0 - Section 2: Blob Service."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _accounts(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            accs = list(arm.storage(sub).storage_accounts.list())
        except Exception as exc:
            log.warning("stg list failed: %s", exc)
            continue
        for a in accs:
            out.append((sub, a))
    return out


def _rg(rid: str) -> str:
    if "/resourceGroups/" not in (rid or ""):
        return ""
    return rid.split("/resourceGroups/")[1].split("/")[0]


@check("CIS-AZ-STG-2.1")
def blob_soft_delete(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures = []
    for sub, a in accs:
        rg = _rg(a.id)
        try:
            props = arm.storage(sub).blob_services.get_service_properties(rg, a.name)
        except Exception as exc:
            failures.append({"subscription": sub, "name": a.name, "error": str(exc)})
            continue
        drp = getattr(props, "delete_retention_policy", None)
        if not (drp and getattr(drp, "enabled", False)):
            failures.append({"subscription": sub, "name": a.name})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="Blob soft delete enabled on all storage accounts.",
        fail_summary=f"{len(failures)} storage account(s) lack blob soft delete.",
    )


@check("CIS-AZ-STG-2.2")
def container_soft_delete(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures = []
    for sub, a in accs:
        rg = _rg(a.id)
        try:
            props = arm.storage(sub).blob_services.get_service_properties(rg, a.name)
        except Exception as exc:
            failures.append({"subscription": sub, "name": a.name, "error": str(exc)})
            continue
        drp = getattr(props, "container_delete_retention_policy", None)
        if not (drp and getattr(drp, "enabled", False)):
            failures.append({"subscription": sub, "name": a.name})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="Container soft delete enabled on all storage accounts.",
        fail_summary=f"{len(failures)} storage account(s) lack container soft delete.",
    )


@check("CIS-AZ-STG-2.6")
def container_no_anon(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures = []
    total = 0
    for sub, a in accs:
        rg = _rg(a.id)
        try:
            containers = list(arm.storage(sub).blob_containers.list(rg, a.name))
        except Exception as exc:
            log.warning("container list failed: %s", exc)
            continue
        for c in containers:
            total += 1
            access = (getattr(c, "public_access", "") or "").lower()
            if access not in ("none", ""):
                failures.append({
                    "subscription": sub,
                    "name": a.name,
                    "container": c.name,
                    "public_access": access,
                })
    return fail_or_pass(
        control, failures=failures, total=total,
        pass_summary="No blob containers allow anonymous access.",
        fail_summary=f"{len(failures)} container(s) allow anonymous access.",
    )
