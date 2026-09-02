"""Azure Storage 1.0.0 - Section 1: Storage Account-level controls."""

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
            accs = cached(
                ctx, "stg2.list", sub,
                factory=lambda s=sub: list(arm.storage(s).storage_accounts.list()),
            )
        except Exception as exc:
            log.warning("stg list failed: %s", exc)
            continue
        for a in accs:
            out.append((sub, a))
    return out


@check("CIS-AZ-STG-1.1")
def secure_transfer(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = [{"subscription": s, "name": a.name} for s, a in accs if not getattr(a, "enable_https_traffic_only", True)]
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="All storage accounts require secure transfer.",
        fail_summary=f"{len(failures)} storage account(s) allow HTTP.",
    )


@check("CIS-AZ-STG-1.2")
def min_tls(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for s, a in accs:
        tls = (getattr(a, "minimum_tls_version", "") or "").upper().replace("_", "")
        if tls not in ("TLS12", "TLS13"):
            failures.append({"subscription": s, "name": a.name, "min_tls": tls or "unset"})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="All storage accounts enforce TLS 1.2 minimum.",
        fail_summary=f"{len(failures)} storage account(s) allow TLS < 1.2.",
    )


@check("CIS-AZ-STG-1.3")
def public_network_access_restricted(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for s, a in accs:
        pna = (getattr(a, "public_network_access", "") or "").lower()
        if pna == "enabled":
            failures.append({"subscription": s, "name": a.name, "public_network_access": pna})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="Storage accounts restrict public network access.",
        fail_summary=f"{len(failures)} storage account(s) allow public network access.",
    )


@check("CIS-AZ-STG-1.4")
def default_deny(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for s, a in accs:
        rules = getattr(a, "network_rule_set", None)
        action = (getattr(rules, "default_action", "") or "").lower() if rules else ""
        if action != "deny":
            failures.append({"subscription": s, "name": a.name, "default_action": action})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="All storage accounts default-deny network access.",
        fail_summary=f"{len(failures)} storage account(s) default-allow.",
    )


@check("CIS-AZ-STG-1.6")
def blob_anon_disabled(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = [{"subscription": s, "name": a.name} for s, a in accs if getattr(a, "allow_blob_public_access", False)]
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="No storage accounts allow anonymous blob access.",
        fail_summary=f"{len(failures)} storage account(s) allow anonymous blob access.",
    )


@check("CIS-AZ-STG-1.7")
def cross_tenant_replication(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = [{"subscription": s, "name": a.name} for s, a in accs if getattr(a, "allow_cross_tenant_replication", False)]
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="No storage accounts have cross-tenant replication enabled.",
        fail_summary=f"{len(failures)} storage account(s) allow cross-tenant replication.",
    )


@check("CIS-AZ-STG-1.8")
def shared_key_disabled(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for s, a in accs:
        # When None, default is True (allowed).
        if getattr(a, "allow_shared_key_access", True):
            failures.append({"subscription": s, "name": a.name})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="All storage accounts disable shared key access.",
        fail_summary=f"{len(failures)} storage account(s) still allow shared key access.",
    )


@check("CIS-AZ-STG-1.13")
def infra_encryption(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for s, a in accs:
        enc = getattr(a, "encryption", None)
        infra = getattr(enc, "require_infrastructure_encryption", None) if enc else None
        if not infra:
            failures.append({"subscription": s, "name": a.name})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="Infrastructure encryption is enabled on all storage accounts.",
        fail_summary=f"{len(failures)} storage account(s) lack infrastructure encryption.",
    )


@check("CIS-AZ-STG-1.14")
def private_endpoints(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for s, a in accs:
        peconns = list(getattr(a, "private_endpoint_connections", []) or [])
        if not peconns:
            failures.append({"subscription": s, "name": a.name})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="All storage accounts have private endpoints.",
        fail_summary=f"{len(failures)} storage account(s) lack private endpoints.",
    )


@check("CIS-AZ-STG-1.12")
def cmk_encryption(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for s, a in accs:
        enc = getattr(a, "encryption", None)
        ks = getattr(enc, "key_source", None) if enc else None
        if str(ks).lower() != "microsoft.keyvault":
            failures.append({"subscription": s, "name": a.name, "key_source": str(ks)})
    return fail_or_pass(
        control, failures=failures, total=len(accs),
        pass_summary="All storage accounts use customer-managed keys.",
        fail_summary=f"{len(failures)} storage account(s) use Microsoft-managed keys.",
    )
