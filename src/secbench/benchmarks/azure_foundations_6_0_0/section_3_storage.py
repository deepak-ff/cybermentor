"""Azure Foundations 6.0.0 - Section 3: Storage Accounts."""

from __future__ import annotations

import logging
from typing import Any

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, make_result, iter_subscriptions
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check

log = logging.getLogger(__name__)


def _all_storage_accounts(ctx: Context) -> list[tuple[str, Any]]:
    """Return list of (subscription_id, storage_account_obj)."""
    arm = ArmClient(ctx.credential)
    out: list[tuple[str, Any]] = []
    for sub_id in iter_subscriptions(ctx):
        try:
            accs = cached(
                ctx, "stg.list", sub_id,
                factory=lambda s=sub_id: list(arm.storage(s).storage_accounts.list()),
            )
        except Exception as exc:
            log.warning("Failed listing storage accounts for %s: %s", sub_id, exc)
            continue
        for acc in accs:
            out.append((sub_id, acc))
    return out


@check("CIS-AZ-FND-3.1")
def secure_transfer(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        if not getattr(acc, "enable_https_traffic_only", True):
            failures.append({"subscription": sub_id, "name": acc.name, "id": acc.id})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary=f"All {len(accs)} storage accounts require secure transfer.",
        fail_summary=f"{len(failures)} storage account(s) allow non-HTTPS traffic.",
    )


@check("CIS-AZ-FND-3.2")
def infra_encryption(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        enc = getattr(acc, "encryption", None)
        infra = getattr(enc, "require_infrastructure_encryption", None) if enc else None
        if not infra:
            failures.append({"subscription": sub_id, "name": acc.name, "id": acc.id})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All storage accounts require infrastructure encryption.",
        fail_summary=f"{len(failures)} storage account(s) lack infrastructure encryption.",
    )


@check("CIS-AZ-FND-3.7")
def public_network_access_disabled(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        pna = getattr(acc, "public_network_access", None) or ""
        if str(pna).lower() not in ("disabled",):
            failures.append({
                "subscription": sub_id,
                "name": acc.name,
                "public_network_access": str(pna),
            })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All storage accounts have Public Network Access set to Disabled.",
        fail_summary=f"{len(failures)} storage account(s) allow public network access.",
    )


@check("CIS-AZ-FND-3.8")
def default_deny_network(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        rules = getattr(acc, "network_rule_set", None)
        default_action = getattr(rules, "default_action", None) if rules else None
        if str(default_action).lower() != "deny":
            failures.append({
                "subscription": sub_id,
                "name": acc.name,
                "default_action": str(default_action),
            })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All storage accounts default-deny network access.",
        fail_summary=f"{len(failures)} storage account(s) default-allow network access.",
    )


@check("CIS-AZ-FND-3.15")
def minimum_tls_version(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        tls = (getattr(acc, "minimum_tls_version", "") or "").upper().replace("_", "")
        if tls not in ("TLS12", "TLS13"):
            failures.append({"subscription": sub_id, "name": acc.name, "min_tls": tls or "unset"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All storage accounts enforce TLS 1.2 minimum.",
        fail_summary=f"{len(failures)} storage account(s) allow TLS < 1.2.",
    )


@check("CIS-AZ-FND-3.16")
def cross_tenant_replication(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        if getattr(acc, "allow_cross_tenant_replication", False):
            failures.append({"subscription": sub_id, "name": acc.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="No storage accounts have cross-tenant replication enabled.",
        fail_summary=f"{len(failures)} storage account(s) allow cross-tenant replication.",
    )


@check("CIS-AZ-FND-3.17")
def blob_anonymous_access(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        if getattr(acc, "allow_blob_public_access", False):
            failures.append({"subscription": sub_id, "name": acc.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="No storage accounts allow anonymous blob access.",
        fail_summary=f"{len(failures)} storage account(s) allow blob anonymous access.",
    )


@check("CIS-AZ-FND-3.10")
def private_endpoints(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        peconns = list(getattr(acc, "private_endpoint_connections", []) or [])
        if not peconns:
            failures.append({"subscription": sub_id, "name": acc.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All storage accounts have at least one private endpoint connection.",
        fail_summary=f"{len(failures)} storage account(s) have no private endpoint connections.",
    )


@check("CIS-AZ-FND-3.11")
def soft_delete(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    for sub_id, acc in accs:
        rg = (acc.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (acc.id or "") else None
        if not rg:
            continue
        try:
            props = cached(
                ctx, "stg.blobservice", sub_id, rg, acc.name,
                factory=lambda s=sub_id, r=rg, n=acc.name: arm.storage(s).blob_services.get_service_properties(r, n),
            )
        except Exception as exc:
            failures.append({"subscription": sub_id, "name": acc.name, "error": str(exc)})
            continue
        dbsd = getattr(props, "delete_retention_policy", None)
        cont_dbsd = getattr(props, "container_delete_retention_policy", None)
        if not (dbsd and getattr(dbsd, "enabled", False)):
            failures.append({"subscription": sub_id, "name": acc.name, "issue": "blob soft delete disabled"})
        elif not (cont_dbsd and getattr(cont_dbsd, "enabled", False)):
            failures.append({"subscription": sub_id, "name": acc.name, "issue": "container soft delete disabled"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="Soft delete is enabled for blobs and containers.",
        fail_summary=f"{len(failures)} storage account(s) lack soft-delete settings.",
    )


@check("CIS-AZ-FND-3.9")
def trusted_services_bypass(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        rules = getattr(acc, "network_rule_set", None)
        bypass = getattr(rules, "bypass", None) if rules else None
        if str(bypass or "").lower().find("azureservices") < 0:
            failures.append({
                "subscription": sub_id,
                "name": acc.name,
                "bypass": str(bypass),
            })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All storage accounts allow trusted Azure services bypass.",
        fail_summary=f"{len(failures)} storage account(s) do not include AzureServices in bypass.",
    )


def _storage_service_logging_check(service: str):
    """service is one of 'blobServices', 'queueServices', 'tableServices'."""
    def fn(ctx: Context, control: Control) -> CheckResult:
        try:
            accs = _all_storage_accounts(ctx)
        except Exception as exc:
            return error_result(control, exc)
        arm = ArmClient(ctx.credential)
        failures: list[dict] = []
        for sub_id, acc in accs:
            target_id = f"{acc.id}/{service}/default"
            try:
                ds = list(arm.monitor(sub_id).diagnostic_settings.list(target_id).value or [])
            except Exception as exc:
                failures.append({"subscription": sub_id, "name": acc.name, "error": str(exc)})
                continue
            ok = False
            needed = {"StorageRead", "StorageWrite", "StorageDelete"}
            for s in ds:
                enabled_logs = {
                    lg.category for lg in (getattr(s, "logs", []) or [])
                    if getattr(lg, "enabled", False) and getattr(lg, "category", None)
                }
                if needed.issubset(enabled_logs):
                    ok = True
                    break
            if not ok:
                failures.append({"subscription": sub_id, "name": acc.name, "service": service})
        return fail_or_pass(
            control,
            failures=failures,
            total=len(accs),
            pass_summary=f"All storage accounts log Read/Write/Delete on {service}.",
            fail_summary=f"{len(failures)} storage account(s) miss Read/Write/Delete diagnostic logs on {service}.",
        )
    return fn


check("CIS-AZ-FND-3.13")(_storage_service_logging_check("blobServices"))
check("CIS-AZ-FND-3.5")(_storage_service_logging_check("queueServices"))
check("CIS-AZ-FND-3.14")(_storage_service_logging_check("tableServices"))


@check("CIS-AZ-FND-3.3")
def key_rotation_reminders(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        policy = getattr(acc, "key_policy", None)
        days = int(getattr(policy, "key_expiration_period_in_days", 0) or 0) if policy else 0
        if days <= 0:
            failures.append({"subscription": sub_id, "name": acc.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All storage accounts have a key expiration / rotation reminder configured.",
        fail_summary=f"{len(failures)} storage account(s) lack key rotation reminders.",
    )


@check("CIS-AZ-FND-3.12")
def cmk_encryption(ctx: Context, control: Control) -> CheckResult:
    try:
        accs = _all_storage_accounts(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub_id, acc in accs:
        enc = getattr(acc, "encryption", None)
        ks = getattr(enc, "key_source", None) if enc else None
        if str(ks).lower() != "microsoft.keyvault":
            failures.append({"subscription": sub_id, "name": acc.name, "key_source": str(ks)})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(accs),
        pass_summary="All storage accounts use customer-managed keys.",
        fail_summary=f"{len(failures)} storage account(s) use Microsoft-managed keys.",
    )
