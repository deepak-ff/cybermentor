"""Azure Foundations 6.0.0 - Section 5: Logging and Monitoring."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


@check("CIS-AZ-FND-5.1.1")
def subscription_diagnostic_setting(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            settings = list(arm.monitor(sub).subscription_diagnostic_settings.list().value or [])
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        if not settings:
            failures.append({"subscription": sub, "issue": "no subscription diagnostic settings configured"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="Subscription Activity Log diagnostic settings present on all subscriptions.",
        fail_summary=f"{len(failures)} subscription(s) have no Activity Log diagnostic setting.",
    )


_REQUIRED_CATEGORIES = {"Administrative", "Alert", "Policy", "Security", "ServiceHealth"}


@check("CIS-AZ-FND-5.1.2")
def subscription_diagnostic_categories(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            settings = list(arm.monitor(sub).subscription_diagnostic_settings.list().value or [])
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        for s in settings:
            enabled = {
                lg.category for lg in (getattr(s, "logs", []) or [])
                if getattr(lg, "enabled", False) and getattr(lg, "category", None)
            }
            missing = _REQUIRED_CATEGORIES - enabled
            if missing:
                failures.append({
                    "subscription": sub,
                    "setting": s.name,
                    "missing_categories": sorted(missing),
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="Activity Log diagnostic settings cover required categories.",
        fail_summary=f"{len(failures)} setting(s) miss required Activity Log categories.",
    )


_ALERT_OPERATIONS = {
    "CIS-AZ-FND-5.2.1": "microsoft.authorization/policyassignments/write",
    "CIS-AZ-FND-5.2.2": "microsoft.authorization/policyassignments/delete",
    "CIS-AZ-FND-5.2.3": "microsoft.network/networksecuritygroups/write",
    "CIS-AZ-FND-5.2.4": "microsoft.network/networksecuritygroups/delete",
    "CIS-AZ-FND-5.2.5": "microsoft.resources/deployments/write",
    "CIS-AZ-FND-5.2.6": "microsoft.sql/servers/firewallrules/write",
    "CIS-AZ-FND-5.2.7": "microsoft.sql/servers/firewallrules/delete",
    "CIS-AZ-FND-5.2.8": "microsoft.network/publicipaddresses/write",
}


def _activity_alert_check(operation_name: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        arm = ArmClient(ctx.credential)
        failures: list[dict] = []
        subs = iter_subscriptions(ctx)
        for sub in subs:
            try:
                alerts = list(arm.monitor(sub).activity_log_alerts.list_by_subscription_id())
            except Exception as exc:
                failures.append({"subscription": sub, "error": str(exc)})
                continue
            ok = False
            for a in alerts:
                if not getattr(a, "enabled", True):
                    continue
                cond = getattr(a, "condition", None)
                all_of = list(getattr(cond, "all_of", []) or []) if cond else []
                for c in all_of:
                    field = (getattr(c, "field", "") or "").lower()
                    eq = (getattr(c, "equals", "") or "").lower()
                    if field == "operationname" and eq == operation_name.lower():
                        ok = True
                        break
                if ok:
                    break
            if not ok:
                failures.append({"subscription": sub, "missing_operation": operation_name})
        return fail_or_pass(
            control,
            failures=failures,
            total=len(subs),
            pass_summary=f"Activity log alert exists for '{operation_name}'.",
            fail_summary=f"No activity log alert for '{operation_name}' on {len(failures)} subscription(s).",
        )
    return fn


for _cid, _op in _ALERT_OPERATIONS.items():
    check(_cid)(_activity_alert_check(_op))


@check("CIS-AZ-FND-5.1.5")
def nsg_flow_logs_to_log_analytics(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            watchers = list(arm.network(sub).network_watchers.list_all())
        except Exception as exc:
            log.warning("nw list failed: %s", exc)
            continue
        for nw in watchers:
            try:
                rg = nw.id.split("/resourceGroups/")[1].split("/")[0]
            except IndexError:
                continue
            try:
                flow_logs = list(arm.network(sub).flow_logs.list(rg, nw.name))
            except Exception:
                continue
            for fl in flow_logs:
                total += 1
                fa = getattr(fl, "flow_analytics_configuration", None)
                nfac = getattr(fa, "network_watcher_flow_analytics_configuration", None) if fa else None
                enabled = getattr(nfac, "enabled", False) if nfac is not None else False
                if not enabled:
                    failures.append({
                        "subscription": sub,
                        "watcher": nw.name,
                        "flow_log": fl.name,
                        "issue": "traffic analytics / Log Analytics integration disabled",
                    })
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All NSG flow logs forward to Log Analytics (Traffic Analytics enabled).",
        fail_summary=f"{len(failures)} NSG flow log(s) do not forward to Log Analytics.",
    )


@check("CIS-AZ-FND-5.1.6")
def appservice_http_logs(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            apps = list(arm.web(sub).web_apps.list())
        except Exception:
            continue
        for a in apps:
            total += 1
            try:
                rg = a.id.split("/resourceGroups/")[1].split("/")[0]
                logs = arm.web(sub).web_apps.get_diagnostic_logs_configuration(rg, a.name)
            except Exception as exc:
                failures.append({"subscription": sub, "app": a.name, "error": str(exc)})
                continue
            http_logs = getattr(logs, "http_logs", None)
            file_sys = getattr(http_logs, "file_system", None) if http_logs else None
            azure_blob = getattr(http_logs, "azure_blob_storage", None) if http_logs else None
            enabled_fs = bool(getattr(file_sys, "enabled", False)) if file_sys else False
            enabled_blob = bool(getattr(azure_blob, "enabled", False)) if azure_blob else False
            if not (enabled_fs or enabled_blob):
                failures.append({"subscription": sub, "app": a.name, "issue": "HTTP logs disabled"})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All App Services have HTTP logging enabled.",
        fail_summary=f"{len(failures)} App Service(s) have HTTP logs disabled.",
    )


@check("CIS-AZ-FND-5.1.3")
def activity_log_storage_cmk(ctx: Context, control: Control) -> CheckResult:
    """When activity logs are sent to a storage account, that account must be encrypted with CMK."""
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    total = 0
    for sub in subs:
        try:
            settings = list(arm.monitor(sub).subscription_diagnostic_settings.list().value or [])
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        for s in settings:
            sa_id = getattr(s, "storage_account_id", None)
            if not sa_id:
                continue
            total += 1
            try:
                rg = sa_id.split("/resourceGroups/")[1].split("/")[0]
                name = sa_id.split("/")[-1]
                acc = arm.storage(sub).storage_accounts.get_properties(rg, name)
            except Exception as exc:
                failures.append({"subscription": sub, "setting": s.name, "error": str(exc)})
                continue
            enc = getattr(acc, "encryption", None)
            ks = (getattr(enc, "key_source", "") or "").lower() if enc else ""
            if ks != "microsoft.keyvault":
                failures.append({
                    "subscription": sub,
                    "setting": s.name,
                    "storage_account": name,
                    "key_source": ks or "Microsoft.Storage",
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="Activity-log storage accounts are encrypted with customer-managed keys.",
        fail_summary=f"{len(failures)} activity-log storage account(s) use Microsoft-managed keys.",
        na_summary="No subscription diagnostic setting routes activity logs to a storage account.",
    )


@check("CIS-AZ-FND-5.5")
def no_basic_sku_on_critical(ctx: Context, control: Control) -> CheckResult:
    """Heuristic: detect Basic/Free/Consumption SKU on Public IPs, Load Balancers and App Service Plans."""
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    total = 0
    bad_skus = ("basic", "free", "consumption", "y1")
    for sub in subs:
        # Public IPs
        try:
            for pip in arm.network(sub).public_ip_addresses.list_all():
                total += 1
                sku = (getattr(getattr(pip, "sku", None), "name", "") or "").lower()
                if sku in bad_skus:
                    failures.append({"subscription": sub, "kind": "publicIp", "name": pip.name, "sku": sku})
        except Exception:
            pass
        # Load balancers
        try:
            for lb in arm.network(sub).load_balancers.list_all():
                total += 1
                sku = (getattr(getattr(lb, "sku", None), "name", "") or "").lower()
                if sku in bad_skus:
                    failures.append({"subscription": sub, "kind": "loadBalancer", "name": lb.name, "sku": sku})
        except Exception:
            pass
        # App Service plans
        try:
            for plan in arm.web(sub).app_service_plans.list():
                total += 1
                tier = (getattr(getattr(plan, "sku", None), "tier", "") or "").lower()
                if tier in bad_skus or tier == "shared":
                    failures.append({"subscription": sub, "kind": "appServicePlan", "name": plan.name, "tier": tier})
        except Exception:
            pass
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="No Public IPs, Load Balancers or App Service Plans use Basic/Free/Consumption SKU.",
        fail_summary=f"{len(failures)} resource(s) on Basic/Free/Consumption SKU; review whether they are production-critical.",
    )


@check("CIS-AZ-FND-5.1.4")
def keyvault_logging(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            vaults = list(arm.keyvault(sub).vaults.list_by_subscription())
        except Exception as exc:
            log.warning("vault list failed: %s", exc)
            continue
        for v in vaults:
            total += 1
            try:
                ds = list(arm.monitor(sub).diagnostic_settings.list(v.id).value or [])
            except Exception as exc:
                failures.append({"vault": v.name, "subscription": sub, "error": str(exc)})
                continue
            ok = False
            for s in ds:
                enabled = any(getattr(lg, "enabled", False) for lg in (getattr(s, "logs", []) or []))
                if enabled:
                    ok = True
                    break
            if not ok:
                failures.append({"vault": v.name, "subscription": sub, "issue": "no diagnostic setting with logs enabled"})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All Key Vaults have diagnostic logging enabled.",
        fail_summary=f"{len(failures)} Key Vault(s) lack diagnostic logging.",
    )
