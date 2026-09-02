"""Azure Foundations 6.0.0 - Section 2: Microsoft Defender for Cloud."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions, make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check

log = logging.getLogger(__name__)


# Mapping CIS control id -> defender pricing plan name (Microsoft Defender plan).
DEFENDER_PLANS = {
    "CIS-AZ-FND-2.1.1": "VirtualMachines",
    "CIS-AZ-FND-2.1.2": "AppServices",
    "CIS-AZ-FND-2.1.3": "OpenSourceRelationalDatabases",
    "CIS-AZ-FND-2.1.4": "SqlServers",
    "CIS-AZ-FND-2.1.5": "SqlServerVirtualMachines",
    "CIS-AZ-FND-2.1.6": "OpenSourceRelationalDatabases",
    "CIS-AZ-FND-2.1.7": "StorageAccounts",
    "CIS-AZ-FND-2.1.8": "Containers",
    "CIS-AZ-FND-2.1.9": "CosmosDbs",
    "CIS-AZ-FND-2.1.10": "KeyVaults",
    "CIS-AZ-FND-2.1.11": "Dns",
    "CIS-AZ-FND-2.1.12": "Arm",
    "CIS-AZ-FND-2.1.17": "CloudPosture",   # CSPM
    "CIS-AZ-FND-2.1.25": "IoT",
    "CIS-AZ-FND-2.1.26": "Api",            # External Attack Surface / API plan
}


def _check_defender_plan(plan: str, ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            pricings = cached(
                ctx, "defender.pricings", sub,
                factory=lambda s=sub: list(arm.security(s).pricings.list().value or []),
            )
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        match = next((p for p in pricings if (p.name or "").lower() == plan.lower()), None)
        tier = (getattr(match, "pricing_tier", "") or "").lower() if match else ""
        if tier != "standard":
            failures.append({"subscription": sub, "plan": plan, "tier": tier or "free"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary=f"Defender plan '{plan}' is on Standard for all subscriptions.",
        fail_summary=f"Defender plan '{plan}' is not Standard on {len(failures)} subscription(s).",
    )


def _factory_for(plan: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        try:
            return _check_defender_plan(plan, ctx, control)
        except Exception as exc:  # pragma: no cover
            return error_result(control, exc)
    return fn


# Register every defender-plan control.
for _cid, _plan in DEFENDER_PLANS.items():
    check(_cid)(_factory_for(_plan))


@check("CIS-AZ-FND-2.1.22")
def security_contact_email(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            contacts = list(arm.security(sub).security_contacts.list())
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        if not any(getattr(c, "emails", "") for c in contacts):
            failures.append({"subscription": sub, "issue": "no security contact email configured"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="Security contact email configured on all subscriptions.",
        fail_summary=f"{len(failures)} subscription(s) lack a security contact email.",
    )


@check("CIS-AZ-FND-2.1.23")
def security_contact_severity_high(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            contacts = list(arm.security(sub).security_contacts.list())
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        ok = False
        for c in contacts:
            cfg = getattr(c, "alert_notifications", None)
            severity = ""
            if cfg is not None:
                severity = (getattr(cfg, "minimal_severity", "") or "").lower()
            if severity in ("high",) and getattr(c, "emails", ""):
                ok = True
                break
        if not ok:
            failures.append({"subscription": sub, "issue": "minimum severity not 'High' or no recipient"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="Defender alert notifications set to severity High on all subscriptions.",
        fail_summary=f"{len(failures)} subscription(s) have alert notifications mis-configured.",
    )


@check("CIS-AZ-FND-2.1.24")
def security_contact_owner_role(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            contacts = list(arm.security(sub).security_contacts.list())
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        ok = False
        for c in contacts:
            cfg = getattr(c, "alert_notifications", None)
            roles = getattr(getattr(c, "notifications_by_role", None), "roles", []) if c else []
            roles = [str(r).lower() for r in (roles or [])]
            if "owner" in roles:
                ok = True
                break
        if not ok:
            failures.append({"subscription": sub, "issue": "Owner role not in notification recipients"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="Owner role receives Defender alerts on all subscriptions.",
        fail_summary=f"{len(failures)} subscription(s) do not notify Owner role.",
    )


# ------------------------------------------------------- 2.1.13 / 2.1.18-21: subassessment / extension status

def _check_defender_extension(extension_name: str, plan_name: str | None = None):
    """Return a check function that requires Defender 'extension' on a plan to be enabled."""
    def fn(ctx: Context, control: Control) -> CheckResult:
        arm = ArmClient(ctx.credential)
        failures: list[dict] = []
        subs = iter_subscriptions(ctx)
        for sub in subs:
            try:
                pricings = list(arm.security(sub).pricings.list().value or [])
            except Exception as exc:
                failures.append({"subscription": sub, "error": str(exc)})
                continue
            ok = False
            for p in pricings:
                if plan_name and (p.name or "").lower() != plan_name.lower():
                    continue
                exts = getattr(p, "extensions", []) or []
                for ext in exts:
                    if (getattr(ext, "name", "") or "").lower() == extension_name.lower() \
                            and (getattr(ext, "is_enabled", "") or "").lower() == "true":
                        ok = True
                        break
                if ok:
                    break
            if not ok:
                failures.append({"subscription": sub, "extension": extension_name, "plan": plan_name or "(any)"})
        return fail_or_pass(
            control,
            failures=failures,
            total=len(subs),
            pass_summary=f"Defender extension '{extension_name}' enabled on all subscriptions.",
            fail_summary=f"Defender extension '{extension_name}' missing on {len(failures)} subscription(s).",
        )
    return fn


check("CIS-AZ-FND-2.1.18")(_check_defender_extension("MdeDesignatedSubscription", "VirtualMachines"))
check("CIS-AZ-FND-2.1.19")(_check_defender_extension("MdeDesignatedSubscription", "VirtualMachines"))
check("CIS-AZ-FND-2.1.20")(_check_defender_extension("AgentlessVmScanning", "VirtualMachines"))
check("CIS-AZ-FND-2.1.21")(_check_defender_extension("AgentlessVmScanning", "Containers"))


@check("CIS-AZ-FND-2.1.13")
def system_updates_recommendation(ctx: Context, control: Control) -> CheckResult:
    """'Apply system updates' recommendation should be Healthy."""
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            assessments = list(arm.security(sub).assessments.list(scope=f"/subscriptions/{sub}"))
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        # Look for the "Apply system updates" assessment by display name.
        offenders = []
        for a in assessments:
            disp = (getattr(a, "display_name", "") or "").lower()
            if "system updates" not in disp and "machines should have a vulnerability assessment" not in disp:
                continue
            status = (getattr(getattr(a, "status", None), "code", "") or "").lower()
            if status not in ("healthy", "notapplicable"):
                offenders.append({"assessment": a.display_name, "status": status})
        if offenders:
            failures.append({"subscription": sub, "assessments": offenders[:5]})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="'Apply system updates' recommendation is Healthy on all subscriptions.",
        fail_summary=f"{len(failures)} subscription(s) have unhealthy 'system updates' assessments.",
    )


# ----------------------------------------------------- 2.1.15 / 2.2.1: auto-provisioning

@check("CIS-AZ-FND-2.1.15")
def auto_prov_log_analytics(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            settings = list(arm.security(sub).auto_provisioning_settings.list())
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        match = next((s for s in settings if (s.name or "").lower() == "default"), None)
        ap = (getattr(match, "auto_provision", "") or "").lower() if match else ""
        if ap != "on":
            failures.append({"subscription": sub, "auto_provision": ap})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="Auto provisioning of Log Analytics agent is On for all subscriptions.",
        fail_summary=f"{len(failures)} subscription(s) have auto-provisioning disabled.",
    )


# 2.2.1 covers the same setting; reuse the implementation by re-registering.
check("CIS-AZ-FND-2.2.1")(auto_prov_log_analytics)


@check("CIS-AZ-FND-2.2.2")
def cloud_apps_integration(ctx: Context, control: Control) -> CheckResult:
    """Defender for Cloud Apps integration -- exposed via security 'settings' API."""
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            settings = list(arm.security(sub).settings.list())
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        mcas = next((s for s in settings if (getattr(s, "name", "") or "").upper() == "MCAS"), None)
        enabled = bool(getattr(mcas, "enabled", False)) if mcas is not None else False
        if not enabled:
            failures.append({"subscription": sub, "issue": "MCAS integration not enabled"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="Defender for Cloud Apps (MCAS) integration enabled on all subscriptions.",
        fail_summary=f"{len(failures)} subscription(s) lack MCAS integration.",
    )


# 2.1.14 - default policy "Initiative" should not have any built-in policies disabled.
@check("CIS-AZ-FND-2.1.14")
def default_policy_not_disabled(ctx: Context, control: Control) -> CheckResult:
    """Best-effort: enumerate Microsoft Cloud Security Benchmark (ASC default) policy assignment effects."""
    try:
        import httpx  # type: ignore
    except ImportError:
        return make_result(control, Status.MANUAL, "httpx not installed; cannot query policy assignments API.")
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    try:
        token = ctx.credential.get_token("https://management.azure.com/.default").token
    except Exception as exc:
        return error_result(control, exc)
    headers = {"Authorization": f"Bearer {token}"}
    for sub in subs:
        url = (
            f"https://management.azure.com/subscriptions/{sub}/providers/"
            "Microsoft.Authorization/policyAssignments"
        )
        try:
            resp = httpx.get(url, params={"api-version": "2022-06-01"}, headers=headers, timeout=30.0)
            resp.raise_for_status()
            assignments = resp.json().get("value", [])
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        ascd = [
            a for a in assignments
            if "asc default" in (a.get("properties", {}).get("displayName") or "").lower()
            or "microsoft cloud security benchmark" in (a.get("properties", {}).get("displayName") or "").lower()
        ]
        if not ascd:
            failures.append({"subscription": sub, "issue": "no ASC Default / MCSB policy assignment found"})
            continue
        for a in ascd:
            params = (a.get("properties", {}) or {}).get("parameters", {}) or {}
            disabled = [k for k, v in params.items()
                        if str((v or {}).get("value", "")).lower() == "disabled"]
            if disabled:
                failures.append({"subscription": sub, "assignment": a.get("name"), "disabled": disabled[:10]})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="ASC Default / MCSB policy initiative has no disabled effects.",
        fail_summary=f"{len(failures)} subscription(s) have disabled effects in ASC Default policy.",
    )


# 2.1.16 - Auto provisioning for VA on machines (extension 'AgentlessVmScanning' or 'MdeDesignatedSubscription'
# proxies for the same intent; reuse the extension check).
check("CIS-AZ-FND-2.1.16")(_check_defender_extension("AgentlessVmScanning", "VirtualMachines"))
