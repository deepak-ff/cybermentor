"""M365 Foundations 6.0.1 - Section 4: Microsoft Entra Admin Center."""

from __future__ import annotations

import logging

from ...azure_client.graph import GraphClient
from ...engine.helpers import error_result, make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check

log = logging.getLogger(__name__)


def _graph(ctx: Context) -> GraphClient:
    cli = ctx.extras.get("graph_client")
    if cli is None:
        cli = GraphClient(ctx.credential)
        ctx.extras["graph_client"] = cli
    return cli


def _auth_policy(ctx: Context) -> dict:
    return _graph(ctx).get("/policies/authorizationPolicy")


@check("CIS-M365-4.4.2")
def restrict_tenant_creation(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _auth_policy(ctx)
    except Exception as exc:
        return error_result(control, exc)
    val = bool(data.get("defaultUserRolePermissions", {}).get("allowedToCreateTenants", True))
    if val is False:
        return make_result(control, Status.PASS, "Non-admin users cannot create tenants.")
    return make_result(control, Status.FAIL, "Non-admin users can create tenants.", evidence=[data])


@check("CIS-M365-4.4.4")
def users_cannot_register_apps(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _auth_policy(ctx)
    except Exception as exc:
        return error_result(control, exc)
    perms = data.get("defaultUserRolePermissions", {}) or {}
    if not perms.get("allowedToCreateApps", True):
        return make_result(control, Status.PASS, "Default users cannot register applications.")
    return make_result(control, Status.FAIL, "Default users can register applications.", evidence=[perms])


@check("CIS-M365-4.4.5")
def user_consent_verified_publishers(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _graph(ctx).get("/policies/authorizationPolicy")
    except Exception as exc:
        return error_result(control, exc)
    consent = (data.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned", []) or []
    # Microsoft's verified-publisher consent policy id contains 'verified'.
    has_verified = any("verified" in p.lower() for p in consent)
    has_low_risk = any("low" in p.lower() for p in consent)
    if has_verified or has_low_risk:
        return make_result(control, Status.PASS,
                           "User consent restricted to verified-publisher / low-risk apps.",
                           evidence=[{"policies": consent}])
    return make_result(control, Status.FAIL,
                       "User consent does not require verified publishers.",
                       evidence=[{"policies": consent}])


@check("CIS-M365-4.4.7")
def guest_invite_restrictions(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _auth_policy(ctx)
    except Exception as exc:
        return error_result(control, exc)
    val = (data.get("allowInvitesFrom") or "").lower()
    if val in ("adminsandguestinviters", "none"):
        return make_result(control, Status.PASS, f"Guest invite restrictions: '{val}'.")
    return make_result(control, Status.FAIL, f"Guest invite restrictions: '{val}'.",
                       evidence=[{"allowInvitesFrom": val}])


@check("CIS-M365-4.4.8")
def guest_user_role_restricted(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _auth_policy(ctx)
    except Exception as exc:
        return error_result(control, exc)
    val = (data.get("guestUserRoleId") or "").lower()
    restricted = "2af84b1e-32c8-42b7-82bc-daa82404023b"
    if val == restricted:
        return make_result(control, Status.PASS, "Guest user role: Restricted Guest User.")
    return make_result(control, Status.FAIL, f"Guest user role id: {val}",
                       evidence=[{"guestUserRoleId": val}])


@check("CIS-M365-4.1.1")
def security_defaults_disabled_when_ca(ctx: Context, control: Control) -> CheckResult:
    g = _graph(ctx)
    try:
        sd = g.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        ca_policies = g.list_all("/identity/conditionalAccess/policies")
    except Exception as exc:
        return error_result(control, exc)
    sd_on = bool(sd.get("isEnabled"))
    ca_on = any(p.get("state") == "enabled" for p in ca_policies)
    if ca_on and not sd_on:
        return make_result(control, Status.PASS,
                           "Security Defaults disabled and Conditional Access policies are in use.")
    if not ca_on and sd_on:
        return make_result(control, Status.PASS,
                           "Conditional Access not in use; Security Defaults remains enabled.")
    if sd_on and ca_on:
        return make_result(control, Status.FAIL,
                           "Security Defaults is enabled while Conditional Access policies are also active.")
    return make_result(control, Status.FAIL,
                       "Neither Security Defaults nor Conditional Access policies are enabled.")


@check("CIS-M365-4.2.1")
def block_legacy_auth(ctx: Context, control: Control) -> CheckResult:
    try:
        policies = _graph(ctx).list_all("/identity/conditionalAccess/policies")
    except Exception as exc:
        return error_result(control, exc)
    for p in policies:
        if p.get("state") != "enabled":
            continue
        conds = p.get("conditions", {}) or {}
        client_apps = conds.get("clientAppTypes") or []
        controls = ((p.get("grantControls") or {}).get("builtInControls") or [])
        if ("exchangeActiveSync" in client_apps or "other" in client_apps) and "block" in controls:
            return make_result(control, Status.PASS,
                               f"Conditional Access policy '{p.get('displayName')}' blocks legacy auth.")
    return make_result(control, Status.FAIL,
                       "No enabled Conditional Access policy blocks legacy authentication.")


@check("CIS-M365-4.2.5")
def mfa_for_admin_roles(ctx: Context, control: Control) -> CheckResult:
    try:
        policies = _graph(ctx).list_all("/identity/conditionalAccess/policies")
    except Exception as exc:
        return error_result(control, exc)
    for p in policies:
        if p.get("state") != "enabled":
            continue
        conds = p.get("conditions", {}) or {}
        roles = ((conds.get("users") or {}).get("includeRoles") or [])
        controls = ((p.get("grantControls") or {}).get("builtInControls") or [])
        if roles and "mfa" in controls:
            return make_result(control, Status.PASS,
                               f"Policy '{p.get('displayName')}' requires MFA for admin role(s).",
                               evidence=[{"includeRoles": roles}])
    return make_result(control, Status.FAIL,
                       "No enabled Conditional Access policy requires MFA on directory roles.")
