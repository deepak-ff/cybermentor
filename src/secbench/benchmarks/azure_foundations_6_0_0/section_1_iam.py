"""Azure Foundations 6.0.0 - Section 1: Identity and Access Management."""

from __future__ import annotations

import logging

from ...azure_client.graph import GraphClient
from ...engine.helpers import error_result, fail_or_pass, make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check

log = logging.getLogger(__name__)


def _graph(ctx: Context) -> GraphClient:
    cli = ctx.extras.get("graph_client")
    if cli is None:
        cli = GraphClient(ctx.credential)
        ctx.extras["graph_client"] = cli
    return cli


@check("CIS-AZ-FND-1.1.1")
def security_defaults_enabled(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _graph(ctx).get("/policies/identitySecurityDefaultsEnforcementPolicy")
    except Exception as exc:
        return error_result(control, exc)
    enabled = bool(data.get("isEnabled"))
    if enabled:
        return make_result(control, Status.PASS, "Security Defaults is enabled on the tenant.",
                           evidence=[data])
    return make_result(control, Status.FAIL, "Security Defaults is not enabled.", evidence=[data])


@check("CIS-AZ-FND-1.3")
def restrict_tenant_creation(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _graph(ctx).get("/policies/authorizationPolicy")
    except Exception as exc:
        return error_result(control, exc)
    val = bool(data.get("defaultUserRolePermissions", {}).get("allowedToCreateTenants", True))
    if val is False:
        return make_result(control, Status.PASS, "Non-admin users cannot create tenants.")
    return make_result(control, Status.FAIL, "Non-admin users can create tenants.", evidence=[data])


@check("CIS-AZ-FND-1.14")
def users_cannot_register_apps(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _graph(ctx).get("/policies/authorizationPolicy")
    except Exception as exc:
        return error_result(control, exc)
    perms = data.get("defaultUserRolePermissions", {}) or {}
    val = bool(perms.get("allowedToCreateApps", True))
    if val is False:
        return make_result(control, Status.PASS, "Default users cannot register applications.")
    return make_result(control, Status.FAIL,
                       "Default users can register applications.", evidence=[perms])


@check("CIS-AZ-FND-1.26")
def few_global_admins(ctx: Context, control: Control) -> CheckResult:
    """Ensure fewer than 5 users have global administrator assignment."""
    g = _graph(ctx)
    try:
        # Find Global Administrator role.
        roles = g.list_all(
            "/directoryRoles",
        )
        global_admin = next(
            (r for r in roles if (r.get("displayName") or "").lower() == "global administrator"),
            None,
        )
        if not global_admin:
            # Activate via roleTemplate if not yet present.
            return make_result(
                control, Status.MANUAL,
                "Global Administrator role not found in directoryRoles; activate the role first.",
            )
        members = g.list_all(f"/directoryRoles/{global_admin['id']}/members")
    except Exception as exc:
        return error_result(control, exc)
    count = len(members)
    user_count = sum(1 for m in members if m.get("@odata.type", "").endswith("user"))
    summary = f"{user_count} user(s) hold Global Administrator (total members including service principals: {count})."
    status = Status.PASS if user_count < 5 else Status.FAIL
    return make_result(control, status, summary, evidence=[
        {"displayName": m.get("displayName"), "userPrincipalName": m.get("userPrincipalName"), "type": m.get("@odata.type")}
        for m in members
    ])


@check("CIS-AZ-FND-1.15")
def guest_invite_restrictions(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _graph(ctx).get("/policies/authorizationPolicy")
    except Exception as exc:
        return error_result(control, exc)
    val = (data.get("allowInvitesFrom") or "").lower()
    if val in ("adminsandguestinviters", "none"):
        return make_result(
            control, Status.PASS,
            f"Guest invite restrictions set to '{val}'.",
        )
    return make_result(
        control, Status.FAIL,
        f"Guest invite restrictions set to '{val}', allowing broader invitation rights.",
        evidence=[{"allowInvitesFrom": val}],
    )


@check("CIS-AZ-FND-1.16")
def guest_user_access_restrictions(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _graph(ctx).get("/policies/authorizationPolicy")
    except Exception as exc:
        return error_result(control, exc)
    val = (data.get("guestUserRoleId") or "").lower()
    # Restricted role guid is "2af84b1e-32c8-42b7-82bc-daa82404023b" per Microsoft docs.
    restricted = "2af84b1e-32c8-42b7-82bc-daa82404023b"
    if val == restricted:
        return make_result(control, Status.PASS, "Guest user access restrictions: most restrictive (Restricted Guest User).")
    return make_result(control, Status.FAIL, f"Guest user role id is {val}; expected restricted role.",
                       evidence=[{"guestUserRoleId": val}])


# --------------------------------------------------------------- 1.2.x Conditional Access

def _ca_policies(ctx: Context) -> list[dict]:
    return _graph(ctx).conditional_access_policies()


@check("CIS-AZ-FND-1.2.1")
def trusted_locations_defined(ctx: Context, control: Control) -> CheckResult:
    try:
        locs = _graph(ctx).list_all("/identity/conditionalAccess/namedLocations")
    except Exception as exc:
        return error_result(control, exc)
    trusted = [
        loc for loc in locs
        if loc.get("@odata.type", "").endswith("ipNamedLocation") and loc.get("isTrusted")
    ] or [
        loc for loc in locs
        if loc.get("@odata.type", "").endswith("countryNamedLocation")
    ]
    if trusted:
        return make_result(control, Status.PASS,
                           f"{len(trusted)} trusted/country named location(s) defined.",
                           evidence=[{"id": l.get("id"), "displayName": l.get("displayName")} for l in trusted])
    return make_result(control, Status.FAIL, "No trusted named locations defined.")


def _enabled_ca_with(condition_filter, controls_filter, *, summary_pass: str, summary_fail: str):
    def _eval(ctx: Context, control: Control) -> CheckResult:
        try:
            policies = _ca_policies(ctx)
        except Exception as exc:
            return error_result(control, exc)
        for p in policies:
            if p.get("state") != "enabled":
                continue
            if condition_filter(p) and controls_filter(p):
                return make_result(control, Status.PASS,
                                   f"{summary_pass} (policy '{p.get('displayName')}')",
                                   evidence=[{"id": p.get("id"), "displayName": p.get("displayName")}])
        return make_result(control, Status.FAIL, summary_fail)
    return _eval


def _includes_admin_roles(p: dict) -> bool:
    roles = ((p.get("conditions") or {}).get("users") or {}).get("includeRoles") or []
    return bool(roles)


def _includes_all_users(p: dict) -> bool:
    users = ((p.get("conditions") or {}).get("users") or {}).get("includeUsers") or []
    return any(str(u).lower() == "all" for u in users)


def _grant_requires_mfa(p: dict) -> bool:
    grants = (p.get("grantControls") or {}).get("builtInControls") or []
    return "mfa" in grants


def _includes_app_id(p: dict, app_id: str) -> bool:
    apps = ((p.get("conditions") or {}).get("applications") or {}).get("includeApplications") or []
    return app_id.lower() in [str(a).lower() for a in apps]


@check("CIS-AZ-FND-1.2.3")
def mfa_for_admins(ctx: Context, control: Control) -> CheckResult:
    return _enabled_ca_with(
        _includes_admin_roles, _grant_requires_mfa,
        summary_pass="Enabled CA policy targets directory roles and requires MFA",
        summary_fail="No enabled Conditional Access policy requires MFA on directory roles.",
    )(ctx, control)


@check("CIS-AZ-FND-1.2.4")
def mfa_for_all_users(ctx: Context, control: Control) -> CheckResult:
    return _enabled_ca_with(
        _includes_all_users, _grant_requires_mfa,
        summary_pass="Enabled CA policy targets all users and requires MFA",
        summary_fail="No enabled Conditional Access policy targets all users with MFA.",
    )(ctx, control)


@check("CIS-AZ-FND-1.2.5")
def mfa_for_risky_signins(ctx: Context, control: Control) -> CheckResult:
    def _has_risk(p):
        risk = ((p.get("conditions") or {}).get("signInRiskLevels") or [])
        return any(r in risk for r in ("medium", "high"))
    return _enabled_ca_with(
        _has_risk, _grant_requires_mfa,
        summary_pass="Enabled CA policy requires MFA for risky sign-ins",
        summary_fail="No enabled Conditional Access policy requires MFA on risky sign-ins.",
    )(ctx, control)


@check("CIS-AZ-FND-1.2.6")
def mfa_for_azure_management(ctx: Context, control: Control) -> CheckResult:
    AZURE_MGMT_APP = "797f4846-ba00-4fd7-ba43-dac1f8f63013"  # Microsoft Azure Management
    return _enabled_ca_with(
        lambda p: _includes_app_id(p, AZURE_MGMT_APP), _grant_requires_mfa,
        summary_pass="Enabled CA policy requires MFA for Azure Management",
        summary_fail="No enabled Conditional Access policy requires MFA for Azure Management.",
    )(ctx, control)


@check("CIS-AZ-FND-1.22")
def mfa_for_device_join(ctx: Context, control: Control) -> CheckResult:
    """Require MFA to register or join devices with Microsoft Entra."""
    try:
        data = _graph(ctx).get("/policies/deviceRegistrationPolicy")
    except Exception as exc:
        return error_result(control, exc)
    enforce = bool((data.get("multiFactorAuthConfiguration") or "").lower() in ("required", "true"))
    if enforce or data.get("multiFactorAuthConfiguration") == "required":
        return make_result(control, Status.PASS, "MFA required to register or join devices.")
    return make_result(control, Status.FAIL,
                       f"deviceRegistrationPolicy.multiFactorAuthConfiguration = {data.get('multiFactorAuthConfiguration')}",
                       evidence=[data])


# ----------------------------------------------------- 1.5-1.11 directory settings

def _bool_setting_check(setting_template: str, value_name: str, expected: str,
                        pass_msg: str, fail_msg: str):
    def _eval(ctx: Context, control: Control) -> CheckResult:
        try:
            val = _graph(ctx).directory_setting_value(setting_template, value_name)
        except Exception as exc:
            return error_result(control, exc)
        if val is None:
            return make_result(control, Status.MANUAL,
                               f"Directory setting '{setting_template}/{value_name}' not configured; defaults apply.")
        ok = str(val).lower() == expected.lower()
        return make_result(control, Status.PASS if ok else Status.FAIL,
                           pass_msg if ok else f"{fail_msg} (current: {val})",
                           evidence=[{"setting": setting_template, "value": val}])
    return _eval


# CIS 1.5 - Number of methods required to reset password.
@check("CIS-AZ-FND-1.5")
def num_methods_required(ctx: Context, control: Control) -> CheckResult:
    try:
        val = _graph(ctx).directory_setting_value("Password Rule Settings", "NumberOfQuestionsToRegister")
        # Microsoft's CIS-aligned setting is the "Self-Service Password Reset" policy under
        # /policies/identity/onPremisesPasswordResetPolicies; that endpoint is not always
        # exposed - fall back to MANUAL with a clear hint when missing.
    except Exception as exc:
        return error_result(control, exc)
    if val is None:
        return make_result(control, Status.MANUAL,
                           "SSPR policy not exposed via Graph for this tenant; verify '2 methods required' in Entra portal.")
    try:
        n = int(val)
    except (TypeError, ValueError):
        return make_result(control, Status.MANUAL, f"Could not parse setting value: {val}")
    return make_result(control, Status.PASS if n >= 2 else Status.FAIL,
                       f"NumberOfQuestionsToRegister = {n}",
                       evidence=[{"value": n}])


@check("CIS-AZ-FND-1.6")
def lockout_threshold(ctx: Context, control: Control) -> CheckResult:
    try:
        val = _graph(ctx).directory_setting_value("Password Rule Settings", "LockoutThreshold")
    except Exception as exc:
        return error_result(control, exc)
    if val is None:
        return make_result(control, Status.MANUAL, "Smart lockout threshold not surfaced via Graph (defaults apply).")
    try:
        n = int(val)
    except (TypeError, ValueError):
        return make_result(control, Status.MANUAL, f"Unparseable value: {val}")
    return make_result(control, Status.PASS if n <= 10 else Status.FAIL,
                       f"LockoutThreshold = {n}", evidence=[{"value": n}])


@check("CIS-AZ-FND-1.7")
def lockout_duration(ctx: Context, control: Control) -> CheckResult:
    try:
        val = _graph(ctx).directory_setting_value("Password Rule Settings", "LockoutDurationInSeconds")
    except Exception as exc:
        return error_result(control, exc)
    if val is None:
        return make_result(control, Status.MANUAL, "Smart lockout duration not surfaced via Graph (defaults apply).")
    try:
        n = int(val)
    except (TypeError, ValueError):
        return make_result(control, Status.MANUAL, f"Unparseable value: {val}")
    return make_result(control, Status.PASS if n >= 60 else Status.FAIL,
                       f"LockoutDurationInSeconds = {n}", evidence=[{"value": n}])


@check("CIS-AZ-FND-1.8")
def custom_banned_password(ctx: Context, control: Control) -> CheckResult:
    try:
        enforced = _graph(ctx).directory_setting_value("Password Rule Settings", "EnableBannedPasswordCheck")
        custom = _graph(ctx).directory_setting_value("Password Rule Settings", "BannedPasswordCheckOnPremisesMode")
    except Exception as exc:
        return error_result(control, exc)
    if enforced is None and custom is None:
        return make_result(control, Status.MANUAL,
                           "Banned password settings not surfaced via Graph; verify in the Entra portal.")
    ok = (str(enforced).lower() == "true") and (str(custom).lower() in ("enforce", "enforced"))
    return make_result(control, Status.PASS if ok else Status.FAIL,
                       f"EnableBannedPasswordCheck={enforced}, mode={custom}",
                       evidence=[{"enforced": enforced, "mode": custom}])


# 1.12 - User consent for applications already partially evaluated by authorization policy.
@check("CIS-AZ-FND-1.12")
def user_consent_apps(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _graph(ctx).get("/policies/authorizationPolicy")
    except Exception as exc:
        return error_result(control, exc)
    perms = (data.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned", []) or []
    has_verified = any("verified" in str(p).lower() for p in perms)
    has_low = any("low" in str(p).lower() for p in perms)
    has_disabled = not perms
    if has_verified or has_low or has_disabled:
        return make_result(control, Status.PASS,
                           "User consent restricted (verified-publishers / low-risk / disabled).",
                           evidence=[{"policies": perms}])
    return make_result(control, Status.FAIL,
                       "User consent does not require verified publishers.",
                       evidence=[{"policies": perms}])


# 1.13 - Users can add gallery apps to My Apps.
@check("CIS-AZ-FND-1.13")
def users_add_gallery_apps(ctx: Context, control: Control) -> CheckResult:
    try:
        val = _graph(ctx).directory_setting_value("Application Management Settings", "EnableGalleryApps")
    except Exception as exc:
        return error_result(control, exc)
    if val is None:
        return make_result(control, Status.MANUAL,
                           "Application Management directory setting not configured; verify in the Entra portal.")
    ok = str(val).lower() == "false"
    return make_result(control, Status.PASS if ok else Status.FAIL,
                       f"EnableGalleryApps = {val}", evidence=[{"value": val}])


# 1.18-1.21 - Group-related settings (read from Group.Unified directory setting).
def _group_setting_check(value_name: str, expected: str, label: str):
    def _eval(ctx: Context, control: Control) -> CheckResult:
        try:
            val = _graph(ctx).directory_setting_value("Group.Unified", value_name)
        except Exception as exc:
            return error_result(control, exc)
        if val is None:
            return make_result(control, Status.MANUAL,
                               f"Group.Unified setting '{value_name}' not configured (default applies).")
        ok = str(val).lower() == expected.lower()
        return make_result(control, Status.PASS if ok else Status.FAIL,
                           f"{label}: {val}", evidence=[{value_name: val}])
    return _eval


check("CIS-AZ-FND-1.19")(_group_setting_check("EnableGroupCreation", "false", "EnableGroupCreation"))
check("CIS-AZ-FND-1.20")(_group_setting_check("AllowGuestsToBeGroupOwner", "false", "AllowGuestsToBeGroupOwner"))
check("CIS-AZ-FND-1.21")(_group_setting_check("EnableMSStandardBlockedWords", "true", "EnableMSStandardBlockedWords"))


@check("CIS-AZ-FND-1.23")
def no_custom_subscription_admin_roles(ctx: Context, control: Control) -> CheckResult:
    """Iterate every subscription's role definitions; flag custom roles with subscription-level Owner-equivalent perms."""
    from ...azure_client.arm import ArmClient
    arm = ArmClient(ctx.credential)
    failures = []
    for sub in (ctx.subscription_ids or []):
        try:
            scope = f"/subscriptions/{sub}"
            roles = list(arm.authorization(sub).role_definitions.list(scope))
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        for r in roles:
            if (getattr(r, "role_type", "") or "").lower() != "customrole":
                continue
            for perm in (getattr(r, "permissions", []) or []):
                actions = [str(a).lower() for a in (getattr(perm, "actions", []) or [])]
                if "*" in actions or "microsoft.authorization/roleassignments/write" in actions:
                    failures.append({
                        "subscription": sub,
                        "role": r.role_name,
                        "actions": actions[:5],
                    })
                    break
    return make_result(
        control,
        Status.PASS if not failures else Status.FAIL,
        "No subscription-level custom roles act as Owner-equivalent." if not failures
        else f"{len(failures)} custom role(s) hold Owner-equivalent permissions.",
        evidence=failures,
    )


def _user_registration_details(ctx: Context) -> list[dict]:
    """/reports/authenticationMethods/userRegistrationDetails (requires AuditLog.Read.All)."""
    return _graph(ctx).list_all("/reports/authenticationMethods/userRegistrationDetails")


def _mfa_users_check(*, only_admins: bool):
    def fn(ctx: Context, control: Control) -> CheckResult:
        try:
            details = _user_registration_details(ctx)
        except Exception as exc:
            return error_result(control, exc)
        scope = []
        for d in details:
            is_admin = bool(d.get("isAdmin"))
            if only_admins and not is_admin:
                continue
            if not only_admins and is_admin:
                continue
            scope.append(d)
        offenders = [d for d in scope if not d.get("isMfaRegistered")]
        total = len(scope)
        if total == 0:
            return make_result(control, Status.NOT_APPLICABLE,
                               "No users in scope (admin-only check on tenant with zero admins, or vice versa).")
        if not offenders:
            label = "privileged" if only_admins else "non-privileged"
            return make_result(control, Status.PASS,
                               f"All {total} {label} users have MFA registered.")
        return make_result(control, Status.FAIL,
                           f"{len(offenders)}/{total} users without MFA registered.",
                           evidence=[
                               {"userPrincipalName": d.get("userPrincipalName"),
                                "isAdmin": d.get("isAdmin")}
                               for d in offenders[:50]
                           ])
    return fn


check("CIS-AZ-FND-1.1.2")(_mfa_users_check(only_admins=True))
check("CIS-AZ-FND-1.1.3")(_mfa_users_check(only_admins=False))


@check("CIS-AZ-FND-1.1.4")
def remember_mfa_disabled(ctx: Context, control: Control) -> CheckResult:
    """No enabled CA policy may set sign-in frequency persistent or remember-MFA enabled."""
    try:
        policies = _ca_policies(ctx)
    except Exception as exc:
        return error_result(control, exc)
    offenders = []
    for p in policies:
        if p.get("state") != "enabled":
            continue
        sc = (p.get("sessionControls") or {}) or {}
        sf = sc.get("signInFrequency") or {}
        psbs = sc.get("persistentBrowser") or {}
        if (psbs.get("isEnabled") and (psbs.get("mode") or "").lower() == "always"):
            offenders.append({"policy": p.get("displayName"), "issue": "persistentBrowser=Always"})
        if not sf.get("isEnabled"):
            # No session-frequency control at all is also a fail per CIS.
            pass
    return make_result(
        control,
        Status.PASS if not offenders else Status.FAIL,
        "No CA policy allows trusting devices for extended MFA sessions." if not offenders
        else f"{len(offenders)} CA policy/policies allow extended MFA trust.",
        evidence=offenders,
    )


@check("CIS-AZ-FND-1.27")
def restrict_tenant_creation(ctx: Context, control: Control) -> CheckResult:
    try:
        data = _graph(ctx).get("/policies/authorizationPolicy")
    except Exception as exc:
        return error_result(control, exc)
    role = (data.get("defaultUserRolePermissions") or {})
    can_create = bool(role.get("allowedToCreateTenants"))
    return make_result(
        control,
        Status.PASS if not can_create else Status.FAIL,
        f"defaultUserRolePermissions.allowedToCreateTenants={can_create}",
        evidence=[role],
    )


@check("CIS-AZ-FND-1.24")
def custom_role_for_locks(ctx: Context, control: Control) -> CheckResult:
    from ...azure_client.arm import ArmClient
    arm = ArmClient(ctx.credential)
    found_anywhere = False
    failures: list[dict] = []
    subs = ctx.subscription_ids or []
    for sub in subs:
        try:
            roles = list(arm.authorization(sub).role_definitions.list(f"/subscriptions/{sub}"))
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        for r in roles:
            if (getattr(r, "role_type", "") or "").lower() != "customrole":
                continue
            for perm in (getattr(r, "permissions", []) or []):
                actions = [str(a).lower() for a in (getattr(perm, "actions", []) or [])]
                if any("microsoft.authorization/locks" in a for a in actions):
                    found_anywhere = True
                    break
            if found_anywhere:
                break
        if found_anywhere:
            break
    if found_anywhere:
        return make_result(control, Status.PASS, "Custom role granting Microsoft.Authorization/locks/* exists.")
    return make_result(control, Status.FAIL, "No custom role grants Microsoft.Authorization/locks permissions.",
                       evidence=failures)


@check("CIS-AZ-FND-1.25")
def subscription_tenant_policy(ctx: Context, control: Control) -> CheckResult:
    """Subscription leaving / entering tenant should be blocked."""
    try:
        import httpx  # type: ignore
    except ImportError:
        return make_result(control, Status.MANUAL, "httpx not installed; cannot query subscription policy API.")
    try:
        token = ctx.credential.get_token("https://management.azure.com/.default").token
        resp = httpx.get(
            "https://management.azure.com/providers/Microsoft.Subscription/policies/default",
            params={"api-version": "2021-10-01"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return error_result(control, exc)
    props = data.get("properties", {}) or {}
    leave = props.get("blockSubscriptionsLeavingTenant")
    enter = props.get("blockSubscriptionsIntoTenant")
    ok = bool(leave) and bool(enter)
    return make_result(control, Status.PASS if ok else Status.FAIL,
                       f"leaving_blocked={leave}, entering_blocked={enter}",
                       evidence=[props])
