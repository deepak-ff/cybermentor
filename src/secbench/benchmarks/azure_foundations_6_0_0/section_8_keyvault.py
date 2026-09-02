"""Azure Foundations 6.0.0 - Section 8: Key Vault."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _list_vaults(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            vaults = cached(
                ctx, "kv.list", sub,
                factory=lambda s=sub: list(arm.keyvault(s).vaults.list_by_subscription()),
            )
        except Exception as exc:
            log.warning("kv list failed: %s", exc)
            continue
        for v in vaults:
            out.append((sub, v))
    return out


@check("CIS-AZ-FND-8.5")
def kv_recoverable(ctx: Context, control: Control) -> CheckResult:
    try:
        vaults = _list_vaults(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, v in vaults:
        props = getattr(v, "properties", None)
        soft = bool(getattr(props, "enable_soft_delete", False)) if props else False
        purge = bool(getattr(props, "enable_purge_protection", False)) if props else False
        if not (soft and purge):
            failures.append({
                "subscription": sub,
                "vault": v.name,
                "soft_delete": soft,
                "purge_protection": purge,
            })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(vaults),
        pass_summary="All Key Vaults have soft-delete and purge protection enabled.",
        fail_summary=f"{len(failures)} Key Vault(s) lack soft-delete or purge protection.",
    )


@check("CIS-AZ-FND-8.6")
def kv_rbac(ctx: Context, control: Control) -> CheckResult:
    try:
        vaults = _list_vaults(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, v in vaults:
        props = getattr(v, "properties", None)
        rbac = bool(getattr(props, "enable_rbac_authorization", False)) if props else False
        if not rbac:
            failures.append({"subscription": sub, "vault": v.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(vaults),
        pass_summary="All Key Vaults use Azure RBAC.",
        fail_summary=f"{len(failures)} Key Vault(s) still use access policy authorization.",
    )


def _kv_clients_keys(vault_uri: str, credential):
    from azure.keyvault.keys import KeyClient
    return KeyClient(vault_url=vault_uri, credential=credential)


def _kv_clients_secrets(vault_uri: str, credential):
    from azure.keyvault.secrets import SecretClient
    return SecretClient(vault_url=vault_uri, credential=credential)


def _expiration_check(scope: str, *, rbac: bool):
    """scope is 'keys' or 'secrets'. Filter vaults by RBAC vs access-policy mode."""
    def fn(ctx: Context, control: Control) -> CheckResult:
        try:
            vaults = _list_vaults(ctx)
        except Exception as exc:
            return error_result(control, exc)
        failures: list[dict] = []
        total = 0
        for sub, v in vaults:
            props = getattr(v, "properties", None)
            uses_rbac = bool(getattr(props, "enable_rbac_authorization", False)) if props else False
            if uses_rbac != rbac:
                continue  # this control only targets matching auth mode
            uri = getattr(props, "vault_uri", None) if props else None
            if not uri:
                continue
            try:
                if scope == "keys":
                    items = list(_kv_clients_keys(uri, ctx.credential).list_properties_of_keys())
                    get_expires = lambda x: x.expires_on
                    name_attr = lambda x: x.name
                else:
                    items = list(_kv_clients_secrets(uri, ctx.credential).list_properties_of_secrets())
                    get_expires = lambda x: x.expires_on
                    name_attr = lambda x: x.name
            except Exception as exc:
                failures.append({"subscription": sub, "vault": v.name, "error": str(exc)})
                continue
            for item in items:
                total += 1
                if get_expires(item) is None:
                    failures.append({
                        "subscription": sub,
                        "vault": v.name,
                        scope[:-1]: name_attr(item),
                    })
        return fail_or_pass(
            control,
            failures=failures,
            total=total,
            pass_summary=f"All {scope} in {'RBAC' if rbac else 'non-RBAC'} Key Vaults have expiration dates set.",
            fail_summary=f"{len(failures)} {scope[:-1]}(s) lack expiration in {'RBAC' if rbac else 'non-RBAC'} vaults.",
        )
    return fn


check("CIS-AZ-FND-8.1")(_expiration_check("keys", rbac=True))
check("CIS-AZ-FND-8.2")(_expiration_check("keys", rbac=False))
check("CIS-AZ-FND-8.3")(_expiration_check("secrets", rbac=True))
check("CIS-AZ-FND-8.4")(_expiration_check("secrets", rbac=False))


@check("CIS-AZ-FND-8.8")
def kv_auto_key_rotation(ctx: Context, control: Control) -> CheckResult:
    """Each RSA/EC key in each vault must have a rotation_policy with at least one auto rotate trigger."""
    try:
        vaults = _list_vaults(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    total = 0
    for sub, v in vaults:
        props = getattr(v, "properties", None)
        uri = getattr(props, "vault_uri", None) if props else None
        if not uri:
            continue
        try:
            kc = _kv_clients_keys(uri, ctx.credential)
            keys = list(kc.list_properties_of_keys())
        except Exception as exc:
            failures.append({"subscription": sub, "vault": v.name, "error": str(exc)})
            continue
        for k in keys:
            total += 1
            try:
                policy = kc.get_key_rotation_policy(k.name)
            except Exception:
                failures.append({"subscription": sub, "vault": v.name, "key": k.name, "issue": "no rotation policy"})
                continue
            triggers = getattr(policy.lifetime_actions, "__iter__", None)
            actions = list(policy.lifetime_actions or [])
            has_rotate = any(
                (str(getattr(a.action, "type", "")).lower() == "rotate")
                for a in actions
            )
            if not has_rotate:
                failures.append({"subscription": sub, "vault": v.name, "key": k.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All Key Vault keys have an auto-rotate lifecycle action.",
        fail_summary=f"{len(failures)} Key Vault key(s) have no auto-rotate policy.",
    )


@check("CIS-AZ-FND-8.7")
def kv_private_endpoint(ctx: Context, control: Control) -> CheckResult:
    try:
        vaults = _list_vaults(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, v in vaults:
        props = getattr(v, "properties", None)
        peconns = list(getattr(props, "private_endpoint_connections", []) or []) if props else []
        if not peconns:
            failures.append({"subscription": sub, "vault": v.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(vaults),
        pass_summary="All Key Vaults have at least one private endpoint connection.",
        fail_summary=f"{len(failures)} Key Vault(s) have no private endpoint connections.",
    )
