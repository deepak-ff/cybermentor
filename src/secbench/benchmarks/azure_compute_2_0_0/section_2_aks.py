"""Azure Compute 2.0.0 - Section 2: Azure Kubernetes Service."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _list_clusters(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            clusters = cached(
                ctx, "aks.list", sub,
                factory=lambda s=sub: list(arm.aks(s).managed_clusters.list()),
            )
        except Exception as exc:
            log.warning("aks list failed: %s", exc)
            continue
        for c in clusters:
            out.append((sub, c))
    return out


@check("CIS-AZ-CMP-2.1")
def aks_rbac_enabled(ctx: Context, control: Control) -> CheckResult:
    try:
        clusters = _list_clusters(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, c in clusters:
        if not getattr(c, "enable_rbac", False):
            failures.append({"subscription": sub, "cluster": c.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(clusters),
        pass_summary="All AKS clusters have RBAC enabled.",
        fail_summary=f"{len(failures)} AKS cluster(s) lack RBAC.",
    )


@check("CIS-AZ-CMP-2.2")
def aks_aad_integration(ctx: Context, control: Control) -> CheckResult:
    try:
        clusters = _list_clusters(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, c in clusters:
        aad = getattr(c, "aad_profile", None)
        if aad is None or not getattr(aad, "managed", False):
            failures.append({"subscription": sub, "cluster": c.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(clusters),
        pass_summary="All AKS clusters use Microsoft Entra (managed) integration.",
        fail_summary=f"{len(failures)} AKS cluster(s) lack AAD-managed integration.",
    )


@check("CIS-AZ-CMP-2.3")
def aks_local_accounts_disabled(ctx: Context, control: Control) -> CheckResult:
    try:
        clusters = _list_clusters(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, c in clusters:
        if not getattr(c, "disable_local_accounts", False):
            failures.append({"subscription": sub, "cluster": c.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(clusters),
        pass_summary="All AKS clusters disable local accounts.",
        fail_summary=f"{len(failures)} AKS cluster(s) still permit local accounts.",
    )


@check("CIS-AZ-CMP-2.4")
def aks_api_server_restricted(ctx: Context, control: Control) -> CheckResult:
    try:
        clusters = _list_clusters(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, c in clusters:
        api = getattr(c, "api_server_access_profile", None)
        ranges = list(getattr(api, "authorized_ip_ranges", []) or []) if api else []
        private = bool(getattr(api, "enable_private_cluster", False)) if api else False
        if not (ranges or private):
            failures.append({"subscription": sub, "cluster": c.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(clusters),
        pass_summary="AKS API servers are private or restricted to authorized ranges.",
        fail_summary=f"{len(failures)} AKS cluster(s) expose API server publicly.",
    )
