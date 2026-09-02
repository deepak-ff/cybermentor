"""M365 Foundations 6.0.1 - Section 9: Microsoft Intune (mostly manual)."""

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


@check("CIS-M365-9.1.2")
def compliance_policies_exist(ctx: Context, control: Control) -> CheckResult:
    try:
        policies = _graph(ctx).list_all("/deviceManagement/deviceCompliancePolicies")
    except Exception as exc:
        return error_result(control, exc)
    if not policies:
        return make_result(control, Status.FAIL, "No Intune device compliance policies are configured.")
    return make_result(
        control, Status.PASS,
        f"{len(policies)} compliance policy/policies are configured; review enforcement scope manually.",
        evidence=[{"displayName": p.get("displayName"), "id": p.get("id")} for p in policies[:50]],
    )
