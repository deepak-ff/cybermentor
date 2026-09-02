"""M365 Foundations 6.0.1 - Section 1: Microsoft 365 Admin Center."""

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


@check("CIS-M365-1.1.3")
def two_to_four_globals(ctx: Context, control: Control) -> CheckResult:
    g = _graph(ctx)
    try:
        roles = g.list_all("/directoryRoles")
        ga = next((r for r in roles if (r.get("displayName") or "").lower() == "global administrator"), None)
        if not ga:
            return make_result(control, Status.MANUAL,
                               "Global Administrator role not yet activated in this tenant; cannot enumerate.")
        members = g.list_all(f"/directoryRoles/{ga['id']}/members")
    except Exception as exc:
        return error_result(control, exc)
    user_count = sum(1 for m in members if (m.get("@odata.type") or "").endswith("user"))
    summary = f"{user_count} user(s) hold the Global Administrator role."
    if 2 <= user_count <= 4:
        return make_result(control, Status.PASS, summary)
    return make_result(control, Status.FAIL, summary, evidence=[
        {"displayName": m.get("displayName"), "userPrincipalName": m.get("userPrincipalName")}
        for m in members
    ])


@check("CIS-M365-1.1.2")
def emergency_access_accounts(ctx: Context, control: Control) -> CheckResult:
    """Detects users tagged 'Emergency' or 'Break Glass' (heuristic)."""
    g = _graph(ctx)
    try:
        users = g.list_all("/users", params={"$select": "id,displayName,userPrincipalName"})
    except Exception as exc:
        return error_result(control, exc)
    candidates = [
        u for u in users
        if any(tag in (u.get("displayName") or "").lower() for tag in ("emergency", "break glass", "breakglass"))
    ]
    if len(candidates) >= 2:
        return make_result(control, Status.PASS,
                           f"Detected {len(candidates)} likely emergency-access account(s) by name.",
                           evidence=candidates)
    return make_result(
        control, Status.MANUAL,
        f"Only {len(candidates)} candidate emergency-access account(s) detected by display name; manually confirm.",
        evidence=candidates,
    )
