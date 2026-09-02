"""Azure Database 2.0.0 - Section 1: Azure SQL Database / Managed Instance."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _rg_of(rid: str) -> str:
    if "/resourceGroups/" not in (rid or ""):
        return ""
    return rid.split("/resourceGroups/")[1].split("/")[0]


def _list_servers(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            servers = cached(
                ctx, "sql.servers", sub,
                factory=lambda s=sub: list(arm.sql(s).servers.list()),
            )
        except Exception as exc:
            log.warning("sql list failed: %s", exc)
            continue
        for srv in servers:
            out.append((sub, srv))
    return out


@check("CIS-AZ-DB-1.1")
def auditing_enabled(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            policy = arm.sql(sub).server_blob_auditing_policies.get(rg, srv.name)
        except Exception as exc:
            failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
            continue
        if (getattr(policy, "state", "") or "").lower() != "enabled":
            failures.append({"subscription": sub, "server": srv.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="Auditing enabled on all SQL servers.",
        fail_summary=f"{len(failures)} SQL server(s) have auditing disabled.",
    )


@check("CIS-AZ-DB-1.3")
def no_open_firewall(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            rules = list(arm.sql(sub).firewall_rules.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
            continue
        for r in rules:
            start = getattr(r, "start_ip_address", "")
            end = getattr(r, "end_ip_address", "")
            if start == "0.0.0.0" and end in ("0.0.0.0", "255.255.255.255"):
                failures.append({"subscription": sub, "server": srv.name, "rule": r.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="No SQL servers have ingress from any IP.",
        fail_summary=f"{len(failures)} SQL firewall rule(s) allow any IP.",
    )


@check("CIS-AZ-DB-1.7")
def aad_admin(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            admins = list(arm.sql(sub).server_azure_ad_administrators.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
            continue
        if not admins:
            failures.append({"subscription": sub, "server": srv.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="All SQL servers have an Entra administrator.",
        fail_summary=f"{len(failures)} SQL server(s) lack Entra administrator.",
    )


@check("CIS-AZ-DB-1.11")
def min_tls_version(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, srv in servers:
        tls = (getattr(srv, "minimal_tls_version", "") or "").strip()
        if tls not in ("1.2", "1.3"):
            failures.append({"subscription": sub, "server": srv.name, "min_tls": tls or "unset"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="All SQL servers enforce TLS 1.2+.",
        fail_summary=f"{len(failures)} SQL server(s) allow TLS < 1.2.",
    )


@check("CIS-AZ-DB-1.9")
def public_network_access(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, srv in servers:
        pna = (getattr(srv, "public_network_access", "") or "").lower()
        if pna != "disabled":
            failures.append({"subscription": sub, "server": srv.name, "public_network_access": pna})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="All SQL servers have public network access disabled.",
        fail_summary=f"{len(failures)} SQL server(s) allow public network access.",
    )
