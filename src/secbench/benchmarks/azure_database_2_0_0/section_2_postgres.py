"""Azure Database 2.0.0 - Section 2: Azure Database for PostgreSQL."""

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
                ctx, "pg.servers", sub,
                factory=lambda s=sub: list(arm.postgres(s).servers.list()),
            )
        except Exception as exc:
            log.warning("postgres list failed: %s", exc)
            continue
        for srv in servers:
            out.append((sub, srv))
    return out


def _check_param(ctx, control, param_name, expected_value, description):
    try:
        servers = _list_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            params = list(arm.postgres(sub).configurations.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
            continue
        cfg = next((p for p in params if p.name == param_name), None)
        val = (getattr(cfg, "value", "") or "").lower() if cfg else ""
        if val != expected_value.lower():
            failures.append({"subscription": sub, "server": srv.name, param_name: val or "unset"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary=f"All PostgreSQL servers have '{param_name}' = '{expected_value}'.",
        fail_summary=f"{len(failures)} PostgreSQL server(s) misconfigured for {description}.",
    )


@check("CIS-AZ-DB-2.1")
def ssl_enforced(ctx: Context, control: Control) -> CheckResult:
    return _check_param(ctx, control, "require_secure_transport", "on", "require_secure_transport")


@check("CIS-AZ-DB-2.3")
def log_checkpoints(ctx: Context, control: Control) -> CheckResult:
    return _check_param(ctx, control, "log_checkpoints", "on", "log_checkpoints")


@check("CIS-AZ-DB-2.4")
def log_connections(ctx: Context, control: Control) -> CheckResult:
    return _check_param(ctx, control, "log_connections", "on", "log_connections")


@check("CIS-AZ-DB-2.5")
def log_disconnections(ctx: Context, control: Control) -> CheckResult:
    return _check_param(ctx, control, "log_disconnections", "on", "log_disconnections")


@check("CIS-AZ-DB-2.6")
def connection_throttling(ctx: Context, control: Control) -> CheckResult:
    return _check_param(ctx, control, "connection_throttling", "on", "connection_throttling")
