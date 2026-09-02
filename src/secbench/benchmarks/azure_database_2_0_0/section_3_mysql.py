"""Azure Database 2.0.0 - Section 3: Azure Database for MySQL."""

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
                ctx, "mysql.servers", sub,
                factory=lambda s=sub: list(arm.mysql(s).servers.list()),
            )
        except Exception as exc:
            log.warning("mysql list failed: %s", exc)
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
            params = list(arm.mysql(sub).configurations.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
            continue
        cfg = next((p for p in params if p.name == param_name), None)
        val = (getattr(cfg, "value", "") or "").lower() if cfg else ""
        if expected_value.lower() not in val:
            failures.append({"subscription": sub, "server": srv.name, param_name: val or "unset"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary=f"All MySQL servers have '{param_name}' contains '{expected_value}'.",
        fail_summary=f"{len(failures)} MySQL server(s) misconfigured for {description}.",
    )


@check("CIS-AZ-DB-3.1")
def ssl_enforced(ctx: Context, control: Control) -> CheckResult:
    return _check_param(ctx, control, "require_secure_transport", "on", "require_secure_transport")


@check("CIS-AZ-DB-3.2")
def tls_v12(ctx: Context, control: Control) -> CheckResult:
    return _check_param(ctx, control, "tls_version", "tlsv1.2", "tls_version")


@check("CIS-AZ-DB-3.3")
def audit_log_enabled(ctx: Context, control: Control) -> CheckResult:
    return _check_param(ctx, control, "audit_log_enabled", "on", "audit_log_enabled")
