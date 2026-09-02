"""Azure Foundations 6.0.0 - Section 4: Database Services."""

from __future__ import annotations

import logging
from typing import Any

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions, manual_result
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _list_sql_servers(ctx: Context) -> list[tuple[str, Any]]:
    arm = ArmClient(ctx.credential)
    out: list[tuple[str, Any]] = []
    for sub in iter_subscriptions(ctx):
        try:
            servers = cached(
                ctx, "sql.servers", sub,
                factory=lambda s=sub: list(arm.sql(s).servers.list()),
            )
        except Exception as exc:
            log.warning("sql servers list failed for %s: %s", sub, exc)
            continue
        for s in servers:
            out.append((sub, s))
    return out


def _rg_of(resource_id: str) -> str:
    if "/resourceGroups/" not in (resource_id or ""):
        return ""
    return resource_id.split("/resourceGroups/")[1].split("/")[0]


@check("CIS-AZ-FND-4.1.1")
def sql_auditing(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_sql_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            policy = cached(
                ctx, "sql.audit", sub, rg, srv.name,
                factory=lambda s=sub, r=rg, n=srv.name: arm.sql(s).server_blob_auditing_policies.get(r, n),
            )
        except Exception as exc:
            failures.append({"server": srv.name, "subscription": sub, "error": str(exc)})
            continue
        state = str(getattr(policy, "state", "")).lower()
        if state != "enabled":
            failures.append({"server": srv.name, "subscription": sub, "auditing_state": state})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="All SQL servers have auditing enabled.",
        fail_summary=f"{len(failures)} SQL server(s) without auditing enabled.",
    )


@check("CIS-AZ-FND-4.1.2")
def sql_no_open_firewall(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_sql_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            rules = list(arm.sql(sub).firewall_rules.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"server": srv.name, "subscription": sub, "error": str(exc)})
            continue
        for r in rules:
            start = getattr(r, "start_ip_address", "")
            end = getattr(r, "end_ip_address", "")
            if start == "0.0.0.0" and end in ("0.0.0.0", "255.255.255.255"):
                failures.append({
                    "server": srv.name, "subscription": sub,
                    "rule": r.name, "start": start, "end": end,
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="No SQL server firewall rules expose 0.0.0.0/0.",
        fail_summary=f"{len(failures)} SQL firewall rule(s) allow ingress from any IP.",
    )


@check("CIS-AZ-FND-4.1.4")
def sql_aad_admin(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_sql_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            admins = list(arm.sql(sub).server_azure_ad_administrators.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"server": srv.name, "subscription": sub, "error": str(exc)})
            continue
        if not admins:
            failures.append({"server": srv.name, "subscription": sub, "issue": "no Entra admin configured"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="All SQL servers have Entra ID administrator configured.",
        fail_summary=f"{len(failures)} SQL server(s) lack Entra ID administrator.",
    )


@check("CIS-AZ-FND-4.1.6")
def sql_audit_retention(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_sql_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            policy = arm.sql(sub).server_blob_auditing_policies.get(rg, srv.name)
        except Exception as exc:
            failures.append({"server": srv.name, "subscription": sub, "error": str(exc)})
            continue
        rd = getattr(policy, "retention_days", 0) or 0
        if rd < 90:
            failures.append({"server": srv.name, "subscription": sub, "retention_days": rd})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="All SQL servers retain audit logs >= 90 days.",
        fail_summary=f"{len(failures)} SQL server(s) retain audit logs < 90 days.",
    )


@check("CIS-AZ-FND-4.3.1")
def pg_ssl_required(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            servers = list(arm.postgres(sub).servers.list())
        except Exception as exc:
            log.warning("postgres list failed for %s: %s", sub, exc)
            continue
        for srv in servers:
            total += 1
            rg = _rg_of(srv.id)
            try:
                params = list(arm.postgres(sub).configurations.list_by_server(rg, srv.name))
            except Exception:
                continue
            cfg = next((p for p in params if p.name == "require_secure_transport"), None)
            if cfg is None or str(cfg.value).lower() != "on":
                failures.append({
                    "server": srv.name, "subscription": sub,
                    "require_secure_transport": getattr(cfg, "value", "missing"),
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All PostgreSQL flexible servers require SSL.",
        fail_summary=f"{len(failures)} PostgreSQL server(s) do not require SSL.",
    )


@check("CIS-AZ-FND-4.4.1")
def mysql_ssl_required(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            servers = list(arm.mysql(sub).servers.list())
        except Exception as exc:
            log.warning("mysql list failed for %s: %s", sub, exc)
            continue
        for srv in servers:
            total += 1
            rg = _rg_of(srv.id)
            try:
                params = list(arm.mysql(sub).configurations.list_by_server(rg, srv.name))
            except Exception:
                continue
            cfg = next((p for p in params if p.name == "require_secure_transport"), None)
            if cfg is None or str(cfg.value).lower() != "on":
                failures.append({
                    "server": srv.name, "subscription": sub,
                    "require_secure_transport": getattr(cfg, "value", "missing"),
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All MySQL flexible servers require SSL.",
        fail_summary=f"{len(failures)} MySQL server(s) do not require SSL.",
    )


@check("CIS-AZ-FND-4.4.2")
def mysql_min_tls_12(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            servers = list(arm.mysql(sub).servers.list())
        except Exception as exc:
            log.warning("mysql list failed for %s: %s", sub, exc)
            continue
        for srv in servers:
            total += 1
            rg = _rg_of(srv.id)
            try:
                params = list(arm.mysql(sub).configurations.list_by_server(rg, srv.name))
            except Exception:
                continue
            cfg = next((p for p in params if p.name == "tls_version"), None)
            val = (getattr(cfg, "value", "") or "").lower()
            if "tlsv1.2" not in val:
                failures.append({"server": srv.name, "subscription": sub, "tls_version": val or "missing"})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All MySQL servers enforce TLS 1.2 minimum.",
        fail_summary=f"{len(failures)} MySQL server(s) allow TLS < 1.2.",
    )


@check("CIS-AZ-FND-4.5.1")
def cosmos_selected_networks(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            accs = list(arm.cosmos(sub).database_accounts.list())
        except Exception as exc:
            log.warning("cosmos list failed for %s: %s", sub, exc)
            continue
        for acc in accs:
            total += 1
            if getattr(acc, "is_virtual_network_filter_enabled", False):
                continue
            failures.append({"account": acc.name, "subscription": sub})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All Cosmos DB accounts have VNet filters enabled.",
        fail_summary=f"{len(failures)} Cosmos DB account(s) allow all networks.",
    )


# Manual / non-automated controls fall back to the Runner default; we still
# expose them here to document behaviour explicitly when needed.
# --------------------------------------------------- 4.1.3 / 4.1.5 - SQL TDE / encryption protector

@check("CIS-AZ-FND-4.1.3")
def sql_tde_protector_cmk(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_sql_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            protectors = list(arm.sql(sub).encryption_protectors.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
            continue
        for p in protectors:
            if (getattr(p, "server_key_type", "") or "").lower() != "azurekeyvault":
                failures.append({"subscription": sub, "server": srv.name,
                                 "server_key_type": getattr(p, "server_key_type", None)})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="All SQL servers' TDE protectors use customer-managed keys.",
        fail_summary=f"{len(failures)} SQL server(s) use service-managed TDE protector.",
    )


@check("CIS-AZ-FND-4.1.5")
def sql_db_data_encryption_on(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_sql_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            dbs = list(arm.sql(sub).databases.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
            continue
        for db in dbs:
            if db.name.lower() == "master":
                continue
            total += 1
            try:
                tde = arm.sql(sub).transparent_data_encryptions.get(rg, srv.name, db.name)
            except Exception as exc:
                failures.append({"subscription": sub, "server": srv.name, "db": db.name, "error": str(exc)})
                continue
            state = (getattr(tde, "state", "") or "").lower()
            if state != "enabled":
                failures.append({"subscription": sub, "server": srv.name, "db": db.name, "tde_state": state})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All SQL databases have TDE enabled.",
        fail_summary=f"{len(failures)} database(s) have TDE disabled.",
    )


# ---------------------------------------------- 4.2.1-4.2.5 - Defender for SQL + Vulnerability Assessment

@check("CIS-AZ-FND-4.2.1")
def defender_for_sql_servers(ctx: Context, control: Control) -> CheckResult:
    try:
        servers = _list_sql_servers(ctx)
    except Exception as exc:
        return error_result(control, exc)
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    for sub, srv in servers:
        rg = _rg_of(srv.id)
        try:
            policies = list(arm.sql(sub).server_security_alert_policies.list_by_server(rg, srv.name))
        except Exception as exc:
            failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
            continue
        ok = any((getattr(p, "state", "") or "").lower() == "enabled" for p in policies)
        if not ok:
            failures.append({"subscription": sub, "server": srv.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(servers),
        pass_summary="Defender for SQL is enabled on all SQL servers.",
        fail_summary=f"{len(failures)} SQL server(s) have Defender for SQL disabled.",
    )


def _check_va_setting(field_name: str, summary_label: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        try:
            servers = _list_sql_servers(ctx)
        except Exception as exc:
            return error_result(control, exc)
        arm = ArmClient(ctx.credential)
        failures: list[dict] = []
        for sub, srv in servers:
            rg = _rg_of(srv.id)
            try:
                vas = list(arm.sql(sub).server_vulnerability_assessments.list_by_server(rg, srv.name))
            except Exception as exc:
                failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
                continue
            ok = False
            for va in vas:
                if field_name == "storage_container_path":
                    if getattr(va, "storage_container_path", None):
                        ok = True
                        break
                elif field_name == "recurring_scans.is_enabled":
                    rs = getattr(va, "recurring_scans", None)
                    if rs is not None and getattr(rs, "is_enabled", False):
                        ok = True
                        break
                elif field_name == "recurring_scans.emails":
                    rs = getattr(va, "recurring_scans", None)
                    if rs is not None and (getattr(rs, "emails", []) or []):
                        ok = True
                        break
                elif field_name == "recurring_scans.email_subscription_admins":
                    rs = getattr(va, "recurring_scans", None)
                    if rs is not None and getattr(rs, "email_subscription_admins", False):
                        ok = True
                        break
            if not ok:
                failures.append({"subscription": sub, "server": srv.name, "missing": field_name})
        return fail_or_pass(
            control,
            failures=failures,
            total=len(servers),
            pass_summary=f"All SQL servers have VA {summary_label} configured.",
            fail_summary=f"{len(failures)} SQL server(s) lack VA {summary_label}.",
        )
    return fn


check("CIS-AZ-FND-4.2.2")(_check_va_setting("storage_container_path", "storage account"))
check("CIS-AZ-FND-4.2.3")(_check_va_setting("recurring_scans.is_enabled", "periodic recurring scans"))
check("CIS-AZ-FND-4.2.4")(_check_va_setting("recurring_scans.emails", "scan recipient list"))
check("CIS-AZ-FND-4.2.5")(_check_va_setting("recurring_scans.email_subscription_admins", "email to subscription admins"))


# ----------------------------------------------------------------- 4.3.x PostgreSQL parameters

def _pg_param_check(param: str, expected: str, *, comparator="equals", min_int: int | None = None):
    def fn(ctx: Context, control: Control) -> CheckResult:
        arm = ArmClient(ctx.credential)
        failures: list[dict] = []
        total = 0
        for sub in iter_subscriptions(ctx):
            try:
                servers = list(arm.postgres(sub).servers.list())
            except Exception as exc:
                log.warning("postgres list failed for %s: %s", sub, exc)
                continue
            for srv in servers:
                total += 1
                rg = _rg_of(srv.id)
                try:
                    params = list(arm.postgres(sub).configurations.list_by_server(rg, srv.name))
                except Exception as exc:
                    failures.append({"subscription": sub, "server": srv.name, "error": str(exc)})
                    continue
                cfg = next((p for p in params if p.name == param), None)
                val = (getattr(cfg, "value", "") or "")
                ok = False
                if comparator == "equals":
                    ok = str(val).lower() == str(expected).lower()
                elif comparator == "min_int" and min_int is not None:
                    try:
                        ok = int(val) >= min_int
                    except (TypeError, ValueError):
                        ok = False
                if not ok:
                    failures.append({"subscription": sub, "server": srv.name, param: val or "missing"})
        return fail_or_pass(
            control,
            failures=failures,
            total=total,
            pass_summary=f"All PostgreSQL servers have '{param}' configured correctly.",
            fail_summary=f"{len(failures)} PostgreSQL server(s) misconfigured for '{param}'.",
        )
    return fn


check("CIS-AZ-FND-4.3.2")(_pg_param_check("log_checkpoints", "on"))
check("CIS-AZ-FND-4.3.3")(_pg_param_check("log_connections", "on"))
check("CIS-AZ-FND-4.3.4")(_pg_param_check("log_disconnections", "on"))
check("CIS-AZ-FND-4.3.5")(_pg_param_check("connection_throttle.enable", "on"))
check("CIS-AZ-FND-4.3.6")(_pg_param_check("logfiles.retention_days", "", comparator="min_int", min_int=4))


@check("CIS-AZ-FND-4.3.7")
def pg_no_allow_azure_services(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            servers = list(arm.postgres(sub).servers.list())
        except Exception as exc:
            log.warning("postgres list failed for %s: %s", sub, exc)
            continue
        for srv in servers:
            total += 1
            rg = _rg_of(srv.id)
            try:
                rules = list(arm.postgres(sub).firewall_rules.list_by_server(rg, srv.name))
            except Exception:
                continue
            for r in rules:
                if (getattr(r, "name", "") or "").lower() == "allowallwindowsazureips" or (
                    getattr(r, "start_ip_address", "") == "0.0.0.0"
                    and getattr(r, "end_ip_address", "") == "0.0.0.0"
                ):
                    failures.append({"subscription": sub, "server": srv.name, "rule": r.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="No PostgreSQL servers allow access from Azure services.",
        fail_summary=f"{len(failures)} PostgreSQL server(s) allow Azure services.",
    )


@check("CIS-AZ-FND-4.3.8")
def pg_double_encryption(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            servers = list(arm.postgres(sub).servers.list())
        except Exception as exc:
            log.warning("postgres list failed for %s: %s", sub, exc)
            continue
        for srv in servers:
            total += 1
            inf = getattr(srv, "infrastructure_encryption", None)
            if str(inf).lower() != "enabled":
                failures.append({"subscription": sub, "server": srv.name, "infra": str(inf) or "disabled"})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All PostgreSQL servers have infrastructure double encryption enabled.",
        fail_summary=f"{len(failures)} PostgreSQL server(s) lack double encryption.",
    )


# ----------------------------------------------------------------- 4.4.3 / 4.4.4 - MySQL audit

def _mysql_param_check(param: str, expected_substr: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        arm = ArmClient(ctx.credential)
        failures: list[dict] = []
        total = 0
        for sub in iter_subscriptions(ctx):
            try:
                servers = list(arm.mysql(sub).servers.list())
            except Exception:
                continue
            for srv in servers:
                total += 1
                rg = _rg_of(srv.id)
                try:
                    params = list(arm.mysql(sub).configurations.list_by_server(rg, srv.name))
                except Exception:
                    continue
                cfg = next((p for p in params if p.name == param), None)
                val = (getattr(cfg, "value", "") or "").lower()
                if expected_substr.lower() not in val:
                    failures.append({"subscription": sub, "server": srv.name, param: val or "unset"})
        return fail_or_pass(
            control,
            failures=failures,
            total=total,
            pass_summary=f"All MySQL servers have '{param}' contains '{expected_substr}'.",
            fail_summary=f"{len(failures)} MySQL server(s) misconfigured for '{param}'.",
        )
    return fn


check("CIS-AZ-FND-4.4.3")(_mysql_param_check("audit_log_enabled", "on"))
check("CIS-AZ-FND-4.4.4")(_mysql_param_check("audit_log_events", "connection"))


# ----------------------------------------------------------------- 4.5.2 Cosmos private endpoints

@check("CIS-AZ-FND-4.5.2")
def cosmos_private_endpoints(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            accs = list(arm.cosmos(sub).database_accounts.list())
        except Exception:
            continue
        for acc in accs:
            total += 1
            peconns = list(getattr(acc, "private_endpoint_connections", []) or [])
            if not peconns:
                failures.append({"subscription": sub, "account": acc.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All Cosmos DB accounts have private endpoint connections.",
        fail_summary=f"{len(failures)} Cosmos DB account(s) lack private endpoints.",
    )


@check("CIS-AZ-FND-4.5.3")
def cosmos_aad_clientauth(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            accs = list(arm.cosmos(sub).database_accounts.list())
        except Exception as exc:
            log.warning("cosmos list failed for %s: %s", sub, exc)
            continue
        for acc in accs:
            total += 1
            if not getattr(acc, "disable_local_auth", False):
                failures.append({
                    "account": acc.name, "subscription": sub,
                    "issue": "local auth (account keys) still enabled",
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All Cosmos DB accounts disable local key auth (Entra-only).",
        fail_summary=f"{len(failures)} Cosmos DB account(s) still allow account-key auth.",
    )
