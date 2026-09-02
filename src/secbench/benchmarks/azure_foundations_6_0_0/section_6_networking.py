"""Azure Foundations 6.0.0 - Section 6: Networking."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


_INTERNET_RANGES = ("*", "0.0.0.0/0", "internet", "any")


def _list_nsgs(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            nsgs = cached(
                ctx, "nsg.list", sub,
                factory=lambda s=sub: list(arm.network(s).network_security_groups.list_all()),
            )
        except Exception as exc:
            log.warning("nsg list failed: %s", exc)
            continue
        for nsg in nsgs:
            out.append((sub, nsg))
    return out


def _is_internet_source(rule) -> bool:
    src = (getattr(rule, "source_address_prefix", "") or "").lower()
    if src in _INTERNET_RANGES:
        return True
    src_pfxs = [str(x).lower() for x in (getattr(rule, "source_address_prefixes", []) or [])]
    return any(p in _INTERNET_RANGES for p in src_pfxs)


def _matches_port(rule, port: int) -> bool:
    pr = getattr(rule, "destination_port_range", "") or ""
    pr_list = [str(x) for x in (getattr(rule, "destination_port_ranges", []) or [])]
    candidates = [pr] + pr_list
    for c in candidates:
        if not c:
            continue
        if c == "*":
            return True
        if str(port) == c:
            return True
        if "-" in c:
            try:
                lo, hi = c.split("-", 1)
                if int(lo) <= port <= int(hi):
                    return True
            except ValueError:
                continue
    return False


def _open_to_internet_for_port(port: int, ctx: Context, control: Control, port_label: str) -> CheckResult:
    try:
        nsgs = _list_nsgs(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, nsg in nsgs:
        for rule in (getattr(nsg, "security_rules", []) or []):
            if str(getattr(rule, "access", "")).lower() != "allow":
                continue
            if str(getattr(rule, "direction", "")).lower() != "inbound":
                continue
            if not _is_internet_source(rule):
                continue
            if _matches_port(rule, port):
                failures.append({
                    "subscription": sub,
                    "nsg": nsg.name,
                    "rule": rule.name,
                    "port": port_label,
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(nsgs),
        pass_summary=f"No NSG inbound rules expose {port_label} to the internet.",
        fail_summary=f"{len(failures)} NSG rule(s) expose {port_label} to the internet.",
    )


@check("CIS-AZ-FND-6.1")
def rdp_restricted(ctx: Context, control: Control) -> CheckResult:
    return _open_to_internet_for_port(3389, ctx, control, "RDP/3389")


@check("CIS-AZ-FND-6.2")
def ssh_restricted(ctx: Context, control: Control) -> CheckResult:
    return _open_to_internet_for_port(22, ctx, control, "SSH/22")


@check("CIS-AZ-FND-6.3")
def udp_restricted(ctx: Context, control: Control) -> CheckResult:
    try:
        nsgs = _list_nsgs(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, nsg in nsgs:
        for rule in (getattr(nsg, "security_rules", []) or []):
            if str(getattr(rule, "access", "")).lower() != "allow":
                continue
            if str(getattr(rule, "direction", "")).lower() != "inbound":
                continue
            if str(getattr(rule, "protocol", "")).lower() != "udp":
                continue
            if _is_internet_source(rule):
                failures.append({
                    "subscription": sub,
                    "nsg": nsg.name,
                    "rule": rule.name,
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(nsgs),
        pass_summary="No NSG inbound rules expose UDP services to the internet.",
        fail_summary=f"{len(failures)} NSG rule(s) expose UDP services to the internet.",
    )


@check("CIS-AZ-FND-6.4")
def http_restricted(ctx: Context, control: Control) -> CheckResult:
    try:
        nsgs = _list_nsgs(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, nsg in nsgs:
        for rule in (getattr(nsg, "security_rules", []) or []):
            if str(getattr(rule, "access", "")).lower() != "allow":
                continue
            if str(getattr(rule, "direction", "")).lower() != "inbound":
                continue
            if not _is_internet_source(rule):
                continue
            if _matches_port(rule, 80) or _matches_port(rule, 443):
                failures.append({
                    "subscription": sub,
                    "nsg": nsg.name,
                    "rule": rule.name,
                })
    return fail_or_pass(
        control,
        failures=failures,
        total=len(nsgs),
        pass_summary="HTTP/HTTPS exposure to the internet is restricted (or not present).",
        fail_summary=f"{len(failures)} NSG rule(s) expose HTTP/HTTPS to the internet without restriction.",
    )


@check("CIS-AZ-FND-6.5")
def nsg_flow_log_retention(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            watchers = list(arm.network(sub).network_watchers.list_all())
        except Exception as exc:
            log.warning("nw list failed: %s", exc)
            continue
        for nw in watchers:
            try:
                rg = nw.id.split("/resourceGroups/")[1].split("/")[0]
            except IndexError:
                continue
            try:
                flow_logs = list(arm.network(sub).flow_logs.list(rg, nw.name))
            except Exception:
                continue
            for fl in flow_logs:
                total += 1
                rp = getattr(fl, "retention_policy", None)
                days = int(getattr(rp, "days", 0) or 0) if rp else 0
                enabled = getattr(rp, "enabled", False) if rp else False
                if not enabled or days < 90:
                    failures.append({
                        "subscription": sub,
                        "watcher": nw.name,
                        "flow_log": fl.name,
                        "retention_days": days,
                        "enabled": enabled,
                    })
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All NSG flow logs retain >= 90 days.",
        fail_summary=f"{len(failures)} NSG flow log(s) retain < 90 days.",
    )


@check("CIS-AZ-FND-6.6")
def network_watcher_enabled(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        total += 1
        try:
            watchers = list(arm.network(sub).network_watchers.list_all())
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        if not watchers:
            failures.append({"subscription": sub, "issue": "no Network Watcher exists"})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="Network Watcher exists in every subscription.",
        fail_summary=f"{len(failures)} subscription(s) have no Network Watcher.",
    )
