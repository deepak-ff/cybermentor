"""Azure Foundations 6.0.0 - Section 7: Virtual Machines."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import cached, error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _list_vms(ctx: Context):
    arm = ArmClient(ctx.credential)
    out = []
    for sub in iter_subscriptions(ctx):
        try:
            vms = cached(
                ctx, "vm.list", sub,
                factory=lambda s=sub: list(arm.compute(s).virtual_machines.list_all()),
            )
        except Exception as exc:
            log.warning("vm list failed: %s", exc)
            continue
        for vm in vms:
            out.append((sub, vm))
    return out


@check("CIS-AZ-FND-7.2")
def vm_managed_disks(ctx: Context, control: Control) -> CheckResult:
    try:
        vms = _list_vms(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, vm in vms:
        sp = getattr(vm, "storage_profile", None)
        os_disk = getattr(sp, "os_disk", None) if sp else None
        managed = getattr(os_disk, "managed_disk", None) if os_disk else None
        if managed is None:
            failures.append({"subscription": sub, "vm": vm.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(vms),
        pass_summary="All virtual machines use managed disks.",
        fail_summary=f"{len(failures)} VM(s) still use unmanaged VHDs.",
    )


@check("CIS-AZ-FND-7.9")
def vm_trusted_launch(ctx: Context, control: Control) -> CheckResult:
    try:
        vms = _list_vms(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures: list[dict] = []
    for sub, vm in vms:
        sec = getattr(vm, "security_profile", None)
        st = getattr(sec, "security_type", "") if sec else ""
        if str(st).lower() != "trustedlaunch":
            failures.append({"subscription": sub, "vm": vm.name, "security_type": str(st) or "none"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(vms),
        pass_summary="All VMs use Trusted Launch.",
        fail_summary=f"{len(failures)} VM(s) are not using Trusted Launch.",
    )


@check("CIS-AZ-FND-7.1")
def bastion_exists(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    subs = iter_subscriptions(ctx)
    for sub in subs:
        try:
            hosts = list(arm.network(sub).bastion_hosts.list())
        except Exception as exc:
            failures.append({"subscription": sub, "error": str(exc)})
            continue
        if not hosts:
            failures.append({"subscription": sub, "issue": "no Azure Bastion host exists"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(subs),
        pass_summary="At least one Azure Bastion host exists in every subscription.",
        fail_summary=f"{len(failures)} subscription(s) have no Azure Bastion host.",
    )


@check("CIS-AZ-FND-7.4")
def unattached_disks_cmk(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            disks = list(arm.compute(sub).disks.list())
        except Exception as exc:
            log.warning("disk list failed: %s", exc)
            continue
        for d in disks:
            if getattr(d, "managed_by", None):
                continue  # attached
            total += 1
            enc = getattr(d, "encryption", None)
            t = (getattr(enc, "type", "") or "").lower() if enc else ""
            if "customer" not in t and "platformandcustomer" not in t:
                failures.append({"subscription": sub, "disk": d.name, "type": t or "platform"})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All unattached managed disks use customer-managed keys.",
        fail_summary=f"{len(failures)} unattached disk(s) lack CMK encryption.",
    )


@check("CIS-AZ-FND-7.6")
def endpoint_protection(ctx: Context, control: Control) -> CheckResult:
    """VMs should have an endpoint protection extension (e.g. MDE.Linux/MDE.Windows or IaaSAntimalware)."""
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    accepted = (
        "iaasantimalware",
        "mde.linux",
        "mde.windows",
        "microsoftdefenderforendpoint",
        "azuresecuritylinuxagent",
        "azuresecuritywindowsagent",
    )
    for sub in iter_subscriptions(ctx):
        try:
            vms = list(arm.compute(sub).virtual_machines.list_all())
        except Exception:
            continue
        for vm in vms:
            total += 1
            rg = vm.id.split("/resourceGroups/")[1].split("/")[0]
            try:
                exts = list(arm.compute(sub).virtual_machine_extensions.list(rg, vm.name).value or [])
            except Exception:
                exts = []
            ok = False
            for e in exts:
                t = (getattr(e, "type_properties_type", "") or getattr(e, "virtual_machine_extension_type", "") or "")
                p = (getattr(e, "publisher", "") or "")
                ident = (t + p).lower()
                if any(a in ident for a in accepted):
                    ok = True
                    break
            if not ok:
                failures.append({"subscription": sub, "vm": vm.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All VMs have an endpoint protection extension installed.",
        fail_summary=f"{len(failures)} VM(s) lack an endpoint protection extension.",
    )


@check("CIS-AZ-FND-7.7")
def vhds_encrypted(ctx: Context, control: Control) -> CheckResult:
    """Same intent as 7.3 but covers OS+data disk encryption ('Azure Disk Encryption' or SSE)."""
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            disks = list(arm.compute(sub).disks.list())
        except Exception:
            continue
        for d in disks:
            total += 1
            enc = getattr(d, "encryption_settings_collection", None)
            sse = getattr(d, "encryption", None)
            ade_enabled = bool(getattr(enc, "enabled", False)) if enc else False
            sse_type = (getattr(sse, "type", "") or "").lower() if sse else ""
            if not (ade_enabled or sse_type):
                failures.append({"subscription": sub, "disk": d.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All managed disks have encryption (ADE or SSE) configured.",
        fail_summary=f"{len(failures)} disk(s) appear unencrypted.",
    )


@check("CIS-AZ-FND-7.3")
def vm_disks_cmk(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures: list[dict] = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            disks = list(arm.compute(sub).disks.list())
        except Exception as exc:
            log.warning("disk list failed: %s", exc)
            continue
        for d in disks:
            total += 1
            enc = getattr(d, "encryption", None)
            t = (getattr(enc, "type", "") or "").lower() if enc else ""
            if "customer" not in t and "platformandcustomer" not in t:
                failures.append({"subscription": sub, "disk": d.name, "type": t or "platform"})
    return fail_or_pass(
        control,
        failures=failures,
        total=total,
        pass_summary="All managed disks use customer-managed keys.",
        fail_summary=f"{len(failures)} managed disk(s) lack customer-managed key encryption.",
    )
