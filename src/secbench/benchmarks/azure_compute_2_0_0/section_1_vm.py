"""Azure Compute 2.0.0 - Section 1: Virtual Machines."""

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


@check("CIS-AZ-CMP-1.3")
def managed_disks(ctx: Context, control: Control) -> CheckResult:
    try:
        vms = _list_vms(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, vm in vms:
        sp = getattr(vm, "storage_profile", None)
        os_disk = getattr(sp, "os_disk", None) if sp else None
        if not (os_disk and getattr(os_disk, "managed_disk", None)):
            failures.append({"subscription": sub, "vm": vm.name})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(vms),
        pass_summary="All VMs use managed disks.",
        fail_summary=f"{len(failures)} VM(s) still use unmanaged VHDs.",
    )


@check("CIS-AZ-CMP-1.10")
def trusted_launch(ctx: Context, control: Control) -> CheckResult:
    try:
        vms = _list_vms(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    for sub, vm in vms:
        sec = getattr(vm, "security_profile", None)
        st = (getattr(sec, "security_type", "") or "").lower() if sec else ""
        if st != "trustedlaunch":
            failures.append({"subscription": sub, "vm": vm.name, "security_type": st or "none"})
    return fail_or_pass(
        control,
        failures=failures,
        total=len(vms),
        pass_summary="All VMs use Trusted Launch.",
        fail_summary=f"{len(failures)} VM(s) are not using Trusted Launch.",
    )


@check("CIS-AZ-CMP-1.14")
def no_public_ip(ctx: Context, control: Control) -> CheckResult:
    try:
        vms = _list_vms(ctx)
    except Exception as exc:
        return error_result(control, exc)
    failures = []
    arm = ArmClient(ctx.credential)
    for sub, vm in vms:
        nics = getattr(getattr(vm, "network_profile", None), "network_interfaces", []) or []
        nic_ids = [n.id for n in nics if getattr(n, "id", None)]
        for nic_id in nic_ids:
            try:
                rg = nic_id.split("/resourceGroups/")[1].split("/")[0]
                name = nic_id.split("/")[-1]
                nic = arm.network(sub).network_interfaces.get(rg, name)
                ip_configs = getattr(nic, "ip_configurations", []) or []
                for ipc in ip_configs:
                    if getattr(ipc, "public_ip_address", None) is not None:
                        failures.append({"subscription": sub, "vm": vm.name, "nic": name})
                        break
            except Exception as exc:
                log.warning("nic fetch failed: %s", exc)
    return fail_or_pass(
        control,
        failures=failures,
        total=len(vms),
        pass_summary="No VMs have public IPs attached.",
        fail_summary=f"{len(failures)} VM(s) have a public IP attached.",
    )
