"""Azure Storage 1.0.0 - Section 3: File Service."""

from __future__ import annotations

import logging

from ...azure_client.arm import ArmClient
from ...engine.helpers import error_result, fail_or_pass, iter_subscriptions
from ...engine.models import CheckResult, Context, Control
from ...engine.registry import check

log = logging.getLogger(__name__)


def _rg(rid: str) -> str:
    if "/resourceGroups/" not in (rid or ""):
        return ""
    return rid.split("/resourceGroups/")[1].split("/")[0]


@check("CIS-AZ-STG-3.4")
def file_share_soft_delete(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            accs = list(arm.storage(sub).storage_accounts.list())
        except Exception as exc:
            log.warning("stg list failed: %s", exc)
            continue
        for a in accs:
            total += 1
            rg = _rg(a.id)
            try:
                props = arm.storage(sub).file_services.get_service_properties(rg, a.name)
            except Exception as exc:
                failures.append({"subscription": sub, "name": a.name, "error": str(exc)})
                continue
            drp = getattr(props, "share_delete_retention_policy", None)
            if not (drp and getattr(drp, "enabled", False)):
                failures.append({"subscription": sub, "name": a.name})
    return fail_or_pass(
        control, failures=failures, total=total,
        pass_summary="File share soft delete enabled on all storage accounts.",
        fail_summary=f"{len(failures)} storage account(s) lack file share soft delete.",
    )


@check("CIS-AZ-STG-3.2")
def smb_min_version(ctx: Context, control: Control) -> CheckResult:
    arm = ArmClient(ctx.credential)
    failures = []
    total = 0
    for sub in iter_subscriptions(ctx):
        try:
            accs = list(arm.storage(sub).storage_accounts.list())
        except Exception as exc:
            log.warning("stg list failed: %s", exc)
            continue
        for a in accs:
            total += 1
            rg = _rg(a.id)
            try:
                props = arm.storage(sub).file_services.get_service_properties(rg, a.name)
            except Exception as exc:
                failures.append({"subscription": sub, "name": a.name, "error": str(exc)})
                continue
            smb = getattr(getattr(props, "protocol_settings", None), "smb", None)
            versions = (getattr(smb, "versions", "") or "") if smb else ""
            # Acceptable if explicitly SMB3.0 / 3.1.1 only, or unset (defaults to >=3.0).
            if "SMB2" in versions:
                failures.append({"subscription": sub, "name": a.name, "smb_versions": versions})
    return fail_or_pass(
        control, failures=failures, total=total,
        pass_summary="No storage accounts allow SMB 2.x.",
        fail_summary=f"{len(failures)} storage account(s) allow SMB 2.x.",
    )
