"""Automated check registrations for CIS Microsoft Defender AV v1.0.0."""

from __future__ import annotations

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check
from .._windows_common import checks as W
from .._windows_common import get_mp_computer_status, require_target

# 1. Real-time protection
check("CIS-DEFAV-1.1")(W.defender_status_bool("AntivirusEnabled", True))
check("CIS-DEFAV-1.2")(W.defender_pref_bool("DisableRealtimeMonitoring", False))
check("CIS-DEFAV-1.3")(W.defender_pref_bool("DisableBehaviorMonitoring", False))
check("CIS-DEFAV-1.4")(W.defender_pref_bool("DisableOnAccessProtection", False))
check("CIS-DEFAV-1.5")(W.defender_pref_bool("DisableScriptScanning", False))
check("CIS-DEFAV-1.6")(W.defender_pref_bool("DisableIOAVProtection", False))
check("CIS-DEFAV-1.7")(W.defender_pref_bool("DisableRemovableDriveScanning", False))
check("CIS-DEFAV-1.8")(W.defender_pref_bool("DisableEmailScanning", False))
check("CIS-DEFAV-1.9")(W.defender_pref_bool("DisableArchiveScanning", False))

# 2. Cloud-delivered protection
check("CIS-DEFAV-2.1")(W.defender_pref_int("MAPSReporting", 2))


@check("CIS-DEFAV-2.2")
def cloud_block_level(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    from .._windows_common import get_mp_preference
    v = get_mp_preference(ctx, "CloudBlockLevel")
    if v is None:
        return make_result(control, Status.MANUAL, "Could not read CloudBlockLevel.")
    try:
        iv = int(v.split()[0])
    except (ValueError, IndexError):
        return make_result(control, Status.MANUAL, f"CloudBlockLevel={v}")
    if iv >= 2:
        return make_result(control, Status.PASS, f"CloudBlockLevel={iv}")
    return make_result(control, Status.FAIL, f"CloudBlockLevel={iv} (want >= 2)")


@check("CIS-DEFAV-2.3")
def cloud_extended_timeout(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    from .._windows_common import get_mp_preference
    v = get_mp_preference(ctx, "CloudExtendedTimeout")
    if v is None:
        return make_result(control, Status.MANUAL, "Could not read CloudExtendedTimeout.")
    try:
        iv = int(v.split()[0])
    except (ValueError, IndexError):
        return make_result(control, Status.MANUAL, f"CloudExtendedTimeout={v}")
    if iv >= 50:
        return make_result(control, Status.PASS, f"CloudExtendedTimeout={iv}")
    return make_result(control, Status.FAIL,
                       f"CloudExtendedTimeout={iv} (want >= 50)")


@check("CIS-DEFAV-2.4")
def submit_samples_consent(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    from .._windows_common import get_mp_preference
    v = get_mp_preference(ctx, "SubmitSamplesConsent")
    if v is None:
        return make_result(control, Status.MANUAL, "Could not read SubmitSamplesConsent.")
    try:
        iv = int(v.split()[0])
    except (ValueError, IndexError):
        return make_result(control, Status.MANUAL, f"SubmitSamplesConsent={v}")
    if iv in (1, 3):
        return make_result(control, Status.PASS, f"SubmitSamplesConsent={iv}")
    return make_result(control, Status.FAIL,
                       f"SubmitSamplesConsent={iv} (want 1 or 3)")


check("CIS-DEFAV-2.5")(W.defender_pref_bool("DisableBlockAtFirstSeen", False))

# 3. Network protection and PUA
check("CIS-DEFAV-3.1")(W.defender_pref_int("EnableNetworkProtection", 1))
check("CIS-DEFAV-3.2")(W.defender_pref_int("PUAProtection", 1))
check("CIS-DEFAV-3.3")(W.defender_pref_bool("DisableIntrusionPreventionSystem", False))

# 4. Tamper protection
check("CIS-DEFAV-4.1")(W.defender_status_bool("IsTamperProtected", True))
check("CIS-DEFAV-4.2")(W.defender_pref_bool("DisableLocalAdminMerge", True))
check("CIS-DEFAV-4.3")(W.defender_status_bool("AMServiceEnabled", True))

# 6. Controlled Folder Access
check("CIS-DEFAV-6.1")(W.defender_pref_int("EnableControlledFolderAccess", 1))


# 7. Scanning and updates
@check("CIS-DEFAV-7.3")
def signature_update_interval(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    from .._windows_common import get_mp_preference
    v = get_mp_preference(ctx, "SignatureUpdateInterval")
    if v is None:
        return make_result(control, Status.MANUAL,
                           "Could not read SignatureUpdateInterval.")
    try:
        iv = int(v.split()[0])
    except (ValueError, IndexError):
        return make_result(control, Status.MANUAL,
                           f"SignatureUpdateInterval={v}")
    if iv > 0:
        return make_result(control, Status.PASS,
                           f"SignatureUpdateInterval={iv} hours")
    return make_result(control, Status.FAIL,
                       f"SignatureUpdateInterval={iv} (want > 0)")


@check("CIS-DEFAV-7.4")
def signatures_fresh(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = get_mp_computer_status(ctx, "AntivirusSignatureAge")
    if v is None:
        return make_result(control, Status.MANUAL,
                           "Could not read AntivirusSignatureAge.")
    try:
        days = int(v.split()[0])
    except (ValueError, IndexError):
        return make_result(control, Status.MANUAL,
                           f"AntivirusSignatureAge={v}")
    if days <= 1:
        return make_result(control, Status.PASS,
                           f"AntivirusSignatureAge={days} day(s)")
    return make_result(control, Status.FAIL,
                       f"AntivirusSignatureAge={days} (want <= 1)")


@check("CIS-DEFAV-7.5")
def cpu_load_limited(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    from .._windows_common import get_mp_preference
    v = get_mp_preference(ctx, "ScanAvgCPULoadFactor")
    if v is None:
        return make_result(control, Status.MANUAL,
                           "Could not read ScanAvgCPULoadFactor.")
    try:
        iv = int(v.split()[0])
    except (ValueError, IndexError):
        return make_result(control, Status.MANUAL,
                           f"ScanAvgCPULoadFactor={v}")
    if iv <= 50:
        return make_result(control, Status.PASS, f"ScanAvgCPULoadFactor={iv}")
    return make_result(control, Status.FAIL,
                       f"ScanAvgCPULoadFactor={iv} (want <= 50)")


check("CIS-DEFAV-7.6")(W.defender_pref_bool("DisableCatchupQuickScan", False))


@check("CIS-DEFAV-8.3")
def quarantine_purge(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    from .._windows_common import get_mp_preference
    v = get_mp_preference(ctx, "QuarantinePurgeItemsAfterDelay")
    if v is None:
        return make_result(control, Status.MANUAL,
                           "Could not read QuarantinePurgeItemsAfterDelay.")
    try:
        iv = int(v.split()[0])
    except (ValueError, IndexError):
        return make_result(control, Status.MANUAL, f"value={v}")
    if iv >= 30:
        return make_result(control, Status.PASS,
                           f"QuarantinePurgeItemsAfterDelay={iv}")
    return make_result(control, Status.FAIL,
                       f"QuarantinePurgeItemsAfterDelay={iv} (want >= 30)")
