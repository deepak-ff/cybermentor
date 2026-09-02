"""Section 1 - Software updates."""

from __future__ import annotations

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check
from ._helpers import defaults_bool, require_target, run


@check("CIS-MACOS-1.1")
def all_apple_software_current(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["softwareupdate", "-l"], timeout=120.0)
    out = (res.stdout or "") + "\n" + (res.stderr or "")
    if "No new software available" in out or "No updates available" in out.lower():
        return make_result(control, Status.PASS, "softwareupdate reports no pending updates.")
    if "Software Update found" in out or "* Label:" in out or "Recommended:" in out:
        return make_result(control, Status.FAIL,
                           "softwareupdate found pending updates.",
                           evidence=[{"output": out[:1500]}])
    return make_result(control, Status.MANUAL,
                       "Could not parse softwareupdate output; verify manually.",
                       evidence=[{"output": out[:1500]}])


def _su_bool(key: str, summary_pass: str, summary_fail: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        v = defaults_bool(ctx, "/Library/Preferences/com.apple.SoftwareUpdate", key)
        if v is None:
            return make_result(control, Status.MANUAL,
                               f"Could not read SoftwareUpdate.{key}; verify in System Settings.")
        return make_result(control, Status.PASS if v else Status.FAIL,
                           summary_pass if v else summary_fail)
    return fn


check("CIS-MACOS-1.2")(_su_bool("AutomaticCheckEnabled",
                                "AutomaticCheckEnabled = true.",
                                "AutomaticCheckEnabled is not enabled."))
check("CIS-MACOS-1.3")(_su_bool("AutomaticDownload",
                                "AutomaticDownload = true.",
                                "AutomaticDownload is not enabled."))
check("CIS-MACOS-1.4")(_su_bool("AutomaticallyInstallMacOSUpdates",
                                "AutomaticallyInstallMacOSUpdates = true.",
                                "AutomaticallyInstallMacOSUpdates is not enabled."))


@check("CIS-MACOS-1.5")
def app_store_auto_update(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "/Library/Preferences/com.apple.commerce", "AutoUpdate")
    if v is None:
        return make_result(control, Status.MANUAL, "Could not read commerce.AutoUpdate.")
    return make_result(control, Status.PASS if v else Status.FAIL,
                       "App Store auto-update is enabled." if v
                       else "App Store auto-update is disabled.")


@check("CIS-MACOS-1.6")
def security_responses_install(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    inst = defaults_bool(ctx, "/Library/Preferences/com.apple.SoftwareUpdate",
                         "ConfigDataInstall")
    crit = defaults_bool(ctx, "/Library/Preferences/com.apple.SoftwareUpdate",
                         "CriticalUpdateInstall")
    if inst is None or crit is None:
        return make_result(control, Status.MANUAL,
                           "Could not read ConfigDataInstall / CriticalUpdateInstall.")
    if inst and crit:
        return make_result(control, Status.PASS,
                           "ConfigDataInstall and CriticalUpdateInstall are enabled.")
    return make_result(control, Status.FAIL,
                       f"ConfigDataInstall={inst}, CriticalUpdateInstall={crit}")
