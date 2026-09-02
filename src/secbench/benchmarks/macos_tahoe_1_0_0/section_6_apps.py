"""Section 6 - Applications (Safari, Terminal, Mail)."""

from __future__ import annotations

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check
from ._helpers import defaults_bool, require_target


def _safari(domain_key: str, want: bool, *, prefer_pass_when_unset: bool):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        v = defaults_bool(ctx, "com.apple.Safari", domain_key)
        if v == want:
            return make_result(control, Status.PASS, f"{domain_key}={v}")
        if v is None:
            if prefer_pass_when_unset:
                return make_result(control, Status.PASS, f"{domain_key} unset (default secure).")
            return make_result(control, Status.MANUAL, f"{domain_key} not present in defaults.")
        return make_result(control, Status.FAIL, f"{domain_key}={v}")
    return fn


# 6.2.1 - 'AutoOpenSafeDownloads' must be False
check("CIS-MACOS-6.2.1")(_safari("AutoOpenSafeDownloads", want=False, prefer_pass_when_unset=False))
# 6.2.2 - 'WarnAboutFraudulentWebsites' must be True
check("CIS-MACOS-6.2.2")(_safari("WarnAboutFraudulentWebsites", want=True, prefer_pass_when_unset=False))
# 6.2.3 - Safari Java disabled
check("CIS-MACOS-6.2.3")(_safari("WebKitJavaEnabled", want=False, prefer_pass_when_unset=True))
# 6.2.4 - Show full URL
check("CIS-MACOS-6.2.4")(_safari("ShowFullURLInSmartSearchField", want=True, prefer_pass_when_unset=False))
# 6.2.5 - prevent cross-site tracking
check("CIS-MACOS-6.2.5")(_safari("WebKitPreferences.privateClickMeasurementEnabled", want=True, prefer_pass_when_unset=True))
# 6.2.6 - hide IP from trackers
check("CIS-MACOS-6.2.6")(_safari("WBSPrivacyProxyAvailabilityTraffic", want=True, prefer_pass_when_unset=True))
# 6.2.7 - AutoFill disabled
@check("CIS-MACOS-6.2.7")
def autofill_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    keys = ("AutoFillFromAddressBook", "AutoFillPasswords",
            "AutoFillCreditCardData", "AutoFillMiscellaneousForms")
    bad = []
    for k in keys:
        v = defaults_bool(ctx, "com.apple.Safari", k)
        if v is True:
            bad.append(k)
    if bad:
        return make_result(control, Status.FAIL, f"AutoFill enabled for: {', '.join(bad)}")
    return make_result(control, Status.PASS, "AutoFill disabled across all categories.")


@check("CIS-MACOS-6.3.1")
def terminal_secure_keyboard(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "com.apple.Terminal", "SecureKeyboardEntry")
    if v is True:
        return make_result(control, Status.PASS, "SecureKeyboardEntry=true")
    return make_result(control, Status.FAIL, f"SecureKeyboardEntry={v}")


@check("CIS-MACOS-6.3.2")
def terminal_close_on_exit(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    # WhenToCloseAfterExit: 0 = never, 1 = on clean exit, 2 = always.
    from ._helpers import defaults_int
    v = defaults_int(ctx, "com.apple.Terminal", "shellExitAction")
    if v in (1, 2):
        return make_result(control, Status.PASS, f"shellExitAction={v}")
    if v is None:
        return make_result(control, Status.MANUAL, "shellExitAction not set in defaults.")
    return make_result(control, Status.FAIL, f"shellExitAction={v}")
