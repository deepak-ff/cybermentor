"""Section 4 - Network configurations."""

from __future__ import annotations

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check
from ._helpers import defaults_bool, require_target, run


@check("CIS-MACOS-4.1")
def wifi_in_menubar(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "com.apple.controlcenter", "WiFi")
    if v in (True, None):
        # The default for new accounts is to show Wi-Fi - treat None as PASS.
        return make_result(control, Status.PASS, "Wi-Fi menu bar item present (or default).")
    return make_result(control, Status.FAIL, "Wi-Fi menu bar item disabled.")


@check("CIS-MACOS-4.2")
def bonjour_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "/Library/Preferences/com.apple.mDNSResponder.plist",
                      "NoMulticastAdvertisements")
    if v is True:
        return make_result(control, Status.PASS, "Bonjour multicast advertisements disabled.")
    return make_result(control, Status.FAIL, f"NoMulticastAdvertisements={v}")


def _service_disabled_by_label(label: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, ["sudo", "launchctl", "print-disabled", "system"])
        out = res.stdout
        target = f'"{label}" => true'
        if target in out:
            return make_result(control, Status.PASS, f"{label} disabled.")
        # If the label is simply not loaded at all, that's also OK.
        chk = run(ctx, ["sudo", "launchctl", "list"])
        if label not in chk.stdout:
            return make_result(control, Status.PASS, f"{label} not loaded.")
        return make_result(control, Status.FAIL, f"{label} appears to be enabled/loaded.")
    return fn


check("CIS-MACOS-4.3")(_service_disabled_by_label("org.apache.httpd"))
check("CIS-MACOS-4.4")(_service_disabled_by_label("com.apple.nfsd"))
check("CIS-MACOS-4.5")(_service_disabled_by_label("com.apple.smbd"))
check("CIS-MACOS-4.6")(_service_disabled_by_label("com.apple.ftpd"))


@check("CIS-MACOS-4.7")
def ipv6_forwarding_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "sysctl", "-n", "net.inet6.ip6.forwarding"])
    if res.stdout.strip() == "0":
        return make_result(control, Status.PASS, "net.inet6.ip6.forwarding=0")
    return make_result(control, Status.FAIL, f"net.inet6.ip6.forwarding={res.stdout.strip()}")


@check("CIS-MACOS-4.8")
def ip_forwarding_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "sysctl", "-n", "net.inet.ip.forwarding"])
    if res.stdout.strip() == "0":
        return make_result(control, Status.PASS, "net.inet.ip.forwarding=0")
    return make_result(control, Status.FAIL, f"net.inet.ip.forwarding={res.stdout.strip()}")
