"""Section 5 - System Access, Authentication and Authorization."""

from __future__ import annotations

import re

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check
from ._helpers import defaults_bool, defaults_int, require_target, run


# ----------------------------------------- 5.1 Home / Library / Apps perms

def _home_perm_check(rel: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        # Use the current shell's $HOME on the target.
        res = run(ctx, ["/bin/sh", "-c",
                        f"for u in $(/usr/bin/dscl . -list /Users UniqueID | "
                        f"awk '$2 >= 500 {{print $1}}'); do h=$(/usr/bin/dscl . -read "
                        f"/Users/$u NFSHomeDirectory | awk -F': ' '{{print $2}}'); "
                        f"[ -d \"$h{rel}\" ] && /bin/ls -ld \"$h{rel}\" | "
                        f"awk '{{print $1\"|\"$3\"|\"$NF}}'; done"])
        failures = []
        for line in res.stdout.splitlines():
            try:
                mode, owner, path = line.split("|", 2)
            except ValueError:
                continue
            # Want drwx------ (700) - i.e. no group/other perms.
            if mode[4:] != "------" and mode[4:] != "-x-----" and mode[4:] != "------+":
                # Tolerate '+' (ACL flag).
                if mode[4:].rstrip("+").rstrip() not in ("------",):
                    failures.append(f"{path} {mode}")
        if failures:
            return make_result(control, Status.FAIL,
                               f"{len(failures)} dir(s) too permissive",
                               evidence=[{"items": failures[:20]}])
        return make_result(control, Status.PASS, "Permissions OK on all user homes.")
    return fn


check("CIS-MACOS-5.1.1")(_home_perm_check(""))
check("CIS-MACOS-5.1.2")(_home_perm_check("/Library"))


@check("CIS-MACOS-5.1.4")
def applications_permissions(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["/bin/sh", "-c",
                    "/usr/bin/find /Applications -maxdepth 4 -type d -perm -2 -print 2>/dev/null | head -50"])
    if res.stdout.strip():
        return make_result(control, Status.FAIL,
                           "World-writable directories under /Applications.",
                           evidence=[{"paths": res.stdout.strip().splitlines()[:30]}])
    return make_result(control, Status.PASS, "No world-writable items under /Applications.")


# ----------------------------------------- 5.2 pwpolicy / password policy

def _pwpolicy_match(ctx: Context, regex: str) -> bool:
    res = run(ctx, ["pwpolicy", "-getaccountpolicies"])
    if res.rc != 0:
        return False
    return bool(re.search(regex, res.stdout))


@check("CIS-MACOS-5.2.1")
def pw_lockout(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    if _pwpolicy_match(ctx, r"policyAttributeMaximumFailedAuthentications\s*[<&]"):
        return make_result(control, Status.PASS,
                           "policyAttributeMaximumFailedAuthentications policy present.")
    return make_result(control, Status.FAIL, "Lockout policy not configured.")


@check("CIS-MACOS-5.2.2")
def pw_min_length(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    if _pwpolicy_match(ctx, r"minimumLength.*?>\s*1[5-9]"):
        return make_result(control, Status.PASS, "minimumLength >= 15 enforced.")
    return make_result(control, Status.FAIL, "minimumLength of 15 not enforced.")


@check("CIS-MACOS-5.2.3")
def pw_complex(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["pwpolicy", "-getaccountpolicies"])
    if "MatchesNumber" in res.stdout and ("MatchesAlpha" in res.stdout or "MatchesUpper" in res.stdout):
        return make_result(control, Status.PASS, "Alpha+Numeric complexity required.")
    return make_result(control, Status.FAIL, "Complexity policy not present.")


@check("CIS-MACOS-5.2.4")
def pw_max_age(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    if _pwpolicy_match(ctx, r"policyAttributeCurrentPasswordAge|maxMinutesUntilChangePassword"):
        return make_result(control, Status.PASS, "Maximum password age policy present.")
    return make_result(control, Status.FAIL, "No max-age policy.")


@check("CIS-MACOS-5.2.5")
def pw_history(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["pwpolicy", "-getaccountpolicies"])
    m = re.search(r"policyAttributePasswordHistoryDepth.*?(\d+)", res.stdout)
    if m and int(m.group(1)) >= 15:
        return make_result(control, Status.PASS, f"History depth = {m.group(1)}")
    if m:
        return make_result(control, Status.FAIL, f"History depth = {m.group(1)}")
    return make_result(control, Status.FAIL, "No history policy.")


@check("CIS-MACOS-5.2.6")
def pw_hint_unset(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["/bin/sh", "-c",
                    "for u in $(/usr/bin/dscl . list /Users hint 2>/dev/null | awk '{print $1}'); "
                    "do h=$(/usr/bin/dscl . -read /Users/$u hint 2>/dev/null | awk -F': ' '{print $2}'); "
                    "[ -n \"$h\" ] && echo \"$u\"; done"])
    if res.stdout.strip():
        return make_result(control, Status.FAIL,
                           "Some users have password hints set.",
                           evidence=[{"users": res.stdout.strip().splitlines()}])
    return make_result(control, Status.PASS, "No users have password hints set.")


# ------------------------------------------------------------------- 5.3-5.10

@check("CIS-MACOS-5.3")
def sudo_timeout(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "grep", "-r", "timestamp_timeout", "/etc/sudoers", "/etc/sudoers.d/"],
              timeout=10.0)
    if "timestamp_timeout=0" in res.stdout:
        return make_result(control, Status.PASS, "timestamp_timeout=0 set.")
    if "timestamp_timeout" in res.stdout:
        return make_result(control, Status.FAIL,
                           "timestamp_timeout configured but not 0.",
                           evidence=[{"output": res.stdout[:500]}])
    return make_result(control, Status.FAIL, "No timestamp_timeout=0 in sudoers config.")


@check("CIS-MACOS-5.4")
def cd_dvd_login(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "grep", "-c", "console none", "/etc/ttys"])
    if res.stdout.strip().isdigit() and int(res.stdout.strip()) >= 1:
        # console line should NOT be 'secure' for CD/DVD; CIS check 5.4 is now usually
        # treated as N/A for Apple Silicon.
        return make_result(control, Status.PASS,
                           "ttys console entry exists (CD/DVD root login is constrained on modern macOS).")
    return make_result(control, Status.MANUAL, "Could not parse /etc/ttys.")


@check("CIS-MACOS-5.5")
def root_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["dscl", ".", "-read", "/Users/root", "AuthenticationAuthority"])
    out = (res.stdout + res.stderr).lower()
    if "no such key" in out or "does not exist" in out:
        return make_result(control, Status.PASS, "root has no AuthenticationAuthority (disabled).")
    if "disabledtags" in out:
        return make_result(control, Status.PASS, "root account is disabled.")
    return make_result(control, Status.FAIL,
                       "root account appears enabled.", evidence=[{"output": res.stdout[:500]}])


@check("CIS-MACOS-5.6")
def auto_login_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    rc, out = run(ctx, ["defaults", "read", "/Library/Preferences/com.apple.loginwindow",
                        "autoLoginUser"]).rc, ""
    if rc != 0:
        return make_result(control, Status.PASS, "autoLoginUser not set.")
    return make_result(control, Status.FAIL, "autoLoginUser is set.")


@check("CIS-MACOS-5.8")
def guest_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
    if v is False:
        return make_result(control, Status.PASS, "GuestEnabled=NO")
    if v is None:
        return make_result(control, Status.PASS, "GuestEnabled not set (default disabled).")
    return make_result(control, Status.FAIL, "GuestEnabled=YES")


@check("CIS-MACOS-5.9")
def guest_smb_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "/Library/Preferences/com.apple.AppleFileServer", "guestAccess")
    if v is False or v is None:
        return make_result(control, Status.PASS, "Guest access to file shares disabled.")
    return make_result(control, Status.FAIL, "Guest file share access enabled.")


@check("CIS-MACOS-5.10")
def show_pw_fields(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "/Library/Preferences/com.apple.loginwindow",
                      "DisableFDEAutoLogin")
    if v is True:
        return make_result(control, Status.PASS, "DisableFDEAutoLogin=YES")
    return make_result(control, Status.FAIL, f"DisableFDEAutoLogin={v}")
