"""Section 2 - System Settings (Bluetooth, Sharing, Privacy, FileVault, etc.)."""

from __future__ import annotations

import re

from ...engine.helpers import make_result
from ...engine.models import CheckResult, Context, Control, Status
from ...engine.registry import check
from ._helpers import (
    defaults_bool,
    defaults_int,
    defaults_read,
    launchd_loaded,
    pmset_g,
    require_target,
    run,
)


# ----------------------------------------------------------------- 2.2 time

@check("CIS-MACOS-2.2.1")
def time_auto(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["systemsetup", "-getusingnetworktime"])
    out = res.stdout.lower()
    if "on" in out:
        return make_result(control, Status.PASS, "Network time is enabled.")
    if res.rc != 0:
        return make_result(control, Status.MANUAL,
                           f"systemsetup needs sudo or unavailable: {res.stderr.strip()[:200]}")
    return make_result(control, Status.FAIL, f"systemsetup output: {res.stdout.strip()}")


@check("CIS-MACOS-2.2.2")
def time_server(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["systemsetup", "-getnetworktimeserver"])
    out = res.stdout.strip()
    if res.rc != 0 or not out:
        return make_result(control, Status.MANUAL,
                           f"Could not read time server: {res.stderr.strip()[:200]}")
    server = out.split(":", 1)[-1].strip()
    if server and server.lower() not in ("not set", ""):
        return make_result(control, Status.PASS, f"Time server: {server}")
    return make_result(control, Status.FAIL, f"systemsetup output: {out}")


@check("CIS-MACOS-2.2.3")
def dhcpv6_disabled_when_unused(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["networksetup", "-listallnetworkservices"])
    if res.rc != 0:
        return make_result(control, Status.MANUAL, "networksetup unavailable")
    services = [
        s.strip() for s in res.stdout.splitlines()
        if s and not s.startswith("An asterisk") and not s.startswith("*")
    ][1:]
    failures = []
    for svc in services:
        info = run(ctx, ["networksetup", "-getinfo", svc])
        if "IPv6: Automatic" in info.stdout or "IPv6 IP address:" in info.stdout:
            failures.append(svc)
    if not failures:
        return make_result(control, Status.PASS, "DHCPv6 is not configured on any service.")
    return make_result(control, Status.FAIL,
                       f"DHCPv6/IPv6 active on: {', '.join(failures)}")


# -------------------------------------------------------------- 2.3 Bluetooth

@check("CIS-MACOS-2.3.1")
def bluetooth_off_when_unused(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    state = defaults_int(ctx, "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState")
    res = run(ctx, ["system_profiler", "SPBluetoothDataType"])
    if state == 0:
        return make_result(control, Status.PASS, "Bluetooth controller is off.")
    if "Connected: No" in res.stdout and "Bluetooth Power: Off" in res.stdout:
        return make_result(control, Status.PASS, "Bluetooth has no paired connected devices.")
    if state == 1 and "Bluetooth Power: On" in res.stdout:
        return make_result(control, Status.FAIL, "Bluetooth is enabled.")
    return make_result(control, Status.MANUAL, "Could not determine Bluetooth state.")


@check("CIS-MACOS-2.3.2")
def bluetooth_menubar(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "com.apple.controlcenter.plist", "Bluetooth")
    return make_result(control,
                       Status.PASS if v else Status.MANUAL if v is None else Status.FAIL,
                       "Bluetooth menu bar item present." if v
                       else "Bluetooth menu bar item not enabled.")


# ------------------------------------------------------ 2.4 General sharing

def _service_off(check_argv: list[str], pos_string: str, ok_string: str):
    def fn(ctx: Context, control: Control) -> CheckResult:
        err = require_target(ctx, control)
        if err:
            return err
        res = run(ctx, check_argv)
        out = (res.stdout + res.stderr).strip()
        if pos_string and pos_string in out:
            return make_result(control, Status.FAIL, out[:300])
        if ok_string and ok_string in out:
            return make_result(control, Status.PASS, out[:300])
        if res.rc != 0:
            return make_result(control, Status.MANUAL, f"command failed: {out[:300]}")
        return make_result(control, Status.MANUAL, f"could not parse: {out[:300]}")
    return fn


@check("CIS-MACOS-2.4.1")
def airdrop_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "com.apple.NetworkBrowser", "DisableAirDrop")
    if v is True:
        return make_result(control, Status.PASS, "AirDrop is disabled (DisableAirDrop=YES).")
    return make_result(control, Status.MANUAL,
                       "AirDrop control is per-user and may be enabled; verify by user.")


@check("CIS-MACOS-2.4.2")
def airplay_receiver_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "com.apple.controlcenter", "AirplayRecieverEnabled") or \
        defaults_bool(ctx, "com.apple.controlcenter", "AirPlayReceiverEnabled")
    if v is False:
        return make_result(control, Status.PASS, "AirPlay Receiver is disabled.")
    if v is True:
        return make_result(control, Status.FAIL, "AirPlay Receiver is enabled.")
    return make_result(control, Status.MANUAL, "Could not read AirPlay Receiver state.")


@check("CIS-MACOS-2.4.3")
def handoff_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "~/Library/Preferences/ByHost/com.apple.coreservices.useractivityd",
                      "ActivityAdvertisingAllowed", host=True)
    if v is False:
        return make_result(control, Status.PASS, "Handoff (ActivityAdvertisingAllowed) is disabled.")
    if v is True:
        return make_result(control, Status.FAIL, "Handoff is enabled.")
    return make_result(control, Status.MANUAL, "Could not determine Handoff state.")


check("CIS-MACOS-2.4.4")(_service_off(
    ["launchctl", "print-disabled", "system"], "", '"com.apple.smbd" => true'))
check("CIS-MACOS-2.4.5")(_service_off(
    ["launchctl", "print-disabled", "system"], "", '"org.cups.cupsd" => true'))


@check("CIS-MACOS-2.4.6")
def remote_login_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["systemsetup", "-getremotelogin"])
    out = res.stdout.strip().lower()
    if res.rc != 0:
        return make_result(control, Status.MANUAL,
                           "systemsetup -getremotelogin requires sudo on the target.")
    # Note: when SSH is the *transport*, 'Remote Login: Off' is the desired
    # state for the production policy, but obviously cannot be true here. We
    # surface the contradiction to the user.
    if "off" in out:
        return make_result(control, Status.PASS, out[:300])
    if hasattr(ctx.target, "kind") and getattr(ctx.target.kind, "value", "") == "ssh":
        return make_result(control, Status.FAIL,
                           "Remote Login is on (it must be on to allow this audit; "
                           "consider disabling it in production).")
    return make_result(control, Status.FAIL, out[:300])


@check("CIS-MACOS-2.4.7")
def remote_management_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["pgrep", "-x", "ARDAgent"])
    if res.stdout.strip():
        return make_result(control, Status.FAIL, "ARDAgent (Remote Management) is running.")
    return make_result(control, Status.PASS, "Remote Management agent is not running.")


@check("CIS-MACOS-2.4.8")
def remote_apple_events(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["systemsetup", "-getremoteappleevents"])
    if res.rc != 0:
        return make_result(control, Status.MANUAL, "systemsetup unavailable / requires sudo")
    out = res.stdout.lower()
    if "off" in out:
        return make_result(control, Status.PASS, res.stdout.strip())
    return make_result(control, Status.FAIL, res.stdout.strip())


@check("CIS-MACOS-2.4.9")
def internet_sharing(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    rc, _ = defaults_read(ctx, "/Library/Preferences/SystemConfiguration/com.apple.nat",
                          "NAT")
    if rc != 0:
        return make_result(control, Status.PASS, "No NAT plist - Internet Sharing not configured.")
    res = run(ctx, ["defaults", "read",
                    "/Library/Preferences/SystemConfiguration/com.apple.nat", "NAT"])
    if "Enabled = 1" in res.stdout or "Enabled=1" in res.stdout:
        return make_result(control, Status.FAIL, "Internet Sharing is enabled.",
                           evidence=[{"output": res.stdout[:500]}])
    return make_result(control, Status.PASS, "Internet Sharing is disabled.")


@check("CIS-MACOS-2.4.10")
def content_caching(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "/Library/Preferences/com.apple.AssetCache.plist", "Activated")
    if v is True:
        return make_result(control, Status.FAIL, "Content Caching is activated.")
    return make_result(control, Status.PASS, "Content Caching is not activated.")


@check("CIS-MACOS-2.4.11")
def media_sharing(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    home = defaults_bool(ctx, "com.apple.amp.mediasharingd", "home-sharing-enabled")
    public = defaults_bool(ctx, "com.apple.amp.mediasharingd", "public-sharing-enabled")
    if home is False and public is False:
        return make_result(control, Status.PASS, "Media sharing disabled.")
    if home is None and public is None:
        return make_result(control, Status.PASS, "Media sharing prefs absent (default).")
    return make_result(control, Status.FAIL,
                       f"home-sharing-enabled={home} public-sharing-enabled={public}")


# ------------------------------------------------------- 2.5 Privacy & Security

@check("CIS-MACOS-2.5.1.1")
def filevault_enabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["fdesetup", "status"])
    out = res.stdout.strip()
    if "FileVault is On" in out:
        return make_result(control, Status.PASS, out)
    if "FileVault is Off" in out:
        return make_result(control, Status.FAIL, out)
    return make_result(control, Status.MANUAL, out or res.stderr[:300])


@check("CIS-MACOS-2.5.1.2")
def storage_volumes_encrypted(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["diskutil", "apfs", "list"], timeout=30.0)
    if res.rc != 0:
        return make_result(control, Status.MANUAL, "diskutil unavailable")
    failures = []
    role = None
    encrypted = None
    name = None
    for line in res.stdout.splitlines():
        line = line.strip()
        m_name = re.search(r"Name:\s+(\S.*?)(?:\s+\(|$)", line)
        if m_name:
            name = m_name.group(1)
        if "Role:" in line:
            role = line.split("Role:")[1].strip().rstrip(")")
        if "FileVault:" in line:
            encrypted = "Yes" in line
            # User volumes are 'Data' or 'Volume'
            if role and role.upper() in ("DATA", "USER", "VOLUME"):
                if not encrypted:
                    failures.append(name or role)
    if failures:
        return make_result(control, Status.FAIL,
                           f"Unencrypted user volumes: {', '.join(failures)}")
    return make_result(control, Status.PASS, "All user APFS volumes are encrypted.")


# ------------------------------------------------------------------ Firewall

@check("CIS-MACOS-2.5.2.1")
def firewall_on(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    state = defaults_int(ctx, "/Library/Preferences/com.apple.alf", "globalstate")
    if state in (1, 2):
        return make_result(control, Status.PASS, f"alf.globalstate={state} (firewall on).")
    return make_result(control, Status.FAIL, f"alf.globalstate={state}")


@check("CIS-MACOS-2.5.2.2")
def firewall_stealth(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "/Library/Preferences/com.apple.alf", "stealthenabled")
    if v is True:
        return make_result(control, Status.PASS, "Stealth mode enabled.")
    return make_result(control, Status.FAIL, f"stealthenabled={v}")


@check("CIS-MACOS-2.5.2.3")
def firewall_logging(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    state = defaults_int(ctx, "/Library/Preferences/com.apple.alf", "loggingenabled")
    opt = defaults_int(ctx, "/Library/Preferences/com.apple.alf", "loggingoption")
    if state == 1:
        return make_result(control, Status.PASS,
                           f"loggingenabled={state} loggingoption={opt}")
    return make_result(control, Status.FAIL,
                       f"loggingenabled={state} loggingoption={opt}")


@check("CIS-MACOS-2.5.4")
def accessories_require_approval(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_int(ctx, "/Library/Preferences/com.apple.security",
                     "AllowNewUSBAccessoriesByDefault")
    if v == 0:
        return make_result(control, Status.PASS,
                           "AllowNewUSBAccessoriesByDefault=0 (approval required).")
    if v is None:
        return make_result(control, Status.MANUAL, "Could not read accessory approval setting.")
    return make_result(control, Status.FAIL, f"value={v}")


@check("CIS-MACOS-2.5.6")
def gatekeeper_enabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["spctl", "--status"])
    if "assessments enabled" in res.stdout.lower():
        return make_result(control, Status.PASS, res.stdout.strip())
    return make_result(control, Status.FAIL, res.stdout.strip() or res.stderr.strip())


@check("CIS-MACOS-2.5.7")
def sip_enabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["csrutil", "status"])
    out = res.stdout.strip()
    if "enabled" in out.lower():
        return make_result(control, Status.PASS, out)
    return make_result(control, Status.FAIL, out)


@check("CIS-MACOS-2.5.8")
def admin_password_for_prefs(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["security", "authorizationdb", "read", "system.preferences"])
    if "shared" in res.stdout and "<false/>" in res.stdout.split("shared", 1)[1][:200]:
        return make_result(control, Status.PASS,
                           "system.preferences requires authentication (shared=false).")
    return make_result(control, Status.FAIL,
                       "system.preferences shared=true; admin password not required.",
                       evidence=[{"output": res.stdout[:1500]}])


# ------------------------------------------------------- 2.6 Apple Intelligence / Siri

@check("CIS-MACOS-2.6.2")
def siri_disabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "com.apple.assistant.support", "Assistant Enabled")
    if v is False:
        return make_result(control, Status.PASS, "Siri ('Assistant Enabled')=false.")
    if v is True:
        return make_result(control, Status.FAIL, "Siri is enabled.")
    return make_result(control, Status.MANUAL, "Could not determine Siri state.")


# ----------------------------------------------------------- 2.7 Time Machine

@check("CIS-MACOS-2.7.1")
def tm_enabled(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["tmutil", "destinationinfo"])
    if res.rc == 0 and "Name " in res.stdout:
        return make_result(control, Status.PASS, "Time Machine destination is configured.")
    return make_result(control, Status.FAIL,
                       res.stdout.strip() or res.stderr.strip() or "no destination")


@check("CIS-MACOS-2.7.2")
def tm_encrypted(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["tmutil", "destinationinfo"])
    if "Encrypted" in res.stdout and "Yes" in res.stdout:
        return make_result(control, Status.PASS, "Time Machine destination is encrypted.")
    if "Encrypted" not in res.stdout:
        return make_result(control, Status.MANUAL,
                           "Could not determine Time Machine encryption.")
    return make_result(control, Status.FAIL, "Time Machine destination is not encrypted.")


# --------------------------------------------------------------- 2.8 Energy

@check("CIS-MACOS-2.8.1")
def wake_on_network(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    g = pmset_g(ctx)
    val = g.get("womp")
    if val == "0":
        return make_result(control, Status.PASS, "wake on network access disabled (womp=0).")
    if val is None:
        return make_result(control, Status.MANUAL, "Could not read pmset womp value.")
    return make_result(control, Status.FAIL, f"womp={val}")


@check("CIS-MACOS-2.8.2")
def power_nap(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    g = pmset_g(ctx)
    val = g.get("powernap")
    if val == "0":
        return make_result(control, Status.PASS, "powernap=0")
    if val is None:
        return make_result(control, Status.MANUAL, "Could not read pmset powernap.")
    return make_result(control, Status.FAIL, f"powernap={val}")


# ---------------------------------------------------------- 2.9 Lock screen

@check("CIS-MACOS-2.9.1")
def screensaver_timeout(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    secs = defaults_int(ctx, "com.apple.screensaver", "idleTime", host=True)
    if secs is None:
        return make_result(control, Status.MANUAL, "Could not read screensaver idleTime.")
    minutes = secs / 60.0
    if 0 < secs <= 20 * 60:
        return make_result(control, Status.PASS, f"idleTime={secs}s (~{minutes:.1f} min).")
    return make_result(control, Status.FAIL, f"idleTime={secs}s")


@check("CIS-MACOS-2.9.2")
def lock_immediate(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    delay = defaults_int(ctx, "com.apple.screensaver", "askForPasswordDelay", host=True)
    enabled = defaults_int(ctx, "com.apple.screensaver", "askForPassword", host=True)
    if enabled == 1 and (delay is None or delay <= 5):
        return make_result(control, Status.PASS,
                           f"askForPassword=1, askForPasswordDelay={delay}")
    return make_result(control, Status.FAIL,
                       f"askForPassword={enabled}, askForPasswordDelay={delay}")


@check("CIS-MACOS-2.9.3")
def login_window_message(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    rc, out = defaults_read(ctx, "/Library/Preferences/com.apple.loginwindow",
                            "LoginwindowText")
    if rc == 0 and out.strip():
        return make_result(control, Status.PASS, f"Login window message set ({len(out)} chars).")
    return make_result(control, Status.FAIL, "No login window message set.")


@check("CIS-MACOS-2.9.4")
def login_window_name_pw(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    v = defaults_bool(ctx, "/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME")
    if v is True:
        return make_result(control, Status.PASS, "Login window shows Name and Password.")
    return make_result(control, Status.FAIL, f"SHOWFULLNAME={v}")


@check("CIS-MACOS-2.9.5")
def disable_password_hint(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    n = defaults_int(ctx, "/Library/Preferences/com.apple.loginwindow",
                     "RetriesUntilHint")
    if n == 0:
        return make_result(control, Status.PASS, "RetriesUntilHint=0 (hints suppressed).")
    return make_result(control, Status.FAIL, f"RetriesUntilHint={n}")


@check("CIS-MACOS-2.9.6")
def disable_console_login(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    res = run(ctx, ["sudo", "defaults", "read", "/Library/Preferences/com.apple.loginwindow",
                    "DisableConsoleAccess"])
    if "1" in res.stdout.strip():
        return make_result(control, Status.PASS, "DisableConsoleAccess=1")
    return make_result(control, Status.FAIL, res.stdout.strip() or "DisableConsoleAccess unset")


@check("CIS-MACOS-2.10.2")
def disable_diagnostic_submission(ctx: Context, control: Control) -> CheckResult:
    err = require_target(ctx, control)
    if err:
        return err
    auto = defaults_bool(ctx, "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist",
                         "AutoSubmit")
    siri = defaults_bool(ctx, "com.apple.assistant.support", "Search Queries Data Sharing Status")
    if auto is False:
        return make_result(control, Status.PASS, "Crash reporter AutoSubmit disabled.")
    if auto is True:
        return make_result(control, Status.FAIL, f"AutoSubmit={auto}")
    return make_result(control, Status.MANUAL, "Could not determine analytics submission status.")
