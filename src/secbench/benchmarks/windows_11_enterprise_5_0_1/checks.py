"""Automated check registrations for CIS Windows 11 Enterprise v5.0.1."""

from __future__ import annotations

from ...engine.registry import check
from .._windows_common import checks as W

# Registry roots used repeatedly
_LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
_SYSTEM_POL = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_PRINTERS = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
_DEFENDER = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
_BITLOCKER = r"HKLM\SOFTWARE\Policies\Microsoft\FVE"
_CONTROL_SET = r"HKLM\SYSTEM\CurrentControlSet\Services"
_NETLOGON = r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
_AUTOPLAY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
_PERSONALIZATION = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization"
_WINUPDATE_AU = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"


# 1.1 Password Policy (via secedit)
check("CIS-WIN11E-1.1.1")(W.policy_min("PasswordHistorySize", 24))
check("CIS-WIN11E-1.1.2")(W.policy_max("MaximumPasswordAge", 365))
check("CIS-WIN11E-1.1.3")(W.policy_min("MinimumPasswordAge", 1))
check("CIS-WIN11E-1.1.4")(W.policy_min("MinimumPasswordLength", 14))
check("CIS-WIN11E-1.1.5")(W.policy_eq("PasswordComplexity", 1))
check("CIS-WIN11E-1.1.7")(W.policy_eq("ClearTextPassword", 0))

# 1.2 Lockout Policy
check("CIS-WIN11E-1.2.1")(W.policy_min("LockoutDuration", 15))
check("CIS-WIN11E-1.2.2")(W.policy_max("LockoutBadCount", 5))
check("CIS-WIN11E-1.2.3")(W.policy_min("ResetLockoutCount", 15))

# 2.3.1 Accounts
check("CIS-WIN11E-2.3.1.1")(W.reg_min(
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "NoConnectedUser", 3))
check("CIS-WIN11E-2.3.1.2")(W.policy_eq("EnableGuestAccount", 0))
check("CIS-WIN11E-2.3.1.3")(W.reg_eq(_LSA, "LimitBlankPasswordUse", 1))
check("CIS-WIN11E-2.3.1.4")(W.administrator_renamed())

# 2.3.6 Domain member
check("CIS-WIN11E-2.3.6.1")(W.reg_eq(_NETLOGON, "RequireSignOrSeal", 1))
check("CIS-WIN11E-2.3.6.2")(W.reg_eq(_NETLOGON, "SealSecureChannel", 1))
check("CIS-WIN11E-2.3.6.3")(W.reg_eq(_NETLOGON, "SignSecureChannel", 1))
check("CIS-WIN11E-2.3.6.4")(W.reg_eq(_NETLOGON, "DisablePasswordChange", 0))
check("CIS-WIN11E-2.3.6.5")(W.reg_max(_NETLOGON, "MaximumPasswordAge", 30))
check("CIS-WIN11E-2.3.6.6")(W.reg_eq(_NETLOGON, "RequireStrongKey", 1))

# 2.3.7 Interactive logon
check("CIS-WIN11E-2.3.7.1")(W.reg_eq(_SYSTEM_POL, "DisableCAD", 0))
check("CIS-WIN11E-2.3.7.2")(W.reg_eq(_SYSTEM_POL, "DontDisplayLastUserName", 1))
check("CIS-WIN11E-2.3.7.3")(W.reg_max(_SYSTEM_POL, "InactivityTimeoutSecs", 900))

# 2.3.9 Microsoft network server
_LANMAN = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
check("CIS-WIN11E-2.3.9.1")(W.reg_eq(_LANMAN, "RequireSecuritySignature", 1))
check("CIS-WIN11E-2.3.9.2")(W.reg_eq(_LANMAN, "EnableForcedLogoff", 1))
check("CIS-WIN11E-2.3.9.3")(W.reg_min(_LANMAN, "SmbServerNameHardeningLevel", 1))

# 2.3.10 Network access
check("CIS-WIN11E-2.3.10.1")(W.reg_eq(_LSA, "TurnOffAnonymousBlock", 0))
check("CIS-WIN11E-2.3.10.2")(W.reg_eq(_LSA, "RestrictAnonymousSAM", 1))
check("CIS-WIN11E-2.3.10.3")(W.reg_eq(_LSA, "RestrictAnonymous", 1))
check("CIS-WIN11E-2.3.10.4")(W.reg_eq(_LANMAN, "RestrictNullSessAccess", 1))
check("CIS-WIN11E-2.3.10.5")(W.reg_eq(_LSA, "ForceGuest", 0))

# 2.3.11 Network security
check("CIS-WIN11E-2.3.11.1")(W.reg_eq(_LSA, "AllowNullSessionFallback", 0))
check("CIS-WIN11E-2.3.11.2")(W.reg_eq(_LSA, "NoLMHash", 1))
check("CIS-WIN11E-2.3.11.3")(W.reg_eq(_LSA, "LmCompatibilityLevel", 5))
_MSV = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
check("CIS-WIN11E-2.3.11.4")(W.reg_min(_MSV, "NTLMMinClientSec", 537395200))
check("CIS-WIN11E-2.3.11.5")(W.reg_min(_MSV, "NTLMMinServerSec", 537395200))
check("CIS-WIN11E-2.3.11.6")(W.reg_eq(_MSV, "AuditReceivingNTLMTraffic", 2))
check("CIS-WIN11E-2.3.11.7")(W.reg_eq(_MSV, "RestrictSendingNTLMTraffic", 1))

# 2.3.17 UAC
check("CIS-WIN11E-2.3.17.1")(W.reg_eq(_SYSTEM_POL, "FilterAdministratorToken", 1))
check("CIS-WIN11E-2.3.17.2")(W.reg_min(_SYSTEM_POL, "ConsentPromptBehaviorAdmin", 1))
check("CIS-WIN11E-2.3.17.3")(W.reg_eq(_SYSTEM_POL, "ConsentPromptBehaviorUser", 0))
check("CIS-WIN11E-2.3.17.4")(W.reg_eq(_SYSTEM_POL, "EnableInstallerDetection", 1))
check("CIS-WIN11E-2.3.17.5")(W.reg_eq(_SYSTEM_POL, "EnableLUA", 1))
check("CIS-WIN11E-2.3.17.6")(W.reg_eq(_SYSTEM_POL, "EnableVirtualization", 1))

# 9.x Firewall
check("CIS-WIN11E-9.1.1")(W.firewall_profile_enabled("Domain"))
check("CIS-WIN11E-9.1.2")(W.firewall_default_inbound("Domain", "Block"))
check("CIS-WIN11E-9.2.1")(W.firewall_profile_enabled("Private"))
check("CIS-WIN11E-9.2.2")(W.firewall_default_inbound("Private", "Block"))
check("CIS-WIN11E-9.3.1")(W.firewall_profile_enabled("Public"))
check("CIS-WIN11E-9.3.2")(W.firewall_default_inbound("Public", "Block"))

# 17.x Audit Policy
check("CIS-WIN11E-17.1.1")(W.audit_policy("Credential Validation", "Success and Failure"))
check("CIS-WIN11E-17.2.1")(W.audit_policy("Application Group Management", "Success and Failure"))
check("CIS-WIN11E-17.3.1")(W.audit_policy("Plug and Play Events", "Success"))
check("CIS-WIN11E-17.3.2")(W.audit_policy("Process Creation", "Success"))
check("CIS-WIN11E-17.5.1")(W.audit_policy("Account Lockout", "Success and Failure"))
check("CIS-WIN11E-17.5.2")(W.audit_policy("Group Membership", "Success"))
check("CIS-WIN11E-17.5.3")(W.audit_policy("Logoff", "Success"))
check("CIS-WIN11E-17.5.4")(W.audit_policy("Logon", "Success and Failure"))
check("CIS-WIN11E-17.5.5")(W.audit_policy("Special Logon", "Success"))
check("CIS-WIN11E-17.6.1")(W.audit_policy("Detailed File Share", "Failure"))
check("CIS-WIN11E-17.6.2")(W.audit_policy("File Share", "Success and Failure"))
check("CIS-WIN11E-17.6.3")(W.audit_policy("Other Object Access Events", "Success and Failure"))
check("CIS-WIN11E-17.6.4")(W.audit_policy("Removable Storage", "Success and Failure"))
check("CIS-WIN11E-17.7.1")(W.audit_policy("Audit Policy Change", "Success and Failure"))
check("CIS-WIN11E-17.7.2")(W.audit_policy("Authentication Policy Change", "Success"))
check("CIS-WIN11E-17.7.3")(W.audit_policy("MPSSVC Rule-Level Policy Change", "Success and Failure"))
check("CIS-WIN11E-17.7.4")(W.audit_policy("Other Policy Change Events", "Failure"))
check("CIS-WIN11E-17.8.1")(W.audit_policy("Sensitive Privilege Use", "Success and Failure"))
check("CIS-WIN11E-17.9.1")(W.audit_policy("IPsec Driver", "Success and Failure"))
check("CIS-WIN11E-17.9.2")(W.audit_policy("Other System Events", "Success and Failure"))
check("CIS-WIN11E-17.9.3")(W.audit_policy("Security State Change", "Success"))
check("CIS-WIN11E-17.9.4")(W.audit_policy("Security System Extension", "Success"))
check("CIS-WIN11E-17.9.5")(W.audit_policy("System Integrity", "Success and Failure"))

# 18.x Computer config
check("CIS-WIN11E-18.1.1")(W.reg_eq(_PERSONALIZATION, "NoLockScreenCamera", 1))
check("CIS-WIN11E-18.1.2")(W.reg_eq(_PERSONALIZATION, "NoLockScreenSlideshow", 1))
check("CIS-WIN11E-18.3.1")(W.reg_eq(_SYSTEM_POL, "LocalAccountTokenFilterPolicy", 0))
check("CIS-WIN11E-18.3.2")(W.reg_eq(
    r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 4))
check("CIS-WIN11E-18.3.3")(W.no_smbv1())
check("CIS-WIN11E-18.4.1")(W.reg_eq(
    r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
    "UseLogonCredential", 0))

# BitLocker
check("CIS-WIN11E-18.9.11.1")(W.bitlocker_enabled())

# Defender via reg policies
check("CIS-WIN11E-18.9.45.1")(W.reg_eq(_DEFENDER, "DisableAntiSpyware", 0))
check("CIS-WIN11E-18.9.45.3")(W.reg_eq(
    _DEFENDER + r"\UX Configuration", "DisallowExploitProtectionOverride", 1))

# Windows Update
check("CIS-WIN11E-18.9.108.1")(W.reg_eq(_WINUPDATE_AU, "NoAutoRebootWithLoggedOnUsers", 0))
check("CIS-WIN11E-18.9.108.2")(W.reg_eq(_WINUPDATE_AU, "NoAutoUpdate", 0))
check("CIS-WIN11E-18.9.108.3")(W.reg_eq(_WINUPDATE_AU, "ScheduledInstallDay", 0))

# AutoPlay
check("CIS-WIN11E-18.10.1")(W.reg_eq(_AUTOPLAY, "NoAutoplayfornonVolume", 1))
check("CIS-WIN11E-18.10.2")(W.reg_eq(_AUTOPLAY, "NoAutorun", 1))
check("CIS-WIN11E-18.10.3")(W.reg_eq(_AUTOPLAY, "NoDriveTypeAutoRun", 255))

# 19.x User config
check("CIS-WIN11E-19.1.2")(W.reg_eq(
    r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
    "ScreenSaverIsSecure", 1))
check("CIS-WIN11E-19.1.3")(W.reg_max(
    r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
    "ScreenSaveTimeOut", 900))

# 5.x System Services
check("CIS-WIN11E-5.1")(W.service_disabled_check("BTAGService"))
check("CIS-WIN11E-5.2")(W.service_disabled_check("bthserv"))
check("CIS-WIN11E-5.3")(W.service_disabled_check("Browser"))
check("CIS-WIN11E-5.4")(W.service_disabled_check("lfsvc"))
check("CIS-WIN11E-5.5")(W.service_disabled_check("IISADMIN"))
check("CIS-WIN11E-5.6")(W.service_disabled_check("SharedAccess"))
check("CIS-WIN11E-5.7")(W.service_disabled_check("Spooler"))
check("CIS-WIN11E-5.8")(W.service_disabled_check("RpcLocator"))
check("CIS-WIN11E-5.9")(W.service_disabled_check("RemoteRegistry"))
check("CIS-WIN11E-5.10")(W.service_disabled_check("RemoteAccess"))
check("CIS-WIN11E-5.11")(W.service_disabled_check("LanmanServer"))
check("CIS-WIN11E-5.12")(W.service_disabled_check("simptcp"))
check("CIS-WIN11E-5.13")(W.service_disabled_check("SNMP"))
check("CIS-WIN11E-5.14")(W.service_disabled_check("sacsvr"))
check("CIS-WIN11E-5.15")(W.service_disabled_check("WebClient"))
check("CIS-WIN11E-5.16")(W.service_disabled_check("WerSvc"))
check("CIS-WIN11E-5.17")(W.service_disabled_check("XboxGipSvc"))
check("CIS-WIN11E-5.18")(W.service_disabled_check("XblAuthManager"))
check("CIS-WIN11E-5.19")(W.service_disabled_check("XblGameSave"))
check("CIS-WIN11E-5.20")(W.service_disabled_check("XboxNetApiSvc"))
