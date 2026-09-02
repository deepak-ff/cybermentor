"""Automated check registrations for CIS Red Hat Enterprise Linux 10 v1.0.1."""

from __future__ import annotations

from ...engine.registry import check
from .._linux_common import checks as L

# 1.1.1
check("CIS-RHEL10-1.1.1.1")(L.kmod_check("cramfs"))
check("CIS-RHEL10-1.1.1.2")(L.kmod_check("freevxfs"))
check("CIS-RHEL10-1.1.1.3")(L.kmod_check("hfs"))
check("CIS-RHEL10-1.1.1.4")(L.kmod_check("hfsplus"))
check("CIS-RHEL10-1.1.1.5")(L.kmod_check("jffs2"))
check("CIS-RHEL10-1.1.1.6")(L.kmod_check("overlay"))
check("CIS-RHEL10-1.1.1.7")(L.kmod_check("squashfs"))
check("CIS-RHEL10-1.1.1.8")(L.kmod_check("udf"))
check("CIS-RHEL10-1.1.1.9")(L.kmod_check("usb-storage"))

# 1.1.2 mounts
check("CIS-RHEL10-1.1.2.1.1")(L.separate_partition_check("/tmp"))
check("CIS-RHEL10-1.1.2.1.2")(L.mount_check("/tmp", "nodev"))
check("CIS-RHEL10-1.1.2.1.3")(L.mount_check("/tmp", "nosuid"))
check("CIS-RHEL10-1.1.2.1.4")(L.mount_check("/tmp", "noexec"))
check("CIS-RHEL10-1.1.2.2.1")(L.separate_partition_check("/dev/shm"))
check("CIS-RHEL10-1.1.2.2.2")(L.mount_check("/dev/shm", "nodev"))
check("CIS-RHEL10-1.1.2.2.3")(L.mount_check("/dev/shm", "nosuid"))
check("CIS-RHEL10-1.1.2.2.4")(L.mount_check("/dev/shm", "noexec"))
check("CIS-RHEL10-1.1.2.3.1")(L.separate_partition_check("/home"))
check("CIS-RHEL10-1.1.2.3.2")(L.mount_check("/home", "nodev"))
check("CIS-RHEL10-1.1.2.3.3")(L.mount_check("/home", "nosuid"))
check("CIS-RHEL10-1.1.2.4.1")(L.separate_partition_check("/var"))
check("CIS-RHEL10-1.1.2.4.2")(L.mount_check("/var", "nodev"))
check("CIS-RHEL10-1.1.2.4.3")(L.mount_check("/var", "nosuid"))
check("CIS-RHEL10-1.1.2.5.1")(L.separate_partition_check("/var/tmp"))
check("CIS-RHEL10-1.1.2.5.2")(L.mount_check("/var/tmp", "nodev"))
check("CIS-RHEL10-1.1.2.5.3")(L.mount_check("/var/tmp", "nosuid"))
check("CIS-RHEL10-1.1.2.5.4")(L.mount_check("/var/tmp", "noexec"))
check("CIS-RHEL10-1.1.2.6.1")(L.separate_partition_check("/var/log"))
check("CIS-RHEL10-1.1.2.6.2")(L.mount_check("/var/log", "nodev"))
check("CIS-RHEL10-1.1.2.6.3")(L.mount_check("/var/log", "nosuid"))
check("CIS-RHEL10-1.1.2.6.4")(L.mount_check("/var/log", "noexec"))
check("CIS-RHEL10-1.1.2.7.1")(L.separate_partition_check("/var/log/audit"))
check("CIS-RHEL10-1.1.2.7.2")(L.mount_check("/var/log/audit", "nodev"))
check("CIS-RHEL10-1.1.2.7.3")(L.mount_check("/var/log/audit", "nosuid"))
check("CIS-RHEL10-1.1.2.7.4")(L.mount_check("/var/log/audit", "noexec"))

# 1.2
check("CIS-RHEL10-1.2.1.2")(L.gpgcheck_global())
check("CIS-RHEL10-1.2.1.3")(L.repo_gpgcheck_global())
check("CIS-RHEL10-1.2.2.1")(L.updates_installed())

# 1.3
check("CIS-RHEL10-1.3.1")(L.bootloader_password())
check("CIS-RHEL10-1.3.2")(L.bootloader_perms())

# 1.4
check("CIS-RHEL10-1.4.1")(L.sysctl_check("kernel.randomize_va_space", "2"))
check("CIS-RHEL10-1.4.2")(L.sysctl_check("kernel.yama.ptrace_scope", "1"))
check("CIS-RHEL10-1.4.3")(L.core_dumps_restricted())
check("CIS-RHEL10-1.4.4")(L.package_missing_check("prelink"))
check("CIS-RHEL10-1.4.5")(L.package_missing_check("abrt-cli"))

# 1.5 SELinux
check("CIS-RHEL10-1.5.1.1")(L.selinux_installed())
check("CIS-RHEL10-1.5.1.2")(L.selinux_not_disabled_in_bootloader())
check("CIS-RHEL10-1.5.1.3")(L.selinux_policy_targeted())
check("CIS-RHEL10-1.5.1.4")(L.selinux_enforcing())
check("CIS-RHEL10-1.5.1.6")(L.package_missing_check("setroubleshoot"))
check("CIS-RHEL10-1.5.1.7")(L.package_missing_check("mcstrans"))

# 1.6 crypto
check("CIS-RHEL10-1.6.1")(L.crypto_policy_min())
check("CIS-RHEL10-1.6.2")(L.crypto_policy_no_sha1())

# 1.7 banners
check("CIS-RHEL10-1.7.1")(L.banner_file_check("/etc/motd"))
check("CIS-RHEL10-1.7.2")(L.banner_file_check("/etc/issue"))
check("CIS-RHEL10-1.7.3")(L.banner_file_check("/etc/issue.net"))
check("CIS-RHEL10-1.7.4")(L.file_perm("/etc/motd", max_mode="644"))
check("CIS-RHEL10-1.7.5")(L.file_perm("/etc/issue", max_mode="644"))
check("CIS-RHEL10-1.7.6")(L.file_perm("/etc/issue.net", max_mode="644"))

# 1.8
check("CIS-RHEL10-1.8.1")(L.package_missing_check("gdm"))

# 2.1
check("CIS-RHEL10-2.1.1")(L.chrony_in_use())

# 2.2
check("CIS-RHEL10-2.2.1")(L.package_missing_check("xinetd"))
check("CIS-RHEL10-2.2.2")(L.package_missing_check("xorg-x11-server-common"))
check("CIS-RHEL10-2.2.3")(L.package_missing_check("avahi"))
check("CIS-RHEL10-2.2.4")(L.package_missing_check("cups"))
check("CIS-RHEL10-2.2.5")(L.package_missing_check("dhcp-server"))
check("CIS-RHEL10-2.2.6")(L.package_missing_check("bind"))
check("CIS-RHEL10-2.2.7")(L.package_missing_check("vsftpd"))
check("CIS-RHEL10-2.2.8")(L.package_missing_check("tftp-server"))
check("CIS-RHEL10-2.2.9")(L.package_missing_check("httpd"))
check("CIS-RHEL10-2.2.10")(L.package_missing_check("dovecot"))
check("CIS-RHEL10-2.2.11")(L.package_missing_check("samba"))
check("CIS-RHEL10-2.2.12")(L.package_missing_check("squid"))
check("CIS-RHEL10-2.2.13")(L.package_missing_check("net-snmp"))
check("CIS-RHEL10-2.2.14")(L.package_missing_check("ypserv"))
check("CIS-RHEL10-2.2.15")(L.package_missing_check("telnet-server"))
check("CIS-RHEL10-2.2.16")(L.service_disabled_check("rsyncd",
                                                     also_check_packages=["rsync-daemon"]))

# 2.3
check("CIS-RHEL10-2.3.1")(L.package_missing_check("ypbind"))
check("CIS-RHEL10-2.3.2")(L.package_missing_check("rsh"))
check("CIS-RHEL10-2.3.3")(L.package_missing_check("talk"))
check("CIS-RHEL10-2.3.4")(L.package_missing_check("telnet"))
check("CIS-RHEL10-2.3.5")(L.package_missing_check("openldap-clients"))
check("CIS-RHEL10-2.3.6")(L.package_missing_check("tftp"))

# 2.4
check("CIS-RHEL10-2.4.1.1")(L.service_enabled_check("crond"))
check("CIS-RHEL10-2.4.1.2")(L.file_perm("/etc/crontab", max_mode="600"))
check("CIS-RHEL10-2.4.1.3")(L.file_perm("/etc/cron.hourly", max_mode="700"))
check("CIS-RHEL10-2.4.1.4")(L.file_perm("/etc/cron.daily", max_mode="700"))
check("CIS-RHEL10-2.4.1.5")(L.file_perm("/etc/cron.weekly", max_mode="700"))
check("CIS-RHEL10-2.4.1.6")(L.file_perm("/etc/cron.monthly", max_mode="700"))
check("CIS-RHEL10-2.4.1.7")(L.file_perm("/etc/cron.d", max_mode="700"))
check("CIS-RHEL10-2.4.1.8")(L.file_perm("/etc/cron.allow", max_mode="640"))
check("CIS-RHEL10-2.4.2.1")(L.file_perm("/etc/at.allow", max_mode="640"))

# 3.1
check("CIS-RHEL10-3.1.2")(L.kmod_check("cfg80211"))
check("CIS-RHEL10-3.1.3")(L.service_disabled_check("bluetooth.service",
                                                    also_check_packages=["bluez"]))

# 3.2
check("CIS-RHEL10-3.2.1")(L.kmod_check("dccp"))
check("CIS-RHEL10-3.2.2")(L.kmod_check("tipc"))
check("CIS-RHEL10-3.2.3")(L.kmod_check("rds"))
check("CIS-RHEL10-3.2.4")(L.kmod_check("sctp"))

# 3.3
check("CIS-RHEL10-3.3.1")(L.sysctl_check("net.ipv4.ip_forward", "0"))
check("CIS-RHEL10-3.3.2")(L.sysctl_check("net.ipv4.conf.all.send_redirects", "0"))
check("CIS-RHEL10-3.3.3")(L.sysctl_check("net.ipv4.icmp_ignore_bogus_error_responses", "1"))
check("CIS-RHEL10-3.3.4")(L.sysctl_check("net.ipv4.icmp_echo_ignore_broadcasts", "1"))
check("CIS-RHEL10-3.3.5")(L.sysctl_check("net.ipv4.conf.all.accept_redirects", "0"))
check("CIS-RHEL10-3.3.6")(L.sysctl_check("net.ipv4.conf.all.secure_redirects", "0"))
check("CIS-RHEL10-3.3.7")(L.sysctl_check("net.ipv4.conf.all.rp_filter", "1"))
check("CIS-RHEL10-3.3.8")(L.sysctl_check("net.ipv4.conf.all.accept_source_route", "0"))
check("CIS-RHEL10-3.3.9")(L.sysctl_check("net.ipv4.conf.all.log_martians", "1"))
check("CIS-RHEL10-3.3.10")(L.sysctl_check("net.ipv4.tcp_syncookies", "1"))
check("CIS-RHEL10-3.3.11")(L.sysctl_check("net.ipv6.conf.all.accept_ra", "0"))

# 3.4
check("CIS-RHEL10-3.4.1.1")(L.package_present_check("firewalld"))
check("CIS-RHEL10-3.4.1.2")(L.package_missing_check("iptables-services"))
check("CIS-RHEL10-3.4.1.3")(L.service_enabled_check("firewalld"))

# 4.1
check("CIS-RHEL10-4.1.1.1")(L.auditd_installed())
check("CIS-RHEL10-4.1.1.2")(L.auditd_enabled())
check("CIS-RHEL10-4.1.1.3")(L.audit_grub_arg())
check("CIS-RHEL10-4.1.1.4")(L.audit_backlog_limit())

# 4.2
check("CIS-RHEL10-4.2.1.1")(L.rsyslog_installed())
check("CIS-RHEL10-4.2.1.2")(L.rsyslog_enabled())
check("CIS-RHEL10-4.2.2.1")(L.package_present_check("systemd-journal-remote"))

# 5.1 sshd
check("CIS-RHEL10-5.1.1")(L.file_perm("/etc/ssh/sshd_config", max_mode="600"))
check("CIS-RHEL10-5.1.5")(L.sshd_param("loglevel", ["INFO", "VERBOSE"]))
check("CIS-RHEL10-5.1.6")(L.sshd_param("usepam", "yes"))
check("CIS-RHEL10-5.1.7")(L.sshd_param("permitrootlogin", "no"))
check("CIS-RHEL10-5.1.8")(L.sshd_param("hostbasedauthentication", "no"))
check("CIS-RHEL10-5.1.9")(L.sshd_param("permitemptypasswords", "no"))
check("CIS-RHEL10-5.1.10")(L.sshd_param("permituserenvironment", "no"))
check("CIS-RHEL10-5.1.11")(L.sshd_param("ignorerhosts", "yes"))
check("CIS-RHEL10-5.1.12")(L.sshd_param("x11forwarding", "no"))
check("CIS-RHEL10-5.1.13")(L.sshd_param("allowtcpforwarding", "no"))
check("CIS-RHEL10-5.1.14")(L.sshd_param("banner", "/etc/issue.net"))
check("CIS-RHEL10-5.1.15")(L.sshd_int_max("maxauthtries", 4))
check("CIS-RHEL10-5.1.17")(L.sshd_int_max("maxsessions", 10))
check("CIS-RHEL10-5.1.18")(L.sshd_int_max("logingracetime", 60))

# 5.2 sudo
check("CIS-RHEL10-5.2.1")(L.package_present_check("sudo"))
check("CIS-RHEL10-5.2.2")(L.sudo_use_pty())
check("CIS-RHEL10-5.2.3")(L.sudo_log_file())
check("CIS-RHEL10-5.2.4")(L.sudo_no_nopasswd())
check("CIS-RHEL10-5.2.5")(L.sudo_no_authenticate_disabled())
check("CIS-RHEL10-5.2.6")(L.sudo_timestamp_timeout())
check("CIS-RHEL10-5.2.7")(L.su_restricted())

# 5.4 PAM
check("CIS-RHEL10-5.4.1")(L.password_min_length())
check("CIS-RHEL10-5.4.2")(L.password_lockout())
check("CIS-RHEL10-5.4.3")(L.password_reuse())
check("CIS-RHEL10-5.4.4")(L.password_hash_strong())

# 5.5
check("CIS-RHEL10-5.5.1.1")(L.password_max_days(365))
check("CIS-RHEL10-5.5.1.2")(L.password_min_days(1))
check("CIS-RHEL10-5.5.1.3")(L.password_warn_age(7))
check("CIS-RHEL10-5.5.4")(L.umask_restrictive("027"))

# 6.1
check("CIS-RHEL10-6.1.1")(L.file_perm("/etc/passwd", max_mode="644"))
check("CIS-RHEL10-6.1.2")(L.file_perm("/etc/passwd-", max_mode="644"))
check("CIS-RHEL10-6.1.3")(L.file_perm("/etc/group", max_mode="644"))
check("CIS-RHEL10-6.1.4")(L.file_perm("/etc/group-", max_mode="644"))
check("CIS-RHEL10-6.1.5")(L.file_perm("/etc/shadow", max_mode="000", group="root"))
check("CIS-RHEL10-6.1.6")(L.file_perm("/etc/shadow-", max_mode="000", group="root"))
check("CIS-RHEL10-6.1.7")(L.file_perm("/etc/gshadow", max_mode="000", group="root"))
check("CIS-RHEL10-6.1.8")(L.file_perm("/etc/gshadow-", max_mode="000", group="root"))
check("CIS-RHEL10-6.1.9")(L.no_world_writable())
check("CIS-RHEL10-6.1.10")(L.no_unowned_files())

# 6.2
check("CIS-RHEL10-6.2.1")(L.shadowed_passwords())
check("CIS-RHEL10-6.2.2")(L.no_empty_shadow_pw())
check("CIS-RHEL10-6.2.3")(L.passwd_groups_exist())
check("CIS-RHEL10-6.2.4")(L.duplicate_uids())
check("CIS-RHEL10-6.2.5")(L.duplicate_gids())
check("CIS-RHEL10-6.2.6")(L.duplicate_user_names())
check("CIS-RHEL10-6.2.7")(L.duplicate_group_names())
check("CIS-RHEL10-6.2.9")(L.root_only_uid_zero())
