"""Table-driven tests for every registered security check.

Filesystem/command access is monkeypatched so the suite runs identically on
Linux, Windows and CI containers without touching real system state.
"""

from __future__ import annotations

import stat
from typing import Any, Dict, Optional

import pytest

import audit_tool.checks as checks
from audit_tool.models import CheckResult, Level, Platform, Severity

# ------------------------------------------------------------------ helpers


def fake_read(files: Dict[str, str]):
    def _read(path: str) -> Optional[str]:
        return files.get(path)

    return _read


def fake_mode(modes: Dict[str, int]):
    def _mode(path: str) -> Optional[int]:
        return modes.get(path)

    return _mode


class FakeStat:
    def __init__(self, mode: int):
        self.st_mode = mode


def fake_stat_table(table: Dict[str, int], default_mode: int = 0o755):
    """Robust os.stat replacement: tolerates extra args/kwargs so pytest
    internals that touch the patched function keep working."""

    def _stat(path, *args, **kwargs):
        return FakeStat(table.get(path, default_mode))

    return _stat


def _noop_listdir(p, *a, **k):
    return []


def fake_cmd(handlers: Dict[str, Any]):
    """Match on the first argv element; a callable handler is invoked."""

    def _cmd(args, timeout: float = 15.0):
        key = args[0]
        if key in handlers:
            h = handlers[key]
            if callable(h):
                return h(args)
            return h
        return None

    return _cmd


def run(check_id: str, host: str = "host") -> CheckResult:
    return checks.CHECK_FUNCS[check_id](host)


# ------------------------------------------------------------------ registry


def test_registry_has_at_least_30_checks():
    assert len(checks.CHECK_REGISTRY) >= 30


def test_registry_specs_are_well_formed():
    for cid, spec in checks.CHECK_REGISTRY.items():
        assert cid == spec.id
        assert spec.title
        assert spec.category
        assert isinstance(spec.severity, Severity)
        assert spec.platforms
        for p in spec.platforms:
            assert isinstance(p, Platform)
        assert cid in checks.CHECK_FUNCS


def test_iter_specs_category_filter_case_insensitive():
    ids = [cid for cid, _s in checks.iter_specs(categories=["SSH"])]
    assert set(ids) == {"SSH-001", "SSH-002", "SSH-003", "SSH-004"}


def test_iter_specs_exclude_case_insensitive():
    ids = [cid for cid, _s in checks.iter_specs(exclude=["ssh-001", "SSH-002"])]
    assert "SSH-001" not in ids
    assert "SSH-002" not in ids
    assert "SSH-003" in ids


def test_iter_specs_no_filters_yields_all():
    assert len(list(checks.iter_specs())) == len(checks.CHECK_REGISTRY)


def test_run_all_checks_platform_gating(monkeypatch):
    results = checks.run_all_checks("h", platform=Platform.WINDOWS)
    by_id = {r.id: r for r in results}
    # Linux-only checks must be reported as SKIP on Windows
    assert by_id["SSH-001"].level == Level.SKIP
    assert "not applicable" in by_id["SSH-001"].detail
    # Windows checks run (they degrade to SKIP/INFO without netsh/winreg)
    assert by_id["WIN-001"].level in (Level.SKIP, Level.PASS, Level.FAIL)
    # Every registered check appears exactly once
    assert set(by_id) == set(checks.CHECK_REGISTRY)


def test_run_all_checks_filters():
    results = checks.run_all_checks("h", categories=["ssh"], exclude=["SSH-001"])
    ids = [r.id for r in results]
    assert ids == ["SSH-002", "SSH-003", "SSH-004"]


def test_run_all_checks_contains_exceptions():
    cid = "TEST-ERR"
    spec = checks.CheckSpec(cid, "boom", "Testing", "", Severity.LOW, (Platform.ANY,))
    checks.CHECK_REGISTRY[cid] = spec
    # Lambda body raises; mypy still type-checks it against CheckResult.
    checks.CHECK_FUNCS[cid] = lambda host: 1 / 0  # type: ignore[assignment,return-value]
    try:
        results = checks.run_all_checks("h", categories=["testing"])
    finally:
        del checks.CHECK_REGISTRY[cid]
        del checks.CHECK_FUNCS[cid]
    assert len(results) == 1
    assert results[0].level == Level.INFO
    assert "check error" in results[0].detail


def test_current_platform_is_known():
    assert checks.current_platform() in (Platform.LINUX, Platform.WINDOWS)


# ---------------------------------------------------------------------- SSH


@pytest.mark.parametrize(
    "cfg,expected",
    [
        (None, Level.SKIP),
        ("PermitRootLogin no\n", Level.PASS),
        ("PermitRootLogin prohibit-password\n", Level.PASS),
        ("PermitRootLogin yes\n", Level.FAIL),
        ("# no directive at all\n", Level.FAIL),  # sshd default is yes
    ],
)
def test_ssh_001(monkeypatch, cfg, expected):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/ssh/sshd_config": cfg}))
    res = run("SSH-001")
    assert res.level == expected


@pytest.mark.parametrize(
    "cfg,expected",
    [
        (None, Level.SKIP),
        ("PasswordAuthentication no\n", Level.PASS),
        ("PasswordAuthentication yes\n", Level.FAIL),
        ("# absent -> default yes\n", Level.FAIL),
    ],
)
def test_ssh_002(monkeypatch, cfg, expected):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/ssh/sshd_config": cfg}))
    assert run("SSH-002").level == expected


@pytest.mark.parametrize(
    "cfg,expected",
    [
        (None, Level.SKIP),
        ("PermitEmptyPasswords yes\n", Level.FAIL),
        ("PermitEmptyPasswords no\n", Level.PASS),
        ("# absent -> OpenSSH default is no\n", Level.PASS),
    ],
)
def test_ssh_003(monkeypatch, cfg, expected):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/ssh/sshd_config": cfg}))
    assert run("SSH-003").level == expected


@pytest.mark.parametrize(
    "mode,expected",
    [(None, Level.SKIP), (0o600, Level.PASS), (0o640, Level.PASS), (0o666, Level.FAIL)],
)
def test_ssh_004(monkeypatch, mode, expected):
    monkeypatch.setattr(checks, "_mode", fake_mode({"/etc/ssh/sshd_config": mode}))
    assert run("SSH-004").level == expected


# ---------------------------------------------------------- Filesystem


def test_file_001_world_writable_warn(monkeypatch):
    monkeypatch.setattr(checks.os, "walk", lambda *a, **k: [("/etc", [], ["f1", "f2"])])
    monkeypatch.setattr(
        checks.os,
        "stat",
        fake_stat_table({"/etc/f1": stat.S_IWOTH, "/etc/f2": stat.S_IWOTH}),
    )
    res = run("FILE-001")
    assert res.level == Level.WARN
    assert "2 world-writable" in res.detail


def test_file_001_clean_pass(monkeypatch):
    monkeypatch.setattr(checks.os, "walk", lambda *a, **k: [("/etc", [], ["f1"])])
    monkeypatch.setattr(checks.os, "stat", fake_stat_table({}))
    assert run("FILE-001").level == Level.PASS


def test_file_002_unexpected_world_writable_dir(monkeypatch):
    monkeypatch.setattr(checks.os, "listdir", lambda *a, **k: ["tmp", "weird"])
    monkeypatch.setattr(checks.os.path, "isdir", lambda *a, **k: True)
    # /tmp is allow-listed; /weird is world-writable and must be flagged.
    monkeypatch.setattr(
        checks.os,
        "stat",
        fake_stat_table(
            {"/tmp": 0o1777, "/weird": stat.S_IWOTH | 0o755},
            default_mode=0o755,
        ),
    )
    res = run("FILE-002")
    assert res.level == Level.WARN
    assert "/weird" in res.detail
    assert "/tmp" not in res.detail


def test_file_002_clean(monkeypatch):
    monkeypatch.setattr(checks.os, "listdir", _noop_listdir)
    assert run("FILE-002").level == Level.PASS


@pytest.mark.parametrize(
    "mode,expected",
    [(None, Level.SKIP), (0o644, Level.PASS), (0o646, Level.FAIL), (0o600, Level.FAIL)],
)
def test_file_003(monkeypatch, mode, expected):
    monkeypatch.setattr(checks, "_mode", fake_mode({"/etc/passwd": mode}))
    assert run("FILE-003").level == expected


@pytest.mark.parametrize(
    "mode,expected",
    [(None, Level.SKIP), (0o600, Level.PASS), (0o640, Level.PASS), (0o644, Level.FAIL)],
)
def test_file_004(monkeypatch, mode, expected):
    monkeypatch.setattr(checks, "_mode", fake_mode({"/etc/shadow": mode}))
    assert run("FILE-004").level == expected


def test_file_005_sticky_bits(monkeypatch):
    monkeypatch.setattr(checks.os.path, "isdir", lambda *a, **k: True)
    # /tmp has sticky, /var/tmp does not -> FAIL
    monkeypatch.setattr(
        checks.os,
        "stat",
        fake_stat_table(
            {"/tmp": stat.S_ISVTX | 0o777, "/var/tmp": 0o777},
            default_mode=0o755,
        ),
    )
    assert run("FILE-005").level == Level.FAIL


def test_file_005_all_sticky(monkeypatch):
    monkeypatch.setattr(checks.os.path, "isdir", lambda *a, **k: True)
    monkeypatch.setattr(
        checks.os,
        "stat",
        fake_stat_table({}, default_mode=stat.S_ISVTX | 0o777),
    )
    assert run("FILE-005").level == Level.PASS


def test_file_006_suid_inventory_warn(monkeypatch):
    monkeypatch.setattr(
        checks.os.path,
        "isdir",
        lambda *a, **k: a
        and a[0]
        in (
            "/usr/bin",
            "/bin",
            "/sbin",
            "/usr/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
        ),
    )

    def _listdir(p, *a, **k):
        return ["sudo", "suspicious.bin"] if p == "/usr/bin" else []

    monkeypatch.setattr(checks.os, "listdir", _listdir)
    monkeypatch.setattr(checks.os.path, "isfile", lambda *a, **k: True)
    monkeypatch.setattr(
        checks.os,
        "stat",
        fake_stat_table({}, default_mode=stat.S_ISUID | 0o755),
    )
    res = run("FILE-006")
    assert res.level == Level.WARN
    assert "suspicious.bin" in res.detail


def test_file_006_only_well_known(monkeypatch):
    monkeypatch.setattr(
        checks.os.path, "isdir", lambda *a, **k: a and a[0] == "/usr/bin"
    )

    def _listdir(p, *a, **k):
        return ["sudo"] if p == "/usr/bin" else []

    monkeypatch.setattr(checks.os, "listdir", _listdir)
    monkeypatch.setattr(checks.os.path, "isfile", lambda *a, **k: True)
    monkeypatch.setattr(
        checks.os,
        "stat",
        fake_stat_table({}, default_mode=stat.S_ISUID | 0o755),
    )
    assert run("FILE-006").level == Level.PASS


@pytest.mark.parametrize(
    "mode,expected",
    [(None, Level.SKIP), (0o644, Level.PASS), (0o664, Level.FAIL)],
)
def test_file_007(monkeypatch, mode, expected):
    monkeypatch.setattr(checks, "_mode", fake_mode({"/etc/group": mode}))
    assert run("FILE-007").level == expected


# ------------------------------------------------------------ Authentication


@pytest.mark.parametrize(
    "defs,expected",
    [
        (None, Level.SKIP),
        ("PASS_MAX_DAYS 90\nPASS_MIN_DAYS 2\n", Level.PASS),
        ("PASS_MAX_DAYS 99999\n", Level.FAIL),
        ("# no aging directives\n", Level.FAIL),  # default 99999
    ],
)
def test_auth_001(monkeypatch, defs, expected):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/login.defs": defs}))
    assert run("AUTH-001").level == expected


@pytest.mark.parametrize(
    "defs,expected",
    [
        (None, Level.SKIP),
        ("UMASK 027\n", Level.PASS),
        ("UMASK 077\n", Level.PASS),
        ("UMASK 022\n", Level.FAIL),
        ("# no UMASK\n", Level.INFO),
    ],
)
def test_auth_002(monkeypatch, defs, expected):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/login.defs": defs}))
    assert run("AUTH-002").level == expected


@pytest.mark.parametrize(
    "shadow,expected",
    [
        (None, Level.SKIP),
        ("root:$6$abc:::0:0:::\n", Level.PASS),
        (r"root:$6$abc:::0:0:::" + "\nsvc::0:0:::\n", Level.FAIL),
    ],
)
def test_auth_003(monkeypatch, shadow, expected):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/shadow": shadow}))
    res = run("AUTH-003")
    assert res.level == expected
    if expected == Level.FAIL:
        assert "svc" in res.detail


@pytest.mark.parametrize(
    "shadow,expected",
    [
        (None, Level.SKIP),
        ("root:!:19000:0:99999:7:::\n", Level.PASS),
        ("root:*:19000:0:99999:7:::\n", Level.PASS),
        ("root:$6$realhash:19000:0:99999:7:::\n", Level.WARN),
        ("root::19000:0:99999:7:::\n", Level.FAIL),  # empty hash
        ("nobody:x:19000:0:99999:7:::\n", Level.FAIL),  # no root line
    ],
)
def test_auth_004(monkeypatch, shadow, expected):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/shadow": shadow}))
    assert run("AUTH-004").level == expected


# ---------------------------------------------------------------- Firewall


def test_fire_001_ufw_active(monkeypatch):
    monkeypatch.setattr(checks.shutil, "which", lambda x: "/usr/sbin/ufw")
    monkeypatch.setattr(
        checks, "_cmd", fake_cmd({"ufw": (0, "Status: active\nTo allow:")})
    )
    assert run("FIRE-001").level == Level.PASS


def test_fire_001_ufw_inactive(monkeypatch):
    monkeypatch.setattr(checks.shutil, "which", lambda x: "/usr/sbin/ufw")
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"ufw": (0, "Status: inactive")}))
    assert run("FIRE-001").level == Level.FAIL


def test_fire_001_nft_rules(monkeypatch):
    def which(x):
        return "/usr/sbin/nft" if x == "nft" else None

    monkeypatch.setattr(checks.shutil, "which", which)
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"nft": (0, "table ip filter {\n}")}))
    assert run("FIRE-001").level == Level.PASS


def test_fire_001_iptables_empty(monkeypatch):
    def which(x):
        return "/usr/sbin/iptables" if x == "iptables" else None

    monkeypatch.setattr(checks.shutil, "which", which)
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"iptables": (0, "")}))
    assert run("FIRE-001").level == Level.FAIL


def test_fire_001_no_backend(monkeypatch):
    monkeypatch.setattr(checks.shutil, "which", lambda x: None)
    res = run("FIRE-001")
    assert res.level == Level.INFO
    assert "no firewall tool" in res.detail


# ------------------------------------------------------------------ Network


@pytest.mark.parametrize(
    "val,expected",
    [(None, Level.SKIP), ("0\n", Level.PASS), ("1\n", Level.FAIL)],
)
def test_net_001(monkeypatch, val, expected):
    monkeypatch.setattr(
        checks, "_read", fake_read({"/proc/sys/net/ipv4/ip_forward": val})
    )
    assert run("NET-001").level == expected


@pytest.mark.parametrize(
    "val,expected",
    [(None, Level.SKIP), ("0\n", Level.PASS), ("1\n", Level.FAIL)],
)
def test_net_002(monkeypatch, val, expected):
    path = "/proc/sys/net/ipv4/conf/all/accept_redirects"
    monkeypatch.setattr(checks, "_read", fake_read({path: val}))
    assert run("NET-002").level == expected


def test_net_003_counts_ports(monkeypatch):
    ss_out = (
        "State  Recv-Q Send-Q Local:Port Peer:Port Process\n"
        "LISTEN 0      128    0.0.0.0:80      0.0.0.0:*  users:((nginx))\n"
        "LISTEN 0      128       [::]:22         [::]:*  users:((sshd))\n"
        "LISTEN 0      128    0.0.0.0:80      0.0.0.0:*  users:((nginx))\n"
    )
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"ss": (0, ss_out)}))
    res = run("NET-003")
    assert res.level == Level.INFO
    assert "2 listening" in res.detail


def test_net_003_no_tool(monkeypatch):
    monkeypatch.setattr(checks, "_cmd", lambda *a, **k: None)
    res = run("NET-003")
    assert "0 listening" in res.detail


@pytest.mark.parametrize(
    "val,expected",
    [(None, Level.SKIP), ("1\n", Level.PASS), ("2\n", Level.PASS), ("0\n", Level.FAIL)],
)
def test_net_004(monkeypatch, val, expected):
    monkeypatch.setattr(
        checks, "_read", fake_read({"/proc/sys/net/ipv4/conf/all/rp_filter": val})
    )
    assert run("NET-004").level == expected


# ------------------------------------------------------------------- Kernel


@pytest.mark.parametrize(
    "val,expected",
    [(None, Level.SKIP), ("2\n", Level.PASS), ("1\n", Level.PASS), ("0\n", Level.FAIL)],
)
def test_krnl_001(monkeypatch, val, expected):
    monkeypatch.setattr(
        checks, "_read", fake_read({"/proc/sys/kernel/kptr_restrict": val})
    )
    assert run("KRNL-001").level == expected


@pytest.mark.parametrize(
    "conf,expected",
    [
        (None, Level.INFO),
        ("* soft core 0\n", Level.INFO),
        ("* hard core 0\n", Level.PASS),
    ],
)
def test_krnl_002(monkeypatch, conf, expected):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/security/limits.conf": conf}))
    assert run("KRNL-002").level == expected


@pytest.mark.parametrize(
    "val,expected",
    [(None, Level.SKIP), ("2\n", Level.PASS), ("1\n", Level.FAIL)],
)
def test_krnl_003(monkeypatch, val, expected):
    path = "/proc/sys/kernel/randomize_va_space"
    monkeypatch.setattr(checks, "_read", fake_read({path: val}))
    assert run("KRNL-003").level == expected


# ------------------------------------------------------------------- Logging


@pytest.mark.parametrize(
    "which_result,expected",
    [("/usr/sbin/auditd", Level.PASS), (None, Level.INFO)],
)
def test_logg_001(monkeypatch, which_result, expected):
    monkeypatch.setattr(checks.shutil, "which", lambda x: which_result)
    assert run("LOGG-001").level == expected


@pytest.mark.parametrize(
    "which_result,expected",
    [("/usr/sbin/rsyslogd", Level.PASS), (None, Level.INFO)],
)
def test_logg_002(monkeypatch, which_result, expected):
    monkeypatch.setattr(checks.shutil, "which", lambda x: which_result)
    assert run("LOGG-002").level == expected


# -------------------------------------------------------------------- Misc


def test_misc_001_tmp_mounted(monkeypatch):
    monkeypatch.setattr(checks, "_read", fake_read({}))
    mount_out = "/tmp on /tmp type tmpfs (rw,nosuid)"
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"mount": (0, mount_out)}))
    assert run("MISC-001").level == Level.PASS


def test_misc_001_tmp_in_fstab(monkeypatch):
    fstab = "/dev/sdb1 /tmp ext4 defaults 0 2\n"
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/fstab": fstab}))
    monkeypatch.setattr(checks, "_cmd", lambda *a, **k: None)
    assert run("MISC-001").level == Level.PASS


def test_misc_001_not_separate(monkeypatch):
    monkeypatch.setattr(checks, "_read", fake_read({"/etc/fstab": "none"}))
    mount_out = "/dev/sda1 on / ext4"
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"mount": (0, mount_out)}))
    assert run("MISC-001").level == Level.WARN


def test_misc_001_cannot_inspect(monkeypatch):
    monkeypatch.setattr(checks, "_read", fake_read({}))
    monkeypatch.setattr(checks, "_cmd", lambda *a, **k: None)
    assert run("MISC-001").level == Level.SKIP


@pytest.mark.parametrize(
    "mode,expected",
    [(None, Level.SKIP), (0o440, Level.PASS), (0o400, Level.PASS), (0o644, Level.FAIL)],
)
def test_misc_002(monkeypatch, mode, expected):
    monkeypatch.setattr(checks, "_mode", fake_mode({"/etc/sudoers": mode}))
    assert run("MISC-002").level == expected


# ------------------------------------------------------------------- Windows


def test_win_001_all_on(monkeypatch):
    out = (
        "Domain Profile\nFirewall state: ON\n\n"
        "Private Profile\nFirewall state: ON\n\n"
        "Public Profile\nFirewall state: ON\n"
    )
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"netsh": (0, out)}))
    assert run("WIN-001").level == Level.PASS


def test_win_001_one_off(monkeypatch):
    out = (
        "Domain Profile\nFirewall state: ON\n\n" "Public Profile\nFirewall state: OFF\n"
    )
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"netsh": (0, out)}))
    assert run("WIN-001").level == Level.FAIL


def test_win_001_unavailable(monkeypatch):
    monkeypatch.setattr(checks, "_cmd", lambda *a, **k: None)
    assert run("WIN-001").level == Level.SKIP


def test_win_001_garbage(monkeypatch):
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"netsh": (0, "nonsense")}))
    assert run("WIN-001").level == Level.SKIP


@pytest.mark.parametrize(
    "val,expected",
    [(2, Level.PASS), (0, Level.FAIL), (None, Level.SKIP)],
)
def test_win_002(monkeypatch, val, expected):
    monkeypatch.setattr(checks, "_reg_dword", lambda *a, **k: val)
    assert run("WIN-002").level == expected


@pytest.mark.parametrize(
    "client,server,expected",
    [
        (2, 2, Level.PASS),
        (0, 2, Level.FAIL),
        (2, 0, Level.FAIL),
        (None, None, Level.INFO),
    ],
)
def test_win_003(monkeypatch, client, server, expected):
    def reg(hive, subkey, value):
        return client if "Workstation" in subkey else server

    monkeypatch.setattr(checks, "_reg_dword", reg)
    assert run("WIN-003").level == expected


@pytest.mark.parametrize(
    "val,expected",
    [(1, Level.PASS), (0, Level.FAIL), (None, Level.SKIP)],
)
def test_win_004(monkeypatch, val, expected):
    monkeypatch.setattr(checks, "_reg_dword", lambda *a, **k: val)
    assert run("WIN-004").level == expected


def test_win_005_running(monkeypatch):
    out = (
        "SERVICE_NAME: wuauserv\n"
        "        TYPE               : 110  WIN32_OWN_PROCESS (interactive)\n"
        "        STATE              : 4  RUNNING\n"
    )
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"sc": (0, out)}))
    assert run("WIN-005").level == Level.PASS


def test_win_005_stopped(monkeypatch):
    out = "SERVICE_NAME: wuauserv\n        STATE : 1  STOPPED\n"
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"sc": (0, out)}))
    assert run("WIN-005").level == Level.FAIL


def test_win_005_error(monkeypatch):
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"sc": (1168, "ERROR 1168")}))
    assert run("WIN-005").level == Level.SKIP


def test_win_005_unavailable(monkeypatch):
    monkeypatch.setattr(checks, "_cmd", lambda *a, **k: None)
    assert run("WIN-005").level == Level.SKIP


def test_win_006_good_policy(monkeypatch):
    out = (
        "Password properties for local group policy\n"
        "Minimum password length : 14\n"
        "Maximum password age : 42 days\n"
    )
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"net": (0, out)}))
    assert run("WIN-006").level == Level.PASS


def test_win_006_bad_policy(monkeypatch):
    out = "Minimum password length : 4\n" "Maximum password age : 99 days\n"
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"net": (0, out)}))
    res = run("WIN-006")
    assert res.level == Level.WARN
    assert "max age 99" in res.detail
    assert "min length 4" in res.detail


def test_win_006_requires_admin(monkeypatch):
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"net": (2, "Access is denied")}))
    assert run("WIN-006").level == Level.SKIP


def test_win_006_unparseable(monkeypatch):
    monkeypatch.setattr(checks, "_cmd", fake_cmd({"net": (0, "garbage output")}))
    assert run("WIN-006").level == Level.SKIP


def test_win_006_unavailable(monkeypatch):
    monkeypatch.setattr(checks, "_cmd", lambda *a, **k: None)
    assert run("WIN-006").level == Level.SKIP


# ------------------------------------------------------- helpers themselves


def _install_fake_winreg(
    monkeypatch,
    data: object = 42,
    reg_type: int = 4,
    open_error: Optional[Exception] = None,
):
    """Install a fake winreg module so the Windows-only code path of
    _reg_dword can be exercised on any platform."""
    import sys as _sys
    import types

    fake = types.ModuleType("winreg")

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _open(root, subkey):
        if open_error is not None:
            raise open_error
        return _Key()

    # injecting attributes onto a bare module (mypy: attr-defined)
    fake.HKEY_LOCAL_MACHINE = object()  # type: ignore[attr-defined]
    fake.HKEY_CURRENT_USER = object()  # type: ignore[attr-defined]
    fake.REG_DWORD = 4  # type: ignore[attr-defined]
    fake.OpenKey = _open  # type: ignore[attr-defined]
    fake.QueryValueEx = (  # type: ignore[attr-defined]
        (lambda key, value: (data, reg_type))
        if open_error is None
        else (lambda key, value: (None, 0))
    )
    monkeypatch.setitem(_sys.modules, "winreg", fake)
    monkeypatch.setattr(checks.sys, "platform", "win32")
    return fake


def test_reg_dword_windows_path(monkeypatch):
    _install_fake_winreg(monkeypatch, data=42, reg_type=4)
    assert checks._reg_dword("HKLM", r"SOFTWARE\X", "EnableLUA") == 42


def test_reg_dword_non_dword_type(monkeypatch):
    _install_fake_winreg(monkeypatch, data="string", reg_type=1)  # not DWORD
    assert checks._reg_dword("HKLM", r"SOFTWARE\X", "V") is None


def test_reg_dword_bad_hive(monkeypatch):
    _install_fake_winreg(monkeypatch)
    assert checks._reg_dword("HKEY_BOGUS", r"SOFTWARE\X", "V") is None


def test_reg_dword_open_error(monkeypatch):
    _install_fake_winreg(monkeypatch, open_error=OSError("access denied"))
    assert checks._reg_dword("HKLM", r"SOFTWARE\X", "V") is None


def test_file_001_stat_error(monkeypatch):
    monkeypatch.setattr(checks.os, "walk", lambda *a, **k: [("/etc", [], ["f1"])])
    monkeypatch.setattr(
        checks.os, "stat", lambda *a, **k: (_ for _ in ()).throw(OSError)
    )
    assert run("FILE-001").level == Level.PASS


def test_file_002_listdir_error(monkeypatch):
    def _boom(*a, **k):
        raise OSError

    monkeypatch.setattr(checks.os, "listdir", _boom)
    assert run("FILE-002").level == Level.PASS


def test_file_005_stat_error(monkeypatch):
    monkeypatch.setattr(checks.os.path, "isdir", lambda *a, **k: True)
    monkeypatch.setattr(
        checks.os, "stat", lambda *a, **k: (_ for _ in ()).throw(OSError)
    )
    assert run("FILE-005").level == Level.PASS


def test_file_006_stat_error(monkeypatch):
    monkeypatch.setattr(
        checks.os.path, "isdir", lambda *a, **k: a and a[0] == "/usr/bin"
    )
    monkeypatch.setattr(checks.os, "listdir", lambda *a, **k: ["sudo"])
    monkeypatch.setattr(checks.os.path, "isfile", lambda *a, **k: True)
    monkeypatch.setattr(
        checks.os, "stat", lambda *a, **k: (_ for _ in ()).throw(OSError)
    )
    assert run("FILE-006").level == Level.PASS


def test_cmd_returns_none_on_missing_binary(monkeypatch):
    import subprocess

    def _raise(*a, **k):
        raise FileNotFoundError("no such command")

    monkeypatch.setattr(subprocess, "run", _raise)
    assert checks._cmd(["definitely-not-a-command-xyz"]) is None


def test_read_returns_none_on_missing_file():
    assert checks._read("/nonexistent/path/xyz") is None


def test_mode_returns_none_on_missing_file():
    assert checks._mode("/nonexistent/path/xyz") is None


def test_fmt_mode_zero_pads():
    assert checks._fmt_mode(0o644) == "0644"
    assert checks._fmt_mode(0o44) == "0044"
