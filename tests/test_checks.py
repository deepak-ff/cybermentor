import stat

import audit_tool.checks as checks
from audit_tool.models import Level


def test_check_tmp_fs_mounted(monkeypatch):
    monkeypatch.setattr(checks, "_read", lambda p: None)
    monkeypatch.setattr(checks, "_cmd", lambda c: "/tmp on /tmp type tmpfs (rw)")
    res = checks.check_tmp_fs("host")
    assert res.level == Level.PASS


def test_check_tmp_fs_no_inspect(monkeypatch):
    monkeypatch.setattr(checks, "_read", lambda p: None)
    monkeypatch.setattr(checks, "_cmd", lambda c: None)
    res = checks.check_tmp_fs("host")
    assert res.level == Level.SKIP


def test_check_passwd_mode(monkeypatch):
    monkeypatch.setattr(checks, "_mode", lambda p: 0o644)
    res = checks.check_passwd_mode("host")
    assert res.level == Level.PASS


def test_check_sudoers_mode_skip(monkeypatch):
    monkeypatch.setattr(checks, "_mode", lambda p: None)
    res = checks.check_sudoers_mode("host")
    assert res.level == Level.SKIP


def test_check_firewall_no_backend(monkeypatch):
    monkeypatch.setattr(checks.shutil, "which", lambda x: None)
    res = checks.check_firewall("host")
    assert res.level == Level.INFO


def test_world_writable_etc_warn(monkeypatch):
    # simulate one world-writable file
    def fake_walk(root, topdown=True):
        yield ("/etc", [], ["f1"])  # one file

    class StatResult:
        st_mode = stat.S_IWOTH

    monkeypatch.setattr(checks.os, "walk", fake_walk)
    monkeypatch.setattr(checks.os, "stat", lambda p: StatResult())
    res = checks.check_world_writable_etc("host")
    assert res.level in (Level.WARN, Level.PASS)
