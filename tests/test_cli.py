"""End-to-end tests for the CLI."""

from __future__ import annotations

import json
import logging
import os

import pytest

from audit_tool import cli
from audit_tool.checks import CHECK_REGISTRY
from audit_tool.models import CheckResult, Level, Severity

# ------------------------------------------------------------------ parsing


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("80", [80]),
        ("1-3", [1, 2, 3]),
        ("80,443", [80, 443]),
        ("1-2,4,6-7", [1, 2, 4, 6, 7]),
        ("  22 ,  80 ", [22, 80]),
    ],
)
def test_parse_ports_valid(spec, expected):
    assert cli.parse_ports(spec) == expected


def test_parse_ports_top():
    from audit_tool.scanner import TOP_PORTS

    assert cli.parse_ports("top") == sorted(set(TOP_PORTS))


@pytest.mark.parametrize(
    "spec",
    ["1024-1", "0-100", "1-70000", "abc", "80,99999", ""],
)
def test_parse_ports_invalid(spec):
    with pytest.raises(ValueError):
        cli.parse_ports(spec)


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ("", None),
        ("  ", None),
        ("ssh, kernel", ["ssh", "kernel"]),
        ("ssh", ["ssh"]),
    ],
)
def test_parse_csv_list(value, expected):
    assert cli.parse_csv_list(value) == expected


# ------------------------------------------------------------------- listing


def test_list_checks_prints_table(capsys):
    rc = cli.main(["--list-checks"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SSH-001" in out
    assert "WIN-001" in out
    assert f"{len(CHECK_REGISTRY)} check(s) registered." in out


def test_list_checks_with_filters(capsys):
    rc = cli.main(["--list-checks", "--only", "ssh"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SSH-001" in out
    assert "WIN-001" not in out
    assert "4 check(s) registered." in out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0


# ---------------------------------------------------------------------- runs


def test_main_skip_scan_writes_reports(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="audit_tool")
    out_dir = str(tmp_path / "reports")
    rc = cli.main(
        [
            "--skip-scan",
            "--hostname",
            "unit-test",
            "--out",
            out_dir,
            "--formats",
            "json,html,csv,sarif",
        ]
    )
    assert rc == 0
    assert "Hardening score:" in caplog.text
    files = os.listdir(out_dir)
    assert len(files) == 4
    json_file = [f for f in files if f.endswith(".json") and "sarif" not in f][0]
    doc = json.load(open(os.path.join(out_dir, json_file)))
    assert doc["host"] == "unit-test"
    assert doc["platform"] in ("linux", "windows")
    assert 0 <= doc["score"] <= 100
    assert len(doc["checks"]) == len(CHECK_REGISTRY)
    # scan target is the --host default (127.0.0.1), not the label
    assert doc["scan_targets"] == {"target": "127.0.0.1", "skipped": True}


def test_main_only_category(tmp_path):
    out_dir = str(tmp_path / "r")
    rc = cli.main(
        [
            "--skip-scan",
            "--only",
            "ssh",
            "--out",
            out_dir,
            "--formats",
            "json",
        ]
    )
    assert rc == 0
    doc = _latest_json(out_dir)
    ids = {c["id"] for c in doc["checks"]}
    assert ids == {"SSH-001", "SSH-002", "SSH-003", "SSH-004"}


def test_main_exclude(tmp_path):
    out_dir = str(tmp_path / "r")
    rc = cli.main(
        [
            "--skip-scan",
            "--exclude",
            "SSH-001,ssh-002",
            "--out",
            out_dir,
            "--formats",
            "json",
        ]
    )
    assert rc == 0
    doc = _latest_json(out_dir)
    ids = {c["id"] for c in doc["checks"]}
    assert "SSH-001" not in ids
    assert "SSH-002" not in ids
    assert len(ids) == len(CHECK_REGISTRY) - 2


def test_main_invalid_ports_exit_2(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="audit_tool")
    rc = cli.main(["--ports", "0-70000", "--out", str(tmp_path)])
    assert rc == 2
    assert "invalid" in caplog.text


def test_main_empty_ports_exit_2(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="audit_tool")
    rc = cli.main(["--ports", "", "--out", str(tmp_path)])
    assert rc == 2
    assert "empty port spec" in caplog.text


def test_main_invalid_format_exit_2(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="audit_tool")
    rc = cli.main(["--skip-scan", "--formats", "pdf", "--out", str(tmp_path)])
    assert rc == 2
    assert "unknown report format" in caplog.text


def test_main_real_local_scan(tmp_path):
    """Scan 3 closed localhost ports: fast, no network dependency."""
    out_dir = str(tmp_path / "r")
    rc = cli.main(
        [
            "--host",
            "127.0.0.1",
            "--ports",
            "1-3",
            "--threads",
            "8",
            "--timeout",
            "0.2",
            "--out",
            out_dir,
            "--formats",
            "json",
        ]
    )
    assert rc == 0
    doc = _latest_json(out_dir)
    assert doc["scan_targets"]["target"] == "127.0.0.1"
    assert isinstance(doc["open_ports"], list)


def test_main_show_speedup(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="audit_tool")
    monkeypatch.setattr(cli, "timed_scan", lambda *a, **k: ([], 10))
    monkeypatch.setattr(cli, "sequential_scan", lambda *a, **k: [])
    out_dir = str(tmp_path / "r")
    rc = cli.main(
        [
            "--host",
            "127.0.0.1",
            "--ports",
            "1-3",
            "--show-speedup",
            "--out",
            out_dir,
            "--formats",
            "json",
        ]
    )
    assert rc == 0
    assert "Speed-up vs sequential" in caplog.text


def test_main_fail_exit_returns_1(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="audit_tool")

    def fake_checks(host, categories=None, exclude=None):
        return [
            CheckResult(
                "F-1",
                "forced fail",
                "Testing",
                Level.FAIL,
                "detail",
                severity=Severity.HIGH,
            )
        ]

    monkeypatch.setattr(cli, "run_all_checks", fake_checks)
    out_dir = str(tmp_path / "r")
    rc = cli.main(["--skip-scan", "--fail-exit", "--out", out_dir, "--formats", "json"])
    assert rc == 1
    assert "FAIL" in caplog.text


def test_main_fail_exit_clean_returns_0(monkeypatch, tmp_path):
    def fake_checks(host, categories=None, exclude=None):
        return [
            CheckResult(
                "P-1",
                "forced pass",
                "Testing",
                Level.PASS,
                "detail",
                severity=Severity.LOW,
            )
        ]

    monkeypatch.setattr(cli, "run_all_checks", fake_checks)
    out_dir = str(tmp_path / "r")
    rc = cli.main(["--skip-scan", "--fail-exit", "--out", out_dir, "--formats", "json"])
    assert rc == 0


def test_main_schema_validation_error_exit_3(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="audit_tool")

    def _boom(result, out_dir, formats=("json", "html")):
        raise RuntimeError("report validation failed: bad field")

    monkeypatch.setattr(cli, "write_reports", _boom)
    rc = cli.main(["--skip-scan", "--out", str(tmp_path), "--formats", "json"])
    assert rc == 3
    assert "report validation failed" in caplog.text


def test_main_empty_formats_exit_2(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="audit_tool")
    rc = cli.main(["--skip-scan", "--formats", "", "--out", str(tmp_path)])
    assert rc == 2
    assert "invalid --formats" in caplog.text


def test_main_verbose_does_not_crash(tmp_path):
    rc = cli.main(
        ["-vv", "--skip-scan", "--out", str(tmp_path / "r"), "--formats", "json"]
    )
    assert rc == 0


# ------------------------------------------------------------------- helpers


def _latest_json(out_dir: str) -> dict:
    files = sorted(
        f for f in os.listdir(out_dir) if f.endswith(".json") and "sarif" not in f
    )
    assert files
    with open(os.path.join(out_dir, files[-1]), "r", encoding="utf-8") as fh:
        return json.load(fh)
