"""Tests for data models and the severity-weighted hardening score."""

from __future__ import annotations

from audit_tool.models import (
    LEVEL_SEVERITY,
    SEVERITY_WEIGHTS,
    CheckResult,
    Level,
    Platform,
    ScanResult,
    Severity,
    level_counts,
)


def _check(level: Level, severity: Severity) -> CheckResult:
    return CheckResult(
        id="X",
        title="t",
        category="c",
        level=level,
        detail="d",
        severity=severity,
    )


def test_level_values():
    assert {lvl.value for lvl in Level} == {"PASS", "WARN", "FAIL", "INFO", "SKIP"}


def test_severity_weights_ordering():
    order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    weights = [SEVERITY_WEIGHTS[s] for s in order]
    assert weights == sorted(weights, reverse=True)


def test_platform_values():
    assert {p.value for p in Platform} == {"linux", "windows", "any"}


def test_level_counts():
    checks = [
        _check(Level.PASS, Severity.LOW),
        _check(Level.PASS, Severity.LOW),
        _check(Level.FAIL, Severity.HIGH),
        _check(Level.SKIP, Severity.LOW),
    ]
    counts = level_counts(checks)
    assert counts[Level.PASS] == 2
    assert counts[Level.FAIL] == 1
    assert counts[Level.SKIP] == 1
    assert counts[Level.WARN] == 0
    assert counts[Level.INFO] == 0


def test_check_to_dict_includes_severity():
    c = _check(Level.FAIL, Severity.CRITICAL)
    d = c.to_dict()
    assert d["level"] == "FAIL"
    assert d["severity"] == "CRITICAL"
    assert d["id"] == "X"


def test_scan_to_dict_includes_score_tool_platform():
    sr = ScanResult(
        host="h",
        started_at="s",
        finished_at="f",
        duration_ms=1,
        checks=[_check(Level.PASS, Severity.LOW)],
        tool="tool 1.0",
        platform="linux",
    )
    d = sr.to_dict()
    assert d["score"] == 100
    assert d["tool"] == "tool 1.0"
    assert d["platform"] == "linux"
    assert d["host"] == "h"


def test_score_all_pass_is_100():
    sr = ScanResult(
        host="h",
        started_at="s",
        finished_at="f",
        duration_ms=1,
        checks=[
            _check(Level.PASS, Severity.CRITICAL),
            _check(Level.PASS, Severity.LOW),
        ],
    )
    assert sr.score == 100


def test_score_all_fail_is_0():
    sr = ScanResult(
        host="h",
        started_at="s",
        finished_at="f",
        duration_ms=1,
        checks=[
            _check(Level.FAIL, Severity.CRITICAL),
            _check(Level.FAIL, Severity.LOW),
        ],
    )
    assert sr.score == 0


def test_score_warn_earns_half_weight():
    sr = ScanResult(
        host="h",
        started_at="s",
        finished_at="f",
        duration_ms=1,
        checks=[_check(Level.WARN, Severity.LOW), _check(Level.PASS, Severity.LOW)],
    )
    # earned = 0.5*1 + 1*1 = 1.5 ; total = 2 -> 75
    assert sr.score == 75


def test_score_weights_critical_more_than_low():
    # One CRITICAL fail + one LOW pass should score far below the symmetric
    # LOW-fail + CRITICAL-pass case.
    sr_critical_fail = ScanResult(
        host="h",
        started_at="s",
        finished_at="f",
        duration_ms=1,
        checks=[
            _check(Level.FAIL, Severity.CRITICAL),
            _check(Level.PASS, Severity.LOW),
        ],
    )
    sr_low_fail = ScanResult(
        host="h",
        started_at="s",
        finished_at="f",
        duration_ms=1,
        checks=[
            _check(Level.FAIL, Severity.LOW),
            _check(Level.PASS, Severity.CRITICAL),
        ],
    )
    # critical_fail: (0 + 1)/(8+1) = 11 ; low_fail: (8 + 0)/(1+8) = 89 (rounded)
    assert sr_critical_fail.score == 11
    assert sr_low_fail.score == 89
    assert sr_critical_fail.score < sr_low_fail.score


def test_score_ignores_info_and_skip():
    sr = ScanResult(
        host="h",
        started_at="s",
        finished_at="f",
        duration_ms=1,
        checks=[
            _check(Level.INFO, Severity.HIGH),
            _check(Level.SKIP, Severity.HIGH),
            _check(Level.PASS, Severity.LOW),
        ],
    )
    assert sr.score == 100


def test_score_empty_is_0():
    sr = ScanResult(host="h", started_at="s", finished_at="f", duration_ms=1)
    assert sr.score == 0


def test_level_severity_ranking():
    assert LEVEL_SEVERITY[None] < LEVEL_SEVERITY["PASS"]
    assert LEVEL_SEVERITY["WARN"] < LEVEL_SEVERITY["FAIL"]
    assert LEVEL_SEVERITY["INFO"] == LEVEL_SEVERITY["PASS"]
