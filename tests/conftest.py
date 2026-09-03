"""Shared fixtures for the audit tool test suite."""

from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

import pytest

from audit_tool.models import CheckResult, Level, ScanResult, Severity


def make_check(
    check_id: str,
    level: Level,
    severity: Severity = Severity.MEDIUM,
    category: str = "Test",
    detail: str = "detail",
) -> CheckResult:
    return CheckResult(
        id=check_id,
        title=f"Title {check_id}",
        category=category,
        level=level,
        detail=detail,
        recommendation="do the thing",
        cis_ref="CIS x.y",
        host="testhost",
        severity=severity,
    )


def make_report(
    checks: List[CheckResult],
    host: str = "testhost",
    open_ports: Optional[List[dict]] = None,
) -> ScanResult:
    now = datetime.now().isoformat(timespec="seconds")
    return ScanResult(
        host=host,
        started_at=now,
        finished_at=now,
        duration_ms=123,
        checks=checks,
        open_ports=open_ports if open_ports is not None else [],
        scan_targets={"target": host, "ports": "1-1024"},
        tool="security-audit-tool 1.0.0",
        platform="linux",
    )


@pytest.fixture
def sample_checks() -> List[CheckResult]:
    return [
        make_check("A-001", Level.PASS, Severity.CRITICAL, "SSH"),
        make_check("A-002", Level.WARN, Severity.HIGH, "Filesystem"),
        make_check("A-003", Level.FAIL, Severity.MEDIUM, "Network"),
        make_check("A-004", Level.INFO, Severity.LOW, "Logging"),
        make_check("A-005", Level.SKIP, Severity.LOW, "Windows"),
    ]


@pytest.fixture
def sample_report(sample_checks) -> ScanResult:
    return make_report(
        sample_checks,
        open_ports=[
            {"port": 22, "service": "ssh"},
            {"port": 65001, "service": "unknown"},
        ],
    )


@pytest.fixture
def report_files(tmp_path):
    """Two on-disk report JSON files (new one regresses one check)."""

    def dump(name: str, levels: dict) -> str:
        checks = [
            {
                "id": cid,
                "title": f"Title {cid}",
                "category": "Test",
                "level": lvl,
                "detail": "d",
                "recommendation": "r",
                "cis_ref": "CIS 1.1",
                "host": name,
                "severity": "MEDIUM",
            }
            for cid, lvl in levels.items()
        ]
        doc = {
            "tool": "security-audit-tool 1.0.0",
            "platform": "linux",
            "host": name,
            "started_at": "2026-01-01T00:00:00",
            "finished_at": "2026-01-01T00:01:00",
            "duration_ms": 60000,
            "score": 10,
            "checks": checks,
            "open_ports": [],
            "scan_targets": None,
        }
        path = tmp_path / f"{name}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return str(path)

    base = dump("base", {"C-1": "PASS", "C-2": "PASS", "C-3": "WARN"})
    new = dump("new", {"C-1": "FAIL", "C-2": "PASS", "C-4": "INFO"})
    return base, new
