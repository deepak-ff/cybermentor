"""Core data models for the security audit tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Level(str, Enum):
    """Outcome of a single security check."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"


class Severity(str, Enum):
    """Business impact of a check failing.

    Severity drives the weighted hardening score: a failed CRITICAL check
    hurts the score far more than a failed LOW check.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


#: Relative weight of each severity in the hardening score.
SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 8.0,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
}


class Platform(str, Enum):
    """Target operating system a check applies to."""

    LINUX = "linux"
    WINDOWS = "windows"
    ANY = "any"


#: Order used to rank levels from best to worst (baseline diffing, sorting).
LEVEL_SEVERITY: Dict[Optional[str], int] = {
    "PASS": 0,
    "INFO": 0,
    "SKIP": 0,
    "WARN": 1,
    "FAIL": 2,
    None: -1,
}


def level_counts(checks: List["CheckResult"]) -> Dict[Level, int]:
    """Count checks per level (every level is always present)."""
    counts = {lvl: 0 for lvl in Level}
    for c in checks:
        counts[c.level] += 1
    return counts


@dataclass
class CheckResult:
    """Outcome of a single security check."""

    id: str
    title: str
    category: str
    level: Level
    detail: str
    recommendation: str = ""
    cis_ref: str = ""
    host: str = "localhost"
    severity: Severity = Severity.MEDIUM

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "level": self.level.value,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "cis_ref": self.cis_ref,
            "host": self.host,
            "severity": self.severity.value,
        }


@dataclass
class ScanResult:
    """Container for a full audit run."""

    host: str
    started_at: str
    finished_at: str
    duration_ms: int
    checks: List[CheckResult] = field(default_factory=list)
    open_ports: List[dict] = field(default_factory=list)
    scan_targets: Optional[dict] = None
    tool: str = ""
    platform: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "platform": self.platform,
            "host": self.host,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "score": self.score,
            "checks": [c.to_dict() for c in self.checks],
            "open_ports": self.open_ports,
            "scan_targets": self.scan_targets,
        }

    @property
    def score(self) -> int:
        """Severity-weighted hardening score, 0-100.

        Only checks with an actionable verdict (PASS / WARN / FAIL) take part
        in the score; INFO and SKIP are informational. A WARN earns half the
        weight of a PASS. The denominator is the sum of the severities of the
        participating checks, so a failed CRITICAL check is worth 8x a failed
        LOW check.
        """
        relevant = [
            c for c in self.checks if c.level in (Level.PASS, Level.WARN, Level.FAIL)
        ]
        if not relevant:
            return 0
        total = sum(SEVERITY_WEIGHTS[c.severity] for c in relevant)
        if total <= 0:
            return 0
        earned = sum(
            SEVERITY_WEIGHTS[c.severity] * (1.0 if c.level == Level.PASS else 0.5)
            for c in relevant
            if c.level in (Level.PASS, Level.WARN)
        )
        return round((earned / total) * 100)
