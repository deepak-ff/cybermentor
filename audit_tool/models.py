"""Core data models for the security audit tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Level(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"


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

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "checks": [c.to_dict() for c in self.checks],
            "open_ports": self.open_ports,
            "scan_targets": self.scan_targets,
        }

    @property
    def score(self) -> int:
        """Hardening score 0-100 computed from check levels."""
        if not self.checks:
            return 0
        relevant = [c for c in self.checks if c.level != Level.SKIP]
        if not relevant:
            return 0
        points = 0.0
        for c in relevant:
            if c.level == Level.PASS:
                points += 1.0
            elif c.level == Level.WARN:
                points += 0.5
        return round((points / len(relevant)) * 100)
