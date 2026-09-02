"""Core dataclasses shared between engine, benchmark modules and reporters."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    MANUAL = "manual"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    SKIPPED = "skipped"

    @property
    def label(self) -> str:
        return {
            "pass": "Pass",
            "fail": "Fail",
            "manual": "Manual",
            "not_applicable": "N/A",
            "error": "Error",
            "skipped": "Skipped",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "pass": "#1f9d55",
            "fail": "#cc1f1a",
            "manual": "#b08900",
            "not_applicable": "#777777",
            "error": "#7c2ae8",
            "skipped": "#999999",
        }[self.value]


@dataclass
class Control:
    id: str
    benchmark_id: str
    section: str
    title: str
    level: int = 1
    profile: Optional[str] = None
    automated: bool = True
    rationale: str = ""
    audit: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class Section:
    id: str
    title: str
    controls: list[Control] = field(default_factory=list)


@dataclass
class Benchmark:
    id: str
    title: str
    version: str
    target: str  # "azure" | "m365" | "macos"
    description: str = ""
    sections: list[Section] = field(default_factory=list)
    beta: bool = False

    def all_controls(self) -> list[Control]:
        return [c for s in self.sections for c in s.controls]


@dataclass
class CheckResult:
    control_id: str
    status: Status
    summary: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int = 0
    error: Optional[str] = None
    benchmark_id: str = ""

    def mark_done(self, started_perf: float) -> None:
        self.duration_ms = int((time.perf_counter() - started_perf) * 1000)


@dataclass
class RunSummary:
    benchmark_id: str
    total: int = 0
    by_status: dict[str, int] = field(default_factory=dict)


@dataclass
class Context:
    """Per-run context passed to every check function."""

    credential: Any = None  # azure.core.credentials.TokenCredential
    tenant_id: str = ""
    subscription_ids: list[str] = field(default_factory=list)
    profile: str = "E3"
    cache: Any = None  # ResponseCache
    extras: dict[str, Any] = field(default_factory=dict)
    cancel_event: Any = None  # threading.Event-like
    target: Any = None  # secbench.targets.MachineTarget for OS-level benchmarks

    def is_cancelled(self) -> bool:
        if self.cancel_event is None:
            return False
        try:
            return bool(self.cancel_event.is_set())
        except Exception:
            return False


CheckCallable = Callable[[Context, Control], "CheckResult"]
