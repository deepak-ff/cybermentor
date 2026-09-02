"""Progress reporting primitives shared between Runner, GUI and CLI."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

log = logging.getLogger(__name__)


@dataclass
class ProgressEvent:
    benchmark_id: str
    control_id: str
    completed: int
    total: int
    status: Optional[str] = None
    message: str = ""
    phase: str = "finished"  # "started" when a check begins, "finished" when it ends
    title: str = ""


ProgressCallback = Callable[[ProgressEvent], None]


class NullProgress:
    def __call__(self, event: ProgressEvent) -> None:
        log.debug("[%s] %d/%d %s %s", event.benchmark_id, event.completed,
                  event.total, event.control_id, event.status or "")
