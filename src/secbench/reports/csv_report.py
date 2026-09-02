"""Render a flat CSV report (one row per evaluated control)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..engine.runner import RunResult


CSV_HEADERS = [
    "benchmark_id",
    "benchmark_version",
    "control_id",
    "section",
    "title",
    "level",
    "status",
    "summary",
    "duration_ms",
    "started_at",
    "evidence",
    "error",
]


def render_csv(run: RunResult, out_path: str | Path) -> Path:
    out = Path(out_path)
    # Build a control lookup so we can join titles/levels into rows.
    by_id: dict[str, tuple[str, str, int, str]] = {}
    for bench in run.benchmarks:
        for sec in bench.sections:
            for ctrl in sec.controls:
                by_id[ctrl.id] = (bench.version, sec.id, ctrl.level, ctrl.title)

    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_HEADERS)
        for bench in run.benchmarks:
            for r in run.results.get(bench.id, []):
                version, section, level, title = by_id.get(
                    r.control_id, (bench.version, "", 1, r.control_id)
                )
                writer.writerow(
                    [
                        bench.id,
                        version,
                        r.control_id,
                        section,
                        title,
                        level,
                        r.status.value,
                        r.summary,
                        r.duration_ms,
                        r.started_at.isoformat() if r.started_at else "",
                        json.dumps(r.evidence, default=str),
                        r.error or "",
                    ]
                )
    return out
