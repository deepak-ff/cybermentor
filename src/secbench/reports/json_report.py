"""Render a RunResult to a JSON file."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from ..engine.runner import RunResult


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    return str(value)


def render_json(run: RunResult, out_path: str | Path) -> Path:
    out = Path(out_path)
    payload: dict[str, Any] = {
        "tool_version": run.tool_version,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "tenant_id": run.tenant_id,
        "subscription_ids": run.subscription_ids,
        "profile": run.profile,
        "summary": run.summary(),
        "benchmarks": [],
    }
    for bench in run.benchmarks:
        payload["benchmarks"].append(
            {
                "id": bench.id,
                "title": bench.title,
                "version": bench.version,
                "target": bench.target,
                "results": [
                    {**asdict(r), "status": r.status.value}
                    for r in run.results.get(bench.id, [])
                ],
            }
        )
    out.write_text(json.dumps(payload, indent=2, default=_default), encoding="utf-8")
    return out
