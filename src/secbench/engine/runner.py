"""Runs selected benchmarks against a populated Context, returning aggregated results."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from .models import Benchmark, CheckResult, Context, Control, Status
from .progress import ProgressCallback, ProgressEvent
from .registry import autodiscover, get_check, invoke_check

log = logging.getLogger(__name__)


BENCHMARK_PACKAGE_NAMES = [
    "secbench.benchmarks.azure_foundations_6_0_0",
    "secbench.benchmarks.azure_compute_2_0_0",
    "secbench.benchmarks.azure_database_2_0_0",
    "secbench.benchmarks.azure_storage_1_0_0",
    "secbench.benchmarks.m365_foundations_6_0_1",
    "secbench.benchmarks.macos_tahoe_1_0_0",
    "secbench.benchmarks.rhel_10_1_0_1",
    "secbench.benchmarks.rhel_9_2_0_0",
    "secbench.benchmarks.rhel_9_stig_1_0_0",
    "secbench.benchmarks.rhel_8_4_0_0",
    "secbench.benchmarks.rhel_8_stig_2_0_0",
    "secbench.benchmarks.defender_av_1_0_0",
    "secbench.benchmarks.windows_11_enterprise_5_0_1",
    "secbench.benchmarks.windows_11_standalone_5_0_0",
    "secbench.benchmarks.azure_compute_win_server_2022_1_0_0",
    "secbench.benchmarks.azure_compute_win_server_2019_1_0_0",
    "secbench.benchmarks.win_server_2025_2_0_0",
    "secbench.benchmarks.win_server_2025_standalone_1_0_0",
    "secbench.benchmarks.win_server_2022_5_0_0",
    "secbench.benchmarks.win_server_2022_standalone_2_0_0",
    "secbench.benchmarks.win_server_2022_stig_2_0_0",
    "secbench.benchmarks.win_server_2019_4_0_0",
    "secbench.benchmarks.win_server_2019_standalone_3_0_0",
    "secbench.benchmarks.win_server_2019_stig_3_0_0",
]


@dataclass
class RunResult:
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    benchmarks: list[Benchmark] = field(default_factory=list)
    results: dict[str, list[CheckResult]] = field(default_factory=dict)
    tenant_id: str = ""
    subscription_ids: list[str] = field(default_factory=list)
    profile: str = "E3"
    tool_version: str = ""

    def add(self, benchmark_id: str, result: CheckResult) -> None:
        self.results.setdefault(benchmark_id, []).append(result)

    def summary(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for bid, items in self.results.items():
            counts: dict[str, int] = {}
            for r in items:
                counts[r.status.value] = counts.get(r.status.value, 0) + 1
            out[bid] = counts
        return out


class Runner:
    """Executes selected controls; supports async and progress callbacks."""

    def __init__(self, *, max_concurrency: int = 8) -> None:
        self.max_concurrency = max_concurrency
        self._discovered = False

    def ensure_discovered(self) -> None:
        if not self._discovered:
            count = autodiscover(BENCHMARK_PACKAGE_NAMES)
            log.info("Auto-discovered %d benchmark modules", count)
            self._discovered = True

    async def run(
        self,
        ctx: Context,
        benchmarks: Iterable[Benchmark],
        *,
        level_max: int = 2,
        progress: Optional[ProgressCallback] = None,
        include_manual: bool = True,
    ) -> RunResult:
        self.ensure_discovered()
        run_result = RunResult(
            tenant_id=ctx.tenant_id,
            subscription_ids=list(ctx.subscription_ids),
            profile=ctx.profile,
        )
        try:
            from .. import __version__ as ver  # noqa: WPS433
            run_result.tool_version = ver
        except Exception:
            pass

        all_benches = list(benchmarks)
        run_result.benchmarks = all_benches
        sem = asyncio.Semaphore(self.max_concurrency)

        for bench in all_benches:
            controls = [c for c in bench.all_controls() if c.level <= level_max]
            total = len(controls)
            completed = 0

            async def _eval(control: Control) -> CheckResult:
                if ctx.is_cancelled():
                    res = CheckResult(
                        control_id=control.id,
                        status=Status.SKIPPED,
                        summary="Run cancelled by user",
                        benchmark_id=bench.id,
                    )
                    return res
                started = time.perf_counter()
                fn = get_check(control.id)
                if fn is None:
                    res = CheckResult(
                        control_id=control.id,
                        status=Status.MANUAL,
                        summary="No automated check implementation; review the audit guidance manually.",
                        benchmark_id=bench.id,
                    )
                else:
                    async with sem:
                        if progress is not None:
                            progress(
                                ProgressEvent(
                                    benchmark_id=bench.id,
                                    control_id=control.id,
                                    completed=completed,
                                    total=total,
                                    status="running",
                                    phase="started",
                                    title=control.title,
                                )
                            )
                        res = await invoke_check(fn, ctx, control)
                if not include_manual and res.status == Status.MANUAL:
                    res.status = Status.SKIPPED
                res.mark_done(started)
                return res

            tasks = [asyncio.create_task(_eval(c)) for c in controls]
            for fut in asyncio.as_completed(tasks):
                res = await fut
                completed += 1
                run_result.add(bench.id, res)
                if progress is not None:
                    title = next(
                        (c.title for c in controls if c.id == res.control_id), ""
                    )
                    progress(
                        ProgressEvent(
                            benchmark_id=bench.id,
                            control_id=res.control_id,
                            completed=completed,
                            total=total,
                            status=res.status.value,
                            phase="finished",
                            title=title,
                        )
                    )

        run_result.finished_at = datetime.now(timezone.utc)
        return run_result
