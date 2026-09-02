"""Smoke tests for the engine runner using a stub credential."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from secbench.engine import Context, Runner, load_all_benchmarks
from secbench.engine.models import CheckResult, Status
from secbench.engine.registry import check


def test_runner_skips_with_no_credential():
    benches = [b for b in load_all_benchmarks() if b.id == "azure_storage_1_0_0"]
    assert benches, "storage benchmark not loaded"

    ctx = Context(
        credential=SimpleNamespace(get_token=lambda *a, **kw: SimpleNamespace(token="x")),
        tenant_id="00000000-0000-0000-0000-000000000000",
        subscription_ids=[],  # no subs -> all checks should produce N/A or PASS-empty
    )

    runner = Runner()
    result = asyncio.run(runner.run(ctx, benches, level_max=2, include_manual=True))
    assert result.benchmarks == benches
    total = sum(len(v) for v in result.results.values())
    assert total == sum(len(b.all_controls()) for b in benches)


def test_check_decorator_registers_function():
    @check("TEST-XYZ-1")
    def fn(ctx, control):
        return CheckResult(control_id=control.id, status=Status.PASS, summary="ok")

    from secbench.engine.registry import get_check
    assert get_check("TEST-XYZ-1") is fn
