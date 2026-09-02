"""Common helpers for check implementations: result builders, iteration, caching."""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable

from .models import CheckResult, Context, Control, Status

log = logging.getLogger(__name__)


def make_result(
    control: Control,
    status: Status,
    summary: str,
    *,
    evidence: list[dict] | None = None,
    error: str | None = None,
) -> CheckResult:
    return CheckResult(
        control_id=control.id,
        status=status,
        summary=summary,
        evidence=evidence or [],
        error=error,
        benchmark_id=control.benchmark_id,
    )


def manual_result(control: Control, summary: str = "Requires manual review per CIS audit guidance.") -> CheckResult:
    return make_result(control, Status.MANUAL, summary)


def na_result(control: Control, summary: str) -> CheckResult:
    return make_result(control, Status.NOT_APPLICABLE, summary)


def error_result(control: Control, exc: BaseException) -> CheckResult:
    return make_result(
        control,
        Status.ERROR,
        f"API error: {exc!s}",
        error=repr(exc),
    )


def iter_subscriptions(ctx: Context) -> Iterable[str]:
    return list(ctx.subscription_ids or [])


def cached(ctx: Context, *parts: Any, factory: Callable[[], Any]) -> Any:
    if ctx.cache is None:
        return factory()
    key = ctx.cache.make_key(*parts)
    return ctx.cache.get_or_set(key, factory)


def aggregate_status(failures: list[dict], total: int) -> Status:
    if total == 0:
        return Status.NOT_APPLICABLE
    if not failures:
        return Status.PASS
    return Status.FAIL


def fail_or_pass(
    control: Control,
    *,
    failures: list[dict],
    total: int,
    pass_summary: str,
    fail_summary: str,
    na_summary: str = "No applicable resources found in scope.",
) -> CheckResult:
    status = aggregate_status(failures, total)
    if status == Status.PASS:
        return make_result(control, Status.PASS, pass_summary)
    if status == Status.NOT_APPLICABLE:
        return make_result(control, Status.NOT_APPLICABLE, na_summary)
    return make_result(control, Status.FAIL, fail_summary, evidence=failures)
