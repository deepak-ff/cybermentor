"""Decorator-based registry mapping control IDs to check implementations."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import pkgutil
from typing import Awaitable, Callable, Optional, Union

from .models import CheckResult, Context, Control, Status

log = logging.getLogger(__name__)


CheckFn = Callable[[Context, Control], Union[CheckResult, Awaitable[CheckResult]]]


class Registry:
    def __init__(self) -> None:
        self._fns: dict[str, CheckFn] = {}

    def register(self, control_id: str, fn: CheckFn) -> None:
        if control_id in self._fns:
            log.warning("Overriding existing check registration for %s", control_id)
        self._fns[control_id] = fn

    def get(self, control_id: str) -> Optional[CheckFn]:
        return self._fns.get(control_id)

    def has(self, control_id: str) -> bool:
        return control_id in self._fns

    def all_ids(self) -> list[str]:
        return sorted(self._fns)


registry = Registry()


def check(control_id: str) -> Callable[[CheckFn], CheckFn]:
    """Decorator: associate a function with a CIS control id."""

    def deco(fn: CheckFn) -> CheckFn:
        registry.register(control_id, fn)
        return fn

    return deco


def get_check(control_id: str) -> Optional[CheckFn]:
    return registry.get(control_id)


async def invoke_check(fn: CheckFn, ctx: Context, control: Control) -> CheckResult:
    try:
        result = fn(ctx, control)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, CheckResult):
            return CheckResult(
                control_id=control.id,
                status=Status.ERROR,
                summary=f"Check {control.id} returned {type(result).__name__} instead of CheckResult",
                error="invalid return type",
                benchmark_id=control.benchmark_id,
            )
        result.benchmark_id = result.benchmark_id or control.benchmark_id
        return result
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("Check %s failed", control.id)
        return CheckResult(
            control_id=control.id,
            status=Status.ERROR,
            summary=f"Unhandled exception: {exc!s}",
            error=repr(exc),
            benchmark_id=control.benchmark_id,
        )


def autodiscover(packages: list[str]) -> int:
    """Import every submodule of the given benchmark packages so @check decorators run."""
    discovered = 0
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except Exception as exc:
            log.warning("Could not import benchmark package %s: %s", pkg_name, exc)
            continue
        if not hasattr(pkg, "__path__"):
            continue
        for mod in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
            try:
                importlib.import_module(mod.name)
                discovered += 1
            except Exception as exc:
                log.warning("Could not import %s: %s", mod.name, exc)
    return discovered
