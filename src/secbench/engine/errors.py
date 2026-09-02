"""Custom exception hierarchy for the benchmark engine."""

from __future__ import annotations


class SecBenchError(Exception):
    """Base class for all sec-benchmarks errors."""


class AuthenticationError(SecBenchError):
    """Failed to obtain credentials or required scopes."""


class CatalogError(SecBenchError):
    """Catalog YAML failed to parse or validate."""


class ApiAccessError(SecBenchError):
    """An Azure / Graph API request failed."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
