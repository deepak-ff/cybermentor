"""Tiny per-run response cache so multiple checks share API calls."""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Callable


class ResponseCache:
    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self._lock = threading.Lock()
        self._store: dict[str, Any] = {}

    @staticmethod
    def make_key(*parts: Any) -> str:
        try:
            blob = json.dumps(parts, sort_keys=True, default=repr)
        except Exception:
            blob = repr(parts)
        return hashlib.sha1(blob.encode("utf-8")).hexdigest()

    def get_or_set(self, key: str, factory: Callable[[], Any]) -> Any:
        if not self.enabled:
            return factory()
        with self._lock:
            if key in self._store:
                return self._store[key]
        value = factory()
        with self._lock:
            self._store.setdefault(key, value)
            return self._store[key]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
