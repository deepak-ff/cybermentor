"""Microsoft Graph wrapper using the credential's bearer token + httpx for paging."""

from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

try:  # httpx is optional at import time so the CLI --list works without it.
    import httpx  # type: ignore
except ImportError:  # pragma: no cover - exercised when httpx is missing
    httpx = None  # type: ignore

log = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
DEFAULT_SCOPE = "https://graph.microsoft.com/.default"


class GraphClient:
    def __init__(self, credential: Any, *, timeout: float = 30.0) -> None:
        self.credential = credential
        self.timeout = timeout
        self._client: Optional[Any] = None

    # ----------------------------------------------------------------- internals
    def _client_inst(self):  # type: ignore[override]
        if httpx is None:
            raise RuntimeError(
                "httpx is required for Microsoft Graph calls. "
                "Install with: pip install httpx"
            )
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def _token(self) -> str:
        try:
            tok = self.credential.get_token(DEFAULT_SCOPE)
            return tok.token
        except Exception as exc:
            raise RuntimeError(f"Failed to obtain Graph token: {exc}") from exc

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/json",
            "ConsistencyLevel": "eventual",
        }

    # -------------------------------------------------------------- public API
    def get(self, path: str, *, params: Optional[dict] = None, beta: bool = False) -> Any:
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = path if path.startswith("http") else f"{base}{path}"
        resp = self._client_inst().get(url, headers=self._headers(), params=params)
        resp.raise_for_status()
        return resp.json()

    def list_all(self, path: str, *, params: Optional[dict] = None, beta: bool = False) -> list[dict]:
        items: list[dict] = []
        page = self.get(path, params=params, beta=beta)
        while True:
            for v in page.get("value", []) or []:
                items.append(v)
            next_link = page.get("@odata.nextLink")
            if not next_link:
                break
            page = self.get(next_link)
        return items

    def post(self, path: str, json: Optional[dict] = None, *, beta: bool = False) -> Any:
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = path if path.startswith("http") else f"{base}{path}"
        resp = self._client_inst().post(url, headers=self._headers(), json=json)
        resp.raise_for_status()
        if resp.content:
            try:
                return resp.json()
            except Exception:
                return resp.text
        return None

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    # ----------------------------------------------------- directory settings
    def directory_settings(self) -> list[dict]:
        """Return all GroupSettings (a.k.a. directory settings) configured on the tenant."""
        return self.list_all("/groupSettings")

    def directory_setting_value(self, display_name: str, value_name: str) -> Optional[str]:
        """Look up a single name=value pair in the named directory setting template."""
        for s in self.directory_settings():
            if (s.get("displayName") or "").lower() != display_name.lower():
                continue
            for v in s.get("values", []) or []:
                if (v.get("name") or "").lower() == value_name.lower():
                    return v.get("value")
        return None

    def authentication_methods_policy(self) -> dict:
        return self.get("/policies/authenticationMethodsPolicy")

    def conditional_access_policies(self) -> list[dict]:
        return self.list_all("/identity/conditionalAccess/policies")
