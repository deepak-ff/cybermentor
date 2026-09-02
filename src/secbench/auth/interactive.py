"""Interactive browser sign-in via azure-identity."""

from __future__ import annotations

import logging
from typing import Optional

from .base import AuthMethod, CredentialBundle, CredentialProvider
from ..engine.errors import AuthenticationError

log = logging.getLogger(__name__)


class InteractiveBrowserProvider(CredentialProvider):
    method = AuthMethod.INTERACTIVE

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ) -> None:
        self.tenant_id = tenant_id or "organizations"
        # Microsoft "Azure CLI" public client ID falls back when not set.
        self.client_id = client_id or "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
        self.redirect_uri = redirect_uri

    def acquire(self) -> CredentialBundle:
        try:
            from azure.identity import InteractiveBrowserCredential
        except ImportError as exc:
            raise AuthenticationError(
                "azure-identity is required for interactive sign-in"
            ) from exc

        kwargs: dict[str, object] = {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
        }
        if self.redirect_uri:
            kwargs["redirect_uri"] = self.redirect_uri
        cred = InteractiveBrowserCredential(**kwargs)
        # Force a token request so the sign-in dialog appears now.
        try:
            cred.get_token("https://management.azure.com/.default")
        except Exception as exc:  # pragma: no cover - depends on user's tenant
            raise AuthenticationError(f"Interactive sign-in failed: {exc}") from exc
        return CredentialBundle(
            credential=cred,
            method=self.method,
            tenant_id=self.tenant_id,
            client_id=self.client_id,
        )

    def description(self) -> str:
        return f"Interactive browser (tenant={self.tenant_id})"
