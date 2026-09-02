"""High-level facade that selects/creates a CredentialProvider for the GUI/CLI."""

from __future__ import annotations

import logging
from typing import Any, Optional

from .base import AuthMethod, CredentialBundle, CredentialProvider
from .device_code import DeviceCodeProvider
from .interactive import InteractiveBrowserProvider
from .service_principal import ServicePrincipalProvider
from ..engine.errors import AuthenticationError

log = logging.getLogger(__name__)


class AuthManager:
    def __init__(self) -> None:
        self.provider: Optional[CredentialProvider] = None
        self.bundle: Optional[CredentialBundle] = None

    def configure(
        self,
        method: AuthMethod | str,
        *,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        certificate_path: Optional[str] = None,
        certificate_password: Optional[str] = None,
        prompt_callback: Any = None,
    ) -> CredentialProvider:
        method = AuthMethod(method) if not isinstance(method, AuthMethod) else method
        if method == AuthMethod.INTERACTIVE:
            self.provider = InteractiveBrowserProvider(
                tenant_id=tenant_id, client_id=client_id
            )
        elif method == AuthMethod.DEVICE_CODE:
            self.provider = DeviceCodeProvider(
                tenant_id=tenant_id,
                client_id=client_id,
                prompt_callback=prompt_callback,
            )
        elif method in (AuthMethod.SERVICE_PRINCIPAL_SECRET, AuthMethod.SERVICE_PRINCIPAL_CERT):
            if not tenant_id or not client_id:
                raise AuthenticationError("Service principal requires tenant_id and client_id")
            self.provider = ServicePrincipalProvider(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                certificate_path=certificate_path,
                certificate_password=certificate_password,
            )
        else:
            raise AuthenticationError(f"Unsupported auth method: {method}")
        return self.provider

    def sign_in(self) -> CredentialBundle:
        if self.provider is None:
            raise AuthenticationError("Auth manager not configured")
        self.bundle = self.provider.acquire()
        return self.bundle

    def sign_out(self) -> None:
        if self.bundle is not None:
            self.bundle.close()
        self.bundle = None
        self.provider = None

    def list_subscriptions(self) -> list[dict[str, str]]:
        if self.bundle is None:
            raise AuthenticationError("Not signed in")
        try:
            from azure.mgmt.subscription import SubscriptionClient
        except ImportError as exc:
            raise AuthenticationError("azure-mgmt-subscription is required") from exc
        client = SubscriptionClient(self.bundle.credential)
        out: list[dict[str, str]] = []
        try:
            for sub in client.subscriptions.list():
                out.append(
                    {
                        "id": getattr(sub, "subscription_id", "") or "",
                        "name": getattr(sub, "display_name", "") or "",
                        "state": getattr(sub, "state", "") or "",
                    }
                )
        except Exception as exc:  # pragma: no cover
            raise AuthenticationError(f"Could not list subscriptions: {exc}") from exc
        return out
