"""Device-code flow (browser-less / SSH-friendly)."""

from __future__ import annotations

import logging
from typing import Callable, Optional

from .base import AuthMethod, CredentialBundle, CredentialProvider
from ..engine.errors import AuthenticationError

log = logging.getLogger(__name__)


class DeviceCodeProvider(CredentialProvider):
    method = AuthMethod.DEVICE_CODE

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        prompt_callback: Optional[Callable[[str, str, str], None]] = None,
    ) -> None:
        self.tenant_id = tenant_id or "organizations"
        self.client_id = client_id or "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
        self.prompt_callback = prompt_callback

    def acquire(self) -> CredentialBundle:
        try:
            from azure.identity import DeviceCodeCredential
        except ImportError as exc:
            raise AuthenticationError(
                "azure-identity is required for device-code sign-in"
            ) from exc

        def _prompt(verification_uri: str, user_code: str, expires_on: str) -> None:
            msg = (
                f"Open {verification_uri} and enter the code {user_code} "
                f"(expires {expires_on})."
            )
            log.info(msg)
            if self.prompt_callback:
                try:
                    self.prompt_callback(verification_uri, user_code, expires_on)
                except Exception:  # pragma: no cover - GUI plumbing
                    log.exception("device code prompt callback failed")

        cred = DeviceCodeCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            prompt_callback=_prompt,
        )
        try:
            cred.get_token("https://management.azure.com/.default")
        except Exception as exc:
            raise AuthenticationError(f"Device-code sign-in failed: {exc}") from exc
        return CredentialBundle(
            credential=cred,
            method=self.method,
            tenant_id=self.tenant_id,
            client_id=self.client_id,
        )

    def description(self) -> str:
        return f"Device code (tenant={self.tenant_id})"
