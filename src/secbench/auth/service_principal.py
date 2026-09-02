"""Service Principal sign-in (client secret or certificate)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from .base import AuthMethod, CredentialBundle, CredentialProvider
from ..engine.errors import AuthenticationError

log = logging.getLogger(__name__)


class ServicePrincipalProvider(CredentialProvider):
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        *,
        client_secret: Optional[str] = None,
        certificate_path: Optional[str] = None,
        certificate_password: Optional[str] = None,
    ) -> None:
        if not (client_secret or certificate_path):
            raise AuthenticationError(
                "Service principal requires either a client secret or a certificate"
            )
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.certificate_path = certificate_path
        self.certificate_password = certificate_password
        self.method = (
            AuthMethod.SERVICE_PRINCIPAL_SECRET
            if client_secret
            else AuthMethod.SERVICE_PRINCIPAL_CERT
        )

    def acquire(self) -> CredentialBundle:
        if self.client_secret:
            try:
                from azure.identity import ClientSecretCredential
            except ImportError as exc:
                raise AuthenticationError(
                    "azure-identity is required for service principal sign-in"
                ) from exc
            cred = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        else:
            try:
                from azure.identity import CertificateCredential
            except ImportError as exc:
                raise AuthenticationError(
                    "azure-identity is required for certificate sign-in"
                ) from exc
            cert_path = Path(self.certificate_path or "")
            if not cert_path.is_file():
                raise AuthenticationError(f"Certificate file not found: {cert_path}")
            cred = CertificateCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                certificate_path=str(cert_path),
                password=self.certificate_password,
            )
        try:
            cred.get_token("https://management.azure.com/.default")
        except Exception as exc:
            raise AuthenticationError(f"Service principal sign-in failed: {exc}") from exc
        return CredentialBundle(
            credential=cred,
            method=self.method,
            tenant_id=self.tenant_id,
            client_id=self.client_id,
        )

    def description(self) -> str:
        if self.client_secret:
            return f"Service principal secret (tenant={self.tenant_id}, client={self.client_id})"
        return f"Service principal certificate (tenant={self.tenant_id}, client={self.client_id})"
