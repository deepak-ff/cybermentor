"""Authentication abstractions shared by every credential provider."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AuthMethod(str, Enum):
    INTERACTIVE = "interactive"
    DEVICE_CODE = "device_code"
    SERVICE_PRINCIPAL_SECRET = "sp_secret"
    SERVICE_PRINCIPAL_CERT = "sp_cert"


# Default scopes covering the controls we evaluate.
GRAPH_SCOPES = [
    "https://graph.microsoft.com/.default",
]
ARM_SCOPES = [
    "https://management.azure.com/.default",
]


@dataclass
class CredentialBundle:
    """A single credential object used for both ARM and Graph (.default scopes)."""

    credential: Any
    method: AuthMethod
    tenant_id: str = ""
    client_id: str = ""
    user_id: str = ""
    extras: dict[str, Any] = field(default_factory=dict)

    def close(self) -> None:
        close = getattr(self.credential, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


class CredentialProvider(ABC):
    method: AuthMethod

    @abstractmethod
    def acquire(self) -> CredentialBundle:  # pragma: no cover - interface
        ...

    @abstractmethod
    def description(self) -> str:  # pragma: no cover - interface
        ...
