"""Authentication providers for Azure / Microsoft Graph."""

from .base import AuthMethod, CredentialBundle, CredentialProvider
from .device_code import DeviceCodeProvider
from .interactive import InteractiveBrowserProvider
from .manager import AuthManager
from .service_principal import ServicePrincipalProvider

__all__ = [
    "AuthManager",
    "AuthMethod",
    "CredentialBundle",
    "CredentialProvider",
    "DeviceCodeProvider",
    "InteractiveBrowserProvider",
    "ServicePrincipalProvider",
]
