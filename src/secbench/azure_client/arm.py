"""High-level Azure Resource Manager helpers shared by all Azure benchmarks."""

from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

log = logging.getLogger(__name__)


class ArmClient:
    """Lazy-instantiated wrapper holding mgmt clients keyed by subscription id."""

    def __init__(self, credential: Any) -> None:
        self.credential = credential
        self._sub_clients: dict[tuple[str, str], Any] = {}

    # ------------------------------------------------------------------ helpers
    def _get(self, sub_id: str, key: str, factory):
        ck = (sub_id, key)
        cli = self._sub_clients.get(ck)
        if cli is None:
            cli = factory()
            self._sub_clients[ck] = cli
        return cli

    # --------------------------------------------------------------- top-level
    def list_subscriptions(self) -> list[dict[str, str]]:
        try:
            from azure.mgmt.subscription import SubscriptionClient
        except ImportError:
            return []
        out: list[dict[str, str]] = []
        try:
            sc = SubscriptionClient(self.credential)
            for sub in sc.subscriptions.list():
                out.append(
                    {
                        "id": getattr(sub, "subscription_id", "") or "",
                        "name": getattr(sub, "display_name", "") or "",
                        "state": getattr(sub, "state", "") or "",
                    }
                )
        except Exception as exc:
            log.warning("list_subscriptions failed: %s", exc)
        return out

    # ----------------------------------------------------------- mgmt clients
    def resource(self, sub_id: str):
        from azure.mgmt.resource import ResourceManagementClient
        return self._get(sub_id, "resource", lambda: ResourceManagementClient(self.credential, sub_id))

    def compute(self, sub_id: str):
        from azure.mgmt.compute import ComputeManagementClient
        return self._get(sub_id, "compute", lambda: ComputeManagementClient(self.credential, sub_id))

    def storage(self, sub_id: str):
        from azure.mgmt.storage import StorageManagementClient
        return self._get(sub_id, "storage", lambda: StorageManagementClient(self.credential, sub_id))

    def sql(self, sub_id: str):
        from azure.mgmt.sql import SqlManagementClient
        return self._get(sub_id, "sql", lambda: SqlManagementClient(self.credential, sub_id))

    def network(self, sub_id: str):
        from azure.mgmt.network import NetworkManagementClient
        return self._get(sub_id, "network", lambda: NetworkManagementClient(self.credential, sub_id))

    def keyvault(self, sub_id: str):
        from azure.mgmt.keyvault import KeyVaultManagementClient
        return self._get(sub_id, "keyvault", lambda: KeyVaultManagementClient(self.credential, sub_id))

    def monitor(self, sub_id: str):
        from azure.mgmt.monitor import MonitorManagementClient
        return self._get(sub_id, "monitor", lambda: MonitorManagementClient(self.credential, sub_id))

    def security(self, sub_id: str):
        from azure.mgmt.security import SecurityCenter
        return self._get(sub_id, "security", lambda: SecurityCenter(self.credential, sub_id))

    def policy(self, sub_id: str):
        from azure.mgmt.policyinsights import PolicyInsightsClient
        return self._get(sub_id, "policy", lambda: PolicyInsightsClient(self.credential))

    def authorization(self, sub_id: str):
        from azure.mgmt.authorization import AuthorizationManagementClient
        return self._get(sub_id, "authz", lambda: AuthorizationManagementClient(self.credential, sub_id))

    def web(self, sub_id: str):
        from azure.mgmt.web import WebSiteManagementClient
        return self._get(sub_id, "web", lambda: WebSiteManagementClient(self.credential, sub_id))

    def aks(self, sub_id: str):
        from azure.mgmt.containerservice import ContainerServiceClient
        return self._get(sub_id, "aks", lambda: ContainerServiceClient(self.credential, sub_id))

    def acr(self, sub_id: str):
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
        return self._get(sub_id, "acr", lambda: ContainerRegistryManagementClient(self.credential, sub_id))

    def cosmos(self, sub_id: str):
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
        return self._get(sub_id, "cosmos", lambda: CosmosDBManagementClient(self.credential, sub_id))

    def postgres(self, sub_id: str):
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient
        return self._get(sub_id, "pg", lambda: PostgreSQLManagementClient(self.credential, sub_id))

    def mysql(self, sub_id: str):
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient
        return self._get(sub_id, "mysql", lambda: MySQLManagementClient(self.credential, sub_id))

    # ---------------------------------------------------------- iteration helpers
    @staticmethod
    def safe_list(iterable: Optional[Iterable[Any]]) -> list[Any]:
        if iterable is None:
            return []
        out: list[Any] = []
        try:
            for item in iterable:
                out.append(item)
        except Exception as exc:  # pragma: no cover
            log.warning("safe_list iteration failed: %s", exc)
        return out
