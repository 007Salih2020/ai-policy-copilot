from __future__ import annotations

from soc2_copilot.clients.ado_client import (
    AzureDevOpsClient,
    AzureDevOpsClientError,
    BaseAzureDevOpsClient,
    MockAzureDevOpsClient,
)
from soc2_copilot.config import AppConfig
from soc2_copilot.models import DiscoveryNote, DiscoveredFacts


class DiscoveryCollector:
    def __init__(self, config: AppConfig, client: BaseAzureDevOpsClient | None = None) -> None:
        self.config = config
        self.client = client

    def _build_client(self, mode: str) -> BaseAzureDevOpsClient:
        if self.client is not None:
            return self.client
        if mode == "mock":
            return MockAzureDevOpsClient(self.config.azure_devops_org)
        if not self.config.azure_devops_enabled:
            raise AzureDevOpsClientError("Azure DevOps PAT is not configured for real discovery mode.")
        return AzureDevOpsClient(self.config.azure_devops_org, self.config.azure_devops_pat or "")

    def collect(
        self,
        *,
        project: str | None = None,
        mode: str = "mock",
        audit_period: str | None = None,
        allow_fallback: bool = True,
    ) -> DiscoveredFacts:
        target_project = project or self.config.azure_devops_project
        try:
            return self._build_client(mode).discover_project(target_project, audit_period=audit_period)
        except AzureDevOpsClientError as exc:
            if mode == "real" and allow_fallback:
                fallback = MockAzureDevOpsClient(self.config.azure_devops_org)
                facts = fallback.discover_project(target_project, audit_period=audit_period)
                facts.discovery_notes.insert(
                    0,
                    DiscoveryNote(
                        category="fallback",
                        message=f"Real discovery failed and mock data was used instead: {exc}",
                    ),
                )
                return facts
            raise

