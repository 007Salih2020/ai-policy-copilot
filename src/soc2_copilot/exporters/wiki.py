from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import httpx

from soc2_copilot.attestation import AttestationStore
from soc2_copilot.models import Attestation
from soc2_copilot.state import read_text


class WikiPublicationError(RuntimeError):
    pass


class AzureDevOpsWikiPublisher:
    def __init__(
        self,
        *,
        org_url: str,
        pat: str,
        project: str,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not pat:
            raise WikiPublicationError("Azure DevOps PAT is required for wiki publishing.")
        auth_token = base64.b64encode(f":{pat}".encode("utf-8")).decode("ascii")
        self.org_url = org_url.rstrip("/")
        self.project = project
        self._client = http_client or httpx.Client(
            headers={"Authorization": f"Basic {auth_token}", "Content-Type": "application/json"},
            timeout=20.0,
        )

    def _page_path(self, policy_type: str) -> str:
        title = policy_type.replace("_", " ").replace("policy", "policy").title()
        return f"/Policies/{title}"

    def _build_page_content(self, policy: dict[str, Any], attestation: Attestation) -> str:
        policy_body = read_text(Path(policy["file_path"]))
        front_matter = "\n".join(
            [
                "---",
                f"version: {policy['version']}",
                "attestation_status: approved",
                f"attested_by: {attestation.attested_by}",
                f"attested_date: {attestation.attested_at.date().isoformat()}",
                f"next_review_date: {attestation.next_review_date or 'unspecified'}",
                "---",
                "",
            ]
        )
        return front_matter + policy_body

    def publish_attested_policy(
        self,
        *,
        policy_identifier: str,
        wiki_id: str,
        store: AttestationStore,
    ) -> dict[str, Any]:
        policy, attestation = store.assert_publishable(policy_identifier)
        response = self._client.put(
            f"{self.org_url}/{self.project}/_apis/wiki/wikis/{wiki_id}/pages",
            params={"path": self._page_path(policy["policy_type"]), "api-version": "7.1-preview.1"},
            json={"content": self._build_page_content(policy, attestation)},
        )
        response.raise_for_status()
        return response.json()

