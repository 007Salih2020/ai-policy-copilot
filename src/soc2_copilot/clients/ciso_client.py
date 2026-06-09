from __future__ import annotations

from typing import Any

import httpx

from soc2_copilot.config import AppConfig
from soc2_copilot.models import ControlStatement


class CISOAssistantClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        assessment_id: str,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.assessment_id = assessment_id
        self._client = http_client or httpx.Client(
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=20.0,
        )

    @classmethod
    def from_config(cls, config: AppConfig) -> "CISOAssistantClient":
        if not config.ciso_assistant_enabled:
            raise RuntimeError("CISO Assistant configuration is incomplete.")
        return cls(
            base_url=config.ciso_assistant_url or "",
            api_key=config.ciso_assistant_api_key or "",
            assessment_id=config.ciso_assessment_id or "",
        )

    def push_controls(self, controls: list[ControlStatement]) -> dict[str, Any]:
        response = self._client.post(
            f"{self.base_url}/api/assessments/{self.assessment_id}/control-statements",
            json={"controls": [control.model_dump(mode="json") for control in controls]},
        )
        response.raise_for_status()
        return response.json()

