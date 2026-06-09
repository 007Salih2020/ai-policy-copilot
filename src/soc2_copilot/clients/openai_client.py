from __future__ import annotations

from typing import Any

import httpx

from soc2_copilot.config import AppConfig


class AzureOpenAIClient:
    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        deployment: str,
        api_version: str,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.deployment = deployment
        self.api_version = api_version
        self._client = http_client or httpx.Client(
            headers={"api-key": api_key, "Content-Type": "application/json"},
            timeout=45.0,
        )

    @classmethod
    def from_config(cls, config: AppConfig) -> "AzureOpenAIClient":
        if not config.azure_openai_enabled:
            raise RuntimeError("Azure OpenAI configuration is incomplete.")
        return cls(
            endpoint=config.azure_openai_endpoint or "",
            api_key=config.azure_openai_key or "",
            deployment=config.azure_openai_deployment,
            api_version=config.azure_openai_api_version,
        )

    @property
    def model_name(self) -> str:
        return self.deployment

    def generate_markdown(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 1800,
    ) -> str:
        url = (
            f"{self.endpoint}/openai/deployments/{self.deployment}/chat/completions"
            f"?api-version={self.api_version}"
        )
        response = self._client.post(
            url,
            json={
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        return payload["choices"][0]["message"]["content"].strip()

