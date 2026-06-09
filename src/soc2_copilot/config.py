from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    azure_devops_org: str = Field(default="https://dev.azure.com/yourcompany")
    azure_devops_pat: str | None = None
    azure_devops_project: str = Field(default="ProjectA")
    azure_devops_wiki_id: str | None = None

    azure_openai_endpoint: str | None = None
    azure_openai_key: str | None = None
    azure_openai_deployment: str = Field(default="gpt-4o")
    azure_openai_api_version: str = Field(default="2024-02-01")

    ciso_assistant_url: str | None = None
    ciso_assistant_api_key: str | None = None
    ciso_assessment_id: str | None = None

    copilot_db_path: str = Field(default="./data/copilot.db")
    output_dir: str = Field(default="./output")
    log_level: str = Field(default="INFO")

    @classmethod
    def from_env(cls) -> "AppConfig":
        return cls(
            azure_devops_org=os.getenv("AZURE_DEVOPS_ORG", "https://dev.azure.com/yourcompany"),
            azure_devops_pat=os.getenv("AZURE_DEVOPS_PAT"),
            azure_devops_project=os.getenv("AZURE_DEVOPS_PROJECT", "ProjectA"),
            azure_devops_wiki_id=os.getenv("AZURE_DEVOPS_WIKI_ID"),
            azure_openai_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            azure_openai_key=os.getenv("AZURE_OPENAI_KEY"),
            azure_openai_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
            azure_openai_api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
            ciso_assistant_url=os.getenv("CISO_ASSISTANT_URL"),
            ciso_assistant_api_key=os.getenv("CISO_ASSISTANT_API_KEY"),
            ciso_assessment_id=os.getenv("CISO_ASSESSMENT_ID"),
            copilot_db_path=os.getenv("COPILOT_DB_PATH", "./data/copilot.db"),
            output_dir=os.getenv("OUTPUT_DIR", "./output"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )

    @property
    def db_path(self) -> Path:
        return Path(self.copilot_db_path)

    @property
    def output_path(self) -> Path:
        return Path(self.output_dir)

    @property
    def azure_devops_enabled(self) -> bool:
        return bool(self.azure_devops_pat)

    @property
    def azure_openai_enabled(self) -> bool:
        return bool(self.azure_openai_endpoint and self.azure_openai_key and self.azure_openai_deployment)

    @property
    def ciso_assistant_enabled(self) -> bool:
        return bool(self.ciso_assistant_url and self.ciso_assistant_api_key and self.ciso_assessment_id)

