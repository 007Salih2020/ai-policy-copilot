from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from soc2_copilot.models import DiscoveredFacts, GeneratedPolicy


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def save_json(payload: Any, path: Path) -> Path:
    ensure_directory(path.parent)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def save_discovered_facts(facts: DiscoveredFacts, path: Path) -> Path:
    return save_json(facts.model_dump(mode="json"), path)


def load_discovered_facts(path: Path) -> DiscoveredFacts:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return DiscoveredFacts.model_validate(payload)


def save_generated_policy(policy: GeneratedPolicy, output_dir: Path) -> Path:
    ensure_directory(output_dir)
    file_path = output_dir / f"{policy.policy_type}.md"
    file_path.write_text(policy.content, encoding="utf-8")
    return file_path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

