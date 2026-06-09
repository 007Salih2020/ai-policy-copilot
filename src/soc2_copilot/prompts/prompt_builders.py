from __future__ import annotations

import json

from soc2_copilot.models import DiscoveredFacts


DEFAULT_SECTIONS = [
    "Purpose",
    "Scope",
    "Roles and Responsibilities",
    "Policy Statements",
    "Evidence of Operation",
    "Exceptions",
    "Review Cycle",
    "Policy Owner",
]


def system_prompt() -> str:
    return (
        "You write for external auditors and security leadership. "
        "Be formal, factual, concise, and professional. "
        "Use only supplied facts. Never invent evidence. "
        "If facts are missing, write requirements instead of false claims. "
        "Distinguish observed practice from required practice. "
        "Return valid Markdown with clear headings."
    )


def _facts_payload(facts: DiscoveredFacts) -> str:
    return json.dumps(facts.model_dump(mode="json"), indent=2)


def build_policy_prompt(
    *,
    policy_type: str,
    facts: DiscoveredFacts,
    sections: list[str] | None = None,
) -> tuple[str, str]:
    requested_sections = sections or DEFAULT_SECTIONS
    user_prompt = (
        f"Create a grounded Markdown draft for policy type '{policy_type}'.\n\n"
        f"Required sections: {', '.join(requested_sections)}.\n"
        "State observed evidence explicitly and separately from requirements.\n"
        "Include a clear disclaimer that the draft is AI-assisted and requires human attestation.\n"
        "Do not hallucinate or generalize beyond the supplied facts.\n\n"
        "Discovered facts:\n"
        f"{_facts_payload(facts)}"
    )
    return system_prompt(), user_prompt


def build_control_prompt(*, criteria_id: str, facts: DiscoveredFacts, objective: str) -> tuple[str, str]:
    user_prompt = (
        f"Draft a single SOC 2 control statement for criteria {criteria_id}.\n"
        f"Objective: {objective}\n"
        "The control statement must reference only supplied evidence and must not invent implementation details.\n"
        "Return a concise paragraph only.\n\n"
        "Discovered facts:\n"
        f"{_facts_payload(facts)}"
    )
    return system_prompt(), user_prompt


def build_audit_narrative_prompt(*, facts: DiscoveredFacts, period: str) -> tuple[str, str]:
    user_prompt = (
        f"Draft a third-person audit support narrative for period {period}.\n"
        "The narrative must be suitable for auditors and security leadership, period-aware, and explicit about evidence sources.\n"
        "If evidence is missing, state the requirement or limitation instead of claiming operation.\n\n"
        "Discovered facts:\n"
        f"{_facts_payload(facts)}"
    )
    return system_prompt(), user_prompt

