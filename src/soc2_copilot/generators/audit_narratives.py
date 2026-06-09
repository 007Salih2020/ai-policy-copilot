from __future__ import annotations

from soc2_copilot.clients.openai_client import AzureOpenAIClient
from soc2_copilot.models import DiscoveredFacts
from soc2_copilot.prompts.prompt_builders import build_audit_narrative_prompt


class AuditNarrativeGenerator:
    def __init__(self, llm_client: AzureOpenAIClient | None = None) -> None:
        self.llm_client = llm_client

    def generate(self, facts: DiscoveredFacts, period: str, *, use_ai: bool = False) -> str:
        fallback = self._fallback_narrative(facts, period)
        if use_ai and self.llm_client is not None:
            system_message, user_message = build_audit_narrative_prompt(facts=facts, period=period)
            try:
                result = self.llm_client.generate_markdown(
                    system_prompt=system_message,
                    user_prompt=user_message,
                    max_tokens=1400,
                )
                if result:
                    return result
            except Exception:
                return fallback
        return fallback

    def _fallback_narrative(self, facts: DiscoveredFacts, period: str) -> str:
        change_lines = [line for line in facts.evidence_lines() if "pull request" in line.lower() or "pipeline" in line.lower() or "branch" in line.lower()]
        access_lines = [line for line in facts.evidence_lines() if "security group" in line.lower() or "protected branch" in line.lower()]
        secure_dev_lines = [line for line in facts.evidence_lines() if "scanning" in line.lower() or "build validation" in line.lower()]
        alert_lines = [line for line in facts.evidence_lines() if "service hook" in line.lower()]
        lines = [
            f"# Audit Support Narrative - {period}",
            "",
            "> AI-assisted draft generated from discovered system facts. Human review and attestation required before operational or audit use.",
            "",
            "## Overview",
            "",
            f"During {period}, the organization operated software delivery controls within Azure DevOps project {facts.project}. "
            "The narrative below is based only on supplied discovery results and distinguishes observed evidence from required practice where evidence was incomplete.",
            "",
            "## Change Management",
            "",
        ]
        lines.extend([f"- {line}" for line in change_lines] or ["- The period narrative requires manual confirmation of change-management evidence not present in the supplied facts."])
        lines.extend(
            [
                "",
                "## Access Control",
                "",
            ]
        )
        lines.extend([f"- {line}" for line in access_lines] or ["- Access control observations were limited in the supplied discovery scope and require human confirmation."])
        lines.extend(
            [
                "",
                "## Secure Development and Monitoring",
                "",
            ]
        )
        combined_secure = secure_dev_lines + alert_lines
        lines.extend([f"- {line}" for line in combined_secure] or ["- The supplied facts did not demonstrate scanning or alerting controls, so these remain stated requirements rather than observed practices."])
        lines.extend(
            [
                "",
                "## Evidence Sources",
                "",
                "- Azure DevOps repository and branch policy discovery",
                "- Pull request approval history and pipeline discovery results",
                "- Security group, scanning indicator, and service hook discovery outputs",
                "",
                "## Limitations",
                "",
            ]
        )
        note_lines = [note.message for note in facts.discovery_notes]
        lines.extend([f"- {note}" for note in note_lines] or ["- No additional discovery limitations were recorded in the supplied facts."])
        return "\n".join(lines) + "\n"

