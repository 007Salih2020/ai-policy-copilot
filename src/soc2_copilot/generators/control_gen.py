from __future__ import annotations

from typing import Iterable

from soc2_copilot.clients.openai_client import AzureOpenAIClient
from soc2_copilot.crosswalk import CrosswalkRepository
from soc2_copilot.models import ControlStatement, DiscoveredFacts
from soc2_copilot.prompts.prompt_builders import build_control_prompt


class ControlGenerator:
    def __init__(
        self,
        *,
        crosswalk_repository: CrosswalkRepository | None = None,
        llm_client: AzureOpenAIClient | None = None,
    ) -> None:
        self.crosswalk_repository = crosswalk_repository or CrosswalkRepository()
        self.llm_client = llm_client

    def generate(
        self,
        facts: DiscoveredFacts,
        criteria_ids: Iterable[str] | None = None,
        *,
        use_ai: bool = False,
    ) -> list[ControlStatement]:
        criteria_map = self.crosswalk_repository.load_criteria()
        requested_ids = list(criteria_ids) if criteria_ids is not None else ["all"]
        if "all" in requested_ids:
            resolved_ids = list(criteria_map.keys())
        else:
            resolved_ids = requested_ids
        controls: list[ControlStatement] = []
        for criteria_id in resolved_ids:
            definition = criteria_map[criteria_id]
            control_statement = self._build_control_statement(criteria_id, definition.objective, facts)
            if use_ai and self.llm_client is not None:
                system_message, user_message = build_control_prompt(
                    criteria_id=criteria_id,
                    objective=definition.objective,
                    facts=facts,
                )
                try:
                    ai_control = self.llm_client.generate_markdown(
                        system_prompt=system_message,
                        user_prompt=user_message,
                        max_tokens=500,
                    )
                    if ai_control:
                        control_statement = " ".join(ai_control.split())
                except Exception:
                    pass
            controls.append(
                ControlStatement(
                    criteria_id=criteria_id,
                    control_statement=control_statement,
                    implementation_guidance=self._implementation_guidance(criteria_id),
                    evidence_expectations=self._evidence_expectations(criteria_id, facts),
                    iso_27001_clauses=self.crosswalk_repository.find_iso_clauses_for_criteria(criteria_id),
                )
            )
        return controls

    def _build_control_statement(self, criteria_id: str, objective: str, facts: DiscoveredFacts) -> str:
        summary = self._evidence_summary(criteria_id, facts)
        statement = objective.rstrip(".") + "."
        if summary:
            statement += f" Azure DevOps evidence indicates {summary}."
        else:
            statement += " Current discovery scope did not provide direct supporting evidence, so this remains a required control expectation."
        return statement

    def _evidence_summary(self, criteria_id: str, facts: DiscoveredFacts) -> str:
        if criteria_id.startswith("CC6"):
            if facts.security_groups:
                return "role-based security groups are present and protected branches require approval before merge"
            if facts.branch_policies:
                return "protected branches require approval before merge"
        if criteria_id.startswith("CC7"):
            if facts.service_hooks or any(scan.dependency_scanning_detected or scan.sast_detected for scan in facts.scanning_statuses):
                return "monitoring-relevant hooks or scanning indicators are configured in the development workflow"
        if criteria_id.startswith("CC8"):
            if facts.branch_policies or facts.pipeline_gates:
                return "change approval and delivery gate controls are present in Azure DevOps"
        if criteria_id.startswith("CC1") or criteria_id.startswith("CC2"):
            if facts.discovery_notes:
                return "governance-related discovery notes and retained workflow evidence support internal communication and oversight"
        if criteria_id.startswith("CC9"):
            if facts.pipeline_gates or facts.service_hooks:
                return "release controls and operational notification paths support continuity-oriented risk management"
        return ""

    def _implementation_guidance(self, criteria_id: str) -> str:
        if criteria_id.startswith("CC6"):
            return "Maintain role-based access assignments, protect administrative actions, and retain periodic access review evidence."
        if criteria_id.startswith("CC7"):
            return "Monitor development platform telemetry, route alerts to named responders, and document escalation criteria."
        if criteria_id.startswith("CC8"):
            return "Require change review, validation, approval, and evidence retention for production-impacting changes."
        if criteria_id.startswith("CC9"):
            return "Track dependency risk, release readiness, and continuity-oriented safeguards for delivery tooling and services."
        return "Maintain documented ownership, governance oversight, and evidence retention supporting the stated control objective."

    def _evidence_expectations(self, criteria_id: str, facts: DiscoveredFacts) -> list[str]:
        evidence: list[str] = []
        if criteria_id.startswith("CC6"):
            evidence.extend(
                [
                    "Azure DevOps security group membership and role assignments",
                    "Protected branch policy configuration",
                    "Periodic access review records",
                ]
            )
        elif criteria_id.startswith("CC7"):
            evidence.extend(
                [
                    "Service hook or notification configuration",
                    "Pipeline logs with security validation steps",
                    "Incident or alert triage records",
                ]
            )
        elif criteria_id.startswith("CC8"):
            evidence.extend(
                [
                    "Pull request approval history",
                    "Branch policy settings",
                    "Release approval or gate configuration",
                ]
            )
        elif criteria_id.startswith("CC9"):
            evidence.extend(
                [
                    "Release gate configuration",
                    "Operational notification integrations",
                    "Continuity planning or recovery records",
                ]
            )
        else:
            evidence.extend(
                [
                    "Policy approval records",
                    "Governance meeting outputs",
                    "Documented role assignments",
                ]
            )
        if not facts.evidence_lines():
            evidence.append("Manual evidence collection is required because no Azure DevOps discovery results were supplied.")
        return evidence
