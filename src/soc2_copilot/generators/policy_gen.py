from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from soc2_copilot.clients.openai_client import AzureOpenAIClient
from soc2_copilot.models import DiscoveredFacts, GeneratedPolicy
from soc2_copilot.prompts.prompt_builders import DEFAULT_SECTIONS, build_policy_prompt
from soc2_copilot.state import compute_sha256


POLICY_SPECS: dict[str, dict[str, Any]] = {
    "change_management_policy": {
        "template": "change_management.md.j2",
        "purpose": (
            "This policy defines how software changes are reviewed, validated, approved, and promoted "
            "within Azure DevOps delivery workflows."
        ),
        "scope": "This policy applies to source repositories, pull requests, build validation, and production release approval flows for project {project}.",
        "policy_owner": "Head of Engineering or delegate",
        "review_cycle": "At least annually and after material delivery workflow changes.",
        "exceptions": "Exceptions must be documented, approved by the policy owner, and retained with supporting rationale.",
        "roles": [
            {"title": "Engineering", "description": "Implements changes through approved pull request and pipeline workflows."},
            {"title": "Security", "description": "Reviews control design, required approvals, and security-impacting changes."},
            {"title": "Release Managers", "description": "Approve production promotions where manual approval gates are required."},
        ],
        "policy_statements": [
            "Changes to protected branches must be proposed through pull requests and reviewed before merge.",
            "Build validation must execute prior to merge or release for production-impacting code changes.",
            "Production deployment approvals must be retained when release workflows require manual authorization.",
            "Change evidence must be retained in Azure DevOps for audit support and operational traceability.",
        ],
    },
    "access_control_policy": {
        "template": "access_control.md.j2",
        "purpose": (
            "This policy defines logical access management requirements for Azure DevOps repositories, pipelines, "
            "administrative groups, and publication workflows."
        ),
        "scope": "This policy applies to Azure DevOps users, groups, repository permissions, pipeline permissions, and wiki publication access within project {project}.",
        "policy_owner": "Security Manager",
        "review_cycle": "At least annually and following significant role or platform changes.",
        "exceptions": "Exceptions require documented business justification, named approval, and a compensating control where feasible.",
        "roles": [
            {"title": "Identity Administrators", "description": "Provision and remove access according to approved role assignments."},
            {"title": "Engineering Managers", "description": "Approve developer access and review elevated permission requests."},
            {"title": "Security Management", "description": "Oversees least privilege reviews and exception handling."},
        ],
        "policy_statements": [
            "Access to Azure DevOps must be role-based and limited to the minimum privileges required for job duties.",
            "Administrative actions affecting repositories, branch protection, and pipelines must be restricted to authorized groups.",
            "Protected branches and release workflows must enforce approval steps appropriate to the risk of the action.",
            "Access reviews must be performed on a defined cadence and retained as evidence.",
        ],
    },
    "secure_development_policy": {
        "template": "secure_development.md.j2",
        "purpose": (
            "This policy defines secure software development and verification requirements for code hosted and delivered through Azure DevOps."
        ),
        "scope": "This policy applies to software repositories, CI pipelines, scanning steps, and pull request review controls within project {project}.",
        "policy_owner": "Application Security Lead",
        "review_cycle": "At least annually and after significant SDLC tooling changes.",
        "exceptions": "Approved exceptions must include a remediation date, risk acceptance owner, and interim safeguards.",
        "roles": [
            {"title": "Developers", "description": "Build code in accordance with secure coding and review requirements."},
            {"title": "AppSec", "description": "Defines secure development standards and monitors scanning coverage."},
            {"title": "Platform Engineering", "description": "Maintains CI validation and scanning integrations."},
        ],
        "policy_statements": [
            "Code changes must undergo peer review before merging into protected branches.",
            "CI workflows should enforce security and quality validation before deployment promotion.",
            "Dependency scanning and static analysis should be integrated into the software delivery lifecycle where supported.",
            "Security-significant findings must be tracked to remediation or approved risk acceptance.",
        ],
    },
    "incident_response_policy": {
        "template": "incident_response.md.j2",
        "purpose": (
            "This policy defines how development platform events, delivery anomalies, and security-relevant alerts are escalated and handled."
        ),
        "scope": "This policy applies to Azure DevOps notifications, service hooks, deployment controls, and escalation workflows for project {project}.",
        "policy_owner": "Security Operations Manager",
        "review_cycle": "At least annually and after material incident handling changes.",
        "exceptions": "Exceptions must be documented, time-bound, and approved by the policy owner.",
        "roles": [
            {"title": "Security Operations", "description": "Receives alerts, triages incidents, and coordinates response actions."},
            {"title": "Engineering", "description": "Supports investigation, containment, and corrective action for development platform events."},
            {"title": "Leadership", "description": "Approves material incident communication and post-incident remediation priorities."},
        ],
        "policy_statements": [
            "Security-relevant development platform events must be routed to an identified response channel.",
            "Incidents affecting the software delivery environment must be triaged, assigned, and documented.",
            "Response activities must preserve evidence sufficient for audit and post-incident review.",
            "Material incidents and unresolved control gaps must be escalated through defined management channels.",
        ],
    },
    "availability_policy": {
        "template": "availability.md.j2",
        "purpose": (
            "This policy defines controls intended to support reliable change delivery, controlled production promotion, and operational readiness."
        ),
        "scope": "This policy applies to CI/CD validation, production release approvals, delivery alerting, and operational dependencies within project {project}.",
        "policy_owner": "Platform Engineering Manager",
        "review_cycle": "At least annually and when release processes or operational dependencies materially change.",
        "exceptions": "Exceptions require documented approval, risk acknowledgment, and a follow-up review date.",
        "roles": [
            {"title": "Platform Engineering", "description": "Maintains delivery systems and operational readiness controls."},
            {"title": "Release Management", "description": "Approves or coordinates production promotions when gated approvals apply."},
            {"title": "Service Owners", "description": "Verify service readiness, rollback planning, and recovery expectations."},
        ],
        "policy_statements": [
            "Production-impacting changes should pass defined validation prior to deployment.",
            "Release workflows should use approval or gate mechanisms appropriate to service criticality.",
            "Operational alerting should support timely awareness of delivery and service-impacting events.",
            "Availability-related evidence should be retained to support audits and recovery reviews.",
        ],
    },
}


class PolicyGenerator:
    def __init__(
        self,
        *,
        template_dir: Path | None = None,
        llm_client: AzureOpenAIClient | None = None,
    ) -> None:
        template_path = template_dir or self._default_template_dir()
        self.environment = Environment(
            loader=FileSystemLoader(str(template_path)),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        self.llm_client = llm_client

    def _default_template_dir(self) -> Path:
        candidates = [
            Path.cwd() / "templates",
            Path(__file__).resolve().parents[3] / "templates",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    def generate(self, policy_type: str, facts: DiscoveredFacts, *, use_ai: bool = False) -> GeneratedPolicy:
        if policy_type not in POLICY_SPECS:
            raise ValueError(f"Unsupported policy type: {policy_type}")
        spec = POLICY_SPECS[policy_type]
        context = {
            "purpose": spec["purpose"],
            "scope": spec["scope"].format(project=facts.project),
            "roles": spec["roles"],
            "policy_statements": spec["policy_statements"],
            "observed_facts": self._observed_facts_for_policy(policy_type, facts),
            "required_practices": self._requirements_for_policy(policy_type, facts),
            "exceptions": spec["exceptions"],
            "review_cycle": spec["review_cycle"],
            "policy_owner": spec["policy_owner"],
            "notes": [note.message for note in facts.discovery_notes]
            or ["Observed statements reflect only the supplied Azure DevOps discovery scope."],
        }
        template_content = self.environment.get_template(spec["template"]).render(**context)
        content = template_content
        generator_model = "jinja2-grounded"
        if use_ai and self.llm_client is not None:
            system_message, user_message = build_policy_prompt(
                policy_type=policy_type,
                facts=facts,
                sections=DEFAULT_SECTIONS,
            )
            try:
                ai_content = self.llm_client.generate_markdown(
                    system_prompt=system_message,
                    user_prompt=user_message,
                )
                if ai_content:
                    if "AI-assisted draft generated from discovered system facts" not in ai_content:
                        ai_content = (
                            "> AI-assisted draft generated from discovered system facts. "
                            "Human review and attestation required before operational or audit use.\n\n"
                            + ai_content
                        )
                    content = ai_content
                    generator_model = self.llm_client.model_name
            except Exception:
                content = template_content
                generator_model = "jinja2-grounded"
        version = datetime.now(timezone.utc).strftime("v%Y%m%d%H%M%S")
        return GeneratedPolicy(
            policy_type=policy_type,
            version=version,
            generator_model=generator_model,
            content=content,
            source_facts_snapshot=facts.model_dump(mode="json"),
            content_hash=compute_sha256(content),
        )

    def generate_many(
        self,
        policy_types: list[str],
        facts: DiscoveredFacts,
        *,
        use_ai: bool = False,
    ) -> list[GeneratedPolicy]:
        types = list(POLICY_SPECS.keys()) if "all" in policy_types else policy_types
        return [self.generate(policy_type, facts, use_ai=use_ai) for policy_type in types]

    def _observed_facts_for_policy(self, policy_type: str, facts: DiscoveredFacts) -> list[str]:
        lines: list[str] = []
        if policy_type == "change_management_policy":
            for branch in facts.branch_policies:
                if branch.minimum_reviewers is not None:
                    lines.append(
                        f"Observed evidence indicates branch {branch.branch} in repository {branch.repository} requires {branch.minimum_reviewers} reviewers."
                    )
                if branch.build_validation_enabled is True:
                    lines.append(
                        f"Observed evidence indicates build validation is enabled for repository {branch.repository} branch {branch.branch}."
                    )
            for stat in facts.pr_statistics:
                lines.append(
                    f"Observed evidence indicates {stat.two_approver_rate_pct}% of pull requests in repository {stat.repository} during the last {stat.period_days} days had at least two approvers."
                )
            for gate in facts.pipeline_gates:
                if gate.manual_approval_required is True:
                    lines.append(
                        f"Observed evidence indicates pipeline {gate.pipeline_name} stage {gate.stage} requires manual approval."
                    )
        elif policy_type == "access_control_policy":
            for group in facts.security_groups:
                permissions = ", ".join(f"{name}: {value}" for name, value in group.key_permissions.items())
                suffix = f" Key permissions observed: {permissions}." if permissions else ""
                lines.append(
                    f"Observed evidence indicates security group {group.group_name} governs {group.permission_scope}.{suffix}"
                )
            for branch in facts.branch_policies:
                if branch.minimum_reviewers is not None:
                    lines.append(
                        f"Observed evidence indicates protected branch {branch.branch} in repository {branch.repository} requires approval before merge."
                    )
        elif policy_type == "secure_development_policy":
            for scan in facts.scanning_statuses:
                findings: list[str] = []
                if scan.dependency_scanning_detected is True:
                    findings.append("dependency scanning")
                if scan.sast_detected is True:
                    findings.append("static analysis")
                if findings:
                    lines.append(
                        f"Observed evidence indicates repository {scan.repository} pipeline {scan.pipeline_name or 'unknown'} includes {', '.join(findings)}."
                    )
            for branch in facts.branch_policies:
                if branch.build_validation_enabled is True:
                    lines.append(
                        f"Observed evidence indicates build validation supports code verification for repository {branch.repository}."
                    )
        elif policy_type == "incident_response_policy":
            for hook in facts.service_hooks:
                if hook.active:
                    lines.append(
                        f"Observed evidence indicates an active service hook of type {hook.hook_type} targets {hook.target}."
                    )
            for gate in facts.pipeline_gates:
                if gate.manual_approval_required is True:
                    lines.append(
                        f"Observed evidence indicates manual approval is present in pipeline {gate.pipeline_name}, supporting escalation for release-risk decisions."
                    )
        elif policy_type == "availability_policy":
            for gate in facts.pipeline_gates:
                gate_text = ", ".join(gate.gates) if gate.gates else "release checks"
                lines.append(
                    f"Observed evidence indicates pipeline {gate.pipeline_name} stage {gate.stage} uses {gate_text}."
                )
            for hook in facts.service_hooks:
                if hook.active:
                    lines.append(
                        f"Observed evidence indicates availability-relevant notifications can be routed through {hook.hook_type} to {hook.target}."
                    )
            for branch in facts.branch_policies:
                if branch.build_validation_enabled is True:
                    lines.append(
                        f"Observed evidence indicates build validation is enabled before change promotion for repository {branch.repository}."
                    )
        return lines

    def _requirements_for_policy(self, policy_type: str, facts: DiscoveredFacts) -> list[str]:
        requirements: list[str] = []
        if policy_type == "change_management_policy":
            if not facts.branch_policies:
                requirements.append("The policy requires protected branches to enforce pull request review before merge.")
            if not any(policy.build_validation_enabled is True for policy in facts.branch_policies):
                requirements.append("The policy requires build validation or status checks before production-impacting changes are merged.")
            if not any(gate.manual_approval_required is True for gate in facts.pipeline_gates):
                requirements.append("The policy requires manual approval or equivalent authorization for production promotions.")
        elif policy_type == "access_control_policy":
            if not facts.security_groups:
                requirements.append("The policy requires role-based access groups and documented assignment ownership.")
            if not any(group.least_privilege_reviewed is True for group in facts.security_groups):
                requirements.append("The policy requires periodic least-privilege access reviews for administrative and elevated roles.")
            if not facts.branch_policies:
                requirements.append("The policy requires protected branch approvals to reduce unauthorized changes.")
        elif policy_type == "secure_development_policy":
            if not any(scan.dependency_scanning_detected is True for scan in facts.scanning_statuses):
                requirements.append("The policy requires dependency scanning for supported repositories and build pipelines.")
            if not any(scan.sast_detected is True for scan in facts.scanning_statuses):
                requirements.append("The policy requires static analysis or equivalent security testing before release.")
            if not any(policy.build_validation_enabled is True for policy in facts.branch_policies):
                requirements.append("The policy requires automated validation before merge or release.")
        elif policy_type == "incident_response_policy":
            if not any(hook.active for hook in facts.service_hooks):
                requirements.append("The policy requires alerting or service-hook integration for security-relevant development platform events.")
            requirements.append("The policy requires incident triage, assignment, evidence preservation, and management escalation procedures.")
        elif policy_type == "availability_policy":
            if not facts.pipeline_gates:
                requirements.append("The policy requires release validation checkpoints before production deployment.")
            if not any(hook.active for hook in facts.service_hooks):
                requirements.append("The policy requires operational alerting for service-impacting delivery events.")
            requirements.append("The policy requires rollback planning or documented recovery actions for production-impacting changes.")
        if not requirements:
            requirements.append(
                "No additional requirement statements were triggered by missing evidence within the supplied Azure DevOps discovery scope."
            )
        return requirements
