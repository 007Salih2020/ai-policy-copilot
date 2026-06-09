from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, computed_field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DiscoveryNote(BaseModel):
    category: str
    message: str


class BranchPolicyFact(BaseModel):
    repository: str
    branch: str = "main"
    minimum_reviewers: int | None = None
    required_reviewers: list[str] = Field(default_factory=list)
    build_validation_enabled: bool | None = None
    status_checks: list[str] = Field(default_factory=list)
    observed: bool = True
    source: str = "azure-devops"
    notes: list[str] = Field(default_factory=list)


class PipelineGateFact(BaseModel):
    pipeline_name: str
    stage: str
    manual_approval_required: bool | None = None
    approvers: list[str] = Field(default_factory=list)
    gates: list[str] = Field(default_factory=list)
    observed: bool = True
    source: str = "azure-devops"


class PRStatistics(BaseModel):
    repository: str
    period_days: int = 90
    total_prs: int = 0
    prs_with_two_or_more_approvers: int = 0
    avg_approvers: float | None = None
    median_time_to_merge_hours: float | None = None

    @computed_field  # type: ignore[misc]
    @property
    def two_approver_rate_pct(self) -> float:
        if self.total_prs <= 0:
            return 0.0
        return round((self.prs_with_two_or_more_approvers / self.total_prs) * 100, 2)


class SecurityGroupFact(BaseModel):
    group_name: str
    permission_scope: str
    members_count: int | None = None
    key_permissions: dict[str, str] = Field(default_factory=dict)
    least_privilege_reviewed: bool | None = None


class ScanningStatus(BaseModel):
    repository: str
    pipeline_name: str | None = None
    dependency_scanning_detected: bool | None = None
    sast_detected: bool | None = None
    last_seen: datetime | None = None


class ServiceHookFact(BaseModel):
    hook_type: str
    target: str
    active: bool = True


class DiscoveredFacts(BaseModel):
    org_url: str
    project: str
    generated_at: datetime = Field(default_factory=utc_now)
    mode: str = "mock"
    branch_policies: list[BranchPolicyFact] = Field(default_factory=list)
    pipeline_gates: list[PipelineGateFact] = Field(default_factory=list)
    pr_statistics: list[PRStatistics] = Field(default_factory=list)
    security_groups: list[SecurityGroupFact] = Field(default_factory=list)
    scanning_statuses: list[ScanningStatus] = Field(default_factory=list)
    service_hooks: list[ServiceHookFact] = Field(default_factory=list)
    discovery_notes: list[DiscoveryNote] = Field(default_factory=list)

    def evidence_lines(self) -> list[str]:
        lines: list[str] = []
        for fact in self.branch_policies:
            if fact.minimum_reviewers is not None:
                lines.append(
                    f"Observed evidence indicates repository {fact.repository} branch {fact.branch} requires "
                    f"{fact.minimum_reviewers} reviewers."
                )
            if fact.build_validation_enabled is True:
                lines.append(
                    f"Observed evidence indicates repository {fact.repository} branch {fact.branch} has build validation enabled."
                )
            if fact.required_reviewers:
                reviewers = ", ".join(fact.required_reviewers)
                lines.append(
                    f"Observed evidence indicates repository {fact.repository} branch {fact.branch} uses required reviewers: {reviewers}."
                )
        for stat in self.pr_statistics:
            lines.append(
                f"Observed evidence indicates {stat.two_approver_rate_pct}% of pull requests in repository "
                f"{stat.repository} over the last {stat.period_days} days had at least two approvers."
            )
        for gate in self.pipeline_gates:
            if gate.manual_approval_required is True:
                lines.append(
                    f"Observed evidence indicates pipeline {gate.pipeline_name} stage {gate.stage} requires manual approval."
                )
            if gate.gates:
                lines.append(
                    f"Observed evidence indicates pipeline {gate.pipeline_name} stage {gate.stage} enforces gates: "
                    f"{', '.join(gate.gates)}."
                )
        for group in self.security_groups:
            lines.append(
                f"Observed evidence indicates security group {group.group_name} governs {group.permission_scope} access."
            )
        for scan in self.scanning_statuses:
            findings: list[str] = []
            if scan.dependency_scanning_detected is True:
                findings.append("dependency scanning")
            if scan.sast_detected is True:
                findings.append("SAST")
            if findings:
                lines.append(
                    f"Observed evidence indicates repository {scan.repository} has {', '.join(findings)} steps in pipeline "
                    f"{scan.pipeline_name or 'unknown'}."
                )
        for hook in self.service_hooks:
            status = "active" if hook.active else "inactive"
            lines.append(
                f"Observed evidence indicates service hook {hook.hook_type} targeting {hook.target} is {status}."
            )
        for note in self.discovery_notes:
            lines.append(f"Discovery note: {note.message}")
        return lines


class GeneratedPolicy(BaseModel):
    policy_type: str
    version: str
    generated_at: datetime = Field(default_factory=utc_now)
    generator_model: str
    file_path: str | None = None
    content: str
    source_facts_snapshot: dict[str, Any]
    content_hash: str
    disclaimer: str = (
        "AI-assisted draft generated from discovered system facts. "
        "Human review and attestation required before operational or audit use."
    )


class ControlStatement(BaseModel):
    criteria_id: str
    control_statement: str
    implementation_guidance: str
    evidence_expectations: list[str] = Field(default_factory=list)
    iso_27001_clauses: list[str] = Field(default_factory=list)


class Attestation(BaseModel):
    id: int | None = None
    policy_id: int
    attested_by: str
    role: str
    attested_at: datetime = Field(default_factory=utc_now)
    approved: bool
    comments: str | None = None
    next_review_date: str | None = None
    content_hash: str

