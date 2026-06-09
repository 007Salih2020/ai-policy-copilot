from __future__ import annotations

import base64
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from statistics import mean, median
from typing import Any

import httpx

from soc2_copilot.models import (
    BranchPolicyFact,
    DiscoveryNote,
    DiscoveredFacts,
    PipelineGateFact,
    PRStatistics,
    ScanningStatus,
    SecurityGroupFact,
    ServiceHookFact,
)


class AzureDevOpsClientError(RuntimeError):
    pass


class BaseAzureDevOpsClient(ABC):
    @abstractmethod
    def discover_project(self, project: str, audit_period: str | None = None) -> DiscoveredFacts:
        raise NotImplementedError


class MockAzureDevOpsClient(BaseAzureDevOpsClient):
    def __init__(self, org_url: str = "https://dev.azure.com/yourcompany") -> None:
        self.org_url = org_url

    def discover_project(self, project: str, audit_period: str | None = None) -> DiscoveredFacts:
        now = datetime.now(timezone.utc)
        notes = [
            DiscoveryNote(
                category="mode",
                message="Mock discovery mode was used. Replace with real Azure DevOps credentials for live evidence.",
            )
        ]
        if audit_period:
            notes.append(
                DiscoveryNote(
                    category="audit-period",
                    message=f"Audit narrative period context supplied as {audit_period}.",
                )
            )
        return DiscoveredFacts(
            org_url=self.org_url,
            project=project,
            mode="mock",
            branch_policies=[
                BranchPolicyFact(
                    repository="payments-api",
                    branch="main",
                    minimum_reviewers=2,
                    required_reviewers=["AppSec Team", "Platform Leads"],
                    build_validation_enabled=True,
                    status_checks=["CI", "Unit Tests", "Dependency Scan"],
                    source="mock",
                ),
                BranchPolicyFact(
                    repository="portal-ui",
                    branch="main",
                    minimum_reviewers=2,
                    build_validation_enabled=True,
                    status_checks=["CI", "E2E Tests"],
                    source="mock",
                ),
            ],
            pipeline_gates=[
                PipelineGateFact(
                    pipeline_name="prod-release",
                    stage="Production",
                    manual_approval_required=True,
                    approvers=["Release Managers", "Security Duty Manager"],
                    gates=["Manual approval", "Change ticket linkage"],
                    source="mock",
                )
            ],
            pr_statistics=[
                PRStatistics(
                    repository="payments-api",
                    period_days=90,
                    total_prs=134,
                    prs_with_two_or_more_approvers=130,
                    avg_approvers=2.4,
                    median_time_to_merge_hours=9.2,
                ),
                PRStatistics(
                    repository="portal-ui",
                    period_days=90,
                    total_prs=88,
                    prs_with_two_or_more_approvers=84,
                    avg_approvers=2.1,
                    median_time_to_merge_hours=11.4,
                ),
            ],
            security_groups=[
                SecurityGroupFact(
                    group_name="Project Administrators",
                    permission_scope="Azure DevOps ProjectA administrative settings",
                    members_count=4,
                    key_permissions={
                        "Edit build pipeline": "Allow",
                        "Manage branch policies": "Allow",
                        "Delete repository": "Allow",
                    },
                    least_privilege_reviewed=True,
                ),
                SecurityGroupFact(
                    group_name="Contributors",
                    permission_scope="Repository contribution access",
                    members_count=27,
                    key_permissions={
                        "Contribute": "Allow",
                        "Force push": "Deny",
                        "Bypass pull request policies": "Deny",
                    },
                    least_privilege_reviewed=True,
                ),
            ],
            scanning_statuses=[
                ScanningStatus(
                    repository="payments-api",
                    pipeline_name="ci-payments-api",
                    dependency_scanning_detected=True,
                    sast_detected=True,
                    last_seen=now,
                ),
                ScanningStatus(
                    repository="portal-ui",
                    pipeline_name="ci-portal-ui",
                    dependency_scanning_detected=True,
                    sast_detected=False,
                    last_seen=now,
                ),
            ],
            service_hooks=[
                ServiceHookFact(
                    hook_type="Teams webhook",
                    target="Security Operations Teams channel",
                    active=True,
                ),
                ServiceHookFact(
                    hook_type="ServiceNow",
                    target="Security incident intake",
                    active=True,
                ),
            ],
            discovery_notes=notes,
        )


class AzureDevOpsClient(BaseAzureDevOpsClient):
    def __init__(
        self,
        org_url: str,
        pat: str,
        *,
        timeout: float = 20.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not pat:
            raise AzureDevOpsClientError("Azure DevOps PAT is required for real discovery mode.")
        auth_token = base64.b64encode(f":{pat}".encode("utf-8")).decode("ascii")
        headers = {"Authorization": f"Basic {auth_token}"}
        self.org_url = org_url.rstrip("/")
        self._client = http_client or httpx.Client(headers=headers, timeout=timeout)

    def _get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self._client.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def _safe_get(
        self,
        *,
        url: str,
        notes: list[DiscoveryNote],
        category: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        try:
            return self._get(url, params=params)
        except Exception as exc:  # pragma: no cover - network errors are environment-specific
            notes.append(DiscoveryNote(category=category, message=f"{category} discovery failed: {exc}"))
            return None

    def discover_project(self, project: str, audit_period: str | None = None) -> DiscoveredFacts:
        notes: list[DiscoveryNote] = []
        if audit_period:
            notes.append(
                DiscoveryNote(
                    category="audit-period",
                    message=f"Audit narrative period context supplied as {audit_period}.",
                )
            )

        repositories = self._safe_get(
            url=f"{self.org_url}/{project}/_apis/git/repositories",
            params={"api-version": "7.1-preview.1"},
            notes=notes,
            category="repositories",
        )
        repo_items = repositories.get("value", []) if repositories else []
        repo_lookup = {item.get("id", item.get("name", "")): item.get("name", "unknown-repository") for item in repo_items}

        policy_payload = self._safe_get(
            url=f"{self.org_url}/{project}/_apis/policy/configurations",
            params={"api-version": "7.1-preview.1"},
            notes=notes,
            category="branch-policies",
        )
        branch_policies = self._parse_branch_policies(policy_payload.get("value", []), repo_lookup)

        build_payload = self._safe_get(
            url=f"{self.org_url}/{project}/_apis/build/definitions",
            params={"api-version": "7.1-preview.7", "includeAllProperties": "true"},
            notes=notes,
            category="pipelines",
        )
        pipeline_gates, scanning_statuses = self._parse_build_definitions(build_payload.get("value", []))

        service_hook_payload = self._safe_get(
            url=f"{self.org_url}/{project}/_apis/hooks/subscriptions",
            params={"api-version": "7.1-preview.1"},
            notes=notes,
            category="service-hooks",
        )
        service_hooks = self._parse_service_hooks(service_hook_payload.get("value", []))

        graph_groups = self._safe_get(
            url=f"{self.org_url}/_apis/graph/groups",
            params={"api-version": "7.1-preview.1"},
            notes=notes,
            category="security-groups",
        )
        security_groups = self._parse_security_groups(graph_groups.get("value", []))

        pr_statistics: list[PRStatistics] = []
        for repo in repo_items:
            repo_id = repo.get("id")
            repo_name = repo.get("name", "unknown-repository")
            if not repo_id:
                continue
            pr_statistics.append(self._get_pr_statistics(project, repo_id, repo_name, notes))

        if not any([branch_policies, pipeline_gates, pr_statistics, security_groups, scanning_statuses, service_hooks]):
            notes.append(
                DiscoveryNote(
                    category="coverage",
                    message="Real discovery returned no parseable evidence. Confirm project access and API coverage.",
                )
            )

        return DiscoveredFacts(
            org_url=self.org_url,
            project=project,
            mode="real",
            branch_policies=branch_policies,
            pipeline_gates=pipeline_gates,
            pr_statistics=pr_statistics,
            security_groups=security_groups,
            scanning_statuses=scanning_statuses,
            service_hooks=service_hooks,
            discovery_notes=notes,
        )

    def _parse_branch_policies(
        self,
        policies: list[dict[str, Any]],
        repo_lookup: dict[str, str],
    ) -> list[BranchPolicyFact]:
        aggregated: dict[tuple[str, str], BranchPolicyFact] = {}
        for policy in policies:
            settings = policy.get("settings", {})
            scope_items = settings.get("scope", [{}])
            type_name = policy.get("type", {}).get("displayName", "").lower()
            for scope in scope_items:
                branch = scope.get("refName", "refs/heads/main").replace("refs/heads/", "")
                repository_id = scope.get("repositoryId", "")
                repository = repo_lookup.get(repository_id, "all-repositories")
                key = (repository, branch)
                fact = aggregated.setdefault(
                    key,
                    BranchPolicyFact(repository=repository, branch=branch, observed=True, source="azure-devops"),
                )
                if "reviewer" in type_name and "minimum" in type_name:
                    fact.minimum_reviewers = settings.get("minimumApproverCount")
                if "required reviewers" in type_name:
                    reviewers = settings.get("requiredReviewerIds", [])
                    fact.required_reviewers = [str(item) for item in reviewers]
                if "build" in type_name or "status" in type_name:
                    fact.build_validation_enabled = True
                    display_name = policy.get("type", {}).get("displayName")
                    if display_name and display_name not in fact.status_checks:
                        fact.status_checks.append(display_name)
        return list(aggregated.values())

    def _parse_build_definitions(
        self,
        definitions: list[dict[str, Any]],
    ) -> tuple[list[PipelineGateFact], list[ScanningStatus]]:
        pipeline_gates: list[PipelineGateFact] = []
        scanning_statuses: list[ScanningStatus] = []
        for definition in definitions:
            name = definition.get("name", "unknown-pipeline")
            text = json.dumps(definition).lower()
            manual_approval = any(keyword in text for keyword in ("manualvalidation", "approval"))
            gates: list[str] = []
            if manual_approval:
                gates.append("Manual validation task")
            if "branchpolicy" in text:
                gates.append("Branch policy validation")
            if manual_approval or gates:
                pipeline_gates.append(
                    PipelineGateFact(
                        pipeline_name=name,
                        stage="Production" if "prod" in name.lower() else "Build",
                        manual_approval_required=manual_approval,
                        approvers=[],
                        gates=gates,
                        observed=True,
                        source="azure-devops",
                    )
                )
            scanning_statuses.append(
                ScanningStatus(
                    repository=definition.get("repository", {}).get("name", name),
                    pipeline_name=name,
                    dependency_scanning_detected=any(
                        keyword in text for keyword in ("trivy", "snyk", "dependency", "whitesource", "blackduck")
                    ),
                    sast_detected=any(keyword in text for keyword in ("bandit", "semgrep", "codeql", "sonarqube")),
                )
            )
        return pipeline_gates, scanning_statuses

    def _parse_service_hooks(self, subscriptions: list[dict[str, Any]]) -> list[ServiceHookFact]:
        hooks: list[ServiceHookFact] = []
        for item in subscriptions:
            consumer = item.get("consumerActionId") or item.get("consumerId") or "unknown-consumer"
            publisher = item.get("publisherId") or "unknown-publisher"
            hooks.append(
                ServiceHookFact(
                    hook_type=publisher,
                    target=consumer,
                    active=item.get("status", "enabled").lower() != "disabled",
                )
            )
        return hooks

    def _parse_security_groups(self, groups: list[dict[str, Any]]) -> list[SecurityGroupFact]:
        parsed: list[SecurityGroupFact] = []
        for item in groups:
            parsed.append(
                SecurityGroupFact(
                    group_name=item.get("displayName", "unknown-group"),
                    permission_scope="Azure DevOps security group membership",
                    members_count=None,
                    key_permissions={},
                    least_privilege_reviewed=None,
                )
            )
        return parsed

    def _get_pr_statistics(
        self,
        project: str,
        repo_id: str,
        repo_name: str,
        notes: list[DiscoveryNote],
    ) -> PRStatistics:
        payload = self._safe_get(
            url=f"{self.org_url}/{project}/_apis/git/repositories/{repo_id}/pullrequests",
            params={
                "searchCriteria.status": "completed",
                "$top": 100,
                "api-version": "7.1-preview.1",
            },
            notes=notes,
            category=f"pull-requests:{repo_name}",
        )
        if not payload:
            return PRStatistics(repository=repo_name)
        items = payload.get("value", [])
        approver_counts: list[int] = []
        merge_durations: list[float] = []
        for pr in items:
            reviewers = pr.get("reviewers", [])
            approver_count = sum(1 for reviewer in reviewers if reviewer.get("vote", 0) > 0)
            approver_counts.append(approver_count)
            created = pr.get("creationDate")
            closed = pr.get("closedDate")
            if created and closed:
                created_at = datetime.fromisoformat(created.replace("Z", "+00:00"))
                closed_at = datetime.fromisoformat(closed.replace("Z", "+00:00"))
                merge_durations.append((closed_at - created_at).total_seconds() / 3600)
        total_prs = len(items)
        return PRStatistics(
            repository=repo_name,
            period_days=90,
            total_prs=total_prs,
            prs_with_two_or_more_approvers=sum(1 for count in approver_counts if count >= 2),
            avg_approvers=round(mean(approver_counts), 2) if approver_counts else None,
            median_time_to_merge_hours=round(median(merge_durations), 2) if merge_durations else None,
        )

