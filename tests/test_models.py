from __future__ import annotations

from soc2_copilot.models import BranchPolicyFact, DiscoveredFacts, PRStatistics


def test_pr_statistics_computed_rate() -> None:
    stats = PRStatistics(
        repository="payments-api",
        total_prs=10,
        prs_with_two_or_more_approvers=9,
    )
    assert stats.two_approver_rate_pct == 90.0


def test_discovered_facts_evidence_lines_include_branch_controls() -> None:
    facts = DiscoveredFacts(
        org_url="https://dev.azure.com/example",
        project="ProjectA",
        branch_policies=[
            BranchPolicyFact(
                repository="payments-api",
                branch="main",
                minimum_reviewers=2,
                build_validation_enabled=True,
            )
        ],
    )
    evidence = facts.evidence_lines()
    assert any("requires 2 reviewers" in line for line in evidence)
    assert any("build validation enabled" in line for line in evidence)

