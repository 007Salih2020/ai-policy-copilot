from __future__ import annotations

from soc2_copilot.clients.ado_client import MockAzureDevOpsClient
from soc2_copilot.generators.control_gen import ControlGenerator
from soc2_copilot.generators.policy_gen import PolicyGenerator


def test_policy_generation_uses_grounded_evidence_and_disclaimer() -> None:
    facts = MockAzureDevOpsClient().discover_project("ProjectA")
    policy = PolicyGenerator().generate("change_management_policy", facts)
    assert "AI-assisted draft generated from discovered system facts" in policy.content
    assert "requires 2 reviewers" in policy.content
    assert "97.01%" in policy.content


def test_control_generation_loads_curated_iso_crosswalk() -> None:
    facts = MockAzureDevOpsClient().discover_project("ProjectA")
    controls = ControlGenerator().generate(facts, ["CC8.1"])
    assert controls[0].criteria_id == "CC8.1"
    assert "A.8.32" in controls[0].iso_27001_clauses
