from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from soc2_copilot.attestation import AttestationError, AttestationStore
from soc2_copilot.models import GeneratedPolicy
from soc2_copilot.state import compute_sha256


def test_attestation_rejects_publish_after_content_change(tmp_path: Path) -> None:
    db_path = tmp_path / "copilot.db"
    policy_path = tmp_path / "access_control_policy.md"
    original_content = "# Access Control Policy\n\nVersion one\n"
    policy_path.write_text(original_content, encoding="utf-8")
    store = AttestationStore(db_path)
    generated_policy = GeneratedPolicy(
        policy_type="access_control_policy",
        version="v1",
        generator_model="test",
        file_path=str(policy_path.resolve()),
        content=original_content,
        source_facts_snapshot={},
        content_hash=compute_sha256(original_content),
        generated_at=datetime.now(timezone.utc),
    )
    store.register_generated_policy(generated_policy)
    store.attest_policy_file(
        policy_path.resolve(),
        attested_by="Jane Smith",
        role="Security Manager",
        approved=True,
        next_review_date="2025-12-31",
    )
    policy_path.write_text("# Access Control Policy\n\nChanged after approval\n", encoding="utf-8")
    with pytest.raises(AttestationError):
        store.assert_publishable("access_control_policy")


def test_attestation_diff_returns_previous_version(tmp_path: Path) -> None:
    db_path = tmp_path / "copilot.db"
    policy_path = tmp_path / "availability_policy.md"
    store = AttestationStore(db_path)
    policy_path.write_text("# Availability Policy\n\nVersion one\n", encoding="utf-8")
    first_id = store.ensure_policy_record_for_file(policy_path.resolve(), policy_type="availability_policy")
    assert store.get_previous_version_diff(first_id) == ""
    policy_path.write_text("# Availability Policy\n\nVersion two\n", encoding="utf-8")
    second_id = store.ensure_policy_record_for_file(policy_path.resolve(), policy_type="availability_policy")
    diff = store.get_previous_version_diff(second_id)
    assert "-Version one" in diff
    assert "+Version two" in diff

