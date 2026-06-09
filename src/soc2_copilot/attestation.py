from __future__ import annotations

import difflib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc2_copilot.models import Attestation, GeneratedPolicy
from soc2_copilot.state import compute_sha256, ensure_directory, read_text


class AttestationError(RuntimeError):
    pass


class AttestationStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        ensure_directory(db_path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_type TEXT NOT NULL,
                    version TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    source_facts_snapshot TEXT NOT NULL,
                    generator_model TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    rendered_content TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS attestations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id INTEGER NOT NULL,
                    attested_by TEXT NOT NULL,
                    role TEXT NOT NULL,
                    attested_at TEXT NOT NULL,
                    approved INTEGER NOT NULL,
                    comments TEXT,
                    next_review_date TEXT,
                    content_hash TEXT NOT NULL,
                    FOREIGN KEY(policy_id) REFERENCES policies(id)
                )
                """
            )

    def _next_version(self, policy_type: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM policies WHERE policy_type = ?",
                (policy_type,),
            ).fetchone()
        next_index = int(row["count"]) + 1 if row else 1
        return f"v{next_index}"

    def _row_to_policy(self, row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        payload["source_facts_snapshot"] = json.loads(payload["source_facts_snapshot"])
        return payload

    def get_policy_by_id(self, policy_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if row is None:
            raise AttestationError(f"Unknown policy id: {policy_id}")
        return self._row_to_policy(row)

    def get_policy_by_identifier(self, identifier: str) -> dict[str, Any]:
        path = Path(identifier)
        with self._connect() as connection:
            if path.exists():
                resolved = str(path.resolve())
                row = connection.execute(
                    "SELECT * FROM policies WHERE file_path = ? ORDER BY id DESC LIMIT 1",
                    (resolved,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM policies WHERE policy_type = ? ORDER BY id DESC LIMIT 1",
                    (identifier,),
                ).fetchone()
        if row is None:
            raise AttestationError(f"No policy record found for {identifier}")
        return self._row_to_policy(row)

    def _insert_policy_record(
        self,
        *,
        policy_type: str,
        version: str,
        content_hash: str,
        generated_at: str,
        source_facts_snapshot: dict[str, Any],
        generator_model: str,
        file_path: str,
        rendered_content: str,
    ) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO policies (
                    policy_type,
                    version,
                    content_hash,
                    generated_at,
                    source_facts_snapshot,
                    generator_model,
                    file_path,
                    rendered_content
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy_type,
                    version,
                    content_hash,
                    generated_at,
                    json.dumps(source_facts_snapshot, default=str),
                    generator_model,
                    file_path,
                    rendered_content,
                ),
            )
            return int(cursor.lastrowid)

    def register_generated_policy(self, policy: GeneratedPolicy) -> int:
        existing: dict[str, Any] | None = None
        if policy.file_path:
            try:
                existing = self.get_policy_by_identifier(policy.file_path)
            except AttestationError:
                existing = None
        if existing and existing["content_hash"] == policy.content_hash:
            return int(existing["id"])
        version = policy.version or self._next_version(policy.policy_type)
        return self._insert_policy_record(
            policy_type=policy.policy_type,
            version=version,
            content_hash=policy.content_hash,
            generated_at=policy.generated_at.isoformat(),
            source_facts_snapshot=policy.source_facts_snapshot,
            generator_model=policy.generator_model,
            file_path=policy.file_path or "",
            rendered_content=policy.content,
        )

    def ensure_policy_record_for_file(
        self,
        policy_path: Path,
        policy_type: str | None = None,
        generator_model: str = "manual-review",
        source_facts_snapshot: dict[str, Any] | None = None,
    ) -> int:
        normalized_path = policy_path.resolve()
        content = read_text(normalized_path)
        content_hash = compute_sha256(content)
        record_type = policy_type or normalized_path.stem
        try:
            existing = self.get_policy_by_identifier(str(normalized_path))
        except AttestationError:
            existing = None
        if existing and existing["content_hash"] == content_hash:
            return int(existing["id"])
        return self._insert_policy_record(
            policy_type=record_type,
            version=self._next_version(record_type),
            content_hash=content_hash,
            generated_at=datetime.fromtimestamp(normalized_path.stat().st_mtime, tz=timezone.utc).isoformat(),
            source_facts_snapshot=source_facts_snapshot or {},
            generator_model=generator_model,
            file_path=str(normalized_path),
            rendered_content=content,
        )

    def create_attestation(
        self,
        *,
        policy_id: int,
        attested_by: str,
        role: str,
        approved: bool,
        comments: str | None,
        next_review_date: str | None,
    ) -> Attestation:
        policy = self.get_policy_by_id(policy_id)
        path = Path(policy["file_path"])
        if not path.exists():
            raise AttestationError(f"Policy file does not exist: {path}")
        current_hash = compute_sha256(read_text(path))
        if current_hash != policy["content_hash"]:
            raise AttestationError(
                "Policy content changed after registration. Re-register the file before attesting."
            )
        attestation = Attestation(
            policy_id=policy_id,
            attested_by=attested_by,
            role=role,
            approved=approved,
            comments=comments,
            next_review_date=next_review_date,
            content_hash=current_hash,
        )
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO attestations (
                    policy_id,
                    attested_by,
                    role,
                    attested_at,
                    approved,
                    comments,
                    next_review_date,
                    content_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attestation.policy_id,
                    attestation.attested_by,
                    attestation.role,
                    attestation.attested_at.isoformat(),
                    int(attestation.approved),
                    attestation.comments,
                    attestation.next_review_date,
                    attestation.content_hash,
                ),
            )
        attestation.id = int(cursor.lastrowid)
        return attestation

    def attest_policy_file(
        self,
        policy_path: Path,
        *,
        attested_by: str,
        role: str,
        approved: bool,
        comments: str | None = None,
        next_review_date: str | None = None,
        policy_type: str | None = None,
    ) -> Attestation:
        policy_id = self.ensure_policy_record_for_file(policy_path, policy_type=policy_type)
        return self.create_attestation(
            policy_id=policy_id,
            attested_by=attested_by,
            role=role,
            approved=approved,
            comments=comments,
            next_review_date=next_review_date,
        )

    def get_latest_attestation(self, policy_id: int) -> Attestation | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM attestations WHERE policy_id = ? ORDER BY id DESC LIMIT 1",
                (policy_id,),
            ).fetchone()
        if row is None:
            return None
        return Attestation.model_validate(
            {
                "id": row["id"],
                "policy_id": row["policy_id"],
                "attested_by": row["attested_by"],
                "role": row["role"],
                "attested_at": row["attested_at"],
                "approved": bool(row["approved"]),
                "comments": row["comments"],
                "next_review_date": row["next_review_date"],
                "content_hash": row["content_hash"],
            }
        )

    def assert_publishable(self, identifier: str) -> tuple[dict[str, Any], Attestation]:
        policy = self.get_policy_by_identifier(identifier)
        attestation = self.get_latest_attestation(int(policy["id"]))
        if attestation is None:
            raise AttestationError("No attestation found for the requested policy.")
        if not attestation.approved:
            raise AttestationError("The latest attestation did not approve this policy.")
        path = Path(policy["file_path"])
        if not path.exists():
            raise AttestationError(f"Policy file does not exist: {path}")
        current_hash = compute_sha256(read_text(path))
        if current_hash != policy["content_hash"] or current_hash != attestation.content_hash:
            raise AttestationError("Policy content hash does not match the approved attestation.")
        return policy, attestation

    def get_previous_version_diff(self, policy_id: int) -> str:
        current = self.get_policy_by_id(policy_id)
        with self._connect() as connection:
            previous = connection.execute(
                """
                SELECT * FROM policies
                WHERE policy_type = ? AND id < ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (current["policy_type"], policy_id),
            ).fetchone()
        if previous is None:
            return ""
        previous_policy = self._row_to_policy(previous)
        diff = difflib.unified_diff(
            previous_policy["rendered_content"].splitlines(),
            current["rendered_content"].splitlines(),
            fromfile=previous_policy["version"],
            tofile=current["version"],
            lineterm="",
        )
        return "\n".join(diff)
