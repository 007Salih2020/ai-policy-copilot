from __future__ import annotations

import json
from pathlib import Path

import yaml
from pydantic import BaseModel

from soc2_copilot.state import ensure_directory


class CriteriaDefinition(BaseModel):
    id: str
    domain: str
    title: str
    objective: str


class IsoClause(BaseModel):
    id: str
    title: str


class CrosswalkEntry(BaseModel):
    criteria_id: str
    iso_27001_clauses: list[str]
    rationale: str


class CrosswalkRepository:
    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or self._default_data_dir()

    def _default_data_dir(self) -> Path:
        candidates = [
            Path.cwd() / "data",
            Path(__file__).resolve().parents[2] / "data",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    def _load_yaml(self, name: str) -> dict:
        path = self.data_dir / name
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def load_criteria(self) -> dict[str, CriteriaDefinition]:
        payload = self._load_yaml("soc2_tsc.yaml")
        return {item["id"]: CriteriaDefinition.model_validate(item) for item in payload["criteria"]}

    def load_iso_clauses(self) -> dict[str, IsoClause]:
        payload = self._load_yaml("iso27001_clauses.yaml")
        return {item["id"]: IsoClause.model_validate(item) for item in payload["clauses"]}

    def load_crosswalk(self) -> list[CrosswalkEntry]:
        payload = self._load_yaml("crosswalk.yaml")
        return [CrosswalkEntry.model_validate(item) for item in payload["crosswalk"]]

    def find_iso_clauses_for_criteria(self, criteria_id: str) -> list[str]:
        for entry in self.load_crosswalk():
            if entry.criteria_id == criteria_id:
                return entry.iso_27001_clauses
        return []

    def export_rows(self) -> list[dict[str, str]]:
        criteria = self.load_criteria()
        iso_clauses = self.load_iso_clauses()
        rows: list[dict[str, str]] = []
        for entry in self.load_crosswalk():
            clause_titles = [f"{clause_id} {iso_clauses[clause_id].title}" for clause_id in entry.iso_27001_clauses]
            rows.append(
                {
                    "criteria_id": entry.criteria_id,
                    "criteria_title": criteria[entry.criteria_id].title,
                    "criteria_domain": criteria[entry.criteria_id].domain,
                    "iso_27001_clauses": ", ".join(entry.iso_27001_clauses),
                    "iso_27001_titles": "; ".join(clause_titles),
                    "rationale": entry.rationale,
                }
            )
        return rows

    def export_json(self, output_path: Path) -> Path:
        ensure_directory(output_path.parent)
        output_path.write_text(json.dumps(self.export_rows(), indent=2), encoding="utf-8")
        return output_path

    def export_markdown(self, output_path: Path) -> Path:
        ensure_directory(output_path.parent)
        rows = self.export_rows()
        lines = [
            "| SOC 2 Criteria | Domain | ISO 27001 Clauses | Rationale |",
            "| --- | --- | --- | --- |",
        ]
        for row in rows:
            lines.append(
                f"| {row['criteria_id']} {row['criteria_title']} | {row['criteria_domain']} | "
                f"{row['iso_27001_clauses']} | {row['rationale']} |"
            )
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return output_path
