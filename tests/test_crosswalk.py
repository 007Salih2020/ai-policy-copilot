from __future__ import annotations

from pathlib import Path

from soc2_copilot.crosswalk import CrosswalkRepository


def test_crosswalk_rows_include_curated_mapping() -> None:
    repository = CrosswalkRepository(data_dir=Path(__file__).resolve().parents[1] / "data")
    rows = repository.export_rows()
    cc61 = next(row for row in rows if row["criteria_id"] == "CC6.1")
    assert "A.5.15" in cc61["iso_27001_clauses"]


def test_crosswalk_exports_json_and_markdown(tmp_path: Path) -> None:
    repository = CrosswalkRepository(data_dir=Path(__file__).resolve().parents[1] / "data")
    json_path = repository.export_json(tmp_path / "crosswalk.json")
    markdown_path = repository.export_markdown(tmp_path / "crosswalk.md")
    assert json_path.exists()
    assert markdown_path.exists()
    assert "CC8.1" in markdown_path.read_text(encoding="utf-8")

