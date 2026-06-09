from __future__ import annotations

from pathlib import Path

from openpyxl import Workbook

from soc2_copilot.state import ensure_directory


class ExcelExporter:
    def export_crosswalk(self, rows: list[dict[str, str]], output_path: Path) -> Path:
        ensure_directory(output_path.parent)
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "SOC2_ISO_Crosswalk"
        headers = [
            "criteria_id",
            "criteria_title",
            "criteria_domain",
            "iso_27001_clauses",
            "iso_27001_titles",
            "rationale",
        ]
        sheet.append(headers)
        for row in rows:
            sheet.append([row.get(header, "") for header in headers])
        for column in sheet.columns:
            width = max(len(str(cell.value or "")) for cell in column) + 2
            sheet.column_dimensions[column[0].column_letter].width = min(width, 60)
        workbook.save(output_path)
        return output_path

