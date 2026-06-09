from __future__ import annotations

from pathlib import Path


class PDFExporter:
    def export_markdown(self, markdown_text: str, output_path: Path) -> Path:
        raise RuntimeError(
            "PDF export is intentionally left as an extension point. "
            "Add a renderer such as WeasyPrint or ReportLab for production PDF output."
        )

