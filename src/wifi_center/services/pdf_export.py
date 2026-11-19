"""HTML -> PDF with Qt's own text engine (no extra dependency). Must be called on the UI thread."""
from __future__ import annotations

from pathlib import Path


def html_to_pdf(html_text: str, path: Path, title: str) -> None:
    try:
        from PySide6.QtCore import QMarginsF
        from PySide6.QtGui import QPageLayout, QPageSize, QPdfWriter, QTextDocument
    except ImportError as e:
        raise RuntimeError("PDF output needs PySide6's PDF support; use HTML and print it to PDF instead.") from e
    writer = QPdfWriter(str(path))
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Unit.Millimeter)
    writer.setTitle(title)
    doc = QTextDocument()
    doc.setHtml(html_text)
    doc.print_(writer)
