"""DOCX reader built on python-docx.

Paragraphs and tables are read in document order (IOC tables are common in
threat reports, so tables must not be dropped). Headers, footers, footnotes and
text boxes are not extracted; this is documented as a known limitation.

Security note: python-docx parses XML with ``resolve_entities=False``, so XML
external-entity (XXE) payloads inside a malicious DOCX are not expanded.
"""

from __future__ import annotations

import io
import logging
import zipfile

import docx
from docx.document import Document as DocxDocument
from docx.opc.exceptions import PackageNotFoundError
from docx.table import Table
from docx.text.paragraph import Paragraph
from lxml import etree

from src.ingestion.models import ExtractedDocument, PageText, ValidatedFile, clean_metadata
from src.utils.exceptions import CorruptedFileError

logger = logging.getLogger(__name__)

_CELL_SEPARATOR = " | "
_CORE_PROPERTY_FIELDS = ("title", "author", "subject", "keywords", "created", "modified",
                         "last_modified_by")


def _table_to_lines(table: Table) -> list[str]:
    """Render each table row as one line, cells separated by `` | ``.

    Horizontally merged cells are returned repeatedly by python-docx; they are
    de-duplicated so merged text is not repeated.
    """
    lines: list[str] = []
    for row in table.rows:
        cells: list[str] = []
        previous_tc = None
        for cell in row.cells:
            if cell._tc is previous_tc:  # same underlying cell → horizontal merge
                continue
            previous_tc = cell._tc
            cells.append(" ".join(cell.text.split()))
        if any(cells):
            lines.append(_CELL_SEPARATOR.join(cells))
    return lines


def _body_lines(document: DocxDocument) -> list[str]:
    lines: list[str] = []
    for block in document.iter_inner_content():
        if isinstance(block, Paragraph):
            lines.append(block.text)
        elif isinstance(block, Table):
            lines.extend(_table_to_lines(block))
    return lines


def read_docx(file: ValidatedFile) -> ExtractedDocument:
    """Extract body text (paragraphs + tables) from a validated DOCX upload."""
    try:
        document = docx.Document(io.BytesIO(file.data))
        lines = _body_lines(document)
    except (PackageNotFoundError, zipfile.BadZipFile, KeyError, ValueError,
            etree.XMLSyntaxError) as exc:
        raise CorruptedFileError("DOCX could not be parsed; the file may be corrupted.") from exc

    props = document.core_properties
    metadata = clean_metadata({f: getattr(props, f, None) for f in _CORE_PROPERTY_FIELDS})

    text = "\n".join(lines)
    logger.info("Read DOCX %s (%d blocks, %d chars)", file.filename, len(lines), len(text))
    return ExtractedDocument.from_validated(
        file, pages=[PageText(page_number=1, text=text)], metadata=metadata
    )
