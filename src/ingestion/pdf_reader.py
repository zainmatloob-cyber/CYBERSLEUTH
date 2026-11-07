"""PDF reader built on PyMuPDF.

Produces one ``PageText`` per PDF page so every later finding can cite a page.
Image-only (scanned) pages are detected and reported instead of silently
yielding empty text; OCR is intentionally out of scope.
"""

from __future__ import annotations

import logging

import pymupdf

from config.settings import IngestionSettings, settings
from src.ingestion.models import ExtractedDocument, PageText, ValidatedFile, clean_metadata
from src.utils.exceptions import CorruptedFileError, EncryptedDocumentError, FileTooLargeError

logger = logging.getLogger(__name__)

# MuPDF writes repair warnings straight to stderr; we report problems ourselves.
pymupdf.TOOLS.mupdf_display_errors(False)

_METADATA_KEYS = ("title", "author", "subject", "keywords", "creator", "producer",
                  "creationDate", "modDate")


def _format_pages(numbers: list[int]) -> str:
    return ", ".join(str(n) for n in numbers)


def read_pdf(file: ValidatedFile, limits: IngestionSettings | None = None) -> ExtractedDocument:
    """Extract per-page text from a validated PDF upload."""
    limits = limits or settings.ingestion
    try:
        doc = pymupdf.open(stream=file.data, filetype="pdf")
    except (pymupdf.FileDataError, RuntimeError, ValueError) as exc:
        raise CorruptedFileError("PDF could not be opened; the file may be corrupted.") from exc

    with doc:
        if doc.needs_pass:
            raise EncryptedDocumentError("PDF is password-protected and cannot be read.")
        if doc.page_count == 0:
            raise CorruptedFileError("PDF contains no readable pages; it may be corrupted.")
        if doc.page_count > limits.max_pdf_pages:
            raise FileTooLargeError(
                f"PDF has {doc.page_count} pages (limit {limits.max_pdf_pages})."
            )

        pages: list[PageText] = []
        scanned_pages: list[int] = []
        failed_pages: list[int] = []

        for index, page in enumerate(doc):
            number = index + 1
            try:
                # sort=True orders text blocks top-to-bottom, left-to-right,
                # which gives a more natural reading order than raw stream order.
                text = page.get_text("text", sort=True)
            except (RuntimeError, ValueError):
                logger.warning("Failed to extract text from %s page %d", file.filename, number)
                failed_pages.append(number)
                text = ""
            else:
                if len(text.strip()) < limits.min_chars_per_text_page and page.get_images():
                    scanned_pages.append(number)
            pages.append(PageText(page_number=number, text=text))

        raw_metadata = doc.metadata or {}
        metadata = clean_metadata({k: raw_metadata.get(k) for k in _METADATA_KEYS})
        was_repaired = bool(doc.is_repaired)

    warnings: list[str] = []
    if was_repaired:
        # MuPDF rebuilt a damaged cross-reference table. Text is often fully
        # recoverable, so the document is accepted, but the analyst is told.
        warnings.append("PDF structure was damaged and automatically repaired; "
                        "some content may be missing.")
    if scanned_pages:
        warnings.append(
            f"Page(s) {_format_pages(scanned_pages)} appear to be scanned images with no "
            "text layer. Their content was not extracted (OCR is not supported)."
        )
    if failed_pages:
        warnings.append(f"Text extraction failed on page(s) {_format_pages(failed_pages)}.")

    logger.info(
        "Read PDF %s (%d pages, %d scanned, %d failed)",
        file.filename, len(pages), len(scanned_pages), len(failed_pages),
    )
    return ExtractedDocument.from_validated(
        file, pages=pages, metadata=metadata, warnings=warnings, needs_ocr=bool(scanned_pages)
    )
