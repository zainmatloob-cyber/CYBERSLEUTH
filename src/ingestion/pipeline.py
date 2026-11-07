"""Ingestion orchestrator: bytes in → validated, cleaned, segmented document out.

Stages: validate → read → clean → empty-check → split sentences.
Each stage lives in its own module and is unit-tested on its own; this module
only wires them together and reports progress.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from enum import StrEnum

from config.settings import IngestionSettings, settings
from src.ingestion.docx_reader import read_docx
from src.ingestion.models import ExtractedDocument, FileType, ValidatedFile
from src.ingestion.pdf_reader import read_pdf
from src.ingestion.text_cleaner import clean_pages
from src.ingestion.txt_reader import read_txt
from src.ingestion.validator import validate_upload
from src.nlp.preprocessing import SentenceSplitter, split_sentences
from src.utils.exceptions import EmptyDocumentError

logger = logging.getLogger(__name__)


class Stage(StrEnum):
    """Pipeline stages, reported to an optional progress callback."""

    VALIDATING = "Validating file"
    EXTRACTING = "Extracting text"
    CLEANING = "Cleaning text"
    SEGMENTING = "Segmenting sentences"
    DONE = "Done"


ProgressCallback = Callable[[Stage], None]


def _read(file: ValidatedFile, limits: IngestionSettings) -> ExtractedDocument:
    match file.file_type:
        case FileType.PDF:
            return read_pdf(file, limits)
        case FileType.DOCX:
            return read_docx(file)
        case FileType.TXT:
            return read_txt(file)
    raise AssertionError(f"No reader for {file.file_type}")  # unreachable: enum is exhaustive


def ingest(
    data: bytes,
    filename: str,
    *,
    limits: IngestionSettings | None = None,
    splitter: SentenceSplitter | None = None,
    on_progress: ProgressCallback | None = None,
) -> ExtractedDocument:
    """Run the full ingestion pipeline on raw upload bytes.

    Raises a subclass of ``IngestionError`` for every expected failure (bad type,
    too large, corrupted, encrypted, no extractable text).
    """
    limits = limits or settings.ingestion
    report = on_progress or (lambda _stage: None)
    started = time.perf_counter()

    report(Stage.VALIDATING)
    file = validate_upload(data, filename, limits)

    report(Stage.EXTRACTING)
    document = _read(file, limits)

    report(Stage.CLEANING)
    document.pages = clean_pages(document.pages)

    if document.char_count == 0:
        if document.needs_ocr:
            raise EmptyDocumentError(
                "No extractable text: the document appears to be scanned images. "
                "OCR is not supported yet."
            )
        raise EmptyDocumentError("The document contains no extractable text.")

    report(Stage.SEGMENTING)
    document.sentences = split_sentences(document.pages, splitter)

    report(Stage.DONE)
    logger.info(
        "Ingested %s: %d pages, %d chars, %d sentences, %d warnings in %.0f ms",
        document.filename, document.page_count, document.char_count,
        len(document.sentences), len(document.warnings),
        (time.perf_counter() - started) * 1000,
    )
    return document
