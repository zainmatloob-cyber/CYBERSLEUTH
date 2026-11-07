"""Plain-text reader with explicit, ordered encoding detection.

Order: BOM-declared encodings → strict UTF-8 → Windows-1252 fallback.
Windows-1252 is the realistic fallback for reports authored on Windows; it is
tried last because almost any byte sequence "decodes" in a single-byte codec.
"""

from __future__ import annotations

import codecs
import logging

from src.ingestion.models import ExtractedDocument, PageText, ValidatedFile

logger = logging.getLogger(__name__)

_BOM_ENCODINGS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)
_FALLBACK_ENCODING = "cp1252"


def decode_text(data: bytes) -> tuple[str, str, bool]:
    """Decode bytes to text.

    Returns ``(text, encoding_used, had_replacements)``. Never raises: undecodable
    bytes become U+FFFD and ``had_replacements`` is set so the caller can warn.
    """
    for bom, encoding in _BOM_ENCODINGS:
        if data.startswith(bom):
            text = data.decode(encoding, errors="replace")
            return text, encoding, "�" in text
    try:
        return data.decode("utf-8"), "utf-8", False
    except UnicodeDecodeError:
        pass
    text = data.decode(_FALLBACK_ENCODING, errors="replace")
    return text, _FALLBACK_ENCODING, "�" in text


def read_txt(file: ValidatedFile) -> ExtractedDocument:
    """Read a validated TXT upload into a single-page ``ExtractedDocument``."""
    text, encoding, had_replacements = decode_text(file.data)
    warnings: list[str] = []
    if had_replacements:
        warnings.append(
            f"Some bytes could not be decoded as {encoding} and were replaced with '�'."
        )
    logger.info("Read TXT %s (encoding=%s, %d chars)", file.filename, encoding, len(text))
    return ExtractedDocument.from_validated(
        file,
        pages=[PageText(page_number=1, text=text)],
        metadata={"encoding": encoding},
        warnings=warnings,
    )
