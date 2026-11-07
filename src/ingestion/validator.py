"""Validation of untrusted uploads before any parser touches them.

Checks, in order:
1. Filename sanitisation and extension allow-list.
2. Empty file and size limit.
3. Content sniffing by magic bytes (the extension is never trusted on its own).
4. Extension/content agreement.
5. Structural checks for DOCX (it is a ZIP archive → decompression-bomb guard).

Full parse validity (e.g. a truncated PDF) is detected later by the readers,
which raise ``CorruptedFileError``.
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
import zipfile

from config.settings import IngestionSettings, settings
from src.ingestion.models import EXTENSION_TO_TYPE, FileType, ValidatedFile
from src.utils.exceptions import (
    CorruptedFileError,
    EmptyDocumentError,
    FileTooLargeError,
    UnsupportedFileTypeError,
)

logger = logging.getLogger(__name__)

_PDF_MAGIC = b"%PDF-"
_ZIP_MAGIC = b"PK\x03\x04"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # legacy .doc/.xls/.msg
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")
_DOCX_REQUIRED_PARTS = ("[Content_Types].xml", "word/document.xml")

# PDF spec allows junk before the header; readers such as Acrobat scan the first 1 KiB.
_PDF_HEADER_WINDOW = 1024
_TEXT_SNIFF_BYTES = 8192
# Fraction of non-whitespace control bytes above which content is treated as binary.
_MAX_CONTROL_BYTE_RATIO = 0.05
_ALLOWED_CONTROL_BYTES = {0x09, 0x0A, 0x0C, 0x0D}  # tab, LF, form feed, CR
_MAX_FILENAME_LENGTH = 255


def sanitize_filename(filename: str) -> str:
    """Return a display-safe base name: no directories, no control characters."""
    base = re.split(r"[\\/]", filename or "")[-1]
    base = re.sub(r"[\x00-\x1f\x7f]", "", base).strip()
    if len(base) <= _MAX_FILENAME_LENGTH:
        return base
    ext = _extension(base)[:16]  # keep the extension so validation still works
    return base[: _MAX_FILENAME_LENGTH - len(ext)] + ext


def _extension(filename: str) -> str:
    dot = filename.rfind(".")
    return filename[dot:].lower() if dot > 0 else ""


def _looks_like_text(data: bytes) -> bool:
    if data.startswith(_UTF16_BOMS):
        return True
    sample = data[:_TEXT_SNIFF_BYTES]
    if b"\x00" in sample:
        return False
    control = sum(1 for b in sample if (b < 0x20 and b not in _ALLOWED_CONTROL_BYTES) or b == 0x7F)
    return control / len(sample) <= _MAX_CONTROL_BYTE_RATIO


def _open_zip(data: bytes) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise CorruptedFileError("File looks like a ZIP/DOCX archive but is corrupted.") from exc


def sniff_file_type(data: bytes) -> FileType | None:
    """Identify the real format from content. Returns ``None`` if unrecognised."""
    if _PDF_MAGIC in data[:_PDF_HEADER_WINDOW]:
        return FileType.PDF
    if data.startswith(_ZIP_MAGIC):
        with _open_zip(data) as archive:
            names = set(archive.namelist())
        return FileType.DOCX if all(p in names for p in _DOCX_REQUIRED_PARTS) else None
    if data.startswith(_OLE_MAGIC):
        raise UnsupportedFileTypeError(
            "Legacy Microsoft Office format (.doc) is not supported. Save it as .docx."
        )
    if _looks_like_text(data):
        return FileType.TXT
    return None


def _check_docx_archive(data: bytes, limits: IngestionSettings) -> None:
    """Reject archives whose declared contents would exhaust memory when parsed."""
    with _open_zip(data) as archive:
        entries = archive.infolist()
        if len(entries) > limits.max_docx_zip_entries:
            raise FileTooLargeError(
                f"DOCX contains {len(entries)} archive entries "
                f"(limit {limits.max_docx_zip_entries})."
            )
        total = sum(info.file_size for info in entries)
        if total > limits.max_docx_uncompressed_bytes:
            raise FileTooLargeError(
                f"DOCX expands to {total / 1_048_576:.1f} MB "
                f"(limit {limits.max_docx_uncompressed_bytes / 1_048_576:.0f} MB)."
            )


def validate_upload(
    data: bytes, filename: str, limits: IngestionSettings | None = None
) -> ValidatedFile:
    """Validate raw upload bytes and return a ``ValidatedFile``.

    Raises a subclass of ``IngestionError`` describing exactly why a file was rejected.
    """
    limits = limits or settings.ingestion
    safe_name = sanitize_filename(filename)
    ext = _extension(safe_name)

    if ext not in limits.allowed_extensions or ext not in EXTENSION_TO_TYPE:
        allowed = ", ".join(sorted(limits.allowed_extensions))
        raise UnsupportedFileTypeError(f"Extension {ext or '(none)'!r} is not allowed ({allowed}).")

    size = len(data)
    if size == 0:
        raise EmptyDocumentError("File is empty.")
    if size > limits.max_file_size_bytes:
        raise FileTooLargeError(
            f"File is {size / 1_048_576:.1f} MB "
            f"(limit {limits.max_file_size_bytes / 1_048_576:.0f} MB)."
        )

    detected = sniff_file_type(data)
    expected = EXTENSION_TO_TYPE[ext]
    if detected is None:
        raise UnsupportedFileTypeError("File content is not a recognised PDF, DOCX or text file.")
    if detected is not expected:
        raise UnsupportedFileTypeError(
            f"File extension is {ext!r} but its content is {detected.value.upper()}."
        )

    if detected is FileType.DOCX:
        _check_docx_archive(data, limits)

    digest = hashlib.sha256(data).hexdigest()
    logger.info(
        "Validated %s (%s, %d bytes, sha256=%s...)", safe_name, detected.value, size, digest[:12]
    )
    return ValidatedFile(
        filename=safe_name, file_type=detected, data=data, size_bytes=size, sha256=digest
    )
