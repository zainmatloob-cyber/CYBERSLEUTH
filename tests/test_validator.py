"""Tests for upload validation (src/ingestion/validator.py)."""

from __future__ import annotations

import hashlib

import pytest

from config.settings import IngestionSettings
from src.ingestion.models import FileType
from src.ingestion.validator import sanitize_filename, sniff_file_type, validate_upload
from src.utils.exceptions import (
    CorruptedFileError,
    EmptyDocumentError,
    FileTooLargeError,
    UnsupportedFileTypeError,
)
from tests.conftest import make_zip

FAKE_EXE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" * 64


# --- happy paths --------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "name", "expected"),
    [
        ("pdf_bytes", "report.pdf", FileType.PDF),
        ("docx_bytes", "report.docx", FileType.DOCX),
        ("txt_bytes", "report.txt", FileType.TXT),
    ],
)
def test_valid_files_accepted(request, fixture, name, expected):
    data = request.getfixturevalue(fixture)
    result = validate_upload(data, name)
    assert result.file_type is expected
    assert result.size_bytes == len(data)
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert result.filename == name


def test_extension_is_case_insensitive(pdf_bytes):
    assert validate_upload(pdf_bytes, "REPORT.PDF").file_type is FileType.PDF


def test_utf16_text_accepted():
    data = "UTF-16 advisory text".encode("utf-16")  # includes BOM and NUL bytes
    assert validate_upload(data, "a.txt").file_type is FileType.TXT


def test_pdf_header_after_leading_junk_accepted(pdf_bytes):
    assert sniff_file_type(b"\n\r junk " + pdf_bytes) is FileType.PDF


# --- extension and content checks ---------------------------------------------


@pytest.mark.parametrize("name", ["malware.exe", "script.js", "noextension", ".pdf", ""])
def test_disallowed_extension_rejected(txt_bytes, name):
    with pytest.raises(UnsupportedFileTypeError):
        validate_upload(txt_bytes, name)


def test_executable_renamed_to_pdf_rejected():
    with pytest.raises(UnsupportedFileTypeError, match="not a recognised"):
        validate_upload(FAKE_EXE, "invoice.pdf")


def test_executable_renamed_to_txt_rejected():
    with pytest.raises(UnsupportedFileTypeError):
        validate_upload(FAKE_EXE, "notes.txt")


def test_docx_renamed_to_pdf_rejected(docx_bytes):
    with pytest.raises(UnsupportedFileTypeError, match="content is DOCX"):
        validate_upload(docx_bytes, "report.pdf")


def test_pdf_renamed_to_txt_rejected(pdf_bytes):
    with pytest.raises(UnsupportedFileTypeError, match="content is PDF"):
        validate_upload(pdf_bytes, "report.txt")


def test_plain_zip_named_docx_rejected():
    data = make_zip({"readme.txt": b"hello"})
    with pytest.raises(UnsupportedFileTypeError):
        validate_upload(data, "report.docx")


def test_corrupted_zip_rejected():
    data = b"PK\x03\x04" + b"\x00garbage" * 50
    with pytest.raises(CorruptedFileError):
        validate_upload(data, "report.docx")


def test_legacy_doc_rejected_with_helpful_message():
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512
    with pytest.raises(UnsupportedFileTypeError, match="Save it as .docx"):
        validate_upload(data, "report.docx")


# --- size limits --------------------------------------------------------------


def test_empty_file_rejected():
    with pytest.raises(EmptyDocumentError):
        validate_upload(b"", "empty.txt")


def test_oversized_file_rejected():
    limits = IngestionSettings(max_file_size_bytes=100)
    with pytest.raises(FileTooLargeError):
        validate_upload(b"a" * 101, "big.txt", limits=limits)


def test_file_at_exact_limit_accepted():
    limits = IngestionSettings(max_file_size_bytes=100)
    assert validate_upload(b"a" * 100, "edge.txt", limits=limits).size_bytes == 100


def test_docx_decompression_bomb_rejected(docx_bytes):
    limits = IngestionSettings(max_docx_uncompressed_bytes=1024)
    with pytest.raises(FileTooLargeError, match="expands to"):
        validate_upload(docx_bytes, "bomb.docx", limits=limits)


def test_docx_too_many_entries_rejected(docx_bytes):
    limits = IngestionSettings(max_docx_zip_entries=2)
    with pytest.raises(FileTooLargeError, match="archive entries"):
        validate_upload(docx_bytes, "many.docx", limits=limits)


# --- filename sanitisation ----------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("../../etc/passwd.txt", "passwd.txt"),
        ("C:\\Users\\x\\report.pdf", "report.pdf"),
        ("bad\x00name\x1f.txt", "badname.txt"),
        ("  spaced.txt  ", "spaced.txt"),
    ],
)
def test_sanitize_filename(raw, clean):
    assert sanitize_filename(raw) == clean


def test_sanitize_filename_truncates():
    clean = sanitize_filename("a" * 1000 + ".txt")
    assert len(clean) == 255
    assert clean.endswith(".txt")


def test_path_traversal_name_is_stripped(txt_bytes):
    assert validate_upload(txt_bytes, "../../secret.txt").filename == "secret.txt"
