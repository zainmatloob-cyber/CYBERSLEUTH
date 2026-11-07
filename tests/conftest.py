"""Shared fixtures. Documents are generated in memory (synthetic test data)."""

from __future__ import annotations

import io
import zipfile

import docx
import fitz  # PyMuPDF
import pytest

SAMPLE_TEXT = (
    "SYNTHETIC TEST DOCUMENT. The actor delivered a phishing email "
    "containing a link to hxxp://malicious-example[.]com/payload."
)


def make_pdf(pages: list[str]) -> bytes:
    """Build a PDF with one text page per string (empty string → blank page)."""
    doc = fitz.open()
    for text in pages:
        page = doc.new_page()
        if text:
            page.insert_text((72, 72), text, fontsize=11)
    data = doc.tobytes()
    doc.close()
    return data


def make_docx(paragraphs: list[str]) -> bytes:
    document = docx.Document()
    for text in paragraphs:
        document.add_paragraph(text)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def make_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


@pytest.fixture
def pdf_bytes() -> bytes:
    return make_pdf([SAMPLE_TEXT])


@pytest.fixture
def docx_bytes() -> bytes:
    return make_docx([SAMPLE_TEXT])


@pytest.fixture
def txt_bytes() -> bytes:
    return SAMPLE_TEXT.encode("utf-8")
