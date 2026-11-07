"""Tests for the TXT, PDF and DOCX readers."""

from __future__ import annotations

import io

import docx
import pymupdf
import pytest

from config.settings import IngestionSettings
from src.ingestion.docx_reader import read_docx
from src.ingestion.models import FileType, ValidatedFile, clean_metadata
from src.ingestion.pdf_reader import read_pdf
from src.ingestion.txt_reader import decode_text, read_txt
from src.ingestion.validator import validate_upload
from src.utils.exceptions import CorruptedFileError, EncryptedDocumentError, FileTooLargeError
from tests.conftest import SAMPLE_TEXT, make_pdf


def _raw(data: bytes, file_type: FileType) -> ValidatedFile:
    """Bypass validation to feed readers inputs the validator would normally stop."""
    return ValidatedFile(f"x.{file_type.value}", file_type, data, len(data), "0" * 64)


def _png() -> bytes:
    pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 20, 20), False)
    pix.clear_with(200)
    return pix.tobytes("png")


# --- TXT ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "encoding", "expected"),
    [
        ("Café report".encode(), "utf-8", "Café report"),
        ("﻿Café".encode(), "utf-8-sig", "Café"),  # BOM stripped
        ("Café".encode("utf-16"), "utf-16", "Café"),
        ("Café".encode("cp1252"), "cp1252", "Café"),  # invalid UTF-8 → fallback
    ],
)
def test_decode_text_encodings(data, encoding, expected):
    text, used, replaced = decode_text(data)
    assert (text, used, replaced) == (expected, encoding, False)


def test_undecodable_bytes_are_replaced_and_flagged():
    text, used, replaced = decode_text(b"abc \x81 def")  # 0x81 is undefined in cp1252
    assert used == "cp1252" and replaced and "�" in text


def test_read_txt(txt_bytes):
    doc = read_txt(validate_upload(txt_bytes, "r.txt"))
    assert doc.page_count == 1
    assert doc.pages[0].text == SAMPLE_TEXT
    assert doc.metadata == {"encoding": "utf-8"}
    assert doc.warnings == []


def test_read_txt_warns_on_replacement():
    doc = read_txt(validate_upload(b"abc \x81 def", "r.txt"))
    assert any("could not be decoded" in w for w in doc.warnings)


# --- PDF ----------------------------------------------------------------------


def test_read_pdf_pages_and_identity(pdf_bytes):
    file = validate_upload(pdf_bytes, "r.pdf")
    doc = read_pdf(file)
    assert doc.page_count == 1
    assert doc.pages[0].page_number == 1
    assert "phishing email" in doc.pages[0].text
    assert doc.sha256 == file.sha256 and doc.file_type is FileType.PDF
    assert not doc.needs_ocr and doc.warnings == []


def test_read_pdf_preserves_page_numbers():
    doc = read_pdf(validate_upload(make_pdf(["alpha page", "beta page", "gamma page"]), "r.pdf"))
    assert [p.page_number for p in doc.pages] == [1, 2, 3]
    assert "beta" in doc.pages[1].text


def test_read_pdf_metadata():
    pdf = pymupdf.open()
    pdf.new_page().insert_text((72, 72), "body")
    pdf.set_metadata({"title": "APT Report", "author": "Analyst"})
    doc = read_pdf(validate_upload(pdf.tobytes(), "r.pdf"))
    assert doc.metadata["title"] == "APT Report"
    assert doc.metadata["author"] == "Analyst"


def test_scanned_page_flagged_for_ocr():
    pdf = pymupdf.open()
    pdf.new_page().insert_text((72, 72), "Real text page with enough characters.")
    pdf.new_page().insert_image(pymupdf.Rect(0, 0, 200, 200), stream=_png())
    doc = read_pdf(validate_upload(pdf.tobytes(), "r.pdf"))
    assert doc.needs_ocr
    assert any("Page(s) 2" in w for w in doc.warnings)


def test_blank_page_without_images_is_not_ocr():
    doc = read_pdf(validate_upload(make_pdf(["text page content here", ""]), "r.pdf"))
    assert not doc.needs_ocr
    assert doc.pages[1].text.strip() == ""


def test_encrypted_pdf_rejected():
    pdf = pymupdf.open()
    pdf.new_page().insert_text((72, 72), "secret")
    data = pdf.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, user_pw="u", owner_pw="o")
    with pytest.raises(EncryptedDocumentError):
        read_pdf(validate_upload(data, "r.pdf"))


def test_permission_restricted_pdf_is_readable():
    """Owner password only (no open password) → content must still be extracted."""
    pdf = pymupdf.open()
    pdf.new_page().insert_text((72, 72), "restricted but readable")
    data = pdf.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, user_pw="", owner_pw="o")
    assert "readable" in read_pdf(validate_upload(data, "r.pdf")).pages[0].text


def test_badly_truncated_pdf_rejected(pdf_bytes):
    with pytest.raises(CorruptedFileError):
        read_pdf(validate_upload(pdf_bytes[: int(len(pdf_bytes) * 0.2)], "r.pdf"))


def test_repairable_pdf_accepted_with_warning(pdf_bytes):
    doc = read_pdf(validate_upload(pdf_bytes[: int(len(pdf_bytes) * 0.9)], "r.pdf"))
    assert "phishing email" in doc.pages[0].text
    assert any("repaired" in w for w in doc.warnings)


def test_intact_pdf_has_no_repair_warning(pdf_bytes):
    assert not any("repaired" in w for w in read_pdf(validate_upload(pdf_bytes, "r.pdf")).warnings)


def test_single_page_failure_does_not_abort_document(monkeypatch):
    original = pymupdf.Page.get_text

    def flaky(self, *args, **kwargs):
        if self.number == 1:  # 0-based → second page
            raise RuntimeError("simulated extraction failure")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(pymupdf.Page, "get_text", flaky)
    doc = read_pdf(validate_upload(make_pdf(["first page", "second", "third page"]), "r.pdf"))
    assert doc.page_count == 3
    assert doc.pages[1].text == ""
    assert "third" in doc.pages[2].text
    assert any("failed on page(s) 2" in w for w in doc.warnings)


def test_garbage_pdf_rejected():
    with pytest.raises(CorruptedFileError):
        read_pdf(_raw(b"%PDF-1.7\nnot really a pdf", FileType.PDF))


def test_page_limit_enforced():
    data = make_pdf(["a", "b", "c"])
    with pytest.raises(FileTooLargeError, match="3 pages"):
        read_pdf(validate_upload(data, "r.pdf"), limits=IngestionSettings(max_pdf_pages=2))


# --- DOCX ---------------------------------------------------------------------


def _docx_with_table() -> bytes:
    document = docx.Document()
    document.core_properties.title = "Incident Summary"
    document.core_properties.author = "SOC Team"
    document.add_paragraph("Intro paragraph.")
    table = document.add_table(rows=3, cols=2)
    table.cell(0, 0).text, table.cell(0, 1).text = "Indicator", "Type"
    table.cell(1, 0).text, table.cell(1, 1).text = "198.51.100.7", "IPv4"
    table.cell(2, 0).merge(table.cell(2, 1)).text = "Merged note"
    document.add_paragraph("Closing paragraph.")
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def test_read_docx_paragraphs(docx_bytes):
    doc = read_docx(validate_upload(docx_bytes, "r.docx"))
    assert doc.page_count == 1
    assert SAMPLE_TEXT in doc.pages[0].text


def test_read_docx_tables_in_document_order():
    blocks = read_docx(validate_upload(_docx_with_table(), "r.docx")).pages[0].text.split("\n\n")
    assert blocks == [
        "Intro paragraph.",
        "Indicator | Type",
        "198.51.100.7 | IPv4",
        "Merged note",  # merged cell not duplicated
        "Closing paragraph.",
    ]


def test_read_docx_metadata():
    doc = read_docx(validate_upload(_docx_with_table(), "r.docx"))
    assert doc.metadata["title"] == "Incident Summary"
    assert doc.metadata["author"] == "SOC Team"
    assert "created" in doc.metadata


def test_docx_with_broken_xml_rejected(docx_bytes):
    import zipfile

    source = zipfile.ZipFile(io.BytesIO(docx_bytes))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as target:
        for item in source.infolist():
            content = source.read(item.filename)
            if item.filename == "word/document.xml":
                content = b"<w:document><unclosed>"
            target.writestr(item, content)
    with pytest.raises(CorruptedFileError):
        read_docx(validate_upload(out.getvalue(), "r.docx"))


# --- shared helpers -----------------------------------------------------------


def test_clean_metadata_drops_empty_and_truncates():
    cleaned = clean_metadata({"title": "  T  ", "author": "", "x": None, "long": "a" * 900})
    assert cleaned == {"title": "T", "long": "a" * 500}
