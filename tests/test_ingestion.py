"""End-to-end tests for the ingestion pipeline (src/ingestion/pipeline.py)."""

from __future__ import annotations

import io

import docx
import pymupdf
import pytest

from src.ingestion.models import FileType
from src.ingestion.pipeline import Stage, ingest
from src.utils.exceptions import EmptyDocumentError, UnsupportedFileTypeError
from tests.conftest import make_docx, make_pdf

REPORT = (
    "The ﬁrst stage used spear-phishing. Payloads were hosted at "
    "hxxp://evil[.]example[.]com/a.php and 198.51.100.7.\n\nA second wave began in Jan. 2026."
)
EXPECTED_SENTENCES = [
    "The first stage used spear-phishing.",
    "Payloads were hosted at hxxp://evil[.]example[.]com/a.php and 198.51.100.7.",
    "A second wave began in Jan. 2026.",
]


def _assert_consistent(doc) -> None:
    pages = {p.page_number: p for p in doc.pages}
    for s in doc.sentences:
        assert pages[s.page_number].text[s.char_start : s.char_end] == s.text


@pytest.mark.parametrize(
    ("data", "name", "file_type"),
    [
        (REPORT.encode("utf-8"), "r.txt", FileType.TXT),
        (make_docx(REPORT.split("\n\n")), "r.docx", FileType.DOCX),
    ],
    ids=["txt", "docx"],  # bytes-derived IDs overflow Windows' env-var limit
)
def test_end_to_end_txt_and_docx(data, name, file_type):
    doc = ingest(data, name)
    assert doc.file_type is file_type
    assert [s.text for s in doc.sentences] == EXPECTED_SENTENCES
    _assert_consistent(doc)


def test_end_to_end_pdf_multi_page():
    doc = ingest(make_pdf(["Page one text. More here.", "", "Page three text."]), "r.pdf")
    assert doc.page_count == 3
    assert [(s.page_number, s.text) for s in doc.sentences] == [
        (1, "Page one text."), (1, "More here."), (3, "Page three text."),
    ]
    _assert_consistent(doc)


def test_text_is_cleaned_before_segmentation():
    doc = ingest("Zero​width and ﬁ ligature.   Done.".encode(), "r.txt")
    assert doc.pages[0].text == "Zerowidth and fi ligature. Done."


def test_progress_stages_reported_in_order(txt_bytes):
    seen: list[Stage] = []
    ingest(txt_bytes, "r.txt", on_progress=seen.append)
    assert seen == list(Stage)


def test_validation_failure_propagates():
    with pytest.raises(UnsupportedFileTypeError):
        ingest(b"MZ\x90\x00" * 100, "r.pdf")


@pytest.mark.parametrize("data", [b"   \n\n\t  ", "​​".encode()])
def test_whitespace_only_document_rejected(data):
    with pytest.raises(EmptyDocumentError, match="no extractable text"):
        ingest(data, "r.txt")


def test_empty_docx_rejected():
    buffer = io.BytesIO()
    docx.Document().save(buffer)
    with pytest.raises(EmptyDocumentError):
        ingest(buffer.getvalue(), "r.docx")


def test_scanned_only_pdf_reports_ocr():
    pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 20, 20), False)
    pdf = pymupdf.open()
    pdf.new_page().insert_image(pymupdf.Rect(0, 0, 100, 100), stream=pix.tobytes("png"))
    with pytest.raises(EmptyDocumentError, match="OCR"):
        ingest(pdf.tobytes(), "scan.pdf")


def test_partially_scanned_pdf_succeeds_with_warning():
    pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 20, 20), False)
    pdf = pymupdf.open()
    pdf.new_page().insert_text((72, 72), "Readable first page with real text.")
    pdf.new_page().insert_image(pymupdf.Rect(0, 0, 100, 100), stream=pix.tobytes("png"))
    doc = ingest(pdf.tobytes(), "mixed.pdf")
    assert doc.needs_ocr and doc.sentences
    assert any("OCR" in w for w in doc.warnings)


def test_sample_documents_ingest(tmp_path):
    """The committed demo samples must always ingest cleanly."""
    from scripts import make_samples

    make_samples.write_txt(tmp_path / "s.txt")
    make_samples.write_docx(tmp_path / "s.docx")
    make_samples.write_pdf(tmp_path / "s.pdf")
    for name in ("s.txt", "s.docx", "s.pdf"):
        doc = ingest((tmp_path / name).read_bytes(), name)
        assert "GLASS PANTHER" in doc.full_text
        assert "hxxps://invoice-portal[.]example[.]com/download.php" in doc.full_text
        assert len(doc.sentences) >= 8
        _assert_consistent(doc)
