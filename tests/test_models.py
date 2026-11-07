"""Tests for ingestion data contracts (src/ingestion/models.py)."""

from src.ingestion.models import EXTENSION_TO_TYPE, ExtractedDocument, FileType, PageText


def _doc(pages: list[str]) -> ExtractedDocument:
    return ExtractedDocument(
        filename="x.pdf",
        file_type=FileType.PDF,
        sha256="0" * 64,
        size_bytes=10,
        pages=[PageText(i + 1, t) for i, t in enumerate(pages)],
    )


def test_derived_properties():
    doc = _doc(["first page", "", "third"])
    assert doc.page_count == 3
    assert doc.char_count == len("first page") + len("third")
    assert doc.full_text == "first page\n\nthird"  # blank pages skipped


def test_defaults_are_independent():
    a, b = _doc(["a"]), _doc(["b"])
    a.warnings.append("w")
    assert b.warnings == []


def test_extension_map_covers_every_type():
    assert set(EXTENSION_TO_TYPE.values()) == set(FileType)
    assert FileType.PDF == "pdf"
