"""Data contracts shared by every ingestion component.

Every reader (PDF, DOCX, TXT) returns an ``ExtractedDocument`` so that all
downstream stages (IOC extraction, NER, classification) are format-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class FileType(StrEnum):
    """Document formats CyberSleuth accepts."""

    PDF = "pdf"
    DOCX = "docx"
    TXT = "txt"


# Extension → expected content type. Used to detect extension/content mismatch.
EXTENSION_TO_TYPE: dict[str, FileType] = {
    ".pdf": FileType.PDF,
    ".docx": FileType.DOCX,
    ".txt": FileType.TXT,
}


_MAX_METADATA_VALUE_LENGTH = 500


def clean_metadata(raw: dict[str, object]) -> dict[str, str]:
    """Keep non-empty metadata values as bounded strings.

    Document metadata is attacker-controlled, so values are length-limited and
    always stored as plain strings.
    """
    cleaned: dict[str, str] = {}
    for key, value in raw.items():
        if value is None:
            continue
        text = str(value).strip()
        if text:
            cleaned[str(key)] = text[:_MAX_METADATA_VALUE_LENGTH]
    return cleaned


@dataclass(frozen=True)
class ValidatedFile:
    """An upload that has passed every validation check and may be parsed."""

    filename: str
    file_type: FileType
    data: bytes = field(repr=False)
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class PageText:
    """Text of one logical page.

    PDFs have real pages. DOCX and TXT have no fixed pagination, so they are
    represented as a single page (``page_number=1``).
    """

    page_number: int  # 1-based, matches what a human sees in a PDF viewer
    text: str


@dataclass(frozen=True)
class Sentence:
    """A sentence with an exact pointer back into its source page.

    ``char_start``/``char_end`` index into ``PageText.text`` of the same page, so
    ``page.text[char_start:char_end] == sentence.text`` always holds. This is
    the evidence trail later phases use to justify every extracted indicator.
    """

    text: str
    page_number: int
    char_start: int
    char_end: int


@dataclass
class ExtractedDocument:
    """Normalised result of ingesting one document."""

    filename: str
    file_type: FileType
    sha256: str
    size_bytes: int
    pages: list[PageText]
    metadata: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    needs_ocr: bool = False
    sentences: list[Sentence] = field(default_factory=list)

    @classmethod
    def from_validated(
        cls, file: ValidatedFile, pages: list[PageText], **kwargs
    ) -> ExtractedDocument:
        """Create a document carrying the identity fields of a validated upload."""
        return cls(
            filename=file.filename,
            file_type=file.file_type,
            sha256=file.sha256,
            size_bytes=file.size_bytes,
            pages=pages,
            **kwargs,
        )

    @property
    def page_count(self) -> int:
        return len(self.pages)

    @property
    def full_text(self) -> str:
        """All page text joined with blank lines (for whole-document analysis)."""
        return "\n\n".join(p.text for p in self.pages if p.text)

    @property
    def char_count(self) -> int:
        return sum(len(p.text) for p in self.pages)
