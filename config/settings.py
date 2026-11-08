"""Central configuration for CyberSleuth.

All tunable limits live here so implementation modules never hard-code them.
Values can be overridden with environment variables prefixed ``CYBERSLEUTH_``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int) -> int:
    """Read a positive integer from the environment, falling back to ``default``."""
    raw = os.getenv(f"CYBERSLEUTH_{name}")
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"CYBERSLEUTH_{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"CYBERSLEUTH_{name} must be positive, got {value}")
    return value


@dataclass(frozen=True)
class IngestionSettings:
    """Limits applied to every uploaded (untrusted) document."""

    max_file_size_bytes: int = _env_int("MAX_FILE_SIZE_MB", 20) * 1024 * 1024
    max_pdf_pages: int = _env_int("MAX_PDF_PAGES", 500)
    # DOCX files are ZIP archives: guard against decompression bombs.
    max_docx_uncompressed_bytes: int = _env_int("MAX_DOCX_UNCOMPRESSED_MB", 100) * 1024 * 1024
    max_docx_zip_entries: int = _env_int("MAX_DOCX_ZIP_ENTRIES", 2000)
    # Extracted text can be far larger than the file (compressed PDF streams, DOCX XML):
    # cap it so a small upload can't keep the NLP stages busy indefinitely.
    max_text_chars: int = _env_int("MAX_TEXT_CHARS", 1_000_000)
    # A PDF page with fewer extractable characters than this is treated as image-only.
    min_chars_per_text_page: int = _env_int("MIN_CHARS_PER_TEXT_PAGE", 20)
    allowed_extensions: frozenset[str] = field(
        default_factory=lambda: frozenset({".pdf", ".txt", ".docx"})
    )


@dataclass(frozen=True)
class NlpSettings:
    """NLP model configuration."""

    spacy_model: str = os.getenv("CYBERSLEUTH_SPACY_MODEL", "en_core_web_sm")
    spacy_batch_size: int = _env_int("SPACY_BATCH_SIZE", 64)


@dataclass(frozen=True)
class DatabaseSettings:
    """Persistence configuration."""

    url: str = os.getenv("CYBERSLEUTH_DB_URL",
                         f"sqlite:///{(PROJECT_ROOT / 'data' / 'cybersleuth.db').as_posix()}")
    # Privacy default: keep only evidence sentences that support findings, not the full text.
    store_full_text: bool = os.getenv("CYBERSLEUTH_STORE_FULL_TEXT", "0") == "1"
    analyst_name: str = os.getenv("CYBERSLEUTH_ANALYST", "analyst")


@dataclass(frozen=True)
class Settings:
    """Top-level application settings."""

    app_name: str = "CyberSleuth"
    log_level: str = os.getenv("CYBERSLEUTH_LOG_LEVEL", "INFO").upper()
    data_dir: Path = PROJECT_ROOT / "data"
    samples_dir: Path = PROJECT_ROOT / "data" / "samples"
    processed_dir: Path = PROJECT_ROOT / "data" / "processed"
    knowledge_base_dir: Path = PROJECT_ROOT / "data" / "knowledge_base"
    ingestion: IngestionSettings = field(default_factory=IngestionSettings)
    nlp: NlpSettings = field(default_factory=NlpSettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)


settings = Settings()
