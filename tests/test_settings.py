"""Tests for configuration and the exception hierarchy."""

import pytest

from config.settings import IngestionSettings, _env_int, settings
from src.utils.exceptions import (
    CorruptedFileError,
    CyberSleuthError,
    EmptyDocumentError,
    EncryptedDocumentError,
    FileTooLargeError,
    IngestionError,
    UnsupportedFileTypeError,
)


def test_default_limits_are_sane():
    ing = settings.ingestion
    assert ing.max_file_size_bytes == 20 * 1024 * 1024
    assert ing.allowed_extensions == {".pdf", ".txt", ".docx"}
    assert ing.max_pdf_pages > 0


def test_settings_are_immutable():
    with pytest.raises(AttributeError):
        settings.ingestion.max_pdf_pages = 1  # type: ignore[misc]


def test_env_override(monkeypatch):
    monkeypatch.setenv("CYBERSLEUTH_TEST_VALUE", "7")
    assert _env_int("TEST_VALUE", 3) == 7


@pytest.mark.parametrize("bad", ["abc", "0", "-5"])
def test_env_override_rejects_invalid(monkeypatch, bad):
    monkeypatch.setenv("CYBERSLEUTH_TEST_VALUE", bad)
    with pytest.raises(ValueError):
        _env_int("TEST_VALUE", 3)


@pytest.mark.parametrize(
    "exc",
    [
        UnsupportedFileTypeError,
        FileTooLargeError,
        CorruptedFileError,
        EncryptedDocumentError,
        EmptyDocumentError,
    ],
)
def test_ingestion_errors_share_base(exc):
    assert issubclass(exc, IngestionError)
    assert issubclass(exc, CyberSleuthError)


def test_ingestion_settings_constructible():
    assert isinstance(IngestionSettings(), IngestionSettings)
