"""Domain-specific exceptions.

A single base class (``CyberSleuthError``) lets the UI catch every expected
failure in one place, while subclasses carry precise, user-presentable meaning.
"""

from __future__ import annotations


class CyberSleuthError(Exception):
    """Base class for all expected application errors."""


class IngestionError(CyberSleuthError):
    """Base class for document ingestion failures."""


class UnsupportedFileTypeError(IngestionError):
    """File extension or actual content is not an allowed document type."""


class FileTooLargeError(IngestionError):
    """File exceeds a configured size, page, or decompression limit."""


class CorruptedFileError(IngestionError):
    """File claims a supported format but cannot be parsed."""


class EncryptedDocumentError(IngestionError):
    """Document is password-protected and cannot be read."""


class EmptyDocumentError(IngestionError):
    """Document parsed successfully but contains no extractable text."""


class NLPError(CyberSleuthError):
    """Base class for NLP component failures."""


class ModelNotAvailableError(NLPError):
    """A required NLP model is not installed."""


class KnowledgeBaseError(NLPError):
    """A bundled knowledge-base file is missing or malformed."""
