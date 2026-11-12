"""Application-wide logging setup.

Modules obtain loggers with ``logging.getLogger(__name__)``; this function is
called once at the entry point (``python -m src.web`` or tests) to configure handlers.
"""

from __future__ import annotations

import logging

from config.settings import settings

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_configured = False


def configure_logging(level: str | None = None) -> None:
    """Configure the root logger exactly once (safe to call repeatedly)."""
    global _configured
    if _configured:
        return
    logging.basicConfig(level=(level or settings.log_level), format=_LOG_FORMAT)
    # Third-party libraries can be noisy at INFO.
    for noisy in ("fitz", "PIL", "urllib3", "watchdog"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True
