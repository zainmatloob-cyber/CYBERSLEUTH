"""Server-side state: the lazily loaded analyzer and a small cache of recent results.

The full document text is not saved to the database by default (privacy), but the
Evidence, Text and Sentences tabs need it. Recent ``AnalysisResult`` objects are kept in
memory, bounded in count, and are lost on restart; those tabs simply disappear then.
"""

from __future__ import annotations

import logging
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable

from src.database.db_manager import AnalysisRepository
from src.intelligence.analyzer import AnalysisResult, Analyzer

logger = logging.getLogger("cybersleuth.web")

UNSAVED_PREFIX = "u-"


class ResultCache:
    """Thread-safe LRU of recent analysis results, keyed by an analysis reference.

    A reference is the database id as text for saved analyses, or ``u-<random token>``
    for analyses that could not be saved.
    """

    def __init__(self, max_items: int = 8) -> None:
        self._items: OrderedDict[str, AnalysisResult] = OrderedDict()
        self._max = max_items
        self._lock = threading.Lock()

    def put(self, ref: str, result: AnalysisResult) -> None:
        with self._lock:
            self._items[ref] = result
            self._items.move_to_end(ref)
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    def get(self, ref: str) -> AnalysisResult | None:
        with self._lock:
            result = self._items.get(ref)
            if result is not None:
                self._items.move_to_end(ref)
            return result

    def discard(self, ref: str) -> None:
        with self._lock:
            self._items.pop(ref, None)

    def __len__(self) -> int:
        return len(self._items)


def new_unsaved_ref() -> str:
    return UNSAVED_PREFIX + secrets.token_urlsafe(12)


class AppState:
    """Dependencies shared by every request. Tests pass their own factories."""

    def __init__(self, analyzer_factory: Callable[[], Analyzer],
                 repository_factory: Callable[[], AnalysisRepository | None],
                 cache_size: int = 8) -> None:
        self._analyzer_factory = analyzer_factory
        self._analyzer: Analyzer | None = None
        self._analyzer_lock = threading.Lock()
        self.repo = repository_factory()
        self.cache = ResultCache(cache_size)

    @property
    def analyzer(self) -> Analyzer:
        """Loaded on first use: spaCy and the trained models take seconds to load."""
        if self._analyzer is None:
            with self._analyzer_lock:
                if self._analyzer is None:
                    self._analyzer = self._analyzer_factory()
        return self._analyzer


def default_repository() -> AnalysisRepository | None:
    """The configured database, or ``None`` if it cannot be opened (analysis still works)."""
    try:
        return AnalysisRepository()
    except Exception:  # noqa: BLE001 — persistence is optional; the reason is logged
        logger.exception("Database unavailable; analyses will not be saved.")
        return None
