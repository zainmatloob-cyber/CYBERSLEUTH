"""Shared UI helpers: escaping, cached resources, running an analysis with progress.

Security: document content is untrusted. It is rendered only through plain-text widgets
(text, text_area, dataframe), never st.markdown or unsafe HTML. Strings that must pass
through markdown-rendering widgets go through ``md_escape``. The only clickable links are
built from validated ATT&CK / CVE identifiers; extracted URLs are never made clickable.
"""

from __future__ import annotations

import logging
import re

import streamlit as st

from src.database.db_manager import AnalysisRepository
from src.intelligence.analyzer import AnalysisResult, AnalysisStage, Analyzer
from src.utils.exceptions import CyberSleuthError

logger = logging.getLogger("cybersleuth.ui")

BAND_ICON = {"Low": "🟢", "Moderate": "🟡", "High": "🟠", "Critical": "🔴"}
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|~$:])")


def md_escape(text: str) -> str:
    """Escape user-controlled text before it reaches a markdown-rendering widget."""
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)


@st.cache_resource(show_spinner="Loading NLP models…")
def get_analyzer() -> Analyzer:
    """Load the spaCy model, knowledge bases and trained models once per server process."""
    return Analyzer()


@st.cache_resource(show_spinner=False)
def get_repository() -> AnalysisRepository | None:
    """The configured database, or ``None`` if it cannot be opened (analysis still works)."""
    try:
        return AnalysisRepository()
    except Exception:  # noqa: BLE001 — persistence is optional; the reason is logged
        logger.exception("Database unavailable; analyses will not be saved.")
        return None


def run_analysis(analyzer: Analyzer, data: bytes,
                 filename: str) -> tuple[AnalysisResult | None, str | None]:
    """Return ``(result, error_message)``; exactly one of them is ``None``."""
    stages = list(AnalysisStage)
    progress = st.progress(0, text="Starting…")

    def on_progress(stage: AnalysisStage) -> None:
        progress.progress((stages.index(stage) + 1) / len(stages), text=stage.value)

    try:
        return analyzer.analyze(data, filename, on_progress=on_progress), None
    except CyberSleuthError as exc:
        return None, str(exc)
    except Exception:  # unexpected bug: log full details, show a generic message
        logger.exception("Unexpected failure analysing %s", filename)
        return None, "An unexpected error occurred while processing this file. See the logs."
    finally:
        progress.empty()
