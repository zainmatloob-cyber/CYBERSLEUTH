"""Smoke tests for the Streamlit UI (app.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from app import md_escape

APP_PATH = Path(__file__).resolve().parent.parent / "app.py"


def test_app_renders_without_errors():
    at = AppTest.from_file(str(APP_PATH), default_timeout=30).run()
    assert not at.exception
    assert at.header[0].value == "Document Analysis"
    assert any("Upload a PDF" in info.value for info in at.info)


def _render_results_script() -> None:
    """Runs inside AppTest: ingest a real multi-page PDF and render every results view."""
    import pymupdf

    import app
    from src.ingestion.pipeline import ingest

    pdf = pymupdf.open()
    pdf.new_page().insert_text((72, 72), "The actor used phishing. Then 198.51.100.7 was seen.")
    pdf.new_page().insert_text((72, 72), "Second page sentence.")
    doc = ingest(pdf.tobytes(), "[x](http://evil).pdf")
    app._render_summary(doc)
    app._render_text_tab(doc)
    app._render_sentences_tab(doc)
    app._render_metadata_tab(doc)


def test_result_views_render_real_document():
    at = AppTest.from_function(_render_results_script, default_timeout=30).run()
    assert not at.exception
    assert [m.value for m in at.metric][:2] == ["PDF", "2"]
    assert at.success  # no warnings → success banner
    assert at.selectbox[0].options == ["1", "2"]
    assert "198.51.100.7" in at.text_area[0].value

    at.text_input[0].set_value("198.51.100").run()  # sentence filter
    assert not at.exception
    assert any("1 of 3 sentences" in c.value for c in at.caption)


def _run_ingestion_script() -> None:
    import app

    document, error = app._run_ingestion(b"MZ\x90\x00" * 64, "evil.pdf")
    import streamlit as st

    st.write(f"doc={document is None} error={error}")


def test_run_ingestion_returns_error_message_for_bad_file():
    at = AppTest.from_function(_run_ingestion_script, default_timeout=30).run()
    assert not at.exception
    assert "doc=True" in at.markdown[0].value
    assert "not a recognised" in at.markdown[0].value


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [
        ("[a](http://x)", r"\[a\]\(http\://x\)"),
        ("**bold**", r"\*\*bold\*\*"),
        ("<img src=x>", r"\<img src=x\>"),
    ],
)
def test_md_escape_neutralises_markup(raw, escaped):
    assert md_escape(raw) == escaped


def test_md_escape_keeps_plain_text_readable():
    assert md_escape("report 2026") == "report 2026"
