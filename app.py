"""CyberSleuth Streamlit entry point (Phase 1: document ingestion).

Run with:  streamlit run app.py

Security note: document content is untrusted. It is only rendered through
components that display plain text (text_area, dataframe, code), never through
st.markdown / unsafe HTML, so a crafted report cannot inject links or markup.
"""

from __future__ import annotations

import logging
import re

import pandas as pd
import streamlit as st

from config.settings import settings
from src.ingestion.models import ExtractedDocument
from src.ingestion.pipeline import Stage, ingest
from src.utils.exceptions import IngestionError
from src.utils.logging_config import configure_logging

configure_logging()
logger = logging.getLogger("cybersleuth.app")

_UPCOMING_MODULES = [
    ("Document Analysis", "Available"),
    ("IOC Explorer", "Phase 2"),
    ("Entity Explorer", "Phase 2"),
    ("Threat Classification", "Phase 3"),
    ("MITRE ATT&CK Explorer", "Phase 3"),
    ("Risk Analysis", "Phase 3"),
    ("Dashboard & Reports", "Phase 4"),
]

_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|~$:])")


def md_escape(text: str) -> str:
    """Escape user-controlled text before it reaches a markdown-rendering widget."""
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)


def _render_sidebar() -> None:
    with st.sidebar:
        st.title(f"🛡️ {settings.app_name}")
        st.caption("Cyber Threat Intelligence Extraction & Analysis")
        st.divider()
        st.subheader("Modules")
        for name, status in _UPCOMING_MODULES:
            icon = "🟢" if status == "Available" else "⚪"
            st.write(f"{icon} {name} — *{status}*")
        st.divider()
        limits = settings.ingestion
        st.caption(
            f"Accepted: PDF, DOCX, TXT · max {limits.max_file_size_bytes // 1_048_576} MB · "
            f"max {limits.max_pdf_pages} PDF pages. Files are processed in memory and "
            "are not stored."
        )


def _run_ingestion(data: bytes, filename: str) -> tuple[ExtractedDocument | None, str | None]:
    """Return ``(document, error_message)``; exactly one of them is ``None``."""
    stages = list(Stage)
    progress = st.progress(0, text="Starting…")

    def on_progress(stage: Stage) -> None:
        progress.progress((stages.index(stage) + 1) / len(stages), text=stage.value)

    try:
        return ingest(data, filename, on_progress=on_progress), None
    except IngestionError as exc:
        return None, str(exc)
    except Exception:  # unexpected bug: log full details, show a generic message
        logger.exception("Unexpected failure ingesting %s", filename)
        return None, "An unexpected error occurred while processing this file. See the logs."
    finally:
        progress.empty()


def _render_summary(doc: ExtractedDocument) -> None:
    cols = st.columns(5)
    cols[0].metric("Format", doc.file_type.value.upper())
    cols[1].metric("Pages", doc.page_count)
    cols[2].metric("Characters", f"{doc.char_count:,}")
    cols[3].metric("Sentences", f"{len(doc.sentences):,}")
    cols[4].metric("Size", f"{doc.size_bytes / 1024:,.1f} KB")
    for warning in doc.warnings:
        st.warning(md_escape(warning))
    if not doc.warnings:
        st.success("Document ingested without warnings.")


def _render_text_tab(doc: ExtractedDocument) -> None:
    page_numbers = [p.page_number for p in doc.pages]
    selected = st.selectbox("Page", page_numbers) if len(page_numbers) > 1 else page_numbers[0]
    page = next(p for p in doc.pages if p.page_number == selected)
    st.text_area(
        f"Cleaned text — page {selected}",
        page.text or "(no extractable text on this page)",
        height=420,
        disabled=True,
    )


def _render_sentences_tab(doc: ExtractedDocument) -> None:
    query = st.text_input("Filter sentences", placeholder="e.g. phishing, 198.51.100, CVE-")
    frame = pd.DataFrame(
        {
            "Page": s.page_number,
            "Start": s.char_start,
            "End": s.char_end,
            "Sentence": " ".join(s.text.split()),
        }
        for s in doc.sentences
    )
    if query:
        frame = frame[frame["Sentence"].str.contains(query, case=False, regex=False)]
    st.caption(f"{len(frame):,} of {len(doc.sentences):,} sentences")
    st.dataframe(frame, width="stretch", hide_index=True, height=420)


def _render_metadata_tab(doc: ExtractedDocument) -> None:
    st.write("**File**")
    st.dataframe(
        pd.DataFrame(
            [
                ("Filename", doc.filename),
                ("SHA-256", doc.sha256),
                ("Size (bytes)", f"{doc.size_bytes:,}"),
                ("Needs OCR", "Yes" if doc.needs_ocr else "No"),
            ],
            columns=["Field", "Value"],
        ),
        hide_index=True,
        width="stretch",
    )
    st.write("**Embedded document metadata** (untrusted, author-supplied)")
    if doc.metadata:
        st.dataframe(
            pd.DataFrame(doc.metadata.items(), columns=["Field", "Value"]),
            hide_index=True,
            width="stretch",
        )
    else:
        st.caption("No embedded metadata.")


def main() -> None:
    st.set_page_config(page_title=settings.app_name, page_icon="🛡️", layout="wide")
    _render_sidebar()

    st.header("Document Analysis")
    st.caption(
        "Phase 1 — validated ingestion, text extraction, cleaning and sentence segmentation."
    )

    uploaded = st.file_uploader(
        "Upload a threat report", type=["pdf", "docx", "txt"], accept_multiple_files=False
    )
    if uploaded is None:
        st.info("Upload a PDF, DOCX or TXT threat report to begin. Sample files are in "
                "`data/samples/`.")
        return

    # Streamlit reruns the script on every interaction; only re-ingest on a new upload.
    if st.session_state.get("upload_id") != uploaded.file_id:
        st.session_state["upload_id"] = uploaded.file_id
        document, error = _run_ingestion(uploaded.getvalue(), uploaded.name)
        st.session_state["document"], st.session_state["error"] = document, error

    error: str | None = st.session_state.get("error")
    if error:
        st.error(f"Could not process {md_escape(uploaded.name)}: {md_escape(error)}")
        return
    document: ExtractedDocument | None = st.session_state.get("document")
    if document is None:
        return

    st.subheader(md_escape(document.filename))
    _render_summary(document)
    text_tab, sentences_tab, metadata_tab = st.tabs(["📄 Text", "🔤 Sentences", "ℹ️ Metadata"])
    with text_tab:
        _render_text_tab(document)
    with sentences_tab:
        _render_sentences_tab(document)
    with metadata_tab:
        _render_metadata_tab(document)


if __name__ == "__main__":
    main()
