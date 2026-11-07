"""CyberSleuth Streamlit entry point.

Run with:  streamlit run app.py

Security note: document content is untrusted. It is only rendered through
components that display plain text (text_area, dataframe), never through
st.markdown / unsafe HTML, so a crafted report cannot inject links or markup.
Strings that must pass through markdown-rendering widgets go through md_escape().
The only clickable links are built from validated ATT&CK / CVE identifiers and
point to attack.mitre.org and nvd.nist.gov; extracted URLs are never linkified.
"""

from __future__ import annotations

import logging
import re

import pandas as pd
import streamlit as st

from config.settings import settings
from src.ingestion.models import ExtractedDocument
from src.intelligence.analyzer import AnalysisResult, AnalysisStage, Analyzer
from src.nlp.entity_models import EntityType
from src.nlp.ioc_models import IOCType
from src.utils.exceptions import CyberSleuthError
from src.utils.logging_config import configure_logging
from src.visualization import tables

configure_logging()
logger = logging.getLogger("cybersleuth.app")

_MODULES = [
    ("Document Analysis", "Available"),
    ("IOC Extraction", "Available"),
    ("Entity Recognition", "Available"),
    ("Threat Classification", "Phase 3"),
    ("MITRE ATT&CK Mapping", "Phase 3"),
    ("Risk Analysis", "Phase 3"),
    ("Dashboard & Reports", "Phase 4"),
]

_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|~$:])")


def md_escape(text: str) -> str:
    """Escape user-controlled text before it reaches a markdown-rendering widget."""
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)


@st.cache_resource(show_spinner="Loading NLP models…")
def get_analyzer() -> Analyzer:
    """Load the spaCy model and knowledge base once per server process."""
    return Analyzer()


def _render_sidebar() -> None:
    with st.sidebar:
        st.title(f"🛡️ {settings.app_name}")
        st.caption("Cyber Threat Intelligence Extraction & Analysis")
        st.divider()
        st.subheader("Modules")
        for name, status in _MODULES:
            icon = "🟢" if status == "Available" else "⚪"
            st.write(f"{icon} {name} — *{status}*")
        st.divider()
        limits = settings.ingestion
        st.caption(
            f"Accepted: PDF, DOCX, TXT · max {limits.max_file_size_bytes // 1_048_576} MB · "
            f"max {limits.max_pdf_pages} PDF pages. Files are processed in memory and "
            "are not stored. Extracted indicators are never contacted."
        )


def _run_analysis(
    analyzer: Analyzer, data: bytes, filename: str
) -> tuple[AnalysisResult | None, str | None]:
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


# --- summary ------------------------------------------------------------------


def _render_summary(result: AnalysisResult) -> None:
    doc = result.document
    cols = st.columns(6)
    cols[0].metric("Format", doc.file_type.value.upper())
    cols[1].metric("Pages", doc.page_count)
    cols[2].metric("Sentences", f"{len(doc.sentences):,}")
    cols[3].metric("Unique IOCs", len(result.indicators))
    cols[4].metric("Entities", len(result.entities))
    cols[5].metric("Analysis time", f"{result.timings_ms.get('total', 0) / 1000:.1f} s")
    for warning in [*result.warnings, *doc.warnings]:
        st.warning(md_escape(warning))
    if not (result.warnings or doc.warnings):
        st.success("Document analysed without warnings.")


# --- document tabs (Phase 1) --------------------------------------------------


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
        [
            {"Page": s.page_number, "Start": s.char_start, "End": s.char_end,
             "Sentence": " ".join(s.text.split())}
            for s in doc.sentences
        ],
        columns=["Page", "Start", "End", "Sentence"],
    )
    if query:
        frame = frame[frame["Sentence"].str.contains(query, case=False, regex=False)]
    st.caption(f"{len(frame):,} of {len(doc.sentences):,} sentences")
    st.dataframe(frame, width="stretch", hide_index=True, height=420)


def _render_metadata_tab(result: AnalysisResult) -> None:
    doc = result.document
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
        st.dataframe(pd.DataFrame(doc.metadata.items(), columns=["Field", "Value"]),
                     hide_index=True, width="stretch")
    else:
        st.caption("No embedded metadata.")
    st.write("**Analysis provenance**")
    provenance = [
        ("NER model", result.model_name or "none (rules only)"),
        *((f"Knowledge base: {k}", v) for k, v in result.kb_versions.items()),
        *((f"Time: {k}", f"{v:,.0f} ms") for k, v in result.timings_ms.items()),
    ]
    st.dataframe(pd.DataFrame(provenance, columns=["Field", "Value"]), hide_index=True,
                 width="stretch")


# --- intelligence tabs (Phase 2) ----------------------------------------------


def _render_iocs_tab(result: AnalysisResult) -> None:
    indicators = result.indicators
    if not indicators:
        st.info("No indicators of compromise were found in this document.")
        return
    st.caption(
        "Extracted indicators are **unverified**: appearing in a report does not make a value "
        "malicious. Flags describe what a value is (e.g. a documentation IP range), not a verdict."
    )
    present = [t for t in IOCType if any(i.ioc_type is t for i in indicators)]
    cols = st.columns(len(present))
    for col, ioc_type in zip(cols, present, strict=True):
        col.metric(ioc_type.value.upper(), sum(1 for i in indicators if i.ioc_type is ioc_type))

    left, middle, right = st.columns([2, 2, 1])
    chosen = left.multiselect("Types", [t.value.upper() for t in present],
                              default=[t.value.upper() for t in present], key="ioc_types")
    query = middle.text_input("Search", key="ioc_query", placeholder="value or context")
    hide_flagged = right.checkbox("Hide flagged", key="ioc_hide_flagged",
                                  help="Hide private, documentation and reserved values")

    visible = [
        i for i in indicators
        if i.ioc_type.value.upper() in chosen
        and (not hide_flagged or not i.flags)
        and (not query or query.lower() in i.value.lower()
             or any(query.lower() in o.context.lower() for o in i.occurrences))
    ]
    st.caption(f"{len(visible)} of {len(indicators)} indicators")
    st.dataframe(tables.indicators_frame(visible), hide_index=True, width="stretch")

    if visible:
        labels = [f"{i.ioc_type.value.upper()} · {i.value}" for i in visible]
        selected = st.selectbox("Evidence for indicator", range(len(visible)),
                                format_func=labels.__getitem__, key="ioc_detail")
        st.dataframe(tables.occurrences_frame(visible[selected]), hide_index=True,
                     width="stretch")


def _render_entities_tab(result: AnalysisResult) -> None:
    entities = result.entities
    if not entities:
        st.info("No cybersecurity entities were recognised in this document.")
    else:
        st.caption(
            "Sources: **kb:mitre-attack** / **kb:curated** are deterministic knowledge-base "
            "matches; **rule:actor-pattern** uses vendor naming conventions; **model:spacy** "
            "is a statistical prediction and may be wrong. No confidence scores are shown "
            "because none of these components produces calibrated probabilities."
        )
        present = [t for t in EntityType if any(e.entity_type is t for e in entities)]
        label = {t: t.value.replace("_", " ").title() for t in present}
        cols = st.columns(len(present))
        for col, entity_type in zip(cols, present, strict=True):
            col.metric(label[entity_type],
                       sum(1 for e in entities if e.entity_type is entity_type))

        left, right = st.columns(2)
        chosen = left.multiselect("Types", [label[t] for t in present],
                                  default=[label[t] for t in present], key="entity_types")
        query = right.text_input("Search", key="entity_query", placeholder="name or alias")
        visible = [
            e for e in entities
            if label[e.entity_type] in chosen
            and (not query or query.lower() in e.name.lower()
                 or any(query.lower() in m.text.lower() for m in e.mentions))
        ]
        st.caption(f"{len(visible)} of {len(entities)} entities")
        st.dataframe(
            tables.entities_frame(visible), hide_index=True, width="stretch",
            column_config={"Reference": st.column_config.LinkColumn(
                "Reference", display_text="ATT&CK ↗")},
        )
        if visible:
            names = [f"{label[e.entity_type]} · {e.name}" for e in visible]
            selected = st.selectbox("Evidence for entity", range(len(visible)),
                                    format_func=names.__getitem__, key="entity_detail")
            st.dataframe(tables.mentions_frame(visible[selected]), hide_index=True,
                         width="stretch")

    st.subheader("Vulnerabilities")
    if result.vulnerabilities:
        st.caption("CVE identifiers and named vulnerabilities (e.g. Log4Shell) merged per CVE.")
        st.dataframe(
            tables.vulnerabilities_frame(result.vulnerabilities), hide_index=True,
            width="stretch",
            column_config={"NVD": st.column_config.LinkColumn("NVD", display_text="NVD ↗")},
        )
    else:
        st.caption("No vulnerabilities mentioned.")


def _render_evidence_tab(result: AnalysisResult) -> None:
    only_findings = st.checkbox("Only sentences with findings", value=True, key="ev_only")
    frame = tables.evidence_frame(result.evidence, only_findings=only_findings)
    st.caption(f"{len(frame):,} sentences")
    st.dataframe(frame, hide_index=True, width="stretch", height=480)


# --- page ---------------------------------------------------------------------


def main() -> None:
    st.set_page_config(page_title=settings.app_name, page_icon="🛡️", layout="wide")
    _render_sidebar()

    st.header("Document Analysis")
    st.caption("Ingestion, IOC extraction and cybersecurity entity recognition.")

    uploaded = st.file_uploader(
        "Upload a threat report", type=["pdf", "docx", "txt"], accept_multiple_files=False
    )
    if uploaded is None:
        st.info("Upload a PDF, DOCX or TXT threat report to begin. Sample files are in "
                "`data/samples/`.")
        return

    # Streamlit reruns the script on every interaction; only re-analyse on a new upload.
    if st.session_state.get("upload_id") != uploaded.file_id:
        st.session_state["upload_id"] = uploaded.file_id
        result, error = _run_analysis(get_analyzer(), uploaded.getvalue(), uploaded.name)
        st.session_state["result"], st.session_state["error"] = result, error

    error: str | None = st.session_state.get("error")
    if error:
        st.error(f"Could not process {md_escape(uploaded.name)}: {md_escape(error)}")
        return
    result: AnalysisResult | None = st.session_state.get("result")
    if result is None:
        return

    st.subheader(md_escape(result.document.filename))
    _render_summary(result)
    tabs = st.tabs(["🎯 IOCs", "🧬 Entities", "🔎 Evidence", "📄 Text", "🔤 Sentences",
                    "ℹ️ Metadata"])
    with tabs[0]:
        _render_iocs_tab(result)
    with tabs[1]:
        _render_entities_tab(result)
    with tabs[2]:
        _render_evidence_tab(result)
    with tabs[3]:
        _render_text_tab(result.document)
    with tabs[4]:
        _render_sentences_tab(result.document)
    with tabs[5]:
        _render_metadata_tab(result)


if __name__ == "__main__":
    main()
