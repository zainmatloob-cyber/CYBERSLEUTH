"""Application pages. Each takes its dependencies as arguments, so tests can inject them."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.database.db_manager import AnalysisRepository, DatabaseError
from src.database.views import hydrate, view_from_result
from src.intelligence.analyzer import AnalysisResult, Analyzer
from src.ui.analysis_views import render_analysis
from src.ui.common import BAND_ICON, md_escape, run_analysis


def analysis_page(analyzer: Analyzer, repo: AnalysisRepository | None) -> None:
    st.header("Document Analysis")
    st.caption("Ingestion, IOC and entity extraction, threat classification, ATT&CK mapping and "
               "explainable risk scoring.")
    if repo is None:
        st.warning("The database is unavailable: analyses will not be saved and analyst "
                   "verification is disabled. See the logs.")

    uploaded = st.file_uploader("Upload a threat report", type=["pdf", "docx", "txt"],
                                accept_multiple_files=False)
    if uploaded is None:
        st.info("Upload a PDF, DOCX or TXT threat report to begin. Sample files are in "
                "`data/samples/`.")
        return

    # Streamlit reruns the script on every interaction; only re-analyse on a new upload.
    if st.session_state.get("upload_id") != uploaded.file_id:
        st.session_state["upload_id"] = uploaded.file_id
        result, error = run_analysis(analyzer, uploaded.getvalue(), uploaded.name)
        st.session_state.update(result=result, error=error, analysis_id=None, save_note=None)
        if result is not None and repo is not None:
            _save(repo, result)

    error = st.session_state.get("error")
    if error:
        st.error(f"Could not process {md_escape(uploaded.name)}: {md_escape(error)}")
        return
    result: AnalysisResult | None = st.session_state.get("result")
    if result is None:
        return
    note = st.session_state.get("save_note")
    if note:
        st.info(note)
    analysis_id = st.session_state.get("analysis_id")
    view = hydrate(repo.get_analysis(analysis_id)) if repo and analysis_id \
        else view_from_result(result)
    render_analysis(view, repo if analysis_id else None, result)


def _save(repo: AnalysisRepository, result: AnalysisResult) -> None:
    try:
        outcome = repo.save(result)
    except DatabaseError as exc:
        st.session_state["save_note"] = f"Not saved: {exc}"
        return
    st.session_state["analysis_id"] = outcome.analysis_id
    st.session_state["save_note"] = (
        f"Saved as analysis #{outcome.analysis_id}." if outcome.created else
        f"This document was already analysed with the same components: showing stored "
        f"analysis #{outcome.analysis_id} with its analyst verdicts.")


def history_page(repo: AnalysisRepository | None) -> None:
    st.header("Analysis History")
    if repo is None:
        st.warning("The database is unavailable.")
        return
    analyses = repo.list_analyses()
    if not analyses:
        st.info("No analyses saved yet. Analyse a document first.")
        return
    frame = pd.DataFrame([
        {"Id": a.id, "Analysed (UTC)": a.created_at.strftime("%Y-%m-%d %H:%M"),
         "Document": a.document.filename, "Risk": round(a.risk_score, 1),
         "Band": f"{BAND_ICON.get(a.risk_band, '')} {a.risk_band}",
         "Confidence": a.confidence, "SHA-256": a.document.sha256[:16] + "…"}
        for a in analyses])
    st.dataframe(frame, hide_index=True, width="stretch")

    labels = {a.id: f"#{a.id} · {a.document.filename} · {a.created_at:%Y-%m-%d %H:%M}"
              for a in analyses}
    selected = st.selectbox("Open analysis", list(labels), format_func=labels.__getitem__,
                            key="history_selected")
    analysis = next(a for a in analyses if a.id == selected)
    render_analysis(hydrate(repo.get_analysis(selected)), repo)

    with st.expander("Delete this document and all its analyses"):
        st.text(f"Document: {analysis.document.filename}")
        confirm = st.checkbox("I understand this permanently deletes the document, its "
                              "analyses and verdicts.", key="history_delete_confirm")
        if st.button("Delete", disabled=not confirm, key="history_delete"):
            repo.delete_document(analysis.document_id)
            st.session_state.pop("history_selected", None)
            st.rerun()


def dashboard_page(repo: AnalysisRepository | None) -> None:
    st.header("Dashboard")
    if repo is None:
        st.warning("The database is unavailable.")
        return
    stats = repo.stats()
    cols = st.columns(5)
    cols[0].metric("Documents", stats.documents)
    cols[1].metric("Analyses", stats.analyses)
    cols[2].metric("Indicators", stats.indicators)
    cols[3].metric("Entities", stats.entities)
    cols[4].metric("ATT&CK techniques", stats.techniques)
    st.caption("Counts use the latest analysis of each document. Charts and cross-document "
               "explorers arrive in the next step.")
