"""Application pages. Each takes its dependencies as arguments, so tests can inject them."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.database.db_manager import AnalysisRepository, DatabaseError
from src.database.views import hydrate, view_from_result
from src.intelligence.analyzer import AnalysisResult, Analyzer
from src.ui.analysis_views import render_analysis
from src.ui.common import BAND_ICON, md_escape, run_analysis
from src.visualization import aggregations as agg
from src.visualization import dashboard as charts
from src.visualization import tables


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


def _chart(figure, frame: pd.DataFrame, key: str) -> None:
    """A chart plus its table view (identity is never carried by colour alone)."""
    st.plotly_chart(figure, width="stretch", key=key, config={"displaylogo": False})
    with st.expander("Table view"):
        st.dataframe(frame, hide_index=True, width="stretch")


def _require(repo: AnalysisRepository | None, title: str) -> bool:
    st.header(title)
    if repo is None:
        st.warning("The database is unavailable.")
        return False
    if not repo.stats().documents:
        st.info("No analyses saved yet. Analyse a document first.")
        return False
    return True


def dashboard_page(repo: AnalysisRepository | None) -> None:
    if not _require(repo, "Dashboard"):
        return
    stats = repo.stats()
    analyses = repo.latest_analyses()
    mappings = repo.latest_mappings()
    coverage = agg.verification_coverage(mappings)
    cols = st.columns(6)
    cols[0].metric("Documents", stats.documents)
    cols[1].metric("Analyses", stats.analyses)
    cols[2].metric("Unique IOCs", stats.indicators)
    cols[3].metric("Entities", stats.entities)
    cols[4].metric("ATT&CK mappings", stats.techniques)
    cols[5].metric("Mappings reviewed", f"{coverage['confirmed'] + coverage['rejected']}"
                                        f" / {sum(coverage.values())}")
    st.caption("All figures use the latest analysis of each document and count documents, "
               "not mentions. Negated findings are excluded from the charts.")

    left, right = st.columns(2)
    with left:
        bands = agg.risk_band_counts(analyses)
        _chart(charts.risk_band_bar(bands), bands, "dash_bands")
    with right:
        categories = agg.category_document_counts(repo.latest_categories())
        if categories.empty:
            st.caption("No threat categories detected yet.")
        else:
            _chart(charts.horizontal_bar(categories, "Category", "Documents",
                                         "Threat categories (documents)", "documents"),
                   categories, "dash_categories")
    left, right = st.columns(2)
    with left:
        tactics = agg.tactic_document_counts(mappings)
        if tactics.empty:
            st.caption("No ATT&CK tactics mapped yet.")
        else:
            _chart(charts.horizontal_bar(tactics, "Tactic", "Documents",
                                         "ATT&CK tactics (documents)", "documents"),
                   tactics, "dash_tactics")
    with right:
        iocs = agg.ioc_type_counts(repo.latest_indicators())
        if iocs.empty:
            st.caption("No indicators extracted yet.")
        else:
            _chart(charts.horizontal_bar(iocs, "Type", "Unique indicators",
                                         "Indicators by type", "unique indicators"),
                   iocs, "dash_iocs")
    st.subheader("Recent analyses")
    st.dataframe(agg.recent_analyses(analyses), hide_index=True, width="stretch")


def ioc_explorer_page(repo: AnalysisRepository | None) -> None:
    if not _require(repo, "IOC Explorer"):
        return
    st.caption("Indicators across all documents (latest analysis each). **Documents > 1** means "
               "the same indicator appears in several reports, a correlation lead, not a "
               "verdict. Values are shown as text and are never contacted.")
    indicators = repo.latest_indicators()
    frame = agg.ioc_explorer(indicators)
    if frame.empty:
        st.info("No indicators extracted yet.")
        return
    left, middle, right = st.columns([2, 2, 1])
    types = sorted(frame["Type"].unique())
    chosen = left.multiselect("Types", types, default=types, key="iocx_types")
    verdicts = sorted({v for vs in frame["Verdicts"] for v in vs.split(", ")})
    chosen_verdicts = middle.multiselect("Verdicts", verdicts, default=verdicts,
                                         key="iocx_verdicts")
    shared_only = right.checkbox("In ≥ 2 documents", key="iocx_shared")
    query = st.text_input("Search value", key="iocx_query", placeholder="e.g. 198.51.100")
    visible = frame[
        frame["Type"].isin(chosen)
        & frame["Verdicts"].map(lambda vs: bool(set(vs.split(", ")) & set(chosen_verdicts)))
        & (frame["Documents"] >= (2 if shared_only else 1))
        & frame["Value"].str.contains(query, case=False, regex=False)
    ]
    st.caption(f"{len(visible)} of {len(frame)} indicators")
    st.dataframe(visible, hide_index=True, width="stretch")
    if not visible.empty:
        labels = [f"{t} · {v}" for t, v in zip(visible["Type"], visible["Value"], strict=True)]
        index = st.selectbox("Occurrences of", range(len(labels)), format_func=labels.__getitem__,
                             key="iocx_detail")
        row = visible.iloc[index]
        st.dataframe(agg.ioc_occurrences(indicators, row["Type"], row["Value"]),
                     hide_index=True, width="stretch")


def entity_explorer_page(repo: AnalysisRepository | None) -> None:
    if not _require(repo, "Entity Explorer"):
        return
    frame = agg.entity_explorer(repo.latest_entities())
    if frame.empty:
        st.info("No entities recognised yet.")
        return
    st.caption("Malware, threat actors, tools, vulnerabilities and other entities across "
               "documents. **model:spacy** entities are statistical predictions.")
    left, right = st.columns(2)
    types = sorted(frame["Type"].unique())
    chosen = left.multiselect("Types", types, default=types, key="entx_types")
    query = right.text_input("Search name", key="entx_query")
    visible = frame[frame["Type"].isin(chosen)
                    & frame["Name"].str.contains(query, case=False, regex=False)].copy()
    visible["Reference"] = visible["ATT&CK ID"].map(tables.attack_url)
    st.caption(f"{len(visible)} of {len(frame)} entities")
    st.dataframe(visible, hide_index=True, width="stretch", column_config={
        "Reference": st.column_config.LinkColumn("Reference", display_text="ATT&CK ↗")})


def attack_explorer_page(repo: AnalysisRepository | None) -> None:
    if not _require(repo, "ATT&CK Explorer"):
        return
    mappings = repo.latest_mappings()
    frame = agg.technique_explorer(mappings)
    if frame.empty:
        st.info("No ATT&CK techniques mapped yet.")
        return
    coverage = agg.verification_coverage(mappings)
    cols = st.columns(3)
    cols[0].metric("Confirmed", coverage["confirmed"])
    cols[1].metric("Rejected", coverage["rejected"])
    cols[2].metric("Unverified", coverage["unverified"])
    st.caption("Model-suggested mappings are unverified until reviewed. Verdicts are set in "
               "each analysis's ATT&CK tab.")
    explicit_only = st.checkbox("Techniques with explicit evidence only", key="attx_explicit")
    visible = frame[frame["Explicit in"] > 0] if explicit_only else frame
    st.dataframe(visible, hide_index=True, width="stretch", column_config={
        "ATT&CK": st.column_config.LinkColumn("ATT&CK", display_text="ATT&CK ↗")})
    matrix = agg.tactic_document_matrix(mappings)
    if not matrix.empty:
        _chart(charts.tactic_heatmap(matrix), matrix.reset_index(names="Tactic"), "attx_heatmap")
