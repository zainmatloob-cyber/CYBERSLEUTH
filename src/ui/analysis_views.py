"""Tab renderers for one analysis.

Stored views (``StoredAnalysis``) are used for every finding tab, for fresh and reopened
analyses alike. Session-only views (``AnalysisResult``: Evidence, Text, Sentences) need the
full document text, which is not persisted by default.
"""

from __future__ import annotations

from collections.abc import Callable

import pandas as pd
import streamlit as st

from src.database.db_manager import MAX_NOTE_LENGTH, AnalysisRepository
from src.database.views import StoredAnalysis, rescore_analysis
from src.ingestion.models import ExtractedDocument
from src.intelligence.analyzer import AnalysisResult
from src.intelligence.mitre_mapper import AnalystVerdict
from src.nlp.entity_models import EntityType
from src.nlp.ioc_models import IOCType, VerificationStatus
from src.reporting import csv_report, json_report, pdf_report
from src.reporting.common import report_stem
from src.ui.common import BAND_ICON, md_escape
from src.visualization import tables

FLASH_KEY = "verdict_flash"


def _flash() -> None:
    message = st.session_state.pop(FLASH_KEY, None)
    if message:
        st.success(message)


def _verdict_form(key: str, label: str, options: list[str], current: str, note: str | None,
                  save: Callable[[str, str | None], None]) -> None:
    """Analyst verdict form. ``label`` is untrusted (it contains extracted values)."""
    with st.form(key, clear_on_submit=False):
        st.text(f"Analyst verdict for: {label}")
        verdict = st.selectbox("Verdict", options, index=options.index(current),
                               key=f"{key}_verdict")
        text = st.text_area("Note (optional)", value=note or "", max_chars=MAX_NOTE_LENGTH,
                            key=f"{key}_note")
        if st.form_submit_button("Save verdict"):
            save(verdict, text.strip() or None)
            st.session_state[FLASH_KEY] = f"Saved verdict '{verdict}'."
            st.rerun()


# --- summary ------------------------------------------------------------------


def render_summary(view: StoredAnalysis) -> None:
    risk = view.risk
    cols = st.columns(7)
    cols[0].metric("Risk", f"{risk.score:.0f} · {risk.band}")
    cols[1].metric("Confidence", risk.confidence.level.title())
    cols[2].metric("Pages", view.page_count)
    cols[3].metric("Unique IOCs", len(view.indicators))
    cols[4].metric("Entities", len(view.entities))
    leads = sum(1 for m in view.mappings if m.is_unverified_lead)
    cols[5].metric("ATT&CK techniques", len(view.mappings) - leads,
                   help=f"Explicit or analyst-confirmed. {leads} unverified model "
                        "suggestion(s) are listed separately in the ATT&CK tab.")
    cols[6].metric("Analysis time", f"{view.timings_ms.get('total', 0) / 1000:.1f} s")
    warnings = [*view.warnings, *view.document_warnings]
    for warning in warnings:
        st.warning(md_escape(warning))
    if not warnings:
        st.success("Document analysed without warnings.")


# --- finding tabs (stored) -------------------------------------------------------


def render_risk(view: StoredAnalysis) -> None:
    risk = view.risk
    st.subheader(f"{BAND_ICON.get(risk.band, '')} {risk.score:.1f} / 100 · {risk.band}")
    weights = {c.key: c.weight for c in risk.components}
    st.caption(
        f"R = {weights['vulnerability']:.2f}·V + {weights['malware']:.2f}·M + "
        f"{weights['attack_behaviour']:.2f}·A + {weights['evidence']:.2f}·E · risk model "
        f"{risk.config_version}. Severity and confidence are reported separately."
    )
    for component in risk.components:
        st.write(f"**{component.label}**: {component.value:.0f}/100 × {component.weight:.2f} "
                 f"= {component.contribution:.1f}")
        st.progress(component.value / 100)
        for line in component.explanation:
            st.text(f"  • {line}")
    st.write(f"**Confidence: {risk.confidence.level}**")
    for reason in risk.confidence.reasons:
        st.text(f"  • {reason}")
    with st.expander("Limitations of this score"):
        for limitation in risk.limitations:
            st.text(f"• {limitation}")
    st.dataframe(tables.risk_components_frame(risk), hide_index=True, width="stretch")


def render_threats(view: StoredAnalysis) -> None:
    findings = view.categories
    if not findings:
        st.info("No threat categories were detected.")
        return
    st.caption(
        "Categories are aggregated from sentences. **model** = TF-IDF classifier (score, not a "
        "probability); **rules** = keyword evidence, which also fires on mere mentions. A "
        "category whose only evidence is negated is shown as `negated`. Report-level "
        "aggregation is not validated against labelled reports."
    )
    st.dataframe(tables.categories_frame(findings), hide_index=True, width="stretch")
    labels = [f"{f.category} ({f.status.value})" for f in findings]
    selected = st.selectbox("Evidence for category", range(len(findings)),
                            format_func=labels.__getitem__, key="category_detail")
    st.dataframe(tables.category_evidence_frame(findings[selected]), hide_index=True,
                 width="stretch")


def render_attack(view: StoredAnalysis, repo: AnalysisRepository | None) -> None:
    _flash()
    mappings = view.mappings
    if not mappings:
        st.info("No ATT&CK techniques were mapped.")
        return
    st.caption(
        "**explicit-*** mappings come from the text naming the technique. Status: observed / "
        "capability / possible / negated. Every mapping is **unverified** until an analyst "
        "reviews it; confirming or rejecting one updates the risk score."
    )
    leads = [m for m in mappings if m.is_unverified_lead]
    left, right = st.columns(2)
    show_leads = left.checkbox(
        f"Show {len(leads)} unverified model suggestion(s)", key="attack_show_leads",
        help="Model-only suggestions are leads, not findings: on 14 real CISA advisories only "
             "10% matched a technique CISA cites. They don't count toward the risk score "
             "unless you confirm them.")
    hide_negated = right.checkbox("Hide negated", value=True, key="attack_hide_negated")
    if show_leads and leads:
        st.warning("Model suggestions are shown. Score = SVM margin, not a probability; "
                   "low scores are usually wrong on real reports. Confirm only what the "
                   "evidence sentence supports.")
    visible = [m for m in mappings if (show_leads or not m.is_unverified_lead)
               and (not hide_negated or m.status.value != "negated")]
    st.caption(f"{len(visible)} of {len(mappings)} techniques"
               + ("" if show_leads or not leads else
                  f" · {len(leads)} model suggestion(s) hidden"))
    st.dataframe(
        tables.mappings_frame(visible), hide_index=True, width="stretch",
        column_config={"ATT&CK": st.column_config.LinkColumn("ATT&CK", display_text="ATT&CK ↗")},
    )
    if not visible:
        return
    labels = [f"{m.technique_id} · {m.name}" for m in visible]
    selected = st.selectbox("Evidence for technique", range(len(visible)),
                            format_func=labels.__getitem__, key="attack_detail")
    mapping = visible[selected]
    st.dataframe(tables.mapping_evidence_frame(mapping), hide_index=True, width="stretch")
    mapping_id = view.mapping_ids.get(mapping.technique_id)
    if repo is None or mapping_id is None:
        st.caption("Analyst verification requires the database.")
        return
    _verdict_form(
        f"mapping_verdict_{view.analysis_id}", labels[selected],
        [v.value for v in AnalystVerdict], mapping.verdict.value,
        view.mapping_notes.get(mapping_id),
        lambda verdict, note: _save_mapping_verdict(repo, view.analysis_id, mapping_id,
                                                    verdict, note))


def _save_mapping_verdict(repo: AnalysisRepository, analysis_id: int, mapping_id: int,
                          verdict: str, note: str | None) -> None:
    """Record the verdict, then re-score: confirmed suggestions count, rejected ones don't."""
    repo.set_mapping_verdict(mapping_id, verdict, note)
    rescore_analysis(repo, analysis_id)


def render_iocs(view: StoredAnalysis, repo: AnalysisRepository | None) -> None:
    _flash()
    indicators = view.indicators
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
    if not visible:
        return
    labels = [f"{i.ioc_type.value.upper()} · {i.value}" for i in visible]
    selected = st.selectbox("Evidence for indicator", range(len(visible)),
                            format_func=labels.__getitem__, key="ioc_detail")
    indicator = visible[selected]
    st.dataframe(tables.occurrences_frame(indicator), hide_index=True, width="stretch")
    indicator_id = view.indicator_ids.get((indicator.ioc_type, indicator.value))
    if repo is None or indicator_id is None:
        st.caption("Analyst verification requires the database.")
        return
    _verdict_form(
        f"ioc_verdict_{view.analysis_id}", labels[selected],
        [v.value for v in VerificationStatus], indicator.verification.value,
        view.indicator_notes.get(indicator_id),
        lambda verdict, note: repo.set_indicator_verdict(indicator_id, verdict, note))


def render_entities(view: StoredAnalysis) -> None:
    entities = view.entities
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
    if view.vulnerabilities:
        st.caption("CVE identifiers and named vulnerabilities (e.g. Log4Shell) merged per CVE.")
        st.dataframe(
            tables.vulnerabilities_frame(view.vulnerabilities), hide_index=True,
            width="stretch",
            column_config={"NVD": st.column_config.LinkColumn("NVD", display_text="NVD ↗")},
        )
    else:
        st.caption("No vulnerabilities mentioned.")


def render_metadata(view: StoredAnalysis, repo: AnalysisRepository | None) -> None:
    st.write("**File**")
    st.dataframe(pd.DataFrame([
        ("Filename", view.filename), ("SHA-256", view.sha256),
        ("Size (bytes)", f"{view.size_bytes:,}"), ("Sentences", f"{view.sentence_count:,}"),
        ("Needs OCR", "Yes" if view.needs_ocr else "No"),
        ("Analysis id", str(view.analysis_id or "not saved")),
        ("Analysed at (UTC)", view.created_at.strftime("%Y-%m-%d %H:%M:%S")),
    ], columns=["Field", "Value"]), hide_index=True, width="stretch")
    st.write("**Embedded document metadata** (untrusted, author-supplied)")
    if view.metadata:
        st.dataframe(pd.DataFrame(view.metadata.items(), columns=["Field", "Value"]),
                     hide_index=True, width="stretch")
    else:
        st.caption("No embedded metadata.")
    st.write("**Analysis provenance**")
    provenance = [
        *((f"Component: {k}", v) for k, v in view.components.items()),
        *((f"Knowledge base: {k}", v) for k, v in view.kb_versions.items()),
        *((f"Time: {k}", f"{v:,.0f} ms") for k, v in view.timings_ms.items()),
    ]
    st.dataframe(pd.DataFrame(provenance, columns=["Field", "Value"]), hide_index=True,
                 width="stretch")
    st.write("**Verification history**")
    events = (repo.verification_events(view.analysis_id)
                      if repo and view.analysis_id else [])
    if events:
        st.dataframe(pd.DataFrame([
            {"When (UTC)": e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
             "Target": f"{e.target_type.value} #{e.target_id}", "From": e.old_value,
             "To": e.new_value, "Analyst": e.analyst, "Note": e.note or ""}
            for e in events]), hide_index=True, width="stretch")
    else:
        st.caption("No analyst verdicts recorded yet.")


REPORTS = (
    ("PDF report", "pdf", "application/pdf", pdf_report.to_pdf,
     "Analyst-facing report: summary, risk, findings with evidence, verification, limitations."),
    ("JSON (complete)", "json", "application/json", json_report.to_json,
     "Every finding and evidence sentence, versioned schema. Includes canonical IOC values."),
    ("CSV tables (ZIP)", "zip", "application/zip", csv_report.to_csv_zip,
     "One CSV per finding type, defanged, safe to open in a spreadsheet."),
)


def render_export(view: StoredAnalysis, repo: AnalysisRepository | None) -> None:
    st.caption("Reports contain findings and their evidence sentences, never the full "
               "document text. Network indicators are defanged in the PDF and CSV; verdicts "
               "are exported as currently recorded.")
    if not view.analysis_id:
        st.info("This analysis is not saved, so reports carry no analyst verdicts.")
    stem = report_stem(view)

    def builder(export: Callable) -> Callable[[], bytes]:
        def build() -> bytes:  # runs on click, so verdicts saved since are included
            events = (repo.verification_events(view.analysis_id)
                      if repo and view.analysis_id else [])
            return export(view, events)
        return build

    for column, (label, ext, mime, export, help_text) in zip(
            st.columns(len(REPORTS)), REPORTS, strict=True):
        with column:
            st.download_button(f"⬇️ {label}", data=builder(export), file_name=f"{stem}.{ext}",
                               mime=mime, on_click="ignore", key=f"export_{ext}",
                               width="stretch")
            st.caption(help_text)


# --- session-only tabs (need the document text) -----------------------------------


def render_evidence(result: AnalysisResult) -> None:
    only_findings = st.checkbox("Only sentences with findings", value=True, key="ev_only")
    frame = tables.evidence_frame(result.evidence, only_findings=only_findings)
    st.caption(f"{len(frame):,} sentences")
    st.dataframe(frame, hide_index=True, width="stretch", height=480)


def render_text(doc: ExtractedDocument) -> None:
    page_numbers = [p.page_number for p in doc.pages]
    selected = st.selectbox("Page", page_numbers) if len(page_numbers) > 1 else page_numbers[0]
    page = next(p for p in doc.pages if p.page_number == selected)
    st.text_area(f"Cleaned text — page {selected}",
                 page.text or "(no extractable text on this page)", height=420, disabled=True)


def render_sentences(doc: ExtractedDocument) -> None:
    query = st.text_input("Filter sentences", placeholder="e.g. phishing, 198.51.100, CVE-")
    frame = pd.DataFrame(
        [{"Page": s.page_number, "Start": s.char_start, "End": s.char_end,
          "Sentence": " ".join(s.text.split())} for s in doc.sentences],
        columns=["Page", "Start", "End", "Sentence"])
    if query:
        frame = frame[frame["Sentence"].str.contains(query, case=False, regex=False)]
    st.caption(f"{len(frame):,} of {len(doc.sentences):,} sentences")
    st.dataframe(frame, width="stretch", hide_index=True, height=420)


# --- composition --------------------------------------------------------------


def render_analysis(view: StoredAnalysis, repo: AnalysisRepository | None,
                    result: AnalysisResult | None = None) -> None:
    """Summary plus all tabs. Session-only tabs appear when ``result`` is available."""
    st.subheader(md_escape(view.filename))
    render_summary(view)
    views: list[tuple[str, Callable[[], None]]] = [
        ("⚠️ Risk", lambda: render_risk(view)),
        ("🧭 Threats", lambda: render_threats(view)),
        ("🗺️ ATT&CK", lambda: render_attack(view, repo)),
        ("🎯 IOCs", lambda: render_iocs(view, repo)),
        ("🧬 Entities", lambda: render_entities(view)),
    ]
    if result is not None:
        views += [("🔎 Evidence", lambda: render_evidence(result)),
                  ("📄 Text", lambda: render_text(result.document)),
                  ("🔤 Sentences", lambda: render_sentences(result.document))]
    views.append(("ℹ️ Metadata", lambda: render_metadata(view, repo)))
    views.append(("📤 Export", lambda: render_export(view, repo)))
    for tab, (_, render) in zip(st.tabs([name for name, _ in views]), views, strict=True):
        with tab:
            render()
