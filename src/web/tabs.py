"""Per-tab template data for one analysis.

Stored tabs work from a ``StoredAnalysis`` (fresh or reopened). Session tabs (Evidence,
Text, Sentences) need the full document text, which only the in-memory ``AnalysisResult``
has; they are listed only when that result is still cached.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pandas as pd
from starlette.datastructures import QueryParams

from src.database.views import StoredAnalysis
from src.intelligence.analyzer import AnalysisResult
from src.intelligence.assertion import AssertionStatus
from src.intelligence.mitre_mapper import AnalystVerdict
from src.nlp.entity_models import EntityType
from src.visualization import tables
from src.web.render import key_values, table

MAX_TABLE_ROWS = 2000


@dataclass(frozen=True)
class Tab:
    key: str
    label: str
    session_only: bool = False


TABS = (
    Tab("risk", "Risk"),
    Tab("threats", "Threats"),
    Tab("entities", "Entities"),
    Tab("evidence", "Evidence", session_only=True),
    Tab("text", "Text", session_only=True),
    Tab("sentences", "Sentences", session_only=True),
    Tab("metadata", "Metadata"),
)
TAB_KEYS = {t.key for t in TABS}


def available_tabs(has_result: bool) -> list[Tab]:
    return [t for t in TABS if has_result or not t.session_only]


@dataclass
class TabContext:
    view: StoredAnalysis
    result: AnalysisResult | None
    params: QueryParams
    repo: object | None  # AnalysisRepository; typed loosely to keep tests light


# --- summary (always shown above the tabs) ---------------------------------------


def summary(view: StoredAnalysis) -> dict:
    risk = view.risk
    leads = sum(1 for m in view.mappings if m.is_unverified_lead)
    counted = sum(1 for m in view.mappings
                  if not m.is_unverified_lead and m.verdict != AnalystVerdict.REJECTED
                  and m.status is not AssertionStatus.NEGATED)
    return {
        "metrics": [
            ("Risk", f"{risk.score:.0f}", risk.band),
            ("Confidence", risk.confidence.level.title(), None),
            ("Pages", str(view.page_count), None),
            ("Unique IOCs", str(len(view.indicators)), None),
            ("Entities", str(len(view.entities)), None),
            ("ATT&CK techniques", str(counted),
             f"+{leads} model lead(s)" if leads else None),
            ("Analysis time", f"{view.timings_ms.get('total', 0) / 1000:.1f} s", None),
        ],
        "band": risk.band,
        "warnings": [*view.warnings, *view.document_warnings],
    }


# --- stored tabs -------------------------------------------------------------------


def risk_tab(ctx: TabContext) -> dict:
    risk = ctx.view.risk
    weights = {c.key: c.weight for c in risk.components}
    formula = (f"R = {weights['vulnerability']:.2f}·V + {weights['malware']:.2f}·M + "
               f"{weights['attack_behaviour']:.2f}·A + {weights['evidence']:.2f}·E")
    return {"risk": risk, "formula": formula,
            "components_table": table(tables.risk_components_frame(risk))}


def threats_tab(ctx: TabContext) -> dict:
    findings = ctx.view.categories
    if not findings:
        return {"table": None}
    return {"table": table(tables.categories_frame(findings),
                           details=[tables.category_evidence_frame(f) for f in findings])}


def _entity_label(entity_type: EntityType) -> str:
    return entity_type.value.replace("_", " ").title()


def entities_tab(ctx: TabContext) -> dict:
    entities = ctx.view.entities
    present = [t for t in EntityType if any(e.entity_type is t for e in entities)]
    counts = [(_entity_label(t), t.value, sum(1 for e in entities if e.entity_type is t))
              for t in present]
    filtered = "f" in ctx.params
    chosen = set(ctx.params.getlist("type")) if filtered else {t.value for t in present}
    query = ctx.params.get("q", "").strip()
    needle = query.lower()
    visible = [e for e in entities
               if e.entity_type.value in chosen
               and (not needle or needle in e.name.lower()
                    or any(needle in m.text.lower() for m in e.mentions))]
    vulns = ctx.view.vulnerabilities
    return {
        "total": len(entities), "counts": counts, "chosen": chosen, "query": query,
        "shown": len(visible),
        "table": table(tables.entities_frame(visible),
                       details=[tables.mentions_frame(e) for e in visible]) if visible else None,
        "vulnerabilities": table(tables.vulnerabilities_frame(vulns)) if vulns else None,
    }


def metadata_tab(ctx: TabContext) -> dict:
    view = ctx.view
    file_table = key_values([
        ("Filename", view.filename), ("SHA-256", view.sha256),
        ("Size (bytes)", f"{view.size_bytes:,}"), ("Sentences", f"{view.sentence_count:,}"),
        ("Needs OCR", "Yes" if view.needs_ocr else "No"),
        ("Analysis id", str(view.analysis_id or "not saved")),
        ("Analysed at (UTC)", view.created_at.strftime("%Y-%m-%d %H:%M:%S")),
    ])
    embedded = key_values(view.metadata.items()) if view.metadata else None
    provenance = key_values([
        *((f"Component: {k}", v) for k, v in view.components.items()),
        *((f"Knowledge base: {k}", v) for k, v in view.kb_versions.items()),
        *((f"Time: {k}", f"{v:,.0f} ms") for k, v in view.timings_ms.items()),
    ])
    events = (ctx.repo.verification_events(view.analysis_id)
              if ctx.repo is not None and view.analysis_id else [])
    history = table(pd.DataFrame([
        {"When (UTC)": e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
         "Target": f"{e.target_type.value} #{e.target_id}", "From": e.old_value,
         "To": e.new_value, "Analyst": e.analyst, "Note": e.note or ""}
        for e in events])) if events else None
    return {"file": file_table, "embedded": embedded, "provenance": provenance,
            "history": history}


# --- session tabs ------------------------------------------------------------------


def evidence_tab(ctx: TabContext) -> dict:
    show_all = ctx.params.get("all") == "1"
    frame = tables.evidence_frame(ctx.result.evidence, only_findings=not show_all)
    return {"show_all": show_all, "table": table(frame, max_rows=MAX_TABLE_ROWS)}


def text_tab(ctx: TabContext) -> dict:
    pages = ctx.result.document.pages
    numbers = [p.page_number for p in pages]
    try:
        selected = int(ctx.params.get("page", numbers[0]))
    except ValueError:
        selected = numbers[0]
    page = next((p for p in pages if p.page_number == selected), pages[0])
    return {"numbers": numbers, "page": page}


def sentences_tab(ctx: TabContext) -> dict:
    sentences = ctx.result.document.sentences
    query = ctx.params.get("q", "").strip()
    frame = pd.DataFrame(
        [{"Page": s.page_number, "Start": s.char_start, "End": s.char_end,
          "Sentence": " ".join(s.text.split())} for s in sentences],
        columns=["Page", "Start", "End", "Sentence"])
    if query:
        frame = frame[frame["Sentence"].str.contains(query, case=False, regex=False)]
    return {"query": query, "total": len(sentences),
            "table": table(frame, max_rows=MAX_TABLE_ROWS)}


BUILDERS: dict[str, Callable[[TabContext], dict]] = {
    "risk": risk_tab, "threats": threats_tab, "entities": entities_tab,
    "evidence": evidence_tab, "text": text_tab, "sentences": sentences_tab,
    "metadata": metadata_tab,
}
