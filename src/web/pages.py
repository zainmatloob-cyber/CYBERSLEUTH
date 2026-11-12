"""Template data for the cross-document pages: history, dashboard and the explorers.

All figures use the latest analysis of each document (the repository's ``latest_*``
queries) and count documents, not mentions.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

import pandas as pd
from markupsafe import Markup
from starlette.datastructures import QueryParams

from src.database.db_manager import AnalysisRepository
from src.visualization import aggregations as agg
from src.visualization import dashboard as charts
from src.visualization import tables
from src.web.render import Table, table

_chart_ids = itertools.count(1)
# Inside <script type="application/json"> the HTML parser does not decode entities, so the
# JSON is escaped as JSON instead: no "<", ">" or "&" can end the element early.
_JSON_ESCAPES = str.maketrans({"<": "\\u003c", ">": "\\u003e", "&": "\\u0026"})


@dataclass(frozen=True)
class Chart:
    id: str
    spec: Markup  # escaped Plotly JSON, safe to place inside a JSON script element
    table: Table  # the same data as a table: identity is never carried by colour alone
    title: str


def chart(figure, frame: pd.DataFrame, title: str) -> Chart:
    spec = figure.to_json().translate(_JSON_ESCAPES)
    return Chart(f"chart-{next(_chart_ids)}", Markup(spec), table(frame), title)


def _checked(params: QueryParams, name: str, default: bool) -> bool:
    return params.get(name) == "1" if "f" in params else default


def _chosen(params: QueryParams, name: str, everything: list[str]) -> set[str]:
    return set(params.getlist(name)) if "f" in params else set(everything)


# --- history -------------------------------------------------------------------------


def history(repo: AnalysisRepository) -> dict:
    return {"analyses": [
        {"id": a.id, "created": a.created_at.strftime("%Y-%m-%d %H:%M"),
         "filename": a.document.filename, "document_id": a.document_id,
         "risk": f"{a.risk_score:.1f}", "band": a.risk_band, "confidence": a.confidence,
         "sha256": a.document.sha256[:16] + "…"}
        for a in repo.list_analyses()]}


# --- dashboard -----------------------------------------------------------------------


def dashboard(repo: AnalysisRepository) -> dict:
    stats = repo.stats()
    analyses = repo.latest_analyses()
    mappings = repo.latest_mappings()
    coverage = agg.verification_coverage(mappings)
    reviewed = coverage["confirmed"] + coverage["rejected"]
    metrics = [("Documents", stats.documents), ("Analyses", stats.analyses),
               ("Unique IOCs", stats.indicators), ("Entities", stats.entities),
               ("ATT&CK mappings", stats.techniques),
               ("Mappings reviewed", f"{reviewed} / {sum(coverage.values())}")]

    bands = agg.risk_band_counts(analyses)
    panels: list[tuple[str, Chart | None, str]] = [
        ("bands", chart(charts.risk_band_bar(bands), bands, "Documents by risk band"), "")]
    categories = agg.category_document_counts(repo.latest_categories())
    panels.append(("categories", None if categories.empty else chart(
        charts.horizontal_bar(categories, "Category", "Documents",
                              "Threat categories (documents)", "documents"),
        categories, "Threat categories"), "No threat categories detected yet."))
    tactics = agg.tactic_document_counts(mappings)
    panels.append(("tactics", None if tactics.empty else chart(
        charts.horizontal_bar(tactics, "Tactic", "Documents", "ATT&CK tactics (documents)",
                              "documents"), tactics, "ATT&CK tactics"),
        "No ATT&CK tactics mapped yet."))
    iocs = agg.ioc_type_counts(repo.latest_indicators())
    panels.append(("iocs", None if iocs.empty else chart(
        charts.horizontal_bar(iocs, "Type", "Unique indicators", "Indicators by type",
                              "unique indicators"), iocs, "Indicators by type"),
        "No indicators extracted yet."))
    return {"metrics": metrics, "panels": panels,
            "recent": table(agg.recent_analyses(analyses))}


# --- explorers -----------------------------------------------------------------------


def ioc_explorer(repo: AnalysisRepository, params: QueryParams) -> dict:
    indicators = repo.latest_indicators()
    frame = agg.ioc_explorer(indicators)
    if frame.empty:
        return {"total": 0}
    types = sorted(frame["Type"].unique())
    verdicts = sorted({v for vs in frame["Verdicts"] for v in vs.split(", ")})
    chosen_types = _chosen(params, "type", types)
    chosen_verdicts = _chosen(params, "verdict", verdicts)
    shared_only = _checked(params, "shared", False)
    query = params.get("q", "").strip()
    visible = frame[
        frame["Type"].isin(chosen_types)
        & frame["Verdicts"].map(lambda vs: bool(set(vs.split(", ")) & chosen_verdicts))
        & (frame["Documents"] >= (2 if shared_only else 1))
        & frame["Value"].str.contains(query, case=False, regex=False)
    ]
    details = [agg.ioc_occurrences(indicators, t, v)
               for t, v in zip(visible["Type"], visible["Value"], strict=True)]
    return {"total": len(frame), "shown": len(visible), "types": types,
            "verdicts": verdicts, "chosen_types": chosen_types,
            "chosen_verdicts": chosen_verdicts, "shared_only": shared_only, "query": query,
            "table": table(visible, details=details) if len(visible) else None}


def entity_explorer(repo: AnalysisRepository, params: QueryParams) -> dict:
    frame = agg.entity_explorer(repo.latest_entities())
    if frame.empty:
        return {"total": 0}
    types = sorted(frame["Type"].unique())
    chosen = _chosen(params, "type", types)
    query = params.get("q", "").strip()
    visible = frame[frame["Type"].isin(chosen)
                    & frame["Name"].str.contains(query, case=False, regex=False)].copy()
    visible["Reference"] = visible["ATT&CK ID"].map(tables.attack_url)
    return {"total": len(frame), "shown": len(visible), "types": types, "chosen": chosen,
            "query": query, "table": table(visible) if len(visible) else None}


def attack_explorer(repo: AnalysisRepository, params: QueryParams) -> dict:
    mappings = repo.latest_mappings()
    frame = agg.technique_explorer(mappings)
    if frame.empty:
        return {"total": 0}
    coverage = agg.verification_coverage(mappings)
    explicit_only = _checked(params, "explicit", False)
    visible = frame[frame["Explicit in"] > 0] if explicit_only else frame
    matrix = agg.tactic_document_matrix(mappings)
    heatmap = None if matrix.empty else chart(
        charts.tactic_heatmap(matrix), matrix.reset_index(names="Tactic"),
        "ATT&CK tactics per document")
    return {"total": len(frame), "shown": len(visible), "coverage": coverage,
            "explicit_only": explicit_only, "table": table(visible), "heatmap": heatmap}
