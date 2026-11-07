"""Cross-document aggregations for the dashboard and explorers.

Pure functions over repository records (latest analysis per document), returning
DataFrames, so they can be unit-tested without Streamlit or a browser.

Counting rule used everywhere: **documents, not mentions**. A technique mentioned 40 times
in one report counts as one document. Negated findings are excluded from "seen in"
counts, but remain visible in the explorers with their status.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

import pandas as pd

from src.database.models import (
    Analysis,
    EntityRecord,
    Indicator,
    TechniqueMappingRecord,
    ThreatCategoryRecord,
)

RISK_BANDS = ("Low", "Moderate", "High", "Critical")
CATEGORY_LABELS = {
    "ddos": "DDoS", "credential_theft": "Credential Theft", "data_breach": "Data Breach",
    "vulnerability_exploitation": "Vulnerability Exploitation", "ransomware": "Ransomware",
    "phishing": "Phishing", "malware": "Malware",
}


def category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, category.replace("_", " ").title())
_NEGATED = "negated"


def risk_band_counts(analyses: Sequence[Analysis]) -> pd.DataFrame:
    counts = {band: 0 for band in RISK_BANDS}
    for analysis in analyses:
        counts[analysis.risk_band] = counts.get(analysis.risk_band, 0) + 1
    return pd.DataFrame({"Band": list(counts), "Documents": list(counts.values())})


def category_document_counts(categories: Sequence[ThreatCategoryRecord]) -> pd.DataFrame:
    documents: dict[str, set[int]] = defaultdict(set)
    for record in categories:
        if record.status.value != _NEGATED:
            documents[record.category].add(record.analysis.document_id)
    rows = [{"Category": category_label(c), "Documents": len(d)}
            for c, d in documents.items()]
    return pd.DataFrame(rows, columns=["Category", "Documents"]).sort_values(
        ["Documents", "Category"], ascending=[False, True], ignore_index=True)


def tactic_document_counts(mappings: Sequence[TechniqueMappingRecord]) -> pd.DataFrame:
    documents: dict[str, set[int]] = defaultdict(set)
    for record in mappings:
        if record.status.value != _NEGATED:
            for tactic in record.tactics:
                documents[tactic].add(record.analysis.document_id)
    rows = [{"Tactic": t, "Documents": len(d)} for t, d in documents.items()]
    return pd.DataFrame(rows, columns=["Tactic", "Documents"]).sort_values(
        ["Documents", "Tactic"], ascending=[False, True], ignore_index=True)


def ioc_type_counts(indicators: Sequence[Indicator]) -> pd.DataFrame:
    counts: dict[str, int] = defaultdict(int)
    for record in indicators:
        counts[record.ioc_type.value.upper()] += 1
    rows = [{"Type": t, "Unique indicators": n} for t, n in counts.items()]
    return pd.DataFrame(rows, columns=["Type", "Unique indicators"]).sort_values(
        ["Unique indicators", "Type"], ascending=[False, True], ignore_index=True)


def recent_analyses(analyses: Sequence[Analysis], limit: int = 10) -> pd.DataFrame:
    return pd.DataFrame(
        [{"Id": a.id, "Analysed (UTC)": a.created_at.strftime("%Y-%m-%d %H:%M"),
          "Document": a.document.filename, "Risk": round(a.risk_score, 1), "Band": a.risk_band,
          "Confidence": a.confidence} for a in analyses[:limit]],
        columns=["Id", "Analysed (UTC)", "Document", "Risk", "Band", "Confidence"])


# --- explorers ----------------------------------------------------------------------


def ioc_explorer(indicators: Sequence[Indicator]) -> pd.DataFrame:
    """One row per (type, value) across documents: the basis for cross-report correlation."""
    groups: dict[tuple[str, str], list[Indicator]] = defaultdict(list)
    for record in indicators:
        groups[(record.ioc_type.value, record.value)].append(record)
    rows = []
    for (ioc_type, value), records in groups.items():
        rows.append({
            "Type": ioc_type.upper(),
            "Value": value,
            "Documents": len({r.analysis.document_id for r in records}),
            "Occurrences": sum(r.occurrence_count for r in records),
            "Verdicts": ", ".join(sorted({r.verification.value for r in records})),
            "Flags": ", ".join(sorted({f for r in records for f in r.flags})),
            "Seen in": ", ".join(sorted({r.analysis.document.filename for r in records})),
        })
    columns = ["Type", "Value", "Documents", "Occurrences", "Verdicts", "Flags", "Seen in"]
    return pd.DataFrame(rows, columns=columns).sort_values(
        ["Documents", "Occurrences", "Value"], ascending=[False, False, True],
        ignore_index=True)


def ioc_occurrences(indicators: Sequence[Indicator], ioc_type: str, value: str) -> pd.DataFrame:
    rows = [{"Document": r.analysis.document.filename, "Analysis": r.analysis_id,
             "Verdict": r.verification.value, "Page": o.page_number, "As written": o.raw,
             "Context": o.context}
            for r in indicators if r.ioc_type.value == ioc_type.lower() and r.value == value
            for o in r.occurrences]
    return pd.DataFrame(rows, columns=["Document", "Analysis", "Verdict", "Page", "As written",
                                       "Context"])


def entity_explorer(entities: Sequence[EntityRecord]) -> pd.DataFrame:
    groups: dict[tuple[str, str], list[EntityRecord]] = defaultdict(list)
    for record in entities:
        groups[(record.entity_type.value, record.name)].append(record)
    rows = []
    for (entity_type, name), records in groups.items():
        rows.append({
            "Type": entity_type.replace("_", " ").title(),
            "Name": name,
            "ATT&CK ID": next((r.kb_id for r in records if r.kb_id), ""),
            "Documents": len({r.analysis.document_id for r in records}),
            "Mentions": sum(r.mention_count for r in records),
            "Source": ", ".join(sorted({r.source for r in records})),
            "Seen in": ", ".join(sorted({r.analysis.document.filename for r in records})),
        })
    columns = ["Type", "Name", "ATT&CK ID", "Documents", "Mentions", "Source", "Seen in"]
    return pd.DataFrame(rows, columns=columns).sort_values(
        ["Documents", "Mentions", "Name"], ascending=[False, False, True], ignore_index=True)


def technique_explorer(mappings: Sequence[TechniqueMappingRecord]) -> pd.DataFrame:
    groups: dict[str, list[TechniqueMappingRecord]] = defaultdict(list)
    for record in mappings:
        groups[record.technique_id].append(record)
    rows = []
    for technique_id, records in groups.items():
        active = [r for r in records if r.status.value != _NEGATED]
        verdicts = [r.verdict.value for r in records]
        rows.append({
            "Technique": technique_id,
            "Name": records[0].name,
            "Tactics": ", ".join(records[0].tactics),
            "Documents (non-negated)": len({r.analysis.document_id for r in active}),
            "Negated in": len({r.analysis.document_id for r in records} -
                              {r.analysis.document_id for r in active}),
            "Explicit in": len({r.analysis.document_id for r in records if r.explicit}),
            "Confirmed": verdicts.count("confirmed"),
            "Rejected": verdicts.count("rejected"),
            "Unverified": verdicts.count("unverified"),
            "ATT&CK": records[0].url,
        })
    columns = ["Technique", "Name", "Tactics", "Documents (non-negated)", "Negated in",
               "Explicit in", "Confirmed", "Rejected", "Unverified", "ATT&CK"]
    return pd.DataFrame(rows, columns=columns).sort_values(
        ["Documents (non-negated)", "Technique"], ascending=[False, True], ignore_index=True)


def tactic_document_matrix(mappings: Sequence[TechniqueMappingRecord]) -> pd.DataFrame:
    """Rows = tactics, columns = documents, values = number of non-negated techniques."""
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for record in mappings:
        if record.status.value == _NEGATED:
            continue
        for tactic in record.tactics:
            counts[(tactic, record.analysis.document.filename)] += 1
    if not counts:
        return pd.DataFrame()
    frame = pd.Series(counts).unstack(fill_value=0)
    order = frame.sum(axis=1).sort_values(ascending=False).index
    return frame.loc[order, sorted(frame.columns)]


def verification_coverage(mappings: Sequence[TechniqueMappingRecord]) -> dict[str, int]:
    verdicts = [r.verdict.value for r in mappings]
    return {v: verdicts.count(v) for v in ("confirmed", "rejected", "unverified")}
