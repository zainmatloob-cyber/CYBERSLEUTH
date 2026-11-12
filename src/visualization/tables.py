"""Pure functions that turn analysis objects into display tables.

Kept separate from the web layer so they can be unit-tested and reused by the
Phase 4 exports.
"""

from __future__ import annotations

import re

import pandas as pd

from src.intelligence.evidence_manager import SentenceEvidence, VulnerabilityRecord
from src.nlp.entity_models import Entity
from src.nlp.ioc_models import Indicator
from src.visualization.aggregations import category_label

_ATTACK_ID_RE = re.compile(r"^([GS])\d{4}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_ATTACK_SECTIONS = {"G": "groups", "S": "software"}


def attack_url(kb_id: str | None) -> str | None:
    """Reference link to the ATT&CK page for a validated group/software id."""
    match = _ATTACK_ID_RE.match(kb_id or "")
    if not match:
        return None
    return f"https://attack.mitre.org/{_ATTACK_SECTIONS[match.group(1)]}/{kb_id}/"


def nvd_url(cve_id: str) -> str | None:
    """Reference link to NIST NVD for a validated CVE id."""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}" if _CVE_RE.match(cve_id) else None


def _pages(pages: list[int] | tuple[int, ...]) -> str:
    return ", ".join(map(str, pages))


def indicators_frame(indicators: list[Indicator]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Type": i.ioc_type.value.upper(),
                "Value": i.value,
                "Occurrences": i.count,
                "Pages": _pages(i.pages),
                "Defanged": i.defanged,
                "Flags": ", ".join(sorted(f.value for f in i.flags)),
                "Verification": i.verification.value,
                "Source": i.source,
                "Context": i.occurrences[0].context,
            }
            for i in indicators
        ],
        columns=["Type", "Value", "Occurrences", "Pages", "Defanged", "Flags", "Verification",
                 "Source", "Context"],
    )


def occurrences_frame(indicator: Indicator) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"Page": o.page_number, "As written": o.raw, "Start": o.char_start,
             "Context": o.context}
            for o in indicator.occurrences
        ],
        columns=["Page", "As written", "Start", "Context"],
    )


def entities_frame(entities: list[Entity]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Type": e.entity_type.value.replace("_", " ").title(),
                "Name": e.name,
                "ATT&CK ID": e.kb_id or "",
                "Mentions": e.count,
                "Aliases seen": ", ".join(e.aliases_seen),
                "Source": e.source.value,
                "Alternatives": ", ".join(e.alternatives),
                "Details": ", ".join(f"{k}: {v}" for k, v in e.attributes.items()),
                "Reference": attack_url(e.kb_id),
                "Context": e.mentions[0].context,
            }
            for e in entities
        ],
        columns=["Type", "Name", "ATT&CK ID", "Mentions", "Aliases seen", "Source",
                 "Alternatives", "Details", "Reference", "Context"],
    )


def mentions_frame(entity: Entity) -> pd.DataFrame:
    return pd.DataFrame(
        [{"Page": m.page_number, "As written": m.text, "Context": m.context}
         for m in entity.mentions],
        columns=["Page", "As written", "Context"],
    )


def vulnerabilities_frame(records: list[VulnerabilityRecord]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "CVE": r.cve_id,
                "Known as": ", ".join(r.names),
                "Mentioned by": r.mentioned_by,
                "ID mentions": r.id_mentions,
                "Name mentions": r.name_mentions,
                "Pages": _pages(r.pages),
                "NVD": nvd_url(r.cve_id),
            }
            for r in records
        ],
        columns=["CVE", "Known as", "Mentioned by", "ID mentions", "Name mentions", "Pages", "NVD"],
    )


def evidence_frame(evidence: list[SentenceEvidence], only_findings: bool = True) -> pd.DataFrame:
    rows = []
    for item in evidence:
        if only_findings and not item.has_findings:
            continue
        rows.append({
            "Page": item.sentence.page_number,
            "Sentence": " ".join(item.sentence.text.split()),
            "Indicators": "; ".join(f"{i.ioc_type.value}: {i.value}" for i, _ in item.indicators),
            "Entities": "; ".join(
                f"{e.entity_type.value}: {e.name}" for e, _ in item.entities
            ),
        })
    return pd.DataFrame(rows, columns=["Page", "Sentence", "Indicators", "Entities"])


# --- Phase 3: threat categories, ATT&CK mappings, risk ----------------------------------


def categories_frame(findings: list) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Category": category_label(f.category),
                "Status": f.status.value,
                "Sources": ", ".join(f.sources),
                "Sentences": f.sentence_count,
                "Max model score": None if f.max_score is None else round(f.max_score, 2),
                "Example": f.evidence[0].context,
            }
            for f in findings
        ],
        columns=["Category", "Status", "Sources", "Sentences", "Max model score", "Example"],
    )


def category_evidence_frame(finding) -> pd.DataFrame:
    return pd.DataFrame(
        [{"Page": e.page_number, "Source": e.source, "Status": e.status.value,
          "Score / terms": (f"{e.score:.2f}" if e.score is not None else ", ".join(e.terms)),
          "Sentence": e.context} for e in finding.evidence],
        columns=["Page", "Source", "Status", "Score / terms", "Sentence"],
    )


def mappings_frame(mappings: list) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "Technique": m.technique_id,
                "Name": m.name,
                "Tactics": ", ".join(m.tactics),
                "Status": m.status.value,
                "Method": ", ".join(m.methods),
                "Evidence": len(m.evidence),
                "Max model score": None if m.max_score is None else round(m.max_score, 2),
                "Verification": m.verdict.value,
                "ATT&CK": m.url,
            }
            for m in mappings
        ],
        columns=["Technique", "Name", "Tactics", "Status", "Method", "Evidence",
                 "Max model score", "Verification", "ATT&CK"],
    )


def mapping_evidence_frame(mapping) -> pd.DataFrame:
    return pd.DataFrame(
        [{"Page": e.page_number, "Method": e.method.value, "Status": e.status.value,
          "Matched": e.matched_text or "",
          "Score": None if e.score is None else round(e.score, 2),
          "Alternatives": ", ".join(f"{t} ({s:.2f})" for t, s in e.alternatives),
          "Sentence": e.context} for e in mapping.evidence],
        columns=["Page", "Method", "Status", "Matched", "Score", "Alternatives", "Sentence"],
    )


def risk_components_frame(risk) -> pd.DataFrame:
    return pd.DataFrame(
        [{"Component": c.label, "Weight": c.weight, "Value (0-100)": c.value,
          "Contribution": round(c.contribution, 1), "Why": " ".join(c.explanation)}
         for c in risk.components],
        columns=["Component", "Weight", "Value (0-100)", "Contribution", "Why"],
    )
