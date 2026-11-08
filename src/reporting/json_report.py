"""Complete, machine-readable analysis export (versioned schema).

Layout (``schema_version`` 1.1, documented in ``docs/reports.md``)::

    report      generator, schema version, generation time, limitations
    document    filename, hash, type, size, pages, sentences, OCR flag, embedded metadata
    analysis    id, time, risk model version, components, KB versions, warnings
    summary     the template-based executive summary sentences
    risk        score, band, confidence (+ reasons), components with explanations
    indicators  value (canonical) + value_defanged, flags, verdict, note, occurrences
    entities    type, name, ATT&CK id, source, aliases, mentions
    vulnerabilities, threat_categories, attack_techniques   each with full evidence
    verification_history   the append-only audit trail for this analysis

Evidence sentences are defanged. Full document text is never included.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from src.database.models import VerificationEvent
from src.database.views import StoredAnalysis
from src.reporting.common import (
    GENERATOR,
    REPORT_LIMITATIONS,
    REPORT_SCHEMA_VERSION,
    TextDefanger,
    defang,
    executive_summary,
    generated_at,
)
from src.visualization.tables import attack_url, nvd_url


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


def event_dicts(events: Sequence[VerificationEvent]) -> list[dict]:
    return [{"time": e.created_at.isoformat(timespec="seconds"),
             "target_type": e.target_type.value, "target_id": e.target_id,
             "from": e.old_value, "to": e.new_value, "analyst": e.analyst, "note": e.note}
            for e in events]


def build_report(view: StoredAnalysis,
                 events: Sequence[VerificationEvent] = ()) -> dict:
    clean = TextDefanger(view.indicators)
    risk = view.risk
    return {
        "report": {
            "generator": GENERATOR, "schema_version": REPORT_SCHEMA_VERSION,
            "generated_at": generated_at(),
            "limitations": [*REPORT_LIMITATIONS, *risk.limitations],
        },
        "document": {
            "filename": view.filename, "sha256": view.sha256, "file_type": view.file_type,
            "size_bytes": view.size_bytes, "page_count": view.page_count,
            "sentence_count": view.sentence_count, "needs_ocr": view.needs_ocr,
            "embedded_metadata": dict(view.metadata),
        },
        "analysis": {
            "id": view.analysis_id or None,
            "analysed_at": view.created_at.isoformat(timespec="seconds"),
            "risk_model_version": risk.config_version,
            "components": dict(view.components), "knowledge_bases": dict(view.kb_versions),
            "warnings": [*view.warnings, *view.document_warnings],
        },
        "summary": executive_summary(view),
        "risk": {
            "score": round(risk.score, 1), "band": risk.band,
            "confidence": {"level": risk.confidence.level,
                           "reasons": list(risk.confidence.reasons)},
            "components": [
                {"key": c.key, "label": c.label, "weight": c.weight, "value": c.value,
                 "contribution": round(c.contribution, 2), "explanation": list(c.explanation)}
                for c in risk.components],
        },
        "indicators": [
            {
                "type": i.ioc_type.value, "value": i.value,
                "value_defanged": defang(i.ioc_type, i.value),
                "flags": sorted(f.value for f in i.flags), "verification": i.verification.value,
                "analyst_note": view.indicator_notes.get(
                    view.indicator_ids.get((i.ioc_type, i.value), -1)),
                "source": i.source, "pages": i.pages,
                "occurrences": [
                    {"page": o.page_number, "as_written": defang(i.ioc_type, o.raw)
                     if not o.defanged else o.raw, "was_defanged": o.defanged,
                     "sentence_index": o.sentence_index, "context": clean(o.context)}
                    for o in i.occurrences],
            }
            for i in view.indicators
        ],
        "entities": [
            {
                "type": e.entity_type.value, "name": e.name, "attack_id": e.kb_id,
                "reference": attack_url(e.kb_id), "source": e.source.value,
                "aliases_seen": e.aliases_seen, "alternatives": list(e.alternatives),
                "attributes": dict(e.attributes), "confidence": e.confidence,
                "mentions": [{"page": m.page_number, "as_written": m.text,
                              "sentence_index": m.sentence_index, "context": clean(m.context)}
                             for m in e.mentions],
            }
            for e in view.entities
        ],
        "vulnerabilities": [
            {"cve": v.cve_id, "names": list(v.names), "mentioned_by": v.mentioned_by,
             "id_mentions": v.id_mentions, "name_mentions": v.name_mentions,
             "pages": list(v.pages), "reference": nvd_url(v.cve_id)}
            for v in view.vulnerabilities
        ],
        "threat_categories": [
            {
                "category": c.category, "status": c.status.value, "sources": c.sources,
                "sentence_count": c.sentence_count, "max_model_score": _round(c.max_score),
                "evidence": [{"page": e.page_number, "sentence_index": e.sentence_index,
                              "source": e.source, "status": e.status.value,
                              "score": _round(e.score), "terms": list(e.terms),
                              "sentence": clean(e.context)} for e in c.evidence],
            }
            for c in view.categories
        ],
        "attack_techniques": [
            {
                "technique_id": m.technique_id, "name": m.name, "tactics": list(m.tactics),
                "reference": m.url, "status": m.status.value, "methods": m.methods,
                "explicit": m.explicit, "unverified_model_lead": m.is_unverified_lead,
                "max_model_score": _round(m.max_score),
                "verification": m.verdict.value,
                "analyst_note": view.mapping_notes.get(view.mapping_ids.get(m.technique_id, -1)),
                "evidence": [{"page": e.page_number, "sentence_index": e.sentence_index,
                              "method": e.method.value, "status": e.status.value,
                              "matched_text": e.matched_text, "score": _round(e.score),
                              "alternatives": [[t, _round(s)] for t, s in e.alternatives],
                              "sentence": clean(e.context)} for e in m.evidence],
            }
            for m in view.mappings
        ],
        "verification_history": event_dicts(events),
    }


def to_json(view: StoredAnalysis, events: Sequence[VerificationEvent] = ()) -> bytes:
    return json.dumps(build_report(view, events), indent=2, ensure_ascii=False).encode("utf-8")
