"""Rebuild domain objects from stored rows ("hydration").

The UI and reports render a ``StoredAnalysis``, whether the analysis was just run or
reopened from history. That gives one rendering path, and verdict widgets always act on
real database IDs. ``tests/test_views.py`` checks that save → load → hydrate reproduces the
original findings exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cached_property

from src.database.models import Analysis
from src.intelligence.analyzer import AnalysisResult
from src.intelligence.evidence_manager import VulnerabilityRecord, link_vulnerabilities
from src.intelligence.mitre_mapper import MappingMethod, TechniqueEvidence, TechniqueMapping
from src.intelligence.risk_scorer import Confidence, RiskAssessment, RiskComponent
from src.intelligence.threat_assessment import CategoryEvidence, ThreatCategoryFinding
from src.nlp.entity_models import Entity, EntityMention, EntitySource
from src.nlp.ioc_models import Indicator, IOCFlag, IOCOccurrence, IOCType


@dataclass
class StoredAnalysis:
    analysis_id: int
    document_id: int
    created_at: datetime
    filename: str
    sha256: str
    file_type: str
    size_bytes: int
    page_count: int
    sentence_count: int
    needs_ocr: bool
    metadata: dict[str, str]
    full_text: str | None
    indicators: list[Indicator]
    entities: list[Entity]
    categories: list[ThreatCategoryFinding]
    mappings: list[TechniqueMapping]
    risk: RiskAssessment
    components: dict[str, str]
    kb_versions: dict[str, str]
    warnings: list[str]
    document_warnings: list[str]
    timings_ms: dict[str, float]
    indicator_ids: dict[tuple[IOCType, str], int] = field(default_factory=dict)
    indicator_notes: dict[int, str | None] = field(default_factory=dict)
    mapping_ids: dict[str, int] = field(default_factory=dict)
    mapping_notes: dict[int, str | None] = field(default_factory=dict)

    @cached_property
    def vulnerabilities(self) -> list[VulnerabilityRecord]:
        return link_vulnerabilities(self.indicators, self.entities)


def view_from_result(result: AnalysisResult) -> StoredAnalysis:
    """View of an unsaved analysis (used when persistence is unavailable; no DB ids)."""
    doc = result.document
    return StoredAnalysis(
        analysis_id=0, document_id=0, created_at=datetime.now(UTC), filename=doc.filename,
        sha256=doc.sha256, file_type=doc.file_type.value, size_bytes=doc.size_bytes,
        page_count=doc.page_count, sentence_count=len(doc.sentences), needs_ocr=doc.needs_ocr,
        metadata=dict(doc.metadata), full_text=None, indicators=result.indicators,
        entities=result.entities, categories=result.categories, mappings=result.mappings,
        risk=result.risk, components=dict(result.components),
        kb_versions=dict(result.kb_versions), warnings=list(result.warnings),
        document_warnings=list(doc.warnings), timings_ms=dict(result.timings_ms))


def rescore_analysis(repo, analysis_id: int, scorer=None) -> StoredAnalysis:
    """Recompute a stored analysis' risk from its current verdicts and save it.

    Confirming a model suggestion makes it count; rejecting any mapping removes it. The
    findings themselves don't change, so this needs no access to the original document.
    """
    from src.intelligence.risk_scorer import RiskScorer

    view = hydrate(repo.get_analysis(analysis_id))
    risk = (scorer or RiskScorer()).rescore(view.risk, view.indicators, view.entities,
                                            view.vulnerabilities, view.mappings,
                                            view.categories)
    repo.update_risk(analysis_id, risk)
    return hydrate(repo.get_analysis(analysis_id))


def hydrate(analysis: Analysis) -> StoredAnalysis:
    document = analysis.document
    indicators, indicator_ids, indicator_notes = [], {}, {}
    for row in analysis.indicators:
        indicators.append(Indicator(
            ioc_type=row.ioc_type, value=row.value,
            occurrences=[IOCOccurrence(o.raw, o.page_number, o.char_start, o.char_end,
                                       o.defanged, o.sentence_index, o.context)
                         for o in row.occurrences],
            flags=frozenset(IOCFlag(f) for f in row.flags), verification=row.verification,
            source=row.source))
        indicator_ids[(row.ioc_type, row.value)] = row.id
        indicator_notes[row.id] = row.analyst_note

    entities = [
        Entity(entity_type=row.entity_type, name=row.name, source=EntitySource(row.source),
               kb_id=row.kb_id, attributes=dict(row.attributes),
               alternatives=tuple(row.alternatives),
               mentions=[EntityMention(m.text, m.page_number, m.char_start, m.char_end,
                                       m.sentence_index, m.context) for m in row.mentions])
        for row in analysis.entities
    ]
    categories = [
        ThreatCategoryFinding(row.category, [
            CategoryEvidence(e.sentence_index, e.page_number, e.context, e.source, e.status,
                             e.score, tuple(e.terms)) for e in row.evidence])
        for row in analysis.categories
    ]
    mappings, mapping_ids, mapping_notes = [], {}, {}
    for row in analysis.mappings:
        mappings.append(TechniqueMapping(
            row.technique_id, row.name, tuple(row.tactics), row.url,
            [TechniqueEvidence(e.sentence_index, e.page_number, e.context,
                               MappingMethod(e.method), e.status, e.matched_text, e.score,
                               tuple((a[0], a[1]) for a in e.alternatives))
             for e in row.evidence],
            verdict=row.verdict))
        mapping_ids[row.technique_id] = row.id
        mapping_notes[row.id] = row.analyst_note

    risk = RiskAssessment(
        score=analysis.risk_score, band=analysis.risk_band,
        components=tuple(RiskComponent(c.key, c.label, c.weight, c.value, tuple(c.explanation))
                         for c in analysis.risk_components),
        confidence=Confidence(analysis.confidence, tuple(analysis.confidence_reasons)),
        config_version=analysis.risk_config_version)

    return StoredAnalysis(
        analysis_id=analysis.id, document_id=document.id, created_at=analysis.created_at,
        filename=document.filename, sha256=document.sha256, file_type=document.file_type,
        size_bytes=document.size_bytes, page_count=document.page_count,
        sentence_count=document.sentence_count, needs_ocr=document.needs_ocr,
        metadata=dict(document.metadata_json), full_text=document.full_text,
        indicators=indicators, entities=entities, categories=categories, mappings=mappings,
        risk=risk, components=dict(analysis.components), kb_versions=dict(analysis.kb_versions),
        warnings=list(analysis.warnings), document_warnings=list(analysis.document_warnings),
        timings_ms=dict(analysis.timings_ms), indicator_ids=indicator_ids,
        indicator_notes=indicator_notes, mapping_ids=mapping_ids, mapping_notes=mapping_notes)
