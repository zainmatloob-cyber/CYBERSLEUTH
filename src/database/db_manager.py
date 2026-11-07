"""Database access: engine setup and the analysis repository.

The UI and reporting code talk only to ``AnalysisRepository``, never to SQL directly.

* ``save()`` stores an ``AnalysisResult``. The document is reused by SHA-256. An identical
  re-analysis (same document, same component and knowledge-base versions) is **not**
  duplicated unless ``force=True``.
* Verdict updates validate the new value, record an audit event, and run in one transaction.
* Cross-document queries look at the **latest analysis per document**, so re-analysing a
  report does not double its IOCs on the dashboard.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, selectinload, sessionmaker

from config.settings import settings
from src.database.models import (
    SCHEMA_VERSION,
    Analysis,
    Base,
    CategoryEvidenceRecord,
    Document,
    EntityMentionRecord,
    EntityRecord,
    Indicator,
    IndicatorOccurrence,
    RiskComponentRecord,
    TechniqueEvidenceRecord,
    TechniqueMappingRecord,
    ThreatCategoryRecord,
    VerificationEvent,
    VerificationTarget,
    utcnow,
)
from src.intelligence.analyzer import AnalysisResult
from src.intelligence.mitre_mapper import AnalystVerdict
from src.nlp.ioc_models import VerificationStatus
from src.utils.exceptions import CyberSleuthError

logger = logging.getLogger(__name__)
MAX_NOTE_LENGTH = 2000


class DatabaseError(CyberSleuthError):
    """Persistence failure or invalid request (unknown id, bad verdict, schema mismatch)."""


def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")  # off by default in SQLite, per connection
    cursor.close()


def make_engine(url: str | None = None) -> Engine:
    url = url or settings.database.url
    engine = create_engine(url, future=True)
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def init_db(engine: Engine) -> None:
    """Create tables and check the schema version (stored in PRAGMA user_version)."""
    with engine.begin() as connection:
        if engine.dialect.name == "sqlite":
            version = connection.execute(text("PRAGMA user_version")).scalar()
            has_tables = bool(connection.execute(text(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='documents'"
            )).scalar())
            if has_tables and version != SCHEMA_VERSION:
                raise DatabaseError(f"Database schema version {version} does not match "
                                    f"the application ({SCHEMA_VERSION}).")
        Base.metadata.create_all(connection)
        if engine.dialect.name == "sqlite":
            connection.execute(text(f"PRAGMA user_version = {SCHEMA_VERSION}"))


@dataclass(frozen=True)
class SaveOutcome:
    analysis_id: int
    document_id: int
    created: bool  # False → an identical analysis already existed


@dataclass(frozen=True)
class DashboardStats:
    documents: int
    analyses: int
    indicators: int
    entities: int
    techniques: int


def analysis_fingerprint(result: AnalysisResult) -> str:
    payload = json.dumps({"sha256": result.document.sha256, "components": result.components,
                          "kb": result.kb_versions}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class AnalysisRepository:
    def __init__(self, engine: Engine | None = None) -> None:
        self.engine = engine or make_engine()
        init_db(self.engine)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._sessions()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # --- writing --------------------------------------------------------------------

    def save(self, result: AnalysisResult, force: bool = False,
             store_full_text: bool | None = None) -> SaveOutcome:
        store_full_text = (settings.database.store_full_text if store_full_text is None
                           else store_full_text)
        doc = result.document
        fingerprint = analysis_fingerprint(result)
        with self.session() as session:
            document = session.scalar(select(Document).where(Document.sha256 == doc.sha256))
            if document is None:
                document = Document(
                    sha256=doc.sha256, filename=doc.filename, file_type=doc.file_type.value,
                    size_bytes=doc.size_bytes, page_count=doc.page_count,
                    sentence_count=len(doc.sentences), needs_ocr=doc.needs_ocr,
                    metadata_json=dict(doc.metadata),
                    full_text=doc.full_text if store_full_text else None)
                session.add(document)
                session.flush()
            elif not force:
                existing = session.scalar(
                    select(Analysis).where(Analysis.document_id == document.id,
                                           Analysis.fingerprint == fingerprint)
                    .order_by(Analysis.created_at.desc()))
                if existing is not None:
                    logger.info("Analysis of %s already stored (id %d)", doc.filename,
                                existing.id)
                    return SaveOutcome(existing.id, document.id, created=False)

            analysis = self._build_analysis(result, fingerprint)
            document.analyses.append(analysis)
            session.flush()
            logger.info("Stored analysis %d of %s", analysis.id, doc.filename)
            return SaveOutcome(analysis.id, document.id, created=True)

    @staticmethod
    def _build_analysis(result: AnalysisResult, fingerprint: str) -> Analysis:
        risk = result.risk
        analysis = Analysis(
            fingerprint=fingerprint, components=dict(result.components),
            kb_versions=dict(result.kb_versions), warnings=list(result.warnings),
            document_warnings=list(result.document.warnings),
            timings_ms={k: round(v, 1) for k, v in result.timings_ms.items()},
            risk_score=risk.score, risk_band=risk.band, confidence=risk.confidence.level,
            confidence_reasons=list(risk.confidence.reasons),
            risk_config_version=risk.config_version)

        for i in result.indicators:
            analysis.indicators.append(Indicator(
                ioc_type=i.ioc_type, value=i.value, flags=sorted(f.value for f in i.flags),
                defanged=i.defanged, occurrence_count=i.count, source=i.source,
                verification=i.verification,
                occurrences=[IndicatorOccurrence(raw=o.raw, page_number=o.page_number,
                                                 char_start=o.char_start, char_end=o.char_end,
                                                 context=o.context) for o in i.occurrences]))
        for e in result.entities:
            analysis.entities.append(EntityRecord(
                entity_type=e.entity_type, name=e.name, source=e.source.value, kb_id=e.kb_id,
                attributes=dict(e.attributes), alternatives=list(e.alternatives),
                mention_count=e.count,
                mentions=[EntityMentionRecord(text=m.text, page_number=m.page_number,
                                              char_start=m.char_start, char_end=m.char_end,
                                              context=m.context) for m in e.mentions]))
        for c in result.categories:
            analysis.categories.append(ThreatCategoryRecord(
                category=c.category, status=c.status, sources=c.sources,
                sentence_count=c.sentence_count, max_score=c.max_score,
                evidence=[CategoryEvidenceRecord(page_number=e.page_number, source=e.source,
                                                 status=e.status, score=e.score,
                                                 terms=list(e.terms), context=e.context)
                          for e in c.evidence]))
        for m in result.mappings:
            analysis.mappings.append(TechniqueMappingRecord(
                technique_id=m.technique_id, name=m.name, tactics=list(m.tactics), url=m.url,
                status=m.status, methods=m.methods, explicit=m.explicit,
                max_score=m.max_score, verdict=m.verdict,
                evidence=[TechniqueEvidenceRecord(
                    page_number=e.page_number, method=e.method.value, status=e.status,
                    matched_text=e.matched_text, score=e.score,
                    alternatives=[list(a) for a in e.alternatives], context=e.context)
                    for e in m.evidence]))
        for position, c in enumerate(risk.components):
            analysis.risk_components.append(RiskComponentRecord(
                position=position, key=c.key, label=c.label, weight=c.weight, value=c.value,
                contribution=round(c.contribution, 2), explanation=list(c.explanation)))
        return analysis

    def _set_verdict(self, model, target: VerificationTarget, item_id: int, field: str,
                     new_value, note: str | None, analyst: str | None) -> None:
        if note is not None and len(note) > MAX_NOTE_LENGTH:
            raise DatabaseError(f"Note exceeds {MAX_NOTE_LENGTH} characters.")
        with self.session() as session:
            item = session.get(model, item_id)
            if item is None:
                raise DatabaseError(f"{target.value} {item_id} not found.")
            old = getattr(item, field)
            setattr(item, field, new_value)
            item.analyst_note = note
            item.verified_at = utcnow()
            session.add(VerificationEvent(
                target_type=target, target_id=item_id, analysis_id=item.analysis_id,
                old_value=old.value, new_value=new_value.value, note=note,
                analyst=(analyst or settings.database.analyst_name)[:64]))

    def set_indicator_verdict(self, indicator_id: int, verdict: VerificationStatus | str,
                              note: str | None = None, analyst: str | None = None) -> None:
        try:
            verdict = VerificationStatus(verdict)
        except ValueError as exc:
            raise DatabaseError(f"Invalid indicator verdict {verdict!r}") from exc
        self._set_verdict(Indicator, VerificationTarget.INDICATOR, indicator_id,
                          "verification", verdict, note, analyst)

    def set_mapping_verdict(self, mapping_id: int, verdict: AnalystVerdict | str,
                            note: str | None = None, analyst: str | None = None) -> None:
        try:
            verdict = AnalystVerdict(verdict)
        except ValueError as exc:
            raise DatabaseError(f"Invalid mapping verdict {verdict!r}") from exc
        self._set_verdict(TechniqueMappingRecord, VerificationTarget.TECHNIQUE_MAPPING,
                          mapping_id, "verdict", verdict, note, analyst)

    def delete_document(self, document_id: int) -> None:
        with self.session() as session:
            document = session.get(Document, document_id)
            if document is None:
                raise DatabaseError(f"document {document_id} not found.")
            session.delete(document)

    # --- reading --------------------------------------------------------------------

    def get_analysis(self, analysis_id: int) -> Analysis:
        """Fully loaded analysis (detached; safe to use after the session closes)."""
        with self.session() as session:
            analysis = session.scalar(
                select(Analysis).where(Analysis.id == analysis_id).options(
                    selectinload(Analysis.document),
                    selectinload(Analysis.indicators).selectinload(Indicator.occurrences),
                    selectinload(Analysis.entities).selectinload(EntityRecord.mentions),
                    selectinload(Analysis.categories).selectinload(
                        ThreatCategoryRecord.evidence),
                    selectinload(Analysis.mappings).selectinload(
                        TechniqueMappingRecord.evidence),
                    selectinload(Analysis.risk_components)))
            if analysis is None:
                raise DatabaseError(f"analysis {analysis_id} not found.")
            return analysis

    def list_analyses(self, limit: int = 200) -> list[Analysis]:
        with self.session() as session:
            return list(session.scalars(
                select(Analysis).options(selectinload(Analysis.document))
                .order_by(Analysis.created_at.desc(), Analysis.id.desc()).limit(limit)))

    def _latest_ids(self, session: Session):
        """Subquery: the most recent analysis id per document."""
        return (select(func.max(Analysis.id)).group_by(Analysis.document_id)).scalar_subquery()

    def latest_indicators(self) -> list[Indicator]:
        with self.session() as session:
            return list(session.scalars(
                select(Indicator).where(Indicator.analysis_id.in_(self._latest_ids(session)))
                .options(selectinload(Indicator.occurrences),
                         selectinload(Indicator.analysis).selectinload(Analysis.document))))

    def latest_entities(self) -> list[EntityRecord]:
        with self.session() as session:
            return list(session.scalars(
                select(EntityRecord)
                .where(EntityRecord.analysis_id.in_(self._latest_ids(session)))
                .options(selectinload(EntityRecord.analysis).selectinload(Analysis.document))))

    def latest_mappings(self) -> list[TechniqueMappingRecord]:
        with self.session() as session:
            return list(session.scalars(
                select(TechniqueMappingRecord)
                .where(TechniqueMappingRecord.analysis_id.in_(self._latest_ids(session)))
                .options(selectinload(TechniqueMappingRecord.evidence),
                         selectinload(TechniqueMappingRecord.analysis)
                         .selectinload(Analysis.document))))

    def verification_events(self, analysis_id: int | None = None) -> list[VerificationEvent]:
        with self.session() as session:
            query = select(VerificationEvent).order_by(VerificationEvent.id)
            if analysis_id is not None:
                query = query.where(VerificationEvent.analysis_id == analysis_id)
            return list(session.scalars(query))

    def stats(self) -> DashboardStats:
        with self.session() as session:
            latest = self._latest_ids(session)

            def count(model, *where) -> int:
                return session.scalar(select(func.count()).select_from(model).where(*where))

            return DashboardStats(
                documents=count(Document),
                analyses=count(Analysis),
                indicators=count(Indicator, Indicator.analysis_id.in_(latest)),
                entities=count(EntityRecord, EntityRecord.analysis_id.in_(latest)),
                techniques=count(TechniqueMappingRecord,
                                 TechniqueMappingRecord.analysis_id.in_(latest)),
            )
