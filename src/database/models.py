"""SQLAlchemy 2.0 ORM schema.

Entity–relationship overview::

    Document 1──* Analysis 1──* Indicator 1──* IndicatorOccurrence
                           ├──* EntityRecord 1──* EntityMentionRecord
                           ├──* ThreatCategoryRecord 1──* CategoryEvidenceRecord
                           ├──* TechniqueMappingRecord 1──* TechniqueEvidenceRecord
                           └──* RiskComponentRecord
    VerificationEvent (audit log of analyst verdict changes)

* A ``Document`` is unique by SHA-256. Each (re-)analysis is a separate ``Analysis`` row.
* Finding tables are unique per analysis (for example one row per (type, value) indicator).
* Enum columns are stored as strings with CHECK constraints. Timestamps are UTC.
* Deleting a document cascades to everything derived from it (``ON DELETE CASCADE``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from src.intelligence.assertion import AssertionStatus
from src.intelligence.mitre_mapper import AnalystVerdict
from src.nlp.entity_models import EntityType
from src.nlp.ioc_models import IOCType, VerificationStatus

SCHEMA_VERSION = 1


def utcnow() -> datetime:
    return datetime.now(UTC)


def _enum(cls: type[StrEnum], name: str) -> Enum:
    # native_enum=False → VARCHAR + CHECK constraint (portable, enforced by SQLite).
    return Enum(cls, name=name, native_enum=False, create_constraint=True,
                values_callable=lambda e: [m.value for m in e], length=32)


class VerificationTarget(StrEnum):
    INDICATOR = "indicator"
    TECHNIQUE_MAPPING = "technique_mapping"


class Base(DeclarativeBase):
    type_annotation_map = {dict: JSON, list: JSON}


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_type: Mapped[str] = mapped_column(String(8))
    size_bytes: Mapped[int]
    page_count: Mapped[int]
    sentence_count: Mapped[int]
    needs_ocr: Mapped[bool] = mapped_column(Boolean, default=False)
    metadata_json: Mapped[dict] = mapped_column(default=dict)
    full_text: Mapped[str | None] = mapped_column(Text, default=None)  # only if opted in
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    analyses: Mapped[list[Analysis]] = relationship(
        back_populates="document", cascade="all, delete-orphan", passive_deletes=True,
        order_by="Analysis.created_at")

    __table_args__ = (CheckConstraint("length(sha256) = 64", name="ck_document_sha256"),)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"),
                                             index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow,
                                                 index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))  # component + KB versions
    components: Mapped[dict] = mapped_column(default=dict)
    kb_versions: Mapped[dict] = mapped_column(default=dict)
    warnings: Mapped[list] = mapped_column(default=list)
    document_warnings: Mapped[list] = mapped_column(default=list)
    timings_ms: Mapped[dict] = mapped_column(default=dict)
    risk_score: Mapped[float] = mapped_column(Float)
    risk_band: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(8))
    confidence_reasons: Mapped[list] = mapped_column(default=list)
    risk_config_version: Mapped[str] = mapped_column(String(32))

    document: Mapped[Document] = relationship(back_populates="analyses")
    indicators: Mapped[list[Indicator]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True)
    entities: Mapped[list[EntityRecord]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True)
    categories: Mapped[list[ThreatCategoryRecord]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True)
    mappings: Mapped[list[TechniqueMappingRecord]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True)
    risk_components: Mapped[list[RiskComponentRecord]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True,
        order_by="RiskComponentRecord.position")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_analysis_risk"),
        CheckConstraint("confidence IN ('high', 'medium', 'low')", name="ck_analysis_conf"),
    )


class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"),
                                             index=True)
    ioc_type: Mapped[IOCType] = mapped_column(_enum(IOCType, "ioc_type"), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    flags: Mapped[list] = mapped_column(default=list)
    defanged: Mapped[bool] = mapped_column(Boolean, default=False)
    occurrence_count: Mapped[int]
    source: Mapped[str] = mapped_column(String(32))
    verification: Mapped[VerificationStatus] = mapped_column(
        _enum(VerificationStatus, "verification_status"), default=VerificationStatus.UNVERIFIED)
    analyst_note: Mapped[str | None] = mapped_column(Text, default=None)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    analysis: Mapped[Analysis] = relationship(back_populates="indicators")
    occurrences: Mapped[list[IndicatorOccurrence]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (UniqueConstraint("analysis_id", "ioc_type", "value",
                                       name="uq_indicator_per_analysis"),)


class IndicatorOccurrence(Base):
    __tablename__ = "indicator_occurrences"

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"),
                                              index=True)
    raw: Mapped[str] = mapped_column(String(2048))
    page_number: Mapped[int]
    char_start: Mapped[int]
    char_end: Mapped[int]
    context: Mapped[str] = mapped_column(Text)

    indicator: Mapped[Indicator] = relationship(back_populates="occurrences")


class EntityRecord(Base):
    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"),
                                             index=True)
    entity_type: Mapped[EntityType] = mapped_column(_enum(EntityType, "entity_type"),
                                                    index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(32))
    kb_id: Mapped[str | None] = mapped_column(String(16), default=None)
    attributes: Mapped[dict] = mapped_column(default=dict)
    alternatives: Mapped[list] = mapped_column(default=list)
    mention_count: Mapped[int]

    analysis: Mapped[Analysis] = relationship(back_populates="entities")
    mentions: Mapped[list[EntityMentionRecord]] = relationship(
        back_populates="entity", cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (UniqueConstraint("analysis_id", "entity_type", "name",
                                       name="uq_entity_per_analysis"),)


class EntityMentionRecord(Base):
    __tablename__ = "entity_mentions"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"),
                                           index=True)
    text: Mapped[str] = mapped_column(String(512))
    page_number: Mapped[int]
    char_start: Mapped[int]
    char_end: Mapped[int]
    context: Mapped[str] = mapped_column(Text)

    entity: Mapped[EntityRecord] = relationship(back_populates="mentions")


class ThreatCategoryRecord(Base):
    __tablename__ = "threat_categories"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"),
                                             index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[AssertionStatus] = mapped_column(_enum(AssertionStatus, "assertion_status"))
    sources: Mapped[list] = mapped_column(default=list)
    sentence_count: Mapped[int]
    max_score: Mapped[float | None] = mapped_column(Float, default=None)

    analysis: Mapped[Analysis] = relationship(back_populates="categories")
    evidence: Mapped[list[CategoryEvidenceRecord]] = relationship(
        back_populates="category", cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (UniqueConstraint("analysis_id", "category",
                                       name="uq_category_per_analysis"),)


class CategoryEvidenceRecord(Base):
    __tablename__ = "category_evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    category_id: Mapped[int] = mapped_column(
        ForeignKey("threat_categories.id", ondelete="CASCADE"), index=True)
    page_number: Mapped[int]
    source: Mapped[str] = mapped_column(String(16))
    status: Mapped[AssertionStatus] = mapped_column(_enum(AssertionStatus, "assertion_status"))
    score: Mapped[float | None] = mapped_column(Float, default=None)
    terms: Mapped[list] = mapped_column(default=list)
    context: Mapped[str] = mapped_column(Text)

    category: Mapped[ThreatCategoryRecord] = relationship(back_populates="evidence")


class TechniqueMappingRecord(Base):
    __tablename__ = "technique_mappings"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"),
                                             index=True)
    technique_id: Mapped[str] = mapped_column(String(16), index=True)
    name: Mapped[str] = mapped_column(String(255))
    tactics: Mapped[list] = mapped_column(default=list)
    url: Mapped[str] = mapped_column(String(255))
    status: Mapped[AssertionStatus] = mapped_column(_enum(AssertionStatus, "assertion_status"))
    methods: Mapped[list] = mapped_column(default=list)
    explicit: Mapped[bool] = mapped_column(Boolean)
    max_score: Mapped[float | None] = mapped_column(Float, default=None)
    verdict: Mapped[AnalystVerdict] = mapped_column(_enum(AnalystVerdict, "analyst_verdict"),
                                                    default=AnalystVerdict.UNVERIFIED)
    analyst_note: Mapped[str | None] = mapped_column(Text, default=None)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    analysis: Mapped[Analysis] = relationship(back_populates="mappings")
    evidence: Mapped[list[TechniqueEvidenceRecord]] = relationship(
        back_populates="mapping", cascade="all, delete-orphan", passive_deletes=True)

    __table_args__ = (
        UniqueConstraint("analysis_id", "technique_id", name="uq_mapping_per_analysis"),
        CheckConstraint("technique_id GLOB 'T[0-9][0-9][0-9][0-9]*'", name="ck_technique_id"),
    )


class TechniqueEvidenceRecord(Base):
    __tablename__ = "technique_evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    mapping_id: Mapped[int] = mapped_column(
        ForeignKey("technique_mappings.id", ondelete="CASCADE"), index=True)
    page_number: Mapped[int]
    method: Mapped[str] = mapped_column(String(16))
    status: Mapped[AssertionStatus] = mapped_column(_enum(AssertionStatus, "assertion_status"))
    matched_text: Mapped[str | None] = mapped_column(String(512), default=None)
    score: Mapped[float | None] = mapped_column(Float, default=None)
    alternatives: Mapped[list] = mapped_column(default=list)
    context: Mapped[str] = mapped_column(Text)

    mapping: Mapped[TechniqueMappingRecord] = relationship(back_populates="evidence")


class RiskComponentRecord(Base):
    __tablename__ = "risk_components"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"),
                                             index=True)
    position: Mapped[int]
    key: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(64))
    weight: Mapped[float]
    value: Mapped[float]
    contribution: Mapped[float]
    explanation: Mapped[list] = mapped_column(default=list)

    analysis: Mapped[Analysis] = relationship(back_populates="risk_components")

    __table_args__ = (
        UniqueConstraint("analysis_id", "key", name="uq_risk_component"),
        CheckConstraint("value >= 0 AND value <= 100", name="ck_risk_component_value"),
    )


class VerificationEvent(Base):
    """Append-only audit trail of analyst verdict changes."""

    __tablename__ = "verification_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_type: Mapped[VerificationTarget] = mapped_column(
        _enum(VerificationTarget, "verification_target"))
    target_id: Mapped[int] = mapped_column(Integer, index=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"),
                                             index=True)
    old_value: Mapped[str] = mapped_column(String(32))
    new_value: Mapped[str] = mapped_column(String(32))
    note: Mapped[str | None] = mapped_column(Text, default=None)
    analyst: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
