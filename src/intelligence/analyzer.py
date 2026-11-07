"""Document analysis orchestrator: ingestion → IOC extraction → entity recognition.

``Analyzer`` holds the expensive components (spaCy model, phrase matchers), so
create it once and reuse it (the Streamlit app caches it as a resource).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from functools import cached_property

from config.settings import settings
from src.ingestion.models import ExtractedDocument
from src.ingestion.pipeline import Stage, ingest
from src.intelligence.evidence_manager import (
    SentenceEvidence,
    VulnerabilityRecord,
    build_sentence_evidence,
    link_vulnerabilities,
)
from src.nlp.entity_extractor import EntityExtractor
from src.nlp.entity_models import Entity
from src.nlp.ioc_extractor import IOCExtractor
from src.nlp.ioc_models import Indicator
from src.utils.exceptions import ModelNotAvailableError

logger = logging.getLogger(__name__)


class AnalysisStage(StrEnum):
    """All stages, in order. The first four mirror ``src.ingestion.pipeline.Stage``."""

    VALIDATING = "Validating file"
    EXTRACTING = "Extracting text"
    CLEANING = "Cleaning text"
    SEGMENTING = "Segmenting sentences"
    IOCS = "Extracting indicators"
    ENTITIES = "Recognising entities"
    DONE = "Done"


AnalysisProgress = Callable[[AnalysisStage], None]


@dataclass
class AnalysisResult:
    document: ExtractedDocument
    indicators: list[Indicator]
    entities: list[Entity]
    model_name: str | None  # None → entity recognition ran in rules-only mode
    kb_versions: dict[str, str]
    warnings: list[str] = field(default_factory=list)  # analysis-level (not document) warnings
    timings_ms: dict[str, float] = field(default_factory=dict)

    @cached_property
    def evidence(self) -> list[SentenceEvidence]:
        return build_sentence_evidence(self.document, self.indicators, self.entities)

    @cached_property
    def vulnerabilities(self) -> list[VulnerabilityRecord]:
        return link_vulnerabilities(self.indicators, self.entities)


class Analyzer:
    """Reusable analysis pipeline."""

    def __init__(
        self,
        ioc_extractor: IOCExtractor | None = None,
        entity_extractor: EntityExtractor | None = None,
        model: str | None = settings.nlp.spacy_model,
    ) -> None:
        self.warnings: list[str] = []
        self.ioc_extractor = ioc_extractor or IOCExtractor()
        if entity_extractor is None:
            try:
                entity_extractor = EntityExtractor(model=model)
            except ModelNotAvailableError as exc:
                # Degrade gracefully: deterministic rules still work without the model.
                logger.warning("%s Falling back to rule-based entity recognition.", exc)
                self.warnings.append(
                    f"{exc} Organisation and location recognition is disabled; "
                    "knowledge-base and pattern rules still run."
                )
                entity_extractor = EntityExtractor(model=None)
        self.entity_extractor = entity_extractor

    def analyze(
        self, data: bytes, filename: str, on_progress: AnalysisProgress | None = None
    ) -> AnalysisResult:
        report = on_progress or (lambda _stage: None)
        timings: dict[str, float] = {}

        def forward(stage: Stage) -> None:
            if stage is not Stage.DONE:  # DONE is reported once, at the very end
                report(AnalysisStage(stage.value))

        started = time.perf_counter()
        document = ingest(data, filename, on_progress=forward)
        timings["ingestion"] = (time.perf_counter() - started) * 1000

        report(AnalysisStage.IOCS)
        step = time.perf_counter()
        indicators = self.ioc_extractor.extract(document)
        timings["iocs"] = (time.perf_counter() - step) * 1000

        report(AnalysisStage.ENTITIES)
        step = time.perf_counter()
        entities = self.entity_extractor.extract(document)
        timings["entities"] = (time.perf_counter() - step) * 1000

        report(AnalysisStage.DONE)
        timings["total"] = (time.perf_counter() - started) * 1000
        return AnalysisResult(
            document=document,
            indicators=indicators,
            entities=entities,
            model_name=self.entity_extractor.model_name,
            kb_versions=dict(self.entity_extractor.kb.versions),
            warnings=list(self.warnings),
            timings_ms=timings,
        )
