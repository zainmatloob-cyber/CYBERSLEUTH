"""Document analysis orchestrator.

Stages: ingestion → IOC extraction → entity recognition → threat classification →
ATT&CK mapping → risk scoring.

``Analyzer`` holds the expensive components (spaCy model, phrase matchers, trained
classifiers), so create it once and reuse it (the Streamlit app caches it as a resource).

Graceful degradation: when a model is missing, the stage falls back to its deterministic
part (rules / explicit matching) and the analysis records a warning, which also lowers
the risk assessment's confidence. ``use_models=False`` selects that deterministic mode
on purpose (no warnings), e.g. for tests.
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
from src.intelligence.mitre_mapper import TechniqueMapper, TechniqueMapping
from src.intelligence.risk_scorer import RiskAssessment, RiskScorer
from src.intelligence.threat_assessment import ThreatAssessor, ThreatCategoryFinding
from src.ml.threat_classifier import ModelError, ThreatClassifier
from src.nlp.entity_extractor import EntityExtractor
from src.nlp.entity_models import Entity
from src.nlp.ioc_extractor import IOCExtractor
from src.nlp.ioc_models import Indicator
from src.utils.exceptions import ModelNotAvailableError

logger = logging.getLogger(__name__)
THREAT_MODEL_PATH = settings.data_dir.parent / "models" / "threat_classifier.joblib"


class AnalysisStage(StrEnum):
    """All stages, in order. The first four mirror ``src.ingestion.pipeline.Stage``."""

    VALIDATING = "Validating file"
    EXTRACTING = "Extracting text"
    CLEANING = "Cleaning text"
    SEGMENTING = "Segmenting sentences"
    IOCS = "Extracting indicators"
    ENTITIES = "Recognising entities"
    CLASSIFYING = "Classifying threats"
    MAPPING = "Mapping ATT&CK techniques"
    SCORING = "Scoring risk"
    DONE = "Done"


AnalysisProgress = Callable[[AnalysisStage], None]


@dataclass
class AnalysisResult:
    document: ExtractedDocument
    indicators: list[Indicator]
    entities: list[Entity]
    categories: list[ThreatCategoryFinding]
    mappings: list[TechniqueMapping]
    risk: RiskAssessment
    components: dict[str, str]  # stage → component/mode used (provenance)
    kb_versions: dict[str, str]
    warnings: list[str] = field(default_factory=list)  # analysis-level (not document) warnings
    timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def model_name(self) -> str | None:
        """NER model name; ``None`` when entity recognition ran rules-only."""
        name = self.components.get("entities", "")
        return None if name == "rules-only" else name

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
        threat_classifier: ThreatClassifier | None = None,
        technique_mapper: TechniqueMapper | None = None,
        risk_scorer: RiskScorer | None = None,
        model: str | None = settings.nlp.spacy_model,
        use_models: bool = True,
    ) -> None:
        self.warnings: list[str] = []
        self.ioc_extractor = ioc_extractor or IOCExtractor()

        if entity_extractor is None:
            entity_extractor = self._entity_extractor(model if use_models else None)
        self.entity_extractor = entity_extractor

        if threat_classifier is None and use_models:
            try:
                threat_classifier = ThreatClassifier.load(THREAT_MODEL_PATH)
            except ModelError as exc:
                logger.warning("%s Using the rule baseline only.", exc)
                self.warnings.append(f"{exc} Threat categories come from rules only.")
        self.threat_assessor = ThreatAssessor(threat_classifier)

        if technique_mapper is None:
            technique_mapper = TechniqueMapper(use_model=use_models)
            self.warnings.extend(technique_mapper.warnings)
        self.technique_mapper = technique_mapper
        self.risk_scorer = risk_scorer or RiskScorer()

    def _entity_extractor(self, model: str | None) -> EntityExtractor:
        if model is None:
            return EntityExtractor(model=None)
        try:
            return EntityExtractor(model=model)
        except ModelNotAvailableError as exc:
            # Degrade gracefully: deterministic rules still work without the model.
            logger.warning("%s Falling back to rule-based entity recognition.", exc)
            self.warnings.append(
                f"{exc} Organisation and location recognition is disabled; "
                "knowledge-base and pattern rules still run."
            )
            return EntityExtractor(model=None)

    @property
    def components(self) -> dict[str, str]:
        return {
            "entities": self.entity_extractor.model_name or "rules-only",
            "threat_classification": "model+rules" if self.threat_assessor.classifier
            else "rules-only",
            "technique_mapping": "explicit+model" if self.technique_mapper.model
            else "explicit-only",
        }

    def analyze(
        self, data: bytes, filename: str, on_progress: AnalysisProgress | None = None
    ) -> AnalysisResult:
        report = on_progress or (lambda _stage: None)
        timings: dict[str, float] = {}

        def forward(stage: Stage) -> None:
            if stage is not Stage.DONE:  # DONE is reported once, at the very end
                report(AnalysisStage(stage.value))

        def timed(name: str, stage: AnalysisStage, fn):
            report(stage)
            started = time.perf_counter()
            value = fn()
            timings[name] = (time.perf_counter() - started) * 1000
            return value

        started = time.perf_counter()
        document = ingest(data, filename, on_progress=forward)
        timings["ingestion"] = (time.perf_counter() - started) * 1000

        indicators = timed("iocs", AnalysisStage.IOCS,
                           lambda: self.ioc_extractor.extract(document))
        entities = timed("entities", AnalysisStage.ENTITIES,
                         lambda: self.entity_extractor.extract(document))
        categories = timed("classification", AnalysisStage.CLASSIFYING,
                           lambda: self.threat_assessor.assess(document))
        mappings = timed("mapping", AnalysisStage.MAPPING,
                         lambda: self.technique_mapper.map(document, entities))
        vulnerabilities = link_vulnerabilities(indicators, entities)
        risk = timed("risk", AnalysisStage.SCORING, lambda: self.risk_scorer.score(
            document, indicators, entities, vulnerabilities, mappings, categories,
            degraded=self.warnings))

        report(AnalysisStage.DONE)
        timings["total"] = (time.perf_counter() - started) * 1000
        result = AnalysisResult(
            document=document,
            indicators=indicators,
            entities=entities,
            categories=categories,
            mappings=mappings,
            risk=risk,
            components=self.components,
            kb_versions={**self.entity_extractor.kb.versions,
                         "attack_techniques": self.technique_mapper.kb.version,
                         "risk_model": risk.config_version},
            warnings=list(self.warnings),
            timings_ms=timings,
        )
        result.__dict__["vulnerabilities"] = vulnerabilities  # reuse the computed view
        return result
