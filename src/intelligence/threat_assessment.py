"""Report-level threat categories aggregated from sentence-level predictions.

For each sentence:
* the ML classifier (if available) predicts learned categories, with scores;
* the rule baseline reports keyword evidence for every category (including ``ddos`` and
  ``malware``, which the model cannot learn).

A category is reported when at least one sentence supports it. Each piece of evidence keeps
its source, score or matched terms, and the sentence's assertion status. A category whose
only evidence is negated ("no ransomware was deployed") is kept but marked negated, so the
analyst can see it was considered.

Aggregation is a simple "any sentence" rule. It is **not** validated against report-level
labels (none exist in the training data).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from src.ingestion.models import ExtractedDocument
from src.intelligence.assertion import STATUS_RANK, AssertionStatus, assertion_status
from src.ml.dataset import OTHER
from src.ml.rule_classifier import RuleBasedClassifier
from src.ml.threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)
_MAX_EVIDENCE_PER_SOURCE = 25


@dataclass(frozen=True)
class CategoryEvidence:
    sentence_index: int
    page_number: int
    context: str
    source: str  # "model" | "rules"
    status: AssertionStatus
    score: float | None = None
    terms: tuple[str, ...] = ()


@dataclass
class ThreatCategoryFinding:
    category: str
    evidence: list[CategoryEvidence] = field(default_factory=list)

    @property
    def sources(self) -> list[str]:
        return sorted({e.source for e in self.evidence})

    @property
    def status(self) -> AssertionStatus:
        return min((e.status for e in self.evidence), key=STATUS_RANK.__getitem__)

    @property
    def asserted(self) -> bool:
        """Supported by at least one non-negated sentence."""
        return self.status is not AssertionStatus.NEGATED

    @property
    def sentence_count(self) -> int:
        return len({e.sentence_index for e in self.evidence})

    @property
    def max_score(self) -> float | None:
        scores = [e.score for e in self.evidence if e.score is not None]
        return max(scores) if scores else None


class ThreatAssessor:
    def __init__(self, classifier: ThreatClassifier | None = None,
                 rules: RuleBasedClassifier | None = None) -> None:
        self.classifier = classifier
        self.rules = rules or RuleBasedClassifier()

    def assess(self, document: ExtractedDocument) -> list[ThreatCategoryFinding]:
        sentences = document.sentences
        if not sentences:
            return []
        findings: dict[str, ThreatCategoryFinding] = {}
        statuses = [assertion_status(s.text) for s in sentences]
        counts: dict[tuple[str, str], int] = {}

        def add(category: str, evidence: CategoryEvidence) -> None:
            key = (category, evidence.source)
            counts[key] = counts.get(key, 0) + 1
            if counts[key] <= _MAX_EVIDENCE_PER_SOURCE:
                findings.setdefault(category, ThreatCategoryFinding(category)).evidence.append(
                    evidence)

        if self.classifier is not None:
            texts = [s.text for s in sentences]
            scores = self.classifier.scores(texts)
            for i, predicted in enumerate(self.classifier.predict(texts)):
                for category in predicted - {OTHER}:
                    j = self.classifier.categories.index(category)
                    add(category, CategoryEvidence(
                        i, sentences[i].page_number, " ".join(sentences[i].text.split()),
                        "model", statuses[i], round(float(scores[i, j]), 4)))

        for i, sentence in enumerate(sentences):
            for category, terms in self.rules.explain(sentence.text).evidence.items():
                add(category, CategoryEvidence(
                    i, sentence.page_number, " ".join(sentence.text.split()), "rules",
                    statuses[i], None, terms))

        return sorted(findings.values(), key=lambda f: (
            not f.asserted, "model" not in f.sources, -f.sentence_count, f.category))
