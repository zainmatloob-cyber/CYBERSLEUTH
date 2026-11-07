"""Map document sentences to MITRE ATT&CK techniques.

Two kinds of mapping are kept distinct:

* **Explicit** (``explicit-id`` / ``explicit-name`` / ``explicit-term``): the text names the
  technique, by ID ("T1566.001"), by its multi-word ATT&CK name ("OS Credential Dumping"),
  or by a curated term with hand-assigned IDs ("Kerberoasting" → T1558.003). Deterministic,
  no score.
* **Model** (``model``): a TF-IDF + linear SVM classifier over parent techniques, trained on
  ATT&CK procedure sentences. It suggests a technique when the top decision score reaches a
  threshold chosen on validation data, and abstains otherwise. Scores are SVM margins, not
  probabilities.

Every piece of evidence carries an assertion status (observed / capability / possible /
negated), and every mapping starts ``unverified`` until an analyst confirms or rejects it.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import joblib
import numpy as np
import sklearn
import spacy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import LinearSVC
from spacy.matcher import PhraseMatcher

from config.settings import PROJECT_ROOT, settings
from src.ingestion.models import ExtractedDocument
from src.intelligence.assertion import STATUS_RANK, AssertionStatus, assertion_status
from src.intelligence.attack_kb import TechniqueKB, default_technique_kb
from src.nlp.entity_models import Entity, EntityType
from src.utils.exceptions import CyberSleuthError

logger = logging.getLogger(__name__)

TECHNIQUE_MODEL_PATH = PROJECT_ROOT / "models" / "technique_model.joblib"
CURATED_PATH = settings.knowledge_base_dir / "curated_entities.json"
MODEL_FORMAT_VERSION = 1
MIN_MODEL_WORDS = 4  # headings and fragments are not mapped by the model
_ID_IN_TEXT = re.compile(r"(?<![\w.])T\d{4}(?:\.\d{3})?(?![\w.]|\.\d)")


class MappingMethod(StrEnum):
    EXPLICIT_ID = "explicit-id"
    EXPLICIT_NAME = "explicit-name"
    EXPLICIT_TERM = "explicit-term"
    MODEL = "model"


class AnalystVerdict(StrEnum):
    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class TechniqueModelError(CyberSleuthError):
    """The technique model file is missing, incompatible, or untrained."""


@dataclass(frozen=True)
class TechniqueEvidence:
    sentence_index: int
    page_number: int
    context: str
    method: MappingMethod
    status: AssertionStatus
    matched_text: str | None = None  # for explicit matches
    score: float | None = None  # model decision score (not a probability)
    alternatives: tuple[tuple[str, float], ...] = ()  # model runner-up techniques


@dataclass
class TechniqueMapping:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    evidence: list[TechniqueEvidence] = field(default_factory=list)
    verdict: AnalystVerdict = AnalystVerdict.UNVERIFIED

    @property
    def methods(self) -> list[str]:
        return sorted({e.method.value for e in self.evidence})

    @property
    def explicit(self) -> bool:
        return any(e.method is not MappingMethod.MODEL for e in self.evidence)

    @property
    def status(self) -> AssertionStatus:
        """Strongest status across evidence: one observed sentence makes it observed."""
        return min((e.status for e in self.evidence), key=STATUS_RANK.__getitem__)

    @property
    def max_score(self) -> float | None:
        scores = [e.score for e in self.evidence if e.score is not None]
        return max(scores) if scores else None


# --- model ----------------------------------------------------------------------------


def _features() -> FeatureUnion:
    return FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True,
                                 strip_accents="unicode")),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                 sublinear_tf=True)),
    ])


@dataclass
class TechniqueModel:
    """Linear SVM over parent techniques, with an abstention threshold."""

    C: float = 0.5
    threshold: float = 0.0
    metadata: dict[str, str] = field(default_factory=dict)
    _features: FeatureUnion | None = field(default=None, repr=False)
    _svm: LinearSVC | None = field(default=None, repr=False)
    _labels: LabelEncoder | None = field(default=None, repr=False)

    def fit(self, texts: Sequence[str], labels: Sequence[str]) -> TechniqueModel:
        """One parent technique per training sentence (multi-technique rows are expanded)."""
        self._labels = LabelEncoder().fit(labels)
        self._features = _features()
        x = self._features.fit_transform(texts)
        self._svm = LinearSVC(C=self.C, class_weight="balanced", max_iter=5000)
        self._svm.fit(x, self._labels.transform(labels))
        return self

    @property
    def classes(self) -> list[str]:
        self._require()
        return list(self._labels.classes_)

    def _require(self) -> None:
        if self._svm is None:
            raise TechniqueModelError("The technique model has not been trained or loaded.")

    def decision(self, texts: Sequence[str]) -> np.ndarray:
        self._require()
        return self._svm.decision_function(self._features.transform(texts))

    def top_k(self, texts: Sequence[str], k: int = 5) -> list[list[tuple[str, float]]]:
        scores = self.decision(texts)
        order = np.argsort(-scores, axis=1)[:, :k]
        classes = self._labels.classes_
        return [[(classes[j], float(scores[i, j])) for j in row] for i, row in enumerate(order)]

    def save(self, path: Path, **metadata: str) -> None:
        self._require()
        self.metadata = {"format_version": str(MODEL_FORMAT_VERSION),
                         "sklearn_version": sklearn.__version__,
                         "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
                         **{k: str(v) for k, v in metadata.items()}}
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path = TECHNIQUE_MODEL_PATH) -> TechniqueModel:
        """Load a model produced by this project. Never pass an untrusted file (pickle)."""
        if not path.is_file():
            raise TechniqueModelError(f"Technique model {path} not found. "
                                      "Run: python scripts/train_technique_model.py --final")
        model = joblib.load(path)
        if not isinstance(model, TechniqueModel):
            raise TechniqueModelError(f"{path.name} is not a TechniqueModel.")
        if model.metadata.get("format_version") != str(MODEL_FORMAT_VERSION):
            raise TechniqueModelError(f"{path.name} has an incompatible format version.")
        return model


# --- explicit matching ----------------------------------------------------------------


class ExplicitTechniqueMatcher:
    """Finds technique IDs and multi-word ATT&CK technique names in a sentence."""

    def __init__(self, kb: TechniqueKB) -> None:
        self.kb = kb
        self._nlp = spacy.blank("en")
        self._matcher = PhraseMatcher(self._nlp.vocab, attr="LOWER")
        for technique in kb.techniques.values():
            # Single-word names ("DLL", "Domains", "Proxy") are too ambiguous as text.
            if len(technique.name.split()) >= 2:
                self._matcher.add(technique.id, [self._nlp.make_doc(technique.name)])

    def find(self, sentence: str) -> list[tuple[str, int, int, MappingMethod]]:
        found = []
        for match in _ID_IN_TEXT.finditer(sentence):
            resolved = self.kb.resolve(match.group())
            if resolved:
                found.append((resolved, match.start(), match.end(), MappingMethod.EXPLICIT_ID))
        doc = self._nlp.make_doc(sentence)
        for match_id, start, end in self._matcher(doc):
            span = doc[start:end]
            found.append((self._nlp.vocab.strings[match_id], span.start_char, span.end_char,
                          MappingMethod.EXPLICIT_NAME))
        return found


def load_term_technique_ids(path: Path = CURATED_PATH) -> dict[str, tuple[str, ...]]:
    """Curated technique term (canonical name) → hand-assigned ATT&CK IDs."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return {t["name"]: tuple(t.get("attack_ids", [])) for t in data["attack_techniques"]}


# --- mapper ---------------------------------------------------------------------------


class TechniqueMapper:
    def __init__(self, kb: TechniqueKB | None = None, model: TechniqueModel | None = None,
                 use_model: bool = True) -> None:
        self.kb = kb or default_technique_kb()
        self.explicit = ExplicitTechniqueMatcher(self.kb)
        self.term_ids = load_term_technique_ids()
        self.model = model
        self.warnings: list[str] = []
        if self.model is None and use_model:
            try:
                self.model = TechniqueModel.load()
            except TechniqueModelError as exc:
                logger.warning("%s Mapping explicit mentions only.", exc)
                self.warnings.append(f"{exc} Only explicit technique mentions are mapped.")

    def _add(self, mappings: dict[str, TechniqueMapping], technique_id: str,
             evidence: TechniqueEvidence) -> None:
        technique = self.kb.get(technique_id)
        if technique is None:
            return
        mapping = mappings.setdefault(technique.id, TechniqueMapping(
            technique.id, technique.name, technique.tactics, technique.url))
        if evidence not in mapping.evidence:
            mapping.evidence.append(evidence)

    def map(self, document: ExtractedDocument, entities: Sequence[Entity] = ()) -> list[
            TechniqueMapping]:
        mappings: dict[str, TechniqueMapping] = {}
        sentences = document.sentences

        for index, sentence in enumerate(sentences):
            context = " ".join(sentence.text.split())
            for technique_id, start, end, method in self.explicit.find(sentence.text):
                self._add(mappings, technique_id, TechniqueEvidence(
                    index, sentence.page_number, context, method,
                    assertion_status(sentence.text, start, end), sentence.text[start:end]))

        for entity in entities:
            if entity.entity_type is not EntityType.ATTACK_TECHNIQUE:
                continue
            for technique_id in self.term_ids.get(entity.name, ()):
                for mention in entity.mentions:
                    sentence = sentences[mention.sentence_index]
                    start = mention.char_start - sentence.char_start
                    end = mention.char_end - sentence.char_start
                    self._add(mappings, technique_id, TechniqueEvidence(
                        mention.sentence_index, mention.page_number, mention.context,
                        MappingMethod.EXPLICIT_TERM,
                        assertion_status(sentence.text, start, end), mention.text))

        if self.model is not None:
            candidates = [(i, s) for i, s in enumerate(sentences)
                          if len(s.text.split()) >= MIN_MODEL_WORDS]
            if candidates:
                ranked = self.model.top_k([s.text for _, s in candidates], k=3)
                for (index, sentence), top in zip(candidates, ranked, strict=True):
                    technique_id, score = top[0]
                    if score < self.model.threshold:
                        continue  # abstain
                    self._add(mappings, technique_id, TechniqueEvidence(
                        index, sentence.page_number, " ".join(sentence.text.split()),
                        MappingMethod.MODEL, assertion_status(sentence.text), None,
                        round(score, 4), tuple((t, round(s, 4)) for t, s in top[1:])))

        return sorted(mappings.values(), key=lambda m: (not m.explicit, m.technique_id))
