"""TF-IDF + one-vs-rest Logistic Regression threat-category classifier.

* **Features:** word 1–2-grams plus character 3–5-grams (``char_wb``). Character n-grams
  cope with tool names, morphology ("exfiltrated" / "exfiltration") and unseen tokens.
* **Model:** one binary Logistic Regression per category (multi-label), with
  ``class_weight="balanced"`` because ``other`` dominates.
* **Decision rule:** a category is predicted when its score reaches a per-category
  threshold tuned on the **validation** split. If none does, the prediction is ``other``.
* **Scores** are Logistic Regression outputs under class re-weighting. They rank well but
  are **not calibrated probabilities**, and are reported as "scores".
* **Learned categories** are only those with at least ``MIN_TRAIN_SUPPORT`` training
  examples. Rarer categories are left to the rule baseline.

Model files are joblib (pickle) archives. Loading a pickle can execute code, so only
files produced by this project's training script are ever loaded.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.pipeline import FeatureUnion
from sklearn.preprocessing import MultiLabelBinarizer

from src.ml.dataset import OTHER
from src.utils.exceptions import CyberSleuthError

logger = logging.getLogger(__name__)

MIN_TRAIN_SUPPORT = 30
THRESHOLD_GRID = tuple(round(float(t), 2) for t in np.arange(0.05, 0.96, 0.05))
MODEL_FORMAT_VERSION = 1


class ModelError(CyberSleuthError):
    """A model file is missing, incompatible, or the model is used before training."""


def _features() -> FeatureUnion:
    return FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True,
                                 lowercase=True, strip_accents="unicode")),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                 sublinear_tf=True, lowercase=True)),
    ])


def best_threshold(scores: np.ndarray, truth: np.ndarray) -> tuple[float, float]:
    """Threshold from ``THRESHOLD_GRID`` maximising F1 (ties → the higher threshold)."""
    best = (0.5, -1.0)
    for threshold in map(float, THRESHOLD_GRID):
        predicted = scores >= threshold
        tp = int(np.sum(predicted & truth))
        fp = int(np.sum(predicted & ~truth))
        fn = int(np.sum(~predicted & truth))
        f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        if f1 >= best[1]:
            best = (threshold, f1)
    return best


@dataclass
class ThreatClassifier:
    C: float = 1.0
    categories: tuple[str, ...] = ()
    thresholds: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)
    _features: FeatureUnion | None = field(default=None, repr=False)
    _model: OneVsRestClassifier | None = field(default=None, repr=False)

    # --- training -----------------------------------------------------------------

    def fit(self, texts: Sequence[str], labels: Sequence[Sequence[str]]) -> ThreatClassifier:
        counts: dict[str, int] = {}
        for label_set in labels:
            for label in label_set:
                counts[label] = counts.get(label, 0) + 1
        self.categories = tuple(sorted(
            c for c, n in counts.items() if c != OTHER and n >= MIN_TRAIN_SUPPORT
        ))
        if not self.categories:
            raise ModelError("No category has enough training examples.")
        skipped = sorted(c for c, n in counts.items() if c != OTHER and n < MIN_TRAIN_SUPPORT)
        if skipped:
            logger.info("Categories below %d training examples (rules only): %s",
                        MIN_TRAIN_SUPPORT, skipped)

        y = self._binarize(labels)
        self._features = _features()
        x = self._features.fit_transform(texts)
        self._model = OneVsRestClassifier(LogisticRegression(
            C=self.C, class_weight="balanced", solver="liblinear", max_iter=2000,
        ))
        self._model.fit(x, y)
        self.thresholds = {c: 0.5 for c in self.categories}
        return self

    def tune_thresholds(self, texts: Sequence[str], labels: Sequence[Sequence[str]]) -> dict:
        """Choose per-category thresholds on held-out (validation) data."""
        scores, truth = self.scores(texts), self._binarize(labels).astype(bool)
        report = {}
        for j, category in enumerate(self.categories):
            threshold, f1 = best_threshold(scores[:, j], truth[:, j])
            self.thresholds[category] = threshold
            report[category] = {"threshold": threshold, "val_f1": f1}
        return report

    # --- inference ----------------------------------------------------------------

    def _require_trained(self) -> None:
        if self._model is None or self._features is None:
            raise ModelError("The classifier has not been trained or loaded.")

    def _binarize(self, labels: Sequence[Sequence[str]]) -> np.ndarray:
        binarizer = MultiLabelBinarizer(classes=list(self.categories))
        filtered = [[label for label in label_set if label in self.categories]
                    for label_set in labels]
        return binarizer.fit_transform(filtered)

    def scores(self, texts: Sequence[str]) -> np.ndarray:
        """Score matrix of shape (n_texts, n_categories); columns follow ``categories``."""
        self._require_trained()
        return self._model.predict_proba(self._features.transform(texts))

    def predict(self, texts: Sequence[str]) -> list[frozenset[str]]:
        scores = self.scores(texts)
        limits = np.array([self.thresholds[c] for c in self.categories])
        predictions = []
        for row in scores >= limits:
            chosen = frozenset(c for c, hit in zip(self.categories, row, strict=True) if hit)
            predictions.append(chosen or frozenset({OTHER}))
        return predictions

    def explain(self, text: str, category: str, top_k: int = 8) -> list[tuple[str, float]]:
        """Features that push ``text`` towards ``category`` most (TF-IDF value × weight)."""
        self._require_trained()
        index = self.categories.index(category)
        vector = self._features.transform([text])
        coefficients = self._model.estimators_[index].coef_.ravel()
        names = self._features.get_feature_names_out()
        row = vector.tocoo()
        contributions = sorted(
            ((names[j], float(value * coefficients[j])) for j, value in zip(
                row.col, row.data, strict=True)),
            key=lambda item: -item[1],
        )
        return [(name.split("__", 1)[-1], weight) for name, weight in contributions[:top_k]
                if weight > 0]

    # --- persistence --------------------------------------------------------------

    def save(self, path: Path, **metadata: str) -> None:
        self._require_trained()
        self.metadata = {
            "format_version": str(MODEL_FORMAT_VERSION),
            "sklearn_version": sklearn.__version__,
            "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
            **{k: str(v) for k, v in metadata.items()},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path) -> ThreatClassifier:
        """Load a model produced by this project. Never pass an untrusted file here."""
        if not path.is_file():
            raise ModelError(f"Model file {path} not found. "
                             "Run: python scripts/train_threat_classifier.py")
        model = joblib.load(path)
        if not isinstance(model, ThreatClassifier):
            raise ModelError(f"{path.name} is not a ThreatClassifier.")
        if model.metadata.get("format_version") != str(MODEL_FORMAT_VERSION):
            raise ModelError(f"{path.name} has an incompatible format version.")
        if model.metadata.get("sklearn_version") != sklearn.__version__:
            logger.warning("Model trained with scikit-learn %s, running %s.",
                           model.metadata.get("sklearn_version"), sklearn.__version__)
        return model
