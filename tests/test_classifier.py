"""Tests for threat classification (src/ml/rule_classifier.py, threat_classifier.py, evaluation.py).

The model tests train on a small synthetic corpus: they check behaviour and plumbing,
not real-world accuracy (that is measured by scripts/train_threat_classifier.py).
"""

from __future__ import annotations

import numpy as np
import pytest

from src.ml.dataset import OTHER
from src.ml.evaluation import (
    bootstrap_ci,
    confusion,
    evaluate,
    macro_f1,
    per_category_counts,
    primary,
)
from src.ml.rule_classifier import RuleBasedClassifier
from src.ml.threat_classifier import (
    MIN_TRAIN_SUPPORT,
    ModelError,
    ThreatClassifier,
    best_threshold,
)

# --- rule baseline ------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("The actor sent spear-phishing emails with a malicious attachment.", {"phishing"}),
        ("Ryuk encrypted files and deleted shadow copies.", {"ransomware"}),
        ("They exploited CVE-2021-44228 for remote code execution.",
         {"vulnerability_exploitation"}),
        ("Mimikatz was used to dump credentials from LSASS.", {"credential_theft"}),
        ("Data was exfiltrated to a leak site.", {"data_breach"}),
        ("A DDoS attack used a SYN flood.", {"ddos"}),
        ("The backdoor beacons every minute.", {"malware"}),
        ("The service listens on port 8080.", {OTHER}),
    ],
)
def test_rules(text, expected):
    assert RuleBasedClassifier().predict([text]) == [frozenset(expected)]


def test_rule_evidence_lists_matched_terms():
    prediction = RuleBasedClassifier().explain("Stolen passwords and credentials were exfiltrated.")
    assert prediction.evidence["credential_theft"] == ("passwords", "credentials")
    assert prediction.evidence["data_breach"] == ("exfiltrated",)


def test_rules_respect_word_boundaries():
    # "exploitable" is not "exploit"; "drat" is not "RAT"; "ransomed" still counts.
    assert RuleBasedClassifier().predict(["Drat, the exploitable host."]) == [frozenset({OTHER})]


# --- model ------------------------------------------------------------------------

_TEMPLATES = {
    "phishing": "{a} sent spearphishing emails with malicious attachments to {b}.",
    "credential_theft": "{a} dumped credentials from LSASS memory on {b}.",
    "data_breach": "{a} exfiltrated archives over the C2 channel from {b}.",
}
_OTHER = "{a} enumerated running processes and system information on {b}."
_ACTORS = [f"Actor{i}" for i in range(40)]
_TARGETS = ["servers", "hosts", "workstations", "endpoints"]


def _corpus(rare: str | None = None) -> tuple[list[str], list[frozenset[str]]]:
    texts, labels = [], []
    for i, actor in enumerate(_ACTORS):
        target = _TARGETS[i % len(_TARGETS)]
        for category, template in _TEMPLATES.items():
            texts.append(template.format(a=actor, b=target))
            labels.append(frozenset({category}))
        texts.append(_OTHER.format(a=actor, b=target))
        labels.append(frozenset({OTHER}))
    if rare:  # below MIN_TRAIN_SUPPORT → must be left to rules
        texts += [f"Rare event {i} happened." for i in range(MIN_TRAIN_SUPPORT - 1)]
        labels += [frozenset({rare})] * (MIN_TRAIN_SUPPORT - 1)
    return texts, labels


@pytest.fixture(scope="module")
def trained() -> ThreatClassifier:
    texts, labels = _corpus(rare="ddos")
    model = ThreatClassifier(C=4.0).fit(texts, labels)
    model.tune_thresholds(texts, labels)
    return model


def test_rare_categories_are_not_learned(trained):
    assert trained.categories == ("credential_theft", "data_breach", "phishing")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("NewActor sent spearphishing emails with malicious attachments to laptops.",
         {"phishing"}),
        ("NewActor dumped credentials from LSASS memory on laptops.", {"credential_theft"}),
        ("NewActor enumerated running processes and system information on laptops.", {OTHER}),
    ],
)
def test_model_generalises_to_unseen_actor(trained, text, expected):
    assert trained.predict([text]) == [frozenset(expected)]


def test_scores_shape_and_range(trained):
    scores = trained.scores(["x", "y"])
    assert scores.shape == (2, 3) and np.all((scores >= 0) & (scores <= 1))


def test_explanation_names_behaviour_terms(trained):
    terms = [t for t, _ in trained.explain(
        "NewActor dumped credentials from LSASS memory.", "credential_theft")]
    assert any("credential" in t or "lsass" in t or "dump" in t for t in terms)


def test_untrained_model_raises():
    with pytest.raises(ModelError):
        ThreatClassifier().predict(["x"])


def test_no_learnable_category_raises():
    with pytest.raises(ModelError):
        ThreatClassifier().fit(["a", "b"], [frozenset({OTHER}), frozenset({"ddos"})])


def test_save_and_load_round_trip(trained, tmp_path):
    path = tmp_path / "model.joblib"
    trained.save(path, dataset_revision="abc")
    loaded = ThreatClassifier.load(path)
    sample = ["NewActor exfiltrated archives over the C2 channel from laptops."]
    assert loaded.predict(sample) == trained.predict(sample)
    assert loaded.metadata["dataset_revision"] == "abc"
    np.testing.assert_allclose(loaded.scores(sample), trained.scores(sample))


def test_load_rejects_missing_and_foreign_files(tmp_path):
    with pytest.raises(ModelError, match="not found"):
        ThreatClassifier.load(tmp_path / "missing.joblib")
    import joblib

    joblib.dump({"not": "a model"}, tmp_path / "foreign.joblib")
    with pytest.raises(ModelError, match="not a ThreatClassifier"):
        ThreatClassifier.load(tmp_path / "foreign.joblib")


def test_best_threshold_prefers_f1_optimum():
    scores = np.array([0.9, 0.8, 0.3, 0.2])
    truth = np.array([True, True, False, False])
    threshold, f1 = best_threshold(scores, truth)
    assert f1 == 1.0 and 0.3 < threshold <= 0.8


# --- evaluation ---------------------------------------------------------------

TRUTH = [frozenset({"a"}), frozenset({"b"}), frozenset({OTHER}), frozenset({"a"})]
PRED = [frozenset({"a"}), frozenset({OTHER}), frozenset({"a"}), frozenset({"a", "b"})]


def test_per_category_counts_and_macro():
    counts = per_category_counts(TRUTH, PRED, ["a", "b"])
    assert (counts["a"].tp, counts["a"].fp, counts["a"].fn) == (2, 1, 0)
    assert (counts["b"].tp, counts["b"].fp, counts["b"].fn) == (0, 1, 1)
    assert macro_f1(counts) == pytest.approx((0.8 + 0.0) / 2)


def test_primary_and_confusion():
    assert primary(frozenset({"b", "a"}), ["a", "b"]) == "a"
    assert primary(frozenset({OTHER}), ["a", "b"]) == OTHER
    labels, matrix = confusion(TRUTH, PRED, ["a", "b"])
    assert labels == ["a", "b", OTHER]
    assert matrix == [[2, 0, 0], [0, 0, 1], [1, 0, 0]]
    assert sum(map(sum, matrix)) == len(TRUTH)


def test_bootstrap_ci_is_ordered_and_deterministic():
    truth = TRUTH * 25
    pred = PRED * 25
    groups = [f"g{i % 20}" for i in range(len(truth))]
    first = bootstrap_ci(truth, pred, groups, ["a", "b"], iterations=200)
    assert first == bootstrap_ci(truth, pred, groups, ["a", "b"], iterations=200)
    low, high = first["a"]
    assert 0.0 <= low <= high <= 1.0


def test_evaluate_report_structure():
    result = evaluate(TRUTH, PRED, ["g1", "g2", "g3", "g4"], ["a", "b"], bootstrap=50)
    assert set(result) == {"n", "per_category", "macro_f1", "exact_match", "confusion", "ci95"}
    assert result["exact_match"] == 0.25
