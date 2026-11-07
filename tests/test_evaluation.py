"""Tests for the evaluation metrics and runner (src/evaluation/)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.evaluation.metrics import Counts, macro_f1, micro, score
from src.evaluation.runner import GoldFileError, evaluate_split, load_gold, normalise
from src.intelligence.analyzer import Analyzer

EVAL_DIR = Path(__file__).resolve().parent.parent / "data" / "evaluation"

# --- metrics ------------------------------------------------------------------


def test_score_counts():
    c = score({"a", "b", "c"}, {"b", "c", "d"})
    assert (c.tp, c.fp, c.fn) == (2, 1, 1)
    assert c.precision == pytest.approx(2 / 3) and c.recall == pytest.approx(2 / 3)
    assert c.f1 == pytest.approx(2 / 3)


def test_undefined_metrics_are_none_not_zero_or_one():
    no_predictions = score({"a"}, set())
    assert no_predictions.precision is None and no_predictions.recall == 0.0
    assert no_predictions.f1 is None
    no_gold = score(set(), {"x"})
    assert no_gold.recall is None and no_gold.precision == 0.0


def test_all_wrong_is_zero_f1():
    assert score({"a"}, {"b"}).f1 == 0.0


def test_micro_and_macro():
    per_type = {"x": Counts(tp=9, fp=1, fn=0), "y": Counts(tp=0, fp=0, fn=1)}
    total = micro(per_type.values())
    assert (total.tp, total.fp, total.fn) == (9, 1, 1)
    # "y" has gold support but no predictions: recall 0 → F1 counts as 0 (not skipped).
    assert macro_f1(per_type) == pytest.approx(per_type["x"].f1 / 2)
    # A type with no gold items is not part of the macro average.
    assert macro_f1({**per_type, "z": Counts(fp=3)}) == pytest.approx(per_type["x"].f1 / 2)
    assert macro_f1({}) is None


def test_counts_as_dict():
    assert Counts(1, 0, 1).as_dict() == {
        "tp": 1, "fp": 0, "fn": 1, "support": 2,
        "precision": 1.0, "recall": 0.5, "f1": pytest.approx(2 / 3),
    }


# --- gold files ---------------------------------------------------------------


@pytest.mark.parametrize("split", ["dev", "test"])
def test_all_gold_files_are_valid(split):
    files = sorted((EVAL_DIR / split).glob("*.gold.json"))
    assert len(files) == 4
    for path in files:
        gold = load_gold(path)
        assert gold.labels["iocs"] and gold.labels["entities"]


def test_entity_normalisation():
    assert normalise("entities", "The  University of Oxford") == "university of oxford"
    assert normalise("iocs", "CVE-2024-3400") == "CVE-2024-3400"


def _write(tmp_path: Path, gold: dict, text: str = "APT28 used 198.51.100.7.") -> Path:
    (tmp_path / "doc.txt").write_text(text, encoding="utf-8")
    path = tmp_path / "doc.gold.json"
    path.write_text(json.dumps({"document": "doc.txt", **gold}), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "gold",
    [
        {"iocs": [{"type": "ipv6", "value": "::1"}]},  # unknown type
        {"iocs": [{"type": "ipv4", "value": ""}]},  # empty value
        {"entities": [{"type": "malware", "value": "X"}, {"type": "malware", "value": "x"}]},
    ],
)
def test_invalid_gold_rejected(tmp_path, gold):
    with pytest.raises(GoldFileError):
        load_gold(_write(tmp_path, gold))


def test_gold_with_missing_document_rejected(tmp_path):
    path = tmp_path / "x.gold.json"
    path.write_text(json.dumps({"document": "missing.txt"}), encoding="utf-8")
    with pytest.raises(GoldFileError, match="not found"):
        load_gold(path)


def test_empty_split_rejected(tmp_path):
    with pytest.raises(GoldFileError):
        evaluate_split(tmp_path, Analyzer(use_models=False), "x")


# --- runner -------------------------------------------------------------------


def test_runner_scores_and_lists_errors(tmp_path):
    _write(tmp_path, {
        "iocs": [{"type": "ipv4", "value": "198.51.100.7"}],
        "entities": [{"type": "threat_actor", "value": "APT28"},
                     {"type": "malware", "value": "Emotet"}],  # not in text → FN
    })
    analyzer = Analyzer(use_models=False)
    report = evaluate_split(tmp_path, analyzer, "rules-only")
    assert report.overall("iocs").f1 == 1.0
    entities = report.overall("entities")
    assert (entities.tp, entities.fp, entities.fn) == (1, 0, 1)
    assert report.errors == [{"document": "doc.txt", "task": "entities", "type": "malware",
                              "error": "false_negative", "value": "Emotet"}]
    data = report.as_dict()
    assert data["tasks"]["entities"]["per_type"]["malware"]["recall"] == 0.0
