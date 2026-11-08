"""Model and knowledge-base files: loaders refuse anything that isn't the expected artefact.

Model files are pickles produced by this project and are never accepted from users. These
checks catch a wrong or stale file, not a malicious one: unpickling is what runs code, so
the defence is that only the project's own files are loaded.
"""

from __future__ import annotations

import logging

import joblib
import pytest

from src.intelligence.attack_kb import load_technique_kb
from src.intelligence.mitre_mapper import TechniqueModel, TechniqueModelError
from src.ml.threat_classifier import ModelError, ThreatClassifier
from src.utils.exceptions import KnowledgeBaseError

LOADERS = [
    pytest.param(TechniqueModel, TechniqueModelError, id="technique-model"),
    pytest.param(ThreatClassifier, ModelError, id="threat-classifier"),
]


def _load(cls, path):
    return cls.load(path)


@pytest.mark.parametrize(("cls", "error"), LOADERS)
def test_missing_file(cls, error, tmp_path):
    with pytest.raises(error, match="not found"):
        _load(cls, tmp_path / "absent.joblib")


@pytest.mark.parametrize(("cls", "error"), LOADERS)
def test_wrong_object_type(cls, error, tmp_path):
    path = tmp_path / "m.joblib"
    joblib.dump({"not": "a model"}, path)
    with pytest.raises(error, match="is not a"):
        _load(cls, path)


@pytest.mark.parametrize(("cls", "error"), LOADERS)
def test_incompatible_format_version(cls, error, tmp_path):
    path = tmp_path / "m.joblib"
    joblib.dump(cls(metadata={"format_version": "0"}), path)
    with pytest.raises(error, match="incompatible format version"):
        _load(cls, path)


@pytest.mark.parametrize(("cls", "error"), LOADERS)
def test_other_sklearn_version_loads_with_a_warning(cls, error, tmp_path, caplog):
    path = tmp_path / "m.joblib"
    joblib.dump(cls(metadata={"format_version": "1", "sklearn_version": "0.0"}), path)
    with caplog.at_level(logging.WARNING):
        assert isinstance(_load(cls, path), cls)
    assert "scikit-learn 0.0" in caplog.text


def test_untrained_technique_model_refuses_to_predict():
    with pytest.raises(TechniqueModelError, match="not been trained"):
        _ = TechniqueModel().classes


def test_corrupt_technique_kb(tmp_path):
    path = tmp_path / "kb.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(KnowledgeBaseError, match="Cannot load kb.json"):
        load_technique_kb(path)
    with pytest.raises(KnowledgeBaseError, match="Cannot load"):
        load_technique_kb(tmp_path / "absent.json")


def test_analyzer_falls_back_to_rules_without_the_threat_model(tmp_path, monkeypatch):
    from src.intelligence import analyzer as analyzer_module
    from src.intelligence.mitre_mapper import TechniqueMapper
    from src.nlp.entity_extractor import EntityExtractor

    monkeypatch.setattr(analyzer_module, "THREAT_MODEL_PATH", tmp_path / "absent.joblib")
    analyzer = analyzer_module.Analyzer(entity_extractor=EntityExtractor(model=None),
                                        technique_mapper=TechniqueMapper(use_model=False))
    assert any("Threat categories come from rules only" in w for w in analyzer.warnings)
    result = analyzer.analyze(b"LockBit encrypted the file servers.", "r.txt")
    assert result.components["threat_classification"] == "rules-only"
