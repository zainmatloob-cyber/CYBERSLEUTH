"""Tests for ATT&CK technique mapping (src/intelligence/: attack_kb, assertion, mitre_mapper)."""

from __future__ import annotations

import json

import pytest

from src.ingestion.models import ExtractedDocument, FileType, PageText
from src.intelligence.assertion import AssertionStatus, assertion_status
from src.intelligence.attack_kb import TechniqueKB, default_technique_kb, load_technique_kb
from src.intelligence.mitre_mapper import (
    AnalystVerdict,
    ExplicitTechniqueMatcher,
    MappingMethod,
    TechniqueMapper,
    TechniqueModel,
    TechniqueModelError,
    load_term_technique_ids,
)
from src.nlp.entity_extractor import EntityExtractor
from src.nlp.preprocessing import split_sentences
from src.utils.exceptions import KnowledgeBaseError


@pytest.fixture(scope="module")
def kb() -> TechniqueKB:
    return default_technique_kb()


# --- technique KB -------------------------------------------------------------


def test_kb_loads_v20(kb):
    assert kb.version == "20.1"
    phishing = kb.get("T1566")
    assert phishing.name == "Phishing" and "initial-access" in phishing.tactics
    assert phishing.url == "https://attack.mitre.org/techniques/T1566/"
    assert kb.get("T1566.001").url == "https://attack.mitre.org/techniques/T1566/001/"


@pytest.mark.parametrize(
    ("old", "active"),
    [("T1574.002", "T1574.001"), ("T1562.001", "T1685"), ("T1566", "T1566"), ("T9999", None)],
)
def test_revoked_ids_are_translated(kb, old, active):
    assert kb.resolve(old) == active


def test_parent_resolution(kb):
    assert kb.parent("T1566.001") == "T1566"
    assert kb.parent("T1562.004") == "T1686"  # revoked sub-technique → new parent
    assert kb.parent("T9999.001") is None


def test_revocation_cycle_is_safe():
    cyclic = TechniqueKB({}, {"T0001": "T0002", "T0002": "T0001"}, "x")
    assert cyclic.resolve("T0001") is None


def test_invalid_kb_file_rejected(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"attack_version": "1", "revoked_to": {}, "techniques": [
        {"id": "X1", "name": "n", "tactics": [], "is_subtechnique": False,
         "description": ""}]}), encoding="utf-8")
    with pytest.raises(KnowledgeBaseError):
        load_technique_kb(path)


def test_curated_term_ids_are_active(kb):
    for name, ids in load_term_technique_ids().items():
        for technique_id in ids:
            assert technique_id in kb.techniques, (name, technique_id)


# --- assertion status ---------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "status"),
    [
        ("APT28 has used spearphishing emails.", AssertionStatus.OBSERVED),
        ("Emotet can dump credentials from LSASS.", AssertionStatus.CAPABILITY),
        ("The malware has the ability to capture keystrokes.", AssertionStatus.CAPABILITY),
        ("Phishing was not involved in this intrusion.", AssertionStatus.NEGATED),
        ("There is no evidence of lateral movement.", AssertionStatus.NEGATED),
        ("No DDoS attack was observed.", AssertionStatus.NEGATED),
        ("The actor may have used PowerShell.", AssertionStatus.POSSIBLE),
        ("Defenders should block DNS tunneling.", AssertionStatus.POSSIBLE),
        ("The payload executed without user interaction.", AssertionStatus.OBSERVED),
    ],
)
def test_assertion_status(sentence, status):
    assert assertion_status(sentence) == status


def test_negation_is_scoped_to_the_clause():
    sentence = "Phishing was not observed; however, the actor used Kerberoasting."
    start = sentence.index("Kerberoasting")
    assert assertion_status(sentence, start, start + len("Kerberoasting")) is \
        AssertionStatus.OBSERVED
    assert assertion_status(sentence, 0, len("Phishing")) is AssertionStatus.NEGATED


# --- explicit matching --------------------------------------------------------


def test_explicit_ids_and_names(kb):
    found = ExplicitTechniqueMatcher(kb).find(
        "They used T1566.001 and OS Credential Dumping, plus T1574.002 and T9999.")
    assert {(t, m) for t, _, _, m in found} == {
        ("T1566.001", MappingMethod.EXPLICIT_ID),
        ("T1574.001", MappingMethod.EXPLICIT_ID),  # revoked ID translated
        ("T1003", MappingMethod.EXPLICIT_NAME),
    }


@pytest.mark.parametrize("text", ["The DLL was loaded.", "Version T1566.0012 build", "ST1566"])
def test_explicit_matcher_avoids_false_positives(kb, text):
    assert ExplicitTechniqueMatcher(kb).find(text) == []


# --- mapper -------------------------------------------------------------------


def _doc(text: str) -> ExtractedDocument:
    pages = [PageText(1, text)]
    return ExtractedDocument("x.txt", FileType.TXT, "0" * 64, 1, pages,
                             sentences=split_sentences(pages))


@pytest.fixture(scope="module")
def tiny_model() -> TechniqueModel:
    texts, labels = [], []
    for i in range(30):
        texts += [f"Actor{i} sent spearphishing emails with attachments.",
                  f"Actor{i} dumped credentials from LSASS memory.",
                  f"Actor{i} encrypted files on network shares."]
        labels += ["T1566", "T1003", "T1486"]
    model = TechniqueModel(C=1.0).fit(texts, labels)
    model.threshold = 0.0
    return model


def test_mapper_combines_explicit_and_model(kb, tiny_model):
    text = ("The group used Kerberoasting against service accounts. "
            "NewActor dumped credentials from LSASS memory. "
            "Phishing was not involved.")
    doc = _doc(text)
    entities = EntityExtractor(model=None).extract(doc)
    mappings = {m.technique_id: m for m in TechniqueMapper(kb, tiny_model).map(doc, entities)}

    kerberoasting = mappings["T1558.003"]
    assert kerberoasting.explicit and kerberoasting.methods == ["explicit-term"]
    assert kerberoasting.status is AssertionStatus.OBSERVED
    assert kerberoasting.verdict is AnalystVerdict.UNVERIFIED

    dumping = mappings["T1003"]
    model_evidence = [e for e in dumping.evidence if e.method is MappingMethod.MODEL]
    assert model_evidence and model_evidence[0].score is not None
    assert len(model_evidence[0].alternatives) == 2

    assert mappings["T1566"].status is AssertionStatus.NEGATED
    assert list(mappings) == sorted(mappings, key=lambda t: (not mappings[t].explicit, t))


def test_model_abstains_below_threshold(kb, tiny_model):
    strict = TechniqueModel(C=tiny_model.C, threshold=1e9)
    strict._features, strict._svm, strict._labels = (
        tiny_model._features, tiny_model._svm, tiny_model._labels)
    doc = _doc("NewActor dumped credentials from LSASS memory.")
    mappings = TechniqueMapper(kb, strict).map(doc)
    # No model evidence; the explicit ATT&CK name "LSASS Memory" (T1003.001) still matches.
    assert all(e.method is not MappingMethod.MODEL for m in mappings for e in m.evidence)
    assert [m.technique_id for m in mappings] == ["T1003.001"]


def test_short_sentences_are_not_model_mapped(kb, tiny_model):
    assert TechniqueMapper(kb, tiny_model).map(_doc("Credential dumping.")) == []


def test_missing_model_degrades_to_explicit_only(kb, tmp_path, monkeypatch):
    monkeypatch.setattr("src.intelligence.mitre_mapper.TECHNIQUE_MODEL_PATH",
                        tmp_path / "absent.joblib")
    monkeypatch.setattr(TechniqueModel.load, "__defaults__", (tmp_path / "absent.joblib",))
    mapper = TechniqueMapper(kb)
    assert mapper.model is None and mapper.warnings
    assert [m.technique_id for m in mapper.map(_doc("They used T1059.001 heavily."))] == [
        "T1059.001"]


def test_model_save_load_round_trip(tiny_model, tmp_path):
    path = tmp_path / "m.joblib"
    tiny_model.save(path, dataset_revision="x")
    loaded = TechniqueModel.load(path)
    sample = ["Someone encrypted files on network shares."]
    assert loaded.top_k(sample, 1)[0][0][0] == tiny_model.top_k(sample, 1)[0][0][0] == "T1486"


def test_model_errors(tmp_path):
    with pytest.raises(TechniqueModelError):
        TechniqueModel().top_k(["x"])
    with pytest.raises(TechniqueModelError, match="not found"):
        TechniqueModel.load(tmp_path / "missing.joblib")


# --- document-level cut-off for model-only suggestions --------------------------------


class _FixedModel:
    """Stands in for TechniqueModel: every sentence gets the same ranked scores."""

    threshold = -1.0

    def __init__(self, ranked):
        self.ranked = ranked

    def top_k(self, texts, k=3):
        return [self.ranked for _ in texts]


def _mapped(kb, score, text, cut_off):
    model = _FixedModel([("T1486", score), ("T1059", score - 1)])
    mapper = TechniqueMapper(kb, model, model_only_min_score=cut_off)
    return {m.technique_id: m for m in mapper.map(_doc(text))}


def test_model_only_suggestion_below_cut_off_is_dropped(kb):
    text = "The actors encrypted every file on the servers."
    assert "T1486" not in _mapped(kb, 0.5, text, 0.75)
    assert _mapped(kb, 0.8, text, 0.75)["T1486"].max_score == 0.8
    assert "T1486" in _mapped(kb, 0.5, text, None)  # None turns the cut-off off


def test_cut_off_never_removes_explicit_mappings(kb):
    text = "The actors used T1486 to encrypt every file on the servers."
    mapping = _mapped(kb, 0.1, text, 0.75)["T1486"]
    assert mapping.explicit and "model" in mapping.methods  # low model evidence is kept too


def test_cut_off_is_read_from_config(tmp_path):
    from src.intelligence import mitre_mapper

    path = tmp_path / "c.json"
    path.write_text(json.dumps({"model_only_min_score": 0.75}))
    assert mitre_mapper.load_model_only_min_score(path) == 0.75
    path.write_text(json.dumps({"model_only_min_score": None}))
    assert mitre_mapper.load_model_only_min_score(path) is None
    shipped = mitre_mapper.load_model_only_min_score()
    assert shipped == 0.75  # chosen on the real-world development split
    assert TechniqueMapper(use_model=False).model_only_min_score == shipped
