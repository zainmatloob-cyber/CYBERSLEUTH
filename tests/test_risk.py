"""Tests for risk scoring (src/intelligence/risk_scorer.py) and threat assessment."""

from __future__ import annotations

import copy
import json

import numpy as np
import pytest

from src.ingestion.models import ExtractedDocument, FileType, PageText
from src.intelligence.assertion import AssertionStatus
from src.intelligence.evidence_manager import VulnerabilityRecord
from src.intelligence.mitre_mapper import (
    AnalystVerdict,
    MappingMethod,
    TechniqueEvidence,
    TechniqueMapping,
)
from src.intelligence.risk_scorer import RiskConfigError, RiskScorer, load_risk_config
from src.intelligence.threat_assessment import (
    CategoryEvidence,
    ThreatAssessor,
    ThreatCategoryFinding,
)
from src.nlp.entity_models import Entity, EntitySource, EntityType
from src.nlp.ioc_models import Indicator, IOCOccurrence, IOCType
from src.nlp.preprocessing import split_sentences

KEV = {"CVE-2024-3400": {"ransomware_use": False}, "CVE-2023-4966": {"ransomware_use": True}}


@pytest.fixture(scope="module")
def scorer() -> RiskScorer:
    return RiskScorer(kev=KEV)


def _doc(sentences: int = 10, needs_ocr: bool = False) -> ExtractedDocument:
    pages = [PageText(1, " ".join(f"Sentence number {i} here." for i in range(sentences)))]
    return ExtractedDocument("x", FileType.TXT, "0" * 64, 1, pages, needs_ocr=needs_ocr,
                             sentences=split_sentences(pages))


def _ioc(kind: IOCType, value: str) -> Indicator:
    return Indicator(kind, value, [IOCOccurrence(value, 1, 0, 1, False, 0, "ctx")])


def _vuln(cve: str, names: tuple[str, ...] = ()) -> VulnerabilityRecord:
    return VulnerabilityRecord(cve, names, 1, len(names), (1,))


def _mapping(tid: str, tactics: tuple[str, ...], status=AssertionStatus.OBSERVED,
             method=MappingMethod.EXPLICIT_NAME, sentence: int = 0) -> TechniqueMapping:
    return TechniqueMapping(tid, f"name {tid}", tactics, "u", [TechniqueEvidence(
        sentence, 1, "ctx", method, status, "m", None if method is not MappingMethod.MODEL
        else 1.0)])


def _malware(name: str, source=EntitySource.ATTACK_KB) -> Entity:
    return Entity(EntityType.MALWARE, name, source)


def _category(name: str, status=AssertionStatus.OBSERVED, sentence: int = 0):
    return ThreatCategoryFinding(name, [CategoryEvidence(sentence, 1, "ctx", "rules", status)])


def _score(scorer, **kw):
    args = {"document": _doc(), "indicators": [], "entities": [], "vulnerabilities": [],
            "mappings": [], "categories": []}
    args.update(kw)
    return scorer.score(**args)


def _component(risk, key):
    return next(c for c in risk.components if c.key == key)


# --- configuration ------------------------------------------------------------


def test_default_config_is_valid():
    config = load_risk_config()
    assert sum(config["weights"].values()) == pytest.approx(1.0)
    assert config["weights"] == {"vulnerability": 0.30, "malware": 0.25,
                                 "attack_behaviour": 0.25, "evidence": 0.20}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["weights"].update(vulnerability=0.5),  # sum != 1
        lambda c: c["weights"].pop("evidence"),
        lambda c: c["bands"].__setitem__(0, {"name": "Low", "min": 5}),
        lambda c: c["bands"].reverse(),
    ],
)
def test_invalid_config_rejected(tmp_path, mutate):
    config = copy.deepcopy(load_risk_config())
    mutate(config)
    path = tmp_path / "risk.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(RiskConfigError):
        load_risk_config(path)


@pytest.mark.parametrize(("score", "band"), [(0, "Low"), (29.9, "Low"), (30, "Moderate"),
                                             (49.9, "Moderate"), (50, "High"), (75, "Critical"),
                                             (100, "Critical")])
def test_bands(scorer, score, band):
    assert scorer.band(score) == band


# --- empty and totals -----------------------------------------------------------


def test_no_evidence_scores_zero_with_low_confidence(scorer):
    risk = _score(scorer)
    assert risk.score == 0 and risk.band == "Low"
    assert risk.confidence.level == "low"
    assert all(c.explanation for c in risk.components)  # "no evidence" is explained


def test_contributions_sum_to_score(scorer):
    risk = _score(scorer, vulnerabilities=[_vuln("CVE-2024-3400")],
                  entities=[_malware("Emotet")],
                  mappings=[_mapping("T1486", ("impact",))],
                  indicators=[_ioc(IOCType.IPV4, "198.51.100.1")])
    assert risk.score == pytest.approx(sum(c.contribution for c in risk.components), abs=0.1)


# --- V ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (_vuln("CVE-2023-4966", ("Citrix Bleed",)), 100),  # KEV + ransomware use
        (_vuln("CVE-2024-3400"), 90),  # KEV
        (_vuln("CVE-2021-44228", ("Log4Shell",)), 70),  # named, not in this test KEV
        (_vuln("CVE-2020-00001"), 50),  # mentioned
    ],
)
def test_vulnerability_levels(scorer, record, expected):
    assert _component(_score(scorer, vulnerabilities=[record]), "vulnerability").value == expected


def test_many_cves_do_not_inflate_vulnerability(scorer):
    many = [_vuln(f"CVE-2020-{i:05d}") for i in range(40)]
    assert _component(_score(scorer, vulnerabilities=many), "vulnerability").value == 60  # 50+10


# --- M ------------------------------------------------------------------------


def test_malware_levels(scorer):
    hashes = [_ioc(IOCType.SHA256, "a" * 63 + "1")]
    assert _component(_score(scorer, entities=[_malware("X", EntitySource.MODEL)]),
                      "malware").value == 50
    assert _component(_score(scorer, entities=[_malware("Emotet")]), "malware").value == 60
    assert _component(_score(scorer, entities=[_malware("Emotet")], indicators=hashes),
                      "malware").value == 70
    assert _component(_score(scorer, categories=[_category("ransomware")], indicators=hashes),
                      "malware").value == 95


def test_hashes_alone_are_not_malware_evidence(scorer):
    hashes = [_ioc(IOCType.MD5, f"{i:032x}") for i in range(1, 6)]
    assert _component(_score(scorer, indicators=hashes), "malware").value == 0


def test_negated_ransomware_is_ignored(scorer):
    risk = _score(scorer, categories=[_category("ransomware", AssertionStatus.NEGATED)])
    assert _component(risk, "malware").value == 0


# --- A ------------------------------------------------------------------------


def test_attack_status_and_method_factors(scorer):
    def value(**kw):
        return _component(_score(scorer, mappings=[_mapping("T1486", ("impact",), **kw)]),
                          "attack_behaviour").value

    assert value() == 100
    assert value(status=AssertionStatus.CAPABILITY) == 50
    assert value(method=MappingMethod.MODEL) == 0  # unverified suggestion: a lead, not scored
    assert value(status=AssertionStatus.NEGATED) == 0


def test_verdicts_change_the_attack_component(scorer):
    def value(mapping):
        return _component(_score(scorer, mappings=[mapping]), "attack_behaviour")

    model = _mapping("T1486", ("impact",), method=MappingMethod.MODEL)
    assert value(model).value == 0
    assert any("1 unverified model suggestion" in line for line in value(model).explanation)
    model.verdict = AnalystVerdict.CONFIRMED  # confirmed suggestions count like explicit ones
    assert value(model).value == 100
    explicit = _mapping("T1486", ("impact",))
    explicit.verdict = AnalystVerdict.REJECTED
    assert value(explicit).value == 0


def test_rescore_keeps_confidence_and_reflects_verdicts(scorer):
    model = _mapping("T1486", ("impact",), method=MappingMethod.MODEL)
    before = _score(scorer, mappings=[model])
    model.verdict = AnalystVerdict.CONFIRMED
    after = scorer.rescore(before, [], [], [], [model], [])
    assert after.score > before.score
    assert after.confidence == before.confidence
    assert after.config_version == load_risk_config()["version"]


def test_attack_breadth_bonus_is_capped(scorer):
    tactics = ["discovery", "execution", "persistence", "collection", "stealth",
               "command-and-control", "initial-access", "reconnaissance"]
    mappings = [_mapping(f"T10{i:02d}", (t,), sentence=i) for i, t in enumerate(tactics)]
    # max = 65 (command-and-control) + min(15, 3 × 7) = 80
    assert _component(_score(scorer, mappings=mappings), "attack_behaviour").value == 80


# --- E and volume invariance --------------------------------------------------


def test_ioc_volume_does_not_change_score(scorer):
    base = {"entities": [_malware("Emotet")], "mappings": [_mapping("T1059", ("execution",))]}
    one = _score(scorer, indicators=[_ioc(IOCType.IPV4, "198.51.100.1")], **base)
    many = _score(scorer, indicators=[_ioc(IOCType.IPV4, f"198.51.100.{i}")
                                      for i in range(250)], **base)
    assert one.score == many.score


def test_ioc_type_diversity_raises_evidence_only(scorer):
    diverse = [_ioc(t, v) for t, v in [(IOCType.IPV4, "1.2.3.4"), (IOCType.DOMAIN, "a.com"),
                                       (IOCType.URL, "http://a.com"), (IOCType.MD5, "b" * 32)]]
    risk = _score(scorer, indicators=diverse)
    assert _component(risk, "evidence").value == 30
    assert risk.score == pytest.approx(6.0)  # 0.20 × 30: IOCs alone cannot make a report risky
    assert risk.band == "Low"


def test_model_suggestions_do_not_add_breadth(scorer):
    tactics = ["discovery", "execution", "persistence", "collection", "stealth"]
    mappings = [_mapping(f"T10{i:02d}", (t,), method=MappingMethod.MODEL, sentence=i)
                for i, t in enumerate(tactics)]
    # Unverified model suggestions contribute neither severity nor breadth.
    assert _component(_score(scorer, mappings=mappings), "attack_behaviour").value == 0
    for mapping in mappings[:2]:
        mapping.verdict = AnalystVerdict.CONFIRMED
    # Confirmed: max(35 discovery, 55 execution) + breadth 3 for two corroborated tactics.
    assert _component(_score(scorer, mappings=mappings), "attack_behaviour").value == 58


def test_every_attack_tactic_has_a_severity():
    from src.intelligence.attack_kb import default_technique_kb

    tactics = {t for tech in default_technique_kb().techniques.values() for t in tech.tactics}
    assert tactics <= set(load_risk_config()["attack_behaviour"]["tactic_severity"])


def test_corroboration_raises_evidence(scorer):
    explicit = _score(scorer, mappings=[_mapping("T1486", ("impact",))])
    model = _score(scorer, mappings=[_mapping("T1486", ("impact",), method=MappingMethod.MODEL)])
    assert _component(explicit, "evidence").value > _component(model, "evidence").value


# --- confidence ---------------------------------------------------------------


def test_confidence_is_independent_of_severity(scorer):
    strong = {"vulnerabilities": [_vuln("CVE-2023-4966", ("Citrix Bleed",))],
              "mappings": [_mapping("T1486", ("impact",))]}
    clean = _score(scorer, **strong)
    degraded = _score(scorer, document=_doc(sentences=2, needs_ocr=True),
                      degraded=["Model X missing."], **strong)
    assert clean.score == degraded.score
    assert clean.confidence.level == "high"
    assert degraded.confidence.level == "low"
    assert len(degraded.confidence.reasons) == 3


def test_model_only_mappings_do_not_change_severity_or_confidence(scorer):
    mappings = [_mapping(f"T10{i:02d}", ("execution",), method=MappingMethod.MODEL, sentence=i)
                for i in range(5)]
    with_leads = _score(scorer, mappings=mappings)
    without = _score(scorer, mappings=[])
    assert with_leads.score == without.score
    assert with_leads.confidence == without.confidence


# --- threat assessment ----------------------------------------------------------


def _sentences_doc(text: str) -> ExtractedDocument:
    pages = [PageText(1, text)]
    return ExtractedDocument("x", FileType.TXT, "0" * 64, 1, pages,
                             sentences=split_sentences(pages))


def test_threat_assessor_rules_and_negation():
    doc = _sentences_doc("Ryuk encrypted files on the shares. No DDoS attack was observed.")
    findings = {f.category: f for f in ThreatAssessor().assess(doc)}
    assert findings["ransomware"].asserted and findings["ransomware"].sources == ["rules"]
    assert findings["ddos"].status is AssertionStatus.NEGATED and not findings["ddos"].asserted
    assert list(findings)[-1] == "ddos"  # negated findings sort last


class _FakeClassifier:
    categories = ("phishing",)

    def scores(self, texts):
        return np.array([[0.9] if "lure" in t else [0.1] for t in texts])

    def predict(self, texts):
        return [frozenset({"phishing"}) if "lure" in t else frozenset({"other"}) for t in texts]


def test_threat_assessor_uses_model_scores():
    doc = _sentences_doc("The lure arrived by mail today. Nothing else happened.")
    (finding,) = [f for f in ThreatAssessor(_FakeClassifier()).assess(doc)
                  if f.category == "phishing"]
    assert finding.sources == ["model"] and finding.max_score == 0.9


def test_threat_assessor_empty_document():
    empty = ExtractedDocument("x", FileType.TXT, "0" * 64, 1, [PageText(1, "")])
    assert ThreatAssessor().assess(empty) == []
