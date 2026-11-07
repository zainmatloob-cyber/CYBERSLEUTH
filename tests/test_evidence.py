"""Tests for evidence views, the analysis orchestrator and display tables."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.pipeline import Stage
from src.intelligence import analyzer as analyzer_module
from src.intelligence.analyzer import AnalysisStage, Analyzer
from src.intelligence.evidence_manager import link_vulnerabilities
from src.nlp.entity_extractor import EntityExtractor
from src.nlp.entity_models import EntityType
from src.nlp.ioc_models import IOCType
from src.utils.exceptions import ModelNotAvailableError, UnsupportedFileTypeError
from src.visualization import tables

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
REPORT = (
    "APT28 exploited Log4Shell (CVE-2021-44228) and CVE-2024-3400. "
    "They sent spear-phishing emails from 198.51.100.7.\n\n"
    "No findings in this sentence at all.\n\n"
    "Later, Emotet beaconed to hxxp://evil[.]example[.]com/gate."
)


@pytest.fixture(scope="module")
def analyzer() -> Analyzer:
    return Analyzer(entity_extractor=EntityExtractor(model=None))


@pytest.fixture(scope="module")
def result(analyzer):
    return analyzer.analyze(REPORT.encode(), "report.txt")


# --- analyzer -----------------------------------------------------------------


def test_analysis_combines_all_stages(result):
    assert {(i.ioc_type, i.value) for i in result.indicators} == {
        (IOCType.CVE, "CVE-2021-44228"),
        (IOCType.CVE, "CVE-2024-3400"),
        (IOCType.IPV4, "198.51.100.7"),
        (IOCType.URL, "http://evil.example.com/gate"),
    }
    assert {(e.entity_type, e.name) for e in result.entities} == {
        (EntityType.THREAT_ACTOR, "APT28"),
        (EntityType.MALWARE, "Emotet"),
        (EntityType.VULNERABILITY, "Log4Shell"),
        (EntityType.ATTACK_TECHNIQUE, "Spearphishing"),
    }
    assert result.model_name is None and result.kb_versions["attack"] == "20.1"
    assert set(result.timings_ms) == {"ingestion", "iocs", "entities", "total"}


def test_progress_reports_every_stage_once_in_order(analyzer):
    seen: list[AnalysisStage] = []
    analyzer.analyze(REPORT.encode(), "r.txt", on_progress=seen.append)
    assert seen == list(AnalysisStage)


def test_analysis_stages_mirror_ingestion_stages():
    for stage in Stage:
        assert AnalysisStage(stage.value)  # every ingestion stage can be forwarded


def test_ingestion_errors_propagate(analyzer):
    with pytest.raises(UnsupportedFileTypeError):
        analyzer.analyze(b"MZ\x90\x00" * 64, "evil.pdf")


def test_missing_model_falls_back_to_rules(monkeypatch):
    def unavailable(name):
        raise ModelNotAvailableError(f"spaCy model {name!r} is not installed.")

    monkeypatch.setattr("src.nlp.entity_extractor.load_spacy_model", unavailable)
    fallback = analyzer_module.Analyzer(model="en_core_web_sm")
    result = fallback.analyze(REPORT.encode(), "r.txt")
    assert result.model_name is None
    assert any("not installed" in w for w in result.warnings)
    assert any(e.name == "APT28" for e in result.entities)  # rules still work


# --- evidence -----------------------------------------------------------------


def test_sentence_evidence(result):
    evidence = result.evidence
    assert len(evidence) == len(result.document.sentences)
    first = evidence[0]
    assert [i.value for i, _ in first.indicators] == ["CVE-2021-44228", "CVE-2024-3400"]
    assert [e.name for e, _ in first.entities] == ["APT28", "Log4Shell"]
    empty = next(e for e in evidence if "No findings" in e.sentence.text)
    assert not empty.has_findings


def test_vulnerabilities_merge_id_and_name(result):
    records = {r.cve_id: r for r in result.vulnerabilities}
    log4shell = records["CVE-2021-44228"]
    assert log4shell.names == ("Log4Shell",)
    assert (log4shell.id_mentions, log4shell.name_mentions) == (1, 1)
    assert log4shell.mentioned_by == "id+name"
    assert records["CVE-2024-3400"].mentioned_by == "id"
    assert records["CVE-2024-3400"].names == ()


def test_named_vulnerability_without_cve_mention(analyzer):
    result = analyzer.analyze(b"They abused ProxyShell on Exchange servers.", "r.txt")
    assert [(r.cve_id, r.mentioned_by) for r in result.vulnerabilities] == [
        ("CVE-2021-31207", "name"), ("CVE-2021-34473", "name"), ("CVE-2021-34523", "name"),
    ]


def test_link_vulnerabilities_empty():
    assert link_vulnerabilities([], []) == []


# --- tables -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kb_id", "url"),
    [
        ("G0007", "https://attack.mitre.org/groups/G0007/"),
        ("S0154", "https://attack.mitre.org/software/S0154/"),
        (None, None),
        ("T1566", None),  # techniques handled in Phase 3
        ("G0007/../x", None),
    ],
)
def test_attack_url(kb_id, url):
    assert tables.attack_url(kb_id) == url


@pytest.mark.parametrize(
    ("cve", "url"),
    [("CVE-2021-44228", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
     ("CVE-2021-44228?x=1", None), ("evil.com", None)],
)
def test_nvd_url_only_for_valid_ids(cve, url):
    assert tables.nvd_url(cve) == url


def test_frames_have_expected_shape(result):
    iocs = tables.indicators_frame(result.indicators)
    assert len(iocs) == 4 and set(iocs["Verification"]) == {"unverified"}
    assert iocs.loc[iocs["Value"] == "198.51.100.7", "Flags"].item() == "documentation_range"

    entities = tables.entities_frame(result.entities)
    apt28 = entities[entities["Name"] == "APT28"].iloc[0]
    assert apt28["Reference"] == "https://attack.mitre.org/groups/G0007/"

    evidence = tables.evidence_frame(result.evidence)
    assert len(evidence) == 3  # the finding-free sentence is excluded
    assert len(tables.evidence_frame(result.evidence, only_findings=False)) == len(result.evidence)

    url = next(i for i in result.indicators if i.ioc_type is IOCType.URL)
    occurrences = tables.occurrences_frame(url)
    assert occurrences["As written"].item() == "hxxp://evil[.]example[.]com/gate"
    emotet = next(e for e in result.entities if e.name == "Emotet")
    assert tables.mentions_frame(emotet)["As written"].item() == "Emotet"
    assert list(tables.vulnerabilities_frame(result.vulnerabilities)["CVE"]) == [
        "CVE-2021-44228", "CVE-2024-3400",
    ]


def test_empty_frames_keep_columns():
    assert list(tables.indicators_frame([]).columns)[:2] == ["Type", "Value"]
    assert tables.entities_frame([]).empty
    assert tables.evidence_frame([]).empty


def test_sample_advisory_end_to_end(analyzer):
    result = analyzer.analyze((SAMPLES / "synthetic_advisory.pdf").read_bytes(), "a.pdf")
    assert len(result.indicators) == 8
    assert {r.cve_id for r in result.vulnerabilities} == {"CVE-2024-3400"}
    assert any(item.has_findings for item in result.evidence)
