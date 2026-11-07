"""Round-trip test: save → load → hydrate must reproduce the original findings exactly."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.database.db_manager import AnalysisRepository, make_engine
from src.database.views import hydrate
from src.intelligence.analyzer import Analyzer
from src.intelligence.mitre_mapper import AnalystVerdict
from src.nlp.ioc_models import IOCType, VerificationStatus

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
REPORT = (
    "APT28 exploited Log4Shell (CVE-2021-44228) and dumped credentials with Mimikatz. "
    "They used Kerberoasting and contacted hxxp://evil[.]example[.]com/a and 198.51.100.7.\n\n"
    "Ryuk encrypted files on the shares. Phishing was not involved."
)


@pytest.fixture(scope="module")
def analyzer():
    return Analyzer(use_models=False)


@pytest.fixture
def repo(tmp_path):
    return AnalysisRepository(make_engine(f"sqlite:///{(tmp_path / 'v.db').as_posix()}"))


@pytest.mark.parametrize("source", ["report", "sample"])
def test_round_trip_is_lossless(repo, analyzer, source):
    data, name = ((REPORT.encode(), "r.txt") if source == "report"
                  else ((SAMPLES / "synthetic_advisory.pdf").read_bytes(), "a.pdf"))
    original = analyzer.analyze(data, name)
    view = hydrate(repo.get_analysis(repo.save(original).analysis_id))

    assert view.indicators == original.indicators
    assert view.entities == original.entities
    assert view.categories == original.categories
    assert view.mappings == original.mappings
    assert view.risk == original.risk
    assert view.vulnerabilities == original.vulnerabilities
    assert (view.filename, view.sha256, view.page_count, view.sentence_count) == (
        original.document.filename, original.document.sha256, original.document.page_count,
        len(original.document.sentences))
    assert view.components == original.components and view.kb_versions == original.kb_versions


def test_hydrated_view_reflects_verdicts_and_ids(repo, analyzer):
    analysis_id = repo.save(analyzer.analyze(REPORT.encode(), "r.txt")).analysis_id
    view = hydrate(repo.get_analysis(analysis_id))
    ip_id = view.indicator_ids[(IOCType.IPV4, "198.51.100.7")]
    mapping_id = view.mapping_ids["T1558.003"]
    repo.set_indicator_verdict(ip_id, VerificationStatus.BENIGN, note="Our scanner")
    repo.set_mapping_verdict(mapping_id, AnalystVerdict.CONFIRMED)

    view = hydrate(repo.get_analysis(analysis_id))
    ip = next(i for i in view.indicators if i.value == "198.51.100.7")
    assert ip.verification is VerificationStatus.BENIGN
    assert view.indicator_notes[ip_id] == "Our scanner"
    assert next(m for m in view.mappings if m.technique_id == "T1558.003").verdict is \
        AnalystVerdict.CONFIRMED
