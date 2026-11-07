"""Tests for persistence (src/database/models.py, db_manager.py)."""

from __future__ import annotations

import dataclasses

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from src.database.db_manager import (
    AnalysisRepository,
    DatabaseError,
    analysis_fingerprint,
    init_db,
    make_engine,
)
from src.database.models import (
    Analysis,
    Document,
    Indicator,
    IndicatorOccurrence,
    TechniqueMappingRecord,
    VerificationTarget,
)
from src.intelligence.analyzer import Analyzer
from src.intelligence.mitre_mapper import AnalystVerdict
from src.nlp.ioc_models import IOCType, VerificationStatus

REPORT = (
    "APT28 exploited Log4Shell (CVE-2021-44228) and dumped credentials with Mimikatz. "
    "They used Kerberoasting and contacted 198.51.100.7. Phishing was not involved."
)


@pytest.fixture(scope="module")
def analyzer() -> Analyzer:
    return Analyzer(use_models=False)


@pytest.fixture(scope="module")
def result(analyzer):
    return analyzer.analyze(REPORT.encode(), "report.txt")


@pytest.fixture
def repo(tmp_path) -> AnalysisRepository:
    return AnalysisRepository(make_engine(f"sqlite:///{(tmp_path / 't.db').as_posix()}"))


def _count(repo, model) -> int:
    with repo.session() as session:
        return session.scalar(select(func.count()).select_from(model))


# --- saving and loading -------------------------------------------------------


def test_save_and_load_round_trip(repo, result):
    outcome = repo.save(result)
    assert outcome.created
    stored = repo.get_analysis(outcome.analysis_id)

    assert stored.document.sha256 == result.document.sha256
    assert stored.document.full_text is None  # privacy default
    assert stored.risk_score == result.risk.score and stored.risk_band == result.risk.band
    assert {(i.ioc_type, i.value) for i in stored.indicators} == {
        (i.ioc_type, i.value) for i in result.indicators}
    assert {(e.entity_type, e.name) for e in stored.entities} == {
        (e.entity_type, e.name) for e in result.entities}
    assert {m.technique_id for m in stored.mappings} == {
        m.technique_id for m in result.mappings}
    assert [c.key for c in stored.risk_components] == [c.key for c in result.risk.components]
    ip = next(i for i in stored.indicators if i.ioc_type is IOCType.IPV4)
    assert ip.occurrences[0].context.startswith("They used Kerberoasting")
    phishing = next(m for m in stored.mappings if m.technique_id == "T1566")
    assert phishing.status.value == "negated" and phishing.evidence


def test_full_text_only_when_opted_in(repo, result):
    stored = repo.get_analysis(repo.save(result, store_full_text=True).analysis_id)
    assert stored.document.full_text == result.document.full_text


def test_identical_reanalysis_is_not_duplicated(repo, result):
    first = repo.save(result)
    second = repo.save(result)
    assert not second.created and second.analysis_id == first.analysis_id
    assert _count(repo, Analysis) == 1 and _count(repo, Document) == 1


def test_forced_reanalysis_keeps_history_but_one_document(repo, result):
    repo.save(result)
    repo.save(result, force=True)
    assert _count(repo, Analysis) == 2 and _count(repo, Document) == 1
    # Cross-document views use only the latest analysis per document.
    assert len(repo.latest_indicators()) == len(result.indicators)
    assert repo.stats().indicators == len(result.indicators)


def test_fingerprint_changes_with_components(result):
    changed = dataclasses.replace(result, components={"entities": "other"})
    assert analysis_fingerprint(changed) != analysis_fingerprint(result)


def test_list_analyses_newest_first(repo, analyzer, result):
    repo.save(result)
    repo.save(analyzer.analyze(b"Emotet beaconed to 203.0.113.9 daily.", "other.txt"))
    names = [a.document.filename for a in repo.list_analyses()]
    assert names == ["other.txt", "report.txt"]
    stats = repo.stats()
    assert (stats.documents, stats.analyses) == (2, 2)


# --- verification -------------------------------------------------------------


def test_indicator_verdict_with_audit_trail(repo, result):
    analysis_id = repo.save(result).analysis_id
    indicator = next(i for i in repo.get_analysis(analysis_id).indicators
                     if i.ioc_type is IOCType.IPV4)
    repo.set_indicator_verdict(indicator.id, "malicious", note="Seen in our proxy logs",
                               analyst="alice")
    repo.set_indicator_verdict(indicator.id, VerificationStatus.FALSE_POSITIVE)

    stored = next(i for i in repo.get_analysis(analysis_id).indicators if i.id == indicator.id)
    assert stored.verification is VerificationStatus.FALSE_POSITIVE
    assert stored.verified_at is not None
    events = repo.verification_events(analysis_id)
    assert [(e.old_value, e.new_value, e.analyst) for e in events] == [
        ("unverified", "malicious", "alice"), ("malicious", "false_positive", "analyst")]
    assert events[0].target_type is VerificationTarget.INDICATOR
    assert events[0].note == "Seen in our proxy logs"


def test_mapping_verdict(repo, result):
    analysis_id = repo.save(result).analysis_id
    mapping = next(m for m in repo.get_analysis(analysis_id).mappings
                   if m.technique_id == "T1558.003")
    repo.set_mapping_verdict(mapping.id, AnalystVerdict.CONFIRMED)
    stored = next(m for m in repo.get_analysis(analysis_id).mappings if m.id == mapping.id)
    assert stored.verdict is AnalystVerdict.CONFIRMED


@pytest.mark.parametrize("verdict", ["evil", "", "CONFIRMED"])
def test_invalid_verdicts_rejected(repo, result, verdict):
    analysis_id = repo.save(result).analysis_id
    mapping_id = repo.get_analysis(analysis_id).mappings[0].id
    with pytest.raises(DatabaseError):
        repo.set_mapping_verdict(mapping_id, verdict)
    assert repo.verification_events() == []  # nothing recorded for a rejected update


def test_unknown_ids_and_long_notes_rejected(repo, result):
    with pytest.raises(DatabaseError, match="not found"):
        repo.set_indicator_verdict(999, "benign")
    with pytest.raises(DatabaseError, match="not found"):
        repo.get_analysis(999)
    analysis_id = repo.save(result).analysis_id
    indicator_id = repo.get_analysis(analysis_id).indicators[0].id
    with pytest.raises(DatabaseError, match="Note exceeds"):
        repo.set_indicator_verdict(indicator_id, "benign", note="x" * 5000)


# --- integrity ----------------------------------------------------------------


def test_delete_document_cascades(repo, result):
    outcome = repo.save(result)
    repo.set_indicator_verdict(repo.get_analysis(outcome.analysis_id).indicators[0].id,
                               "benign")
    repo.delete_document(outcome.document_id)
    for model in (Document, Analysis, Indicator, IndicatorOccurrence, TechniqueMappingRecord):
        assert _count(repo, model) == 0
    assert repo.verification_events() == []
    with pytest.raises(DatabaseError):
        repo.delete_document(outcome.document_id)


def test_foreign_keys_are_enforced(repo):
    with pytest.raises(IntegrityError), repo.session() as session:
        session.add(Indicator(analysis_id=12345, ioc_type=IOCType.IPV4, value="1.2.3.4",
                              occurrence_count=1, source="x"))
        session.flush()


def test_duplicate_finding_rejected(repo, result):
    analysis_id = repo.save(result).analysis_id
    existing = repo.get_analysis(analysis_id).indicators[0]
    with pytest.raises(IntegrityError), repo.session() as session:
        session.add(Indicator(analysis_id=analysis_id, ioc_type=existing.ioc_type,
                              value=existing.value, occurrence_count=1, source="x"))
        session.flush()


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE indicators SET verification = 'pwned'",  # enum CHECK
        "UPDATE analyses SET risk_score = 150",  # range CHECK
        "UPDATE analyses SET confidence = 'certain'",
        "UPDATE technique_mappings SET technique_id = 'X1'",
    ],
)
def test_check_constraints(repo, result, sql):
    repo.save(result)
    with pytest.raises(IntegrityError), repo.session() as session:
        session.execute(text(sql))


def test_schema_version_mismatch_detected(tmp_path):
    engine = make_engine(f"sqlite:///{(tmp_path / 'v.db').as_posix()}")
    init_db(engine)
    init_db(engine)  # idempotent for the same version
    with engine.begin() as connection:
        connection.execute(text("PRAGMA user_version = 99"))
    with pytest.raises(DatabaseError, match="schema version"):
        init_db(engine)
