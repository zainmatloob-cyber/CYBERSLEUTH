"""Unverified model suggestions ("leads"): excluded from risk, hidden by default, re-scored on
analyst verdicts, and listed separately in reports and dashboards."""

from __future__ import annotations

import json
from dataclasses import replace

import pymupdf
import pytest
from streamlit.testing.v1 import AppTest

from src.database.db_manager import AnalysisRepository, make_engine
from src.database.views import hydrate, rescore_analysis
from src.intelligence.analyzer import Analyzer
from src.intelligence.assertion import AssertionStatus
from src.intelligence.mitre_mapper import (
    AnalystVerdict,
    MappingMethod,
    TechniqueEvidence,
    TechniqueMapping,
)
from src.intelligence.risk_scorer import RiskScorer
from src.reporting import json_report, pdf_report
from src.visualization import aggregations as agg

TEXT = "APT28 used Kerberoasting against the domain controller. Files were later collected."


def _lead() -> TechniqueMapping:
    return TechniqueMapping(
        "T1486", "Data Encrypted for Impact", ("impact",),
        "https://attack.mitre.org/techniques/T1486/",
        [TechniqueEvidence(1, 1, "Files were later collected.", MappingMethod.MODEL,
                           AssertionStatus.OBSERVED, None, 0.12)])


@pytest.fixture
def stored(tmp_path):
    """A saved analysis: explicit T1558.003 plus a fabricated model-only lead T1486."""
    repo = AnalysisRepository(make_engine(f"sqlite:///{(tmp_path / 'l.db').as_posix()}"))
    result = Analyzer(use_models=False).analyze(TEXT.encode(), "lead.txt")
    mappings = [*result.mappings, _lead()]
    risk = RiskScorer().score(result.document, result.indicators, result.entities,
                              result.vulnerabilities, mappings, result.categories)
    result = replace(result, mappings=mappings, risk=risk)
    analysis_id = repo.save(result).analysis_id
    return repo, analysis_id


def _mapping_id(view, technique_id):
    return view.mapping_ids[technique_id]


def test_lead_property():
    lead = _lead()
    assert lead.is_unverified_lead
    lead.verdict = AnalystVerdict.CONFIRMED
    assert not lead.is_unverified_lead


def test_confirming_a_lead_rescores_and_rejecting_lowers(stored):
    repo, analysis_id = stored
    before = hydrate(repo.get_analysis(analysis_id))
    attack = next(c for c in before.risk.components if c.key == "attack_behaviour")
    assert attack.value == 80  # credential-access only; the impact lead does not count
    assert any("1 unverified model suggestion" in line for line in attack.explanation)

    repo.set_mapping_verdict(_mapping_id(before, "T1486"), "confirmed", "seen in logs")
    after = rescore_analysis(repo, analysis_id)
    attack = next(c for c in after.risk.components if c.key == "attack_behaviour")
    assert attack.value > 80 and after.risk.score > before.risk.score
    assert after.risk.confidence == before.risk.confidence

    repo.set_mapping_verdict(_mapping_id(after, "T1558.003"), "rejected")
    repo.set_mapping_verdict(_mapping_id(after, "T1486"), "rejected")
    rejected = rescore_analysis(repo, analysis_id)
    attack = next(c for c in rejected.risk.components if c.key == "attack_behaviour")
    assert attack.value == 0
    assert len(rejected.risk.components) == 4  # components replaced, not appended


def test_reports_separate_leads(stored):
    repo, analysis_id = stored
    view = hydrate(repo.get_analysis(analysis_id))
    report = json.loads(json_report.to_json(view))
    flags = {m["technique_id"]: m["unverified_model_lead"] for m in report["attack_techniques"]}
    assert flags == {"T1558.003": False, "T1486": True}
    assert any("excluded from the risk score" in line for line in report["summary"])
    text = " ".join(p.get_text() for p in pymupdf.open(stream=pdf_report.to_pdf(view),
                                                       filetype="pdf"))
    assert "Model suggestions (unverified leads)" in text


def test_dashboard_excludes_leads(stored):
    repo, _ = stored
    tactics = agg.tactic_document_counts(repo.latest_mappings()).set_index("Tactic")
    assert "impact" not in tactics.index and "credential-access" in tactics.index
    explorer = agg.technique_explorer(repo.latest_mappings()).set_index("Technique")
    assert explorer.loc["T1486", "Documents (counted)"] == 0
    assert explorer.loc["T1486", "Model lead in"] == 1


def _attack_tab(db_url: str, analysis_id: int) -> None:
    from src.database.db_manager import AnalysisRepository, make_engine
    from src.database.views import hydrate
    from src.ui.analysis_views import render_attack

    repo = AnalysisRepository(make_engine(db_url))
    render_attack(hydrate(repo.get_analysis(analysis_id)), repo)


def test_attack_tab_hides_leads_by_default(stored):
    repo, analysis_id = stored
    at = AppTest.from_function(_attack_tab, kwargs={"db_url": str(repo.engine.url),
                                                    "analysis_id": analysis_id},
                               default_timeout=60).run()
    assert not at.exception
    assert any("1 model suggestion(s) hidden" in c.value for c in at.caption)
    assert list(at.dataframe[0].value["Technique"]) == ["T1558.003"]
    at.checkbox(key="attack_show_leads").check().run()
    assert set(at.dataframe[0].value["Technique"]) == {"T1558.003", "T1486"}
    assert at.warning  # the shown leads come with a caution


def test_verdict_form_rescores(stored):
    from src.ui.analysis_views import _save_mapping_verdict

    repo, analysis_id = stored
    view = hydrate(repo.get_analysis(analysis_id))
    _save_mapping_verdict(repo, analysis_id, _mapping_id(view, "T1486"), "confirmed", None)
    assert hydrate(repo.get_analysis(analysis_id)).risk.score > view.risk.score
