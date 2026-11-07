"""Tests for cross-document aggregations, figures and the dashboard/explorer pages."""

from __future__ import annotations

import pytest
from streamlit.testing.v1 import AppTest

from src.database.db_manager import AnalysisRepository, make_engine
from src.intelligence.analyzer import Analyzer
from src.visualization import aggregations as agg
from src.visualization import dashboard as charts

DOCS = {
    "a.txt": "APT28 used Kerberoasting and contacted 198.51.100.7. Ryuk encrypted files.",
    "b.txt": "Emotet beaconed to 198.51.100.7. The operators used Kerberoasting again. "
             "No phishing was observed.",
    "c.txt": "They exploited CVE-2024-3400 on edge devices.",
}


@pytest.fixture
def repo(tmp_path) -> AnalysisRepository:
    repo = AnalysisRepository(make_engine(f"sqlite:///{(tmp_path / 'd.db').as_posix()}"))
    analyzer = Analyzer(use_models=False)
    for name, text in DOCS.items():
        repo.save(analyzer.analyze(text.encode(), name))
    repo.save(analyzer.analyze(DOCS["a.txt"].encode(), "a.txt"), force=True)  # re-analysis
    return repo


# --- aggregations -------------------------------------------------------------


def test_reanalysis_is_not_double_counted(repo):
    assert len(repo.latest_analyses()) == 3
    ip = agg.ioc_explorer(repo.latest_indicators()).set_index("Value").loc["198.51.100.7"]
    assert ip["Documents"] == 2  # a.txt (latest analysis only) and b.txt
    assert ip["Seen in"] == "a.txt, b.txt"


def test_risk_band_counts_include_empty_bands(repo):
    bands = agg.risk_band_counts(repo.latest_analyses())
    assert list(bands["Band"]) == ["Low", "Moderate", "High", "Critical"]
    assert bands["Documents"].sum() == 3


def test_technique_explorer_counts_documents_and_negation(repo):
    frame = agg.technique_explorer(repo.latest_mappings()).set_index("Technique")
    assert frame.loc["T1558.003", "Documents (non-negated)"] == 2
    assert frame.loc["T1566", "Documents (non-negated)"] == 0
    assert frame.loc["T1566", "Negated in"] == 1
    assert frame.loc["T1558.003", "Unverified"] == 2


def test_tactic_counts_exclude_negated(repo):
    tactics = agg.tactic_document_counts(repo.latest_mappings()).set_index("Tactic")
    assert "initial-access" not in tactics.index  # only the negated T1566 carries it
    assert tactics.loc["credential-access", "Documents"] == 2


def test_verification_coverage_follows_verdicts(repo):
    mapping = next(m for m in repo.latest_mappings() if m.technique_id == "T1558.003")
    repo.set_mapping_verdict(mapping.id, "confirmed")
    coverage = agg.verification_coverage(repo.latest_mappings())
    assert coverage["confirmed"] == 1 and coverage["unverified"] == sum(coverage.values()) - 1


def test_tactic_matrix_shape(repo):
    matrix = agg.tactic_document_matrix(repo.latest_mappings())
    assert set(matrix.columns) <= set(DOCS)
    assert (matrix.values >= 0).all()


def test_entity_and_ioc_occurrence_views(repo):
    entities = agg.entity_explorer(repo.latest_entities()).set_index("Name")
    assert entities.loc["Kerberoasting", "Documents"] == 2
    occurrences = agg.ioc_occurrences(repo.latest_indicators(), "IPV4", "198.51.100.7")
    assert sorted(occurrences["Document"]) == ["a.txt", "b.txt"]


def test_empty_inputs():
    assert agg.category_document_counts([]).empty
    assert agg.ioc_explorer([]).empty
    assert agg.tactic_document_matrix([]).empty
    assert agg.risk_band_counts([])["Documents"].sum() == 0


# --- figures ------------------------------------------------------------------


def test_figures_follow_the_colour_decisions(repo):
    bands = charts.risk_band_bar(agg.risk_band_counts(repo.latest_analyses()))
    assert bands.data[0].marker.color == charts.SERIES  # one hue; labels carry severity
    assert list(bands.data[0].x)[0] == "🟢 Low"
    bar = charts.horizontal_bar(agg.ioc_type_counts(repo.latest_indicators()), "Type",
                                "Unique indicators", "t", "indicators")
    assert bar.layout.showlegend is False and bar.layout.barcornerradius == 4
    assert bar.data[0].hovertemplate  # every mark has a tooltip
    heat = charts.tactic_heatmap(agg.tactic_document_matrix(repo.latest_mappings()))
    assert heat.data[0].colorscale[0][1] == "#0e1117"  # zero recedes into the dark surface


# --- pages ----------------------------------------------------------------------


def _page_script(db_url: str, page: str) -> None:
    from src.database.db_manager import AnalysisRepository, make_engine
    from src.ui import pages

    repo = AnalysisRepository(make_engine(db_url))
    getattr(pages, page)(repo)


@pytest.mark.parametrize("page", ["dashboard_page", "ioc_explorer_page",
                                  "entity_explorer_page", "attack_explorer_page"])
def test_pages_render(repo, page):
    url = str(repo.engine.url)
    at = AppTest.from_function(_page_script, kwargs={"db_url": url, "page": page},
                               default_timeout=60).run()
    assert not at.exception


def test_ioc_explorer_shared_filter(repo):
    at = AppTest.from_function(_page_script, kwargs={"db_url": str(repo.engine.url),
                                                     "page": "ioc_explorer_page"},
                               default_timeout=60).run()
    total = int(next(c.value for c in at.caption if " of " in c.value).split(" of ")[1].split()[0])
    at.checkbox(key="iocx_shared").check().run()
    assert any(f"1 of {total} indicators" in c.value for c in at.caption)


@pytest.mark.parametrize("page", ["dashboard_page", "attack_explorer_page"])
def test_pages_handle_empty_database(tmp_path, page):
    url = f"sqlite:///{(tmp_path / 'empty.db').as_posix()}"
    at = AppTest.from_function(_page_script, kwargs={"db_url": url, "page": page},
                               default_timeout=60).run()
    assert not at.exception
    assert any("No analyses saved yet" in i.value for i in at.info)
