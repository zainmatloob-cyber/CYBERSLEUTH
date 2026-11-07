"""UI tests for the Streamlit app (app.py) using Streamlit's AppTest."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from app import md_escape

APP_PATH = Path(__file__).resolve().parent.parent / "app.py"


def test_app_renders_without_errors():
    at = AppTest.from_file(str(APP_PATH), default_timeout=60).run()
    assert not at.exception
    assert at.header[0].value == "Document Analysis"
    assert any("Upload a PDF" in info.value for info in at.info)


def _render_results_script() -> None:
    """Runs inside AppTest: analyse a real document and render every results view."""
    import pymupdf
    import streamlit as st

    import app
    from src.intelligence.analyzer import Analyzer

    pdf = pymupdf.open()
    pdf.new_page().insert_text((72, 72), "APT28 used Mimikatz. Then 198.51.100.7 was seen.")
    pdf.new_page().insert_text((72, 72), "Log4Shell (CVE-2021-44228) was exploited.")
    pdf.new_page().insert_text((72, 72), "They used Kerberoasting. No phishing was observed.")
    if "result" not in st.session_state:
        analyzer = Analyzer(use_models=False)
        st.session_state["result"] = analyzer.analyze(pdf.tobytes(), "[x](http://evil).pdf")
    result = st.session_state["result"]
    app._render_summary(result)
    app._render_risk_tab(result)
    app._render_threats_tab(result)
    app._render_attack_tab(result)
    app._render_iocs_tab(result)
    app._render_entities_tab(result)
    app._render_evidence_tab(result)
    app._render_text_tab(result.document)
    app._render_sentences_tab(result.document)
    app._render_metadata_tab(result)


@pytest.fixture
def results_app() -> AppTest:
    at = AppTest.from_function(_render_results_script, default_timeout=60).run()
    assert not at.exception
    return at


def test_result_views_render(results_app):
    at = results_app
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Pages"] == "3"
    assert metrics["Unique IOCs"] == "2"  # IP + CVE
    # APT28, Mimikatz, Log4Shell, Kerberoasting, Phishing (the last is a negated mention)
    assert metrics["Entities"] == "5"
    assert metrics["ATT&CK techniques"] == "2"  # T1558.003 observed, T1566 negated
    assert metrics["Risk"].split(" · ")[1] in {"Low", "Moderate", "High", "Critical"}
    assert at.success  # no warnings → success banner


def test_attack_tab_hides_negated_by_default(results_app):
    at = results_app
    assert any("1 of 2 techniques" in c.value for c in at.caption)
    at.checkbox(key="attack_hide_negated").uncheck().run()
    assert any("2 of 2 techniques" in c.value for c in at.caption)


def test_risk_tab_explains_components(results_app):
    texts = " ".join(t.value for t in results_app.text)
    assert "CVE-2021-44228" in texts  # vulnerability explanation names the CVE
    assert "types, not counts" in texts


def test_ioc_filters(results_app):
    at = results_app
    at.text_input(key="ioc_query").set_value("198.51").run()
    assert not at.exception
    assert any("1 of 2 indicators" in c.value for c in at.caption)
    at.checkbox(key="ioc_hide_flagged").check().run()  # 198.51.100.7 is a documentation IP
    assert any("0 of 2 indicators" in c.value for c in at.caption)


def test_entity_filter_and_evidence_toggle(results_app):
    at = results_app
    at.text_input(key="entity_query").set_value("mimi").run()
    assert any("1 of 5 entities" in c.value for c in at.caption)
    at.checkbox(key="ev_only").uncheck().run()
    assert not at.exception


def _error_script() -> None:
    import streamlit as st

    import app
    from src.intelligence.analyzer import Analyzer

    analyzer = Analyzer(use_models=False)
    result, error = app._run_analysis(analyzer, b"MZ\x90\x00" * 64, "evil.pdf")
    st.write(f"result={result is None} error={error}")


def test_run_analysis_returns_error_message_for_bad_file():
    at = AppTest.from_function(_error_script, default_timeout=60).run()
    assert not at.exception
    assert "result=True" in at.markdown[0].value
    assert "not a recognised" in at.markdown[0].value


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [
        ("[a](http://x)", r"\[a\]\(http\://x\)"),
        ("**bold**", r"\*\*bold\*\*"),
        ("<img src=x>", r"\<img src=x\>"),
    ],
)
def test_md_escape_neutralises_markup(raw, escaped):
    assert md_escape(raw) == escaped


def test_md_escape_keeps_plain_text_readable():
    assert md_escape("report 2026") == "report 2026"
