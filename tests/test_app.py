"""UI tests (app.py, src/ui/) using Streamlit's AppTest.

Every test injects a temporary database and a rules-only analyzer, so tests never touch
the real database or load the (slow, optional) trained models.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from src.database.db_manager import AnalysisRepository, make_engine
from src.intelligence.analyzer import Analyzer
from src.nlp.ioc_models import IOCType, VerificationStatus
from src.ui.common import md_escape

APP_PATH = Path(__file__).resolve().parent.parent / "app.py"


@pytest.fixture
def db_url(tmp_path) -> str:
    return f"sqlite:///{(tmp_path / 'ui.db').as_posix()}"


def test_app_renders_without_errors(monkeypatch, db_url):
    import src.ui.common as common

    monkeypatch.setattr(common, "get_repository", lambda: AnalysisRepository(make_engine(db_url)))
    monkeypatch.setattr(common, "get_analyzer", lambda: Analyzer(use_models=False))
    at = AppTest.from_file(str(APP_PATH), default_timeout=60).run()
    assert not at.exception
    assert at.header[0].value == "Document Analysis"
    assert any("Upload a PDF" in info.value for info in at.info)


# --- one analysis, rendered from the database ------------------------------------


def _analysis_script(db_url: str) -> None:
    import pymupdf
    import streamlit as st

    from src.database.db_manager import AnalysisRepository, make_engine
    from src.database.views import hydrate
    from src.intelligence.analyzer import Analyzer
    from src.ui.analysis_views import render_analysis

    repo = AnalysisRepository(make_engine(db_url))
    if "analysis_id" not in st.session_state:
        pdf = pymupdf.open()
        pdf.new_page().insert_text((72, 72), "APT28 used Mimikatz. Then 198.51.100.7 was seen.")
        pdf.new_page().insert_text((72, 72), "Log4Shell (CVE-2021-44228) was exploited.")
        pdf.new_page().insert_text((72, 72), "They used Kerberoasting. No phishing was observed.")
        result = Analyzer(use_models=False).analyze(pdf.tobytes(), "[x](http://evil).pdf")
        st.session_state["result"] = result
        st.session_state["analysis_id"] = repo.save(result).analysis_id
    view = hydrate(repo.get_analysis(st.session_state["analysis_id"]))
    render_analysis(view, repo, st.session_state["result"])


@pytest.fixture
def analysis_app(db_url) -> AppTest:
    at = AppTest.from_function(_analysis_script, kwargs={"db_url": db_url},
                               default_timeout=60).run()
    assert not at.exception
    return at


def test_result_views_render(analysis_app):
    metrics = {m.label: m.value for m in analysis_app.metric}
    assert metrics["Pages"] == "3"
    assert metrics["Unique IOCs"] == "2"  # IP + CVE
    # APT28, Mimikatz, Log4Shell, Kerberoasting, Phishing (the last is a negated mention)
    assert metrics["Entities"] == "5"
    # T1558.003 observed counts; T1566 ("No phishing was observed") is negated, so it doesn't
    assert metrics["ATT&CK techniques"] == "1"
    assert metrics["Risk"].split(" · ")[1] in {"Low", "Moderate", "High", "Critical"}
    assert analysis_app.success  # no warnings → success banner
    assert [t.label for t in analysis_app.tabs][-2:] == ["ℹ️ Metadata",
                                                       "📤 Export"]
    assert "🔤 Sentences" in [t.label for t in analysis_app.tabs]  # session text available


def test_technique_metric_excludes_rejected(analysis_app, db_url):
    from src.intelligence.mitre_mapper import AnalystVerdict

    repo = AnalysisRepository(make_engine(db_url))
    stored = repo.get_analysis(repo.list_analyses()[0].id)
    observed = next(m for m in stored.mappings if m.technique_id == "T1558.003")
    repo.set_mapping_verdict(observed.id, AnalystVerdict.REJECTED, "test")
    at = analysis_app.run()  # the script re-reads the stored analysis
    assert {m.label: m.value for m in at.metric}["ATT&CK techniques"] == "0"


def test_ioc_filters(analysis_app):
    at = analysis_app
    at.text_input(key="ioc_query").set_value("198.51").run()
    assert any("1 of 2 indicators" in c.value for c in at.caption)
    at.checkbox(key="ioc_hide_flagged").check().run()  # 198.51.100.7 is a documentation IP
    assert any("0 of 2 indicators" in c.value for c in at.caption)


def test_attack_tab_hides_negated_by_default(analysis_app):
    at = analysis_app
    assert any("1 of 2 techniques" in c.value for c in at.caption)
    at.checkbox(key="attack_hide_negated").uncheck().run()
    assert any("2 of 2 techniques" in c.value for c in at.caption)


def test_entity_filter_and_evidence_toggle(analysis_app):
    at = analysis_app
    at.text_input(key="entity_query").set_value("mimi").run()
    assert any("1 of 5 entities" in c.value for c in at.caption)
    at.checkbox(key="ev_only").uncheck().run()
    assert not at.exception


def test_risk_tab_explains_components(analysis_app):
    texts = " ".join(t.value for t in analysis_app.text)
    assert "CVE-2021-44228" in texts
    assert "types, not counts" in texts


def test_ioc_verdict_is_saved_with_audit_trail(analysis_app, db_url):
    at = analysis_app
    at.selectbox(key="ioc_detail").set_value(
        next(i for i, label in enumerate(at.selectbox(key="ioc_detail").options)
             if "198.51.100.7" in label)).run()
    verdict_box = next(s for s in at.selectbox
                       if (s.key or "").startswith("ioc_verdict_") and s.key.endswith("_verdict"))
    verdict_box.set_value("malicious")
    note_key = verdict_box.key.removesuffix("_verdict") + "_note"
    next(t for t in at.text_area if t.key == note_key).set_value("Seen in proxy logs")
    # Two forms are on the page (ATT&CK and IOC); pick the IOC form's submit button.
    next(b for b in at.button if "ioc_verdict_" in (b.key or "")).click().run()
    assert not at.exception
    assert any("Saved verdict 'malicious'" in s.value for s in at.success)

    repo = AnalysisRepository(make_engine(db_url))
    stored = repo.get_analysis(repo.list_analyses()[0].id)
    ip = next(i for i in stored.indicators if i.ioc_type is IOCType.IPV4)
    assert ip.verification is VerificationStatus.MALICIOUS
    assert ip.analyst_note == "Seen in proxy logs"
    assert [e.new_value for e in repo.verification_events()] == ["malicious"]


# --- history and dashboard pages --------------------------------------------------


def _pages_script(db_url: str, page: str) -> None:
    from src.database.db_manager import AnalysisRepository, make_engine
    from src.intelligence.analyzer import Analyzer
    from src.ui import pages

    repo = AnalysisRepository(make_engine(db_url))
    if not repo.list_analyses():
        analyzer = Analyzer(use_models=False)
        repo.save(analyzer.analyze(b"Emotet beaconed to 203.0.113.9 daily.", "one.txt"))
        repo.save(analyzer.analyze(b"APT28 exploited CVE-2024-3400 widely.", "two.txt"))
    {"history": lambda: pages.history_page(repo),
     "dashboard": lambda: pages.dashboard_page(repo)}[page]()


def test_history_lists_and_reopens_analyses(db_url):
    at = AppTest.from_function(_pages_script, kwargs={"db_url": db_url, "page": "history"},
                               default_timeout=60).run()
    assert not at.exception
    assert at.header[0].value == "Analysis History"
    assert at.dataframe[0].value["Document"].tolist() == ["two.txt", "one.txt"]
    assert "🔤 Sentences" not in [t.label for t in at.tabs]  # no session text when reopened


def test_history_delete_requires_confirmation(db_url):
    at = AppTest.from_function(_pages_script, kwargs={"db_url": db_url, "page": "history"},
                               default_timeout=60).run()
    delete = at.button(key="history_delete")
    assert delete.disabled
    at.checkbox(key="history_delete_confirm").check().run()
    at.button(key="history_delete").click().run()
    assert not at.exception
    remaining = [a.document.filename for a in
                 AnalysisRepository(make_engine(db_url)).list_analyses()]
    assert remaining == ["one.txt"]


def test_dashboard_counts(db_url):
    at = AppTest.from_function(_pages_script, kwargs={"db_url": db_url, "page": "dashboard"},
                               default_timeout=60).run()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert (metrics["Documents"], metrics["Analyses"]) == ("2", "2")


def _no_db_script() -> None:
    from src.intelligence.analyzer import Analyzer
    from src.ui import pages

    pages.analysis_page(Analyzer(use_models=False), None)
    pages.history_page(None)


def test_pages_degrade_without_database():
    at = AppTest.from_function(_no_db_script, default_timeout=60).run()
    assert not at.exception
    assert any("database is unavailable" in w.value for w in at.warning)


def _error_script() -> None:
    import streamlit as st

    from src.intelligence.analyzer import Analyzer
    from src.ui.common import run_analysis

    result, error = run_analysis(Analyzer(use_models=False), b"MZ\x90\x00" * 64, "evil.pdf")
    st.write(f"result={result is None} error={error}")


def test_run_analysis_returns_error_message_for_bad_file():
    at = AppTest.from_function(_error_script, default_timeout=60).run()
    assert not at.exception
    assert "result=True" in at.markdown[0].value
    assert "not a recognised" in at.markdown[0].value


# --- escaping -----------------------------------------------------------------


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


# --- the upload flow of the analysis page --------------------------------------------


def _upload_script(db_url: str, data: bytes, name: str, file_id: str,
                   fail_save: bool = False) -> None:
    import streamlit as st

    from src.database.db_manager import AnalysisRepository, DatabaseError, make_engine
    from src.intelligence.analyzer import Analyzer
    from src.ui import pages

    class Upload:  # stands in for Streamlit's UploadedFile
        def __init__(self):
            self.name, self.file_id = name, file_id

        def getvalue(self) -> bytes:
            return data

    st.session_state.setdefault("analyses_run", 0)

    class CountingAnalyzer(Analyzer):
        def analyze(self, *args, **kwargs):
            st.session_state["analyses_run"] += 1
            return super().analyze(*args, **kwargs)

    repo = AnalysisRepository(make_engine(db_url))
    if fail_save:
        def refuse(_result):
            raise DatabaseError("disk full")
        repo.save = refuse
    st.file_uploader = lambda *args, **kwargs: Upload()
    pages.analysis_page(CountingAnalyzer(use_models=False), repo)
    st.caption(f"analyses_run={st.session_state['analyses_run']}")


REPORT = b"APT28 used Mimikatz against 198.51.100.7 before deploying LockBit."


def _upload_app(db_url, **kwargs) -> AppTest:
    at = AppTest.from_function(_upload_script, kwargs={"db_url": db_url, **kwargs},
                               default_timeout=60).run()
    assert not at.exception
    return at


def _runs(at) -> str:
    return next(c.value for c in at.caption if c.value.startswith("analyses_run="))


def test_upload_is_analysed_saved_and_not_reanalysed_on_rerun(db_url):
    at = _upload_app(db_url, data=REPORT, name="r.txt", file_id="f1")
    assert any("Saved as analysis #1" in i.value for i in at.info)
    assert _runs(at) == "analyses_run=1"
    at.run()  # any widget interaction reruns the script with the same upload
    assert not at.exception and _runs(at) == "analyses_run=1"


def test_same_document_uploaded_again_reopens_the_stored_analysis(db_url):
    _upload_app(db_url, data=REPORT, name="r.txt", file_id="f1")
    at = _upload_app(db_url, data=REPORT, name="copy.txt", file_id="f2")
    assert any("already analysed" in i.value and "#1" in i.value for i in at.info)


def test_bad_upload_shows_an_escaped_error(db_url):
    at = _upload_app(db_url, data=b"MZ\x90\x00" * 64, name="[x](http://evil).pdf",
                     file_id="f3")
    message = at.error[0].value
    assert "Could not process" in message and r"\[x\]\(http\://evil\)" in message
    assert not at.tabs  # nothing else is rendered for a rejected file


def test_save_failure_still_shows_the_analysis(db_url):
    at = _upload_app(db_url, data=REPORT, name="r.txt", file_id="f4", fail_save=True)
    assert any("Not saved: disk full" in i.value for i in at.info)
    assert at.tabs  # the in-memory analysis is still displayed


def _crash_script() -> None:
    import streamlit as st

    from src.ui.common import run_analysis

    class Broken:
        def analyze(self, *args, **kwargs):
            raise RuntimeError("secret internal detail /etc/app.conf")

    result, error = run_analysis(Broken(), b"x", "r.txt")
    st.write(f"result={result is None} error={error}")


def test_unexpected_failure_shows_a_generic_message_only():
    at = AppTest.from_function(_crash_script, default_timeout=60).run()
    assert not at.exception
    text = at.markdown[0].value
    assert "result=True" in text and "unexpected error" in text
    assert "secret" not in text and "/etc/app.conf" not in text  # details go to the log only


def test_repository_failure_gives_none(monkeypatch):
    import src.ui.common as common

    def broken():
        raise OSError("cannot open database")

    monkeypatch.setattr(common, "AnalysisRepository", broken)
    common.get_repository.clear()
    try:
        assert common.get_repository() is None
    finally:
        common.get_repository.clear()
