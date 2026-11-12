"""Web interface tests (src/web/) using FastAPI's TestClient.

Every test uses a temporary database and a rules-only analyzer, so tests never touch the
real database or load the (slow, optional) trained models.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.database.db_manager import AnalysisRepository, make_engine
from src.intelligence.analyzer import Analyzer
from src.web.app import _safe_filename, create_app
from src.web.render import Cell, format_value, table
from src.web.security import CONTENT_SECURITY_POLICY
from src.web.state import ResultCache

REPORT = (b"APT28 used Mimikatz against the target. Then 198.51.100.7 contacted "
          b"http://evil.example/payload. Log4Shell (CVE-2021-44228) was exploited. "
          b"No phishing was observed.")
TEMPLATES = Path(__file__).resolve().parent.parent / "src" / "web" / "templates"
HX = {"HX-Request": "true"}


@pytest.fixture(scope="module")
def analyzer() -> Analyzer:
    return Analyzer(use_models=False)


@pytest.fixture
def repo(tmp_path) -> AnalysisRepository:
    return AnalysisRepository(make_engine(f"sqlite:///{(tmp_path / 'web.db').as_posix()}"))


@pytest.fixture
def client(analyzer, repo) -> TestClient:
    return TestClient(create_app(lambda: analyzer, lambda: repo))


def upload(client: TestClient, data: bytes = REPORT, name: str = "report.txt", **kwargs):
    return client.post("/analyze", files={"file": (name, data, "text/plain")},
                       follow_redirects=False, **kwargs)


def analysed(client: TestClient, **kwargs) -> str:
    response = upload(client, **kwargs)
    assert response.status_code == 303, response.text
    return response.headers["location"]


# --- pages and headers ---------------------------------------------------------------


def test_home_page_renders_with_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Document analysis" in response.text
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert "script-src 'self'" in CONTENT_SECURITY_POLICY
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


def test_templates_have_no_inline_scripts_or_handlers():
    """The CSP forbids inline scripts; keep templates compatible with it."""
    for path in TEMPLATES.rglob("*.html"):
        source = path.read_text(encoding="utf-8")
        for tag in re.findall(r"<script\b[^>]*>", source):
            # JSON data blocks never execute; anything else must load from a file.
            assert "src=" in tag or 'type="application/json"' in tag, \
                f"inline script in {path.name}"
        assert not re.search(r"\son[a-z]+\s*=", source), f"inline handler in {path.name}"
        assert "hx-on" not in source and "|safe" not in source.replace(" ", "")


def test_static_assets_are_served(client):
    for path in ("/static/app.css", "/static/app.js", "/static/theme.js",
                 "/static/vendor/htmx.min.js", "/static/favicon.svg"):
        assert client.get(path).status_code == 200, path


def test_health(client):
    assert client.get("/healthz").json() == {"status": "ok"}


# --- analysing ---------------------------------------------------------------------


def test_upload_saves_and_redirects_to_the_analysis(client):
    location = analysed(client)
    assert location == "/analyses/1?saved=new"
    page = client.get(location)
    assert page.status_code == 200
    assert "Saved as analysis #1." in page.text
    assert "report.txt" in page.text
    for label in ("Risk", "Threats", "Entities", "Evidence", "Text", "Sentences", "Metadata"):
        assert f">{label}</a>" in page.text


def test_same_document_again_shows_the_stored_analysis(client):
    analysed(client)
    location = analysed(client)
    assert location == "/analyses/1?saved=existing"
    assert "already analysed" in client.get(location).text


def test_htmx_upload_redirects_with_a_header(client):
    response = upload(client, headers=HX)
    assert response.status_code == 204
    assert response.headers["hx-redirect"] == "/analyses/1?saved=new"


@pytest.mark.parametrize(("name", "data", "message"), [
    ("report.exe", b"MZ data", "not allowed"),
    ("empty.txt", b"", "empty"),
])
def test_rejected_uploads_show_an_error(client, name, data, message):
    response = upload(client, data=data, name=name)
    assert response.status_code == 422
    assert "Could not process" in response.text
    assert message in response.text.lower()
    fragment = upload(client, data=data, name=name, headers=HX)
    assert fragment.status_code == 200
    assert "<html" not in fragment.text and "Could not process" in fragment.text


def test_oversized_upload_is_refused_before_analysis(client, monkeypatch):
    import src.web.app as web_app
    from config.settings import IngestionSettings, Settings

    monkeypatch.setattr(web_app, "settings",
                        Settings(ingestion=IngestionSettings(max_file_size_bytes=50)))
    response = upload(client)
    assert response.status_code == 422
    assert "larger than" in response.text


def test_hostile_filename_is_escaped(client):
    name = '<img src=x onerror=alert(1)>.txt'
    page = client.get(analysed(client, name=name))
    assert "<img src=x" not in page.text
    assert "&lt;img src=x onerror=alert(1)&gt;.txt" in page.text


def test_safe_filename_strips_paths():
    assert _safe_filename("C:\\Users\\a\\report.pdf") == "report.pdf"
    assert _safe_filename("../../etc/passwd.txt") == "passwd.txt"
    assert _safe_filename(None) == "upload"


# --- tabs ----------------------------------------------------------------------------


@pytest.mark.parametrize("tab", ["risk", "threats", "entities", "evidence", "text",
                                 "sentences", "metadata"])
def test_every_tab_renders_as_page_and_fragment(client, tab):
    analysed(client)
    page = client.get(f"/analyses/1?tab={tab}")
    assert page.status_code == 200 and "<html" in page.text
    fragment = client.get(f"/analyses/1?tab={tab}", headers={**HX, "HX-Target": "tab-area"})
    assert fragment.status_code == 200
    assert "<html" not in fragment.text and 'id="tab-area"' in fragment.text


def test_unknown_tab_falls_back_to_risk(client):
    analysed(client)
    assert "risk model" in client.get("/analyses/1?tab=nope").text


def test_only_validated_reference_links_are_clickable(client):
    analysed(client)
    text = client.get("/analyses/1?tab=entities").text
    hrefs = set(re.findall(r'href="(https?://[^"]+)"', text))
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in hrefs
    assert all(h.startswith(("https://attack.mitre.org/", "https://nvd.nist.gov/"))
               for h in hrefs)
    evidence = client.get("/analyses/1?tab=evidence").text
    assert "evil.example" in evidence and 'href="http://evil' not in evidence


def test_entity_filters(client):
    analysed(client)
    found = client.get("/analyses/1?tab=entities&f=1&type=malware&type=tool&q=mimikatz").text
    assert "Mimikatz" in found
    none = client.get("/analyses/1?tab=entities&f=1&q=zzzz-not-there").text
    assert "No entities match the filter." in none


def test_sentence_filter_and_evidence_toggle(client):
    analysed(client)
    assert "1 of" in client.get("/analyses/1?tab=sentences&q=Log4Shell").text
    findings_only = client.get("/analyses/1?tab=evidence").text
    everything = client.get("/analyses/1?tab=evidence&all=1").text
    assert "No phishing was observed" in everything
    assert findings_only.count("<tr") <= everything.count("<tr")


def test_text_tab_handles_a_bad_page_number(client):
    analysed(client)
    assert "Cleaned text, page 1" in client.get("/analyses/1?tab=text&page=x").text


def test_reopened_analysis_without_cached_text_hides_session_tabs(analyzer, repo):
    first = TestClient(create_app(lambda: analyzer, lambda: repo))
    analysed(first)
    restarted = TestClient(create_app(lambda: analyzer, lambda: repo))
    page = restarted.get("/analyses/1")
    assert page.status_code == 200
    assert ">Evidence</a>" not in page.text and ">Metadata</a>" in page.text
    assert "risk model" in restarted.get("/analyses/1?tab=evidence").text


@pytest.mark.parametrize("ref", ["999", "abc", "u-unknown"])
def test_missing_analyses_are_404(client, ref):
    response = client.get(f"/analyses/{ref}")
    assert response.status_code == 404


# --- without a database ------------------------------------------------------------------


def test_analysis_works_without_a_database(analyzer):
    client = TestClient(create_app(lambda: analyzer, lambda: None))
    assert "database is unavailable" in client.get("/").text
    location = analysed(client)
    assert location.startswith("/analyses/u-")
    page = client.get(location)
    assert page.status_code == 200 and "not saved" in page.text
    assert ">Evidence</a>" in page.text


# --- CSRF ------------------------------------------------------------------------------


@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Origin": "https://evil.example"},
])
def test_cross_site_posts_are_refused(client, repo, headers):
    response = upload(client, headers=headers)
    assert response.status_code == 403
    assert repo.stats().documents == 0


def test_same_origin_posts_are_allowed(client):
    response = upload(client, headers={"Sec-Fetch-Site": "same-origin",
                                       "Origin": "http://testserver"})
    assert response.status_code == 303


# --- units -----------------------------------------------------------------------------


def test_result_cache_evicts_least_recently_used():
    cache = ResultCache(max_items=2)
    cache.put("a", "A")
    cache.put("b", "B")
    assert cache.get("a") == "A"  # a is now most recent
    cache.put("c", "C")
    assert cache.get("b") is None and cache.get("a") == "A" and len(cache) == 2
    cache.discard("a")
    assert cache.get("a") is None


@pytest.mark.parametrize(("value", "text"), [
    (None, ""), (float("nan"), ""), (True, "Yes"), (3.0, "3"), (0.876, "0.88"),
    (12345, "12,345"), (42, "42"), (["a", "b"], "a, b"), ("x", "x"),
])
def test_format_value(value, text):
    assert format_value(value) == text


def test_table_links_only_reference_sites():
    import pandas as pd

    frame = pd.DataFrame({"NVD": ["https://nvd.nist.gov/vuln/detail/CVE-2021-1",
                                  "http://evil.example"], "Score": [1.5, 2.0]})
    t = table(frame, max_rows=1)
    assert t.rows == [[Cell("NVD ↗", "https://nvd.nist.gov/vuln/detail/CVE-2021-1"),
                       Cell("1.50")]]
    assert t.truncated and t.numeric == {1}
    assert table(frame).rows[1][0] == Cell("")


# --- failure paths ---------------------------------------------------------------------


def test_unexpected_analyzer_failure_shows_a_generic_message(repo):
    class Broken:
        def analyze(self, data, filename):
            raise RuntimeError("secret internal detail")

    client = TestClient(create_app(lambda: Broken(), lambda: repo))
    response = upload(client)
    assert response.status_code == 422
    assert "unexpected error" in response.text
    assert "secret internal detail" not in response.text


def test_failed_save_falls_back_to_an_unsaved_analysis(analyzer, repo, monkeypatch):
    from src.database.db_manager import DatabaseError

    def fail(*_args, **_kwargs):
        raise DatabaseError("disk full")

    monkeypatch.setattr(repo, "save", fail)
    client = TestClient(create_app(lambda: analyzer, lambda: repo))
    location = analysed(client)
    assert location.startswith("/analyses/u-")
    assert client.get(location).status_code == 200


def test_default_repository_returns_none_when_the_database_cannot_open(monkeypatch):
    import src.web.state as state

    def fail():
        raise OSError("cannot open")

    monkeypatch.setattr(state, "AnalysisRepository", fail)
    assert state.default_repository() is None


def test_document_without_categories_shows_the_empty_state(client):
    analysed(client, data=b"The quarterly meeting was held on Tuesday in the main office.")
    assert "No threat categories were detected." in client.get("/analyses/1?tab=threats").text


def test_table_details_are_truncated_with_rows_and_empty_ones_dropped():
    import pandas as pd

    frame = pd.DataFrame({"A": [1, 2, 3]})
    details = [pd.DataFrame({"B": [1]}), pd.DataFrame(), None]
    t = table(frame, details=details, max_rows=2)
    assert len(t.details) == 2 and t.details[1] is None
    assert format_value(pd.NaT) == "" and format_value(pd.Timestamp("2026-01-02")).startswith(
        "2026-01-02")


def test_server_entry_point_binds_to_localhost(monkeypatch):
    import sys

    import src.web.__main__ as entry

    calls = {}
    monkeypatch.setattr(entry.uvicorn, "run", lambda *a, **k: calls.update(args=a, kwargs=k))
    monkeypatch.setattr(sys, "argv", ["cybersleuth"])
    monkeypatch.delenv("CYBERSLEUTH_HOST", raising=False)
    monkeypatch.delenv("CYBERSLEUTH_PORT", raising=False)
    entry.main()
    assert calls["args"] == ("src.web.app:create_app",)
    assert calls["kwargs"]["host"] == "127.0.0.1" and calls["kwargs"]["port"] == 8000
    assert calls["kwargs"]["factory"] is True


# --- step 2: ATT&CK, IOCs, verdicts, export ----------------------------------------------

ATTACK_REPORT = REPORT + b" They used Kerberoasting to steal tickets."


def stored(repo, analysis_id: int = 1):
    from src.database.views import hydrate

    return hydrate(repo.get_analysis(analysis_id))


def test_attack_tab_lists_techniques_and_hides_negated_by_default(client):
    analysed(client, data=ATTACK_REPORT)
    default = client.get("/analyses/1?tab=attack").text
    assert "T1558.003" in default and "T1566" not in default
    assert "Analyst verdict for" in default
    with_negated = client.get("/analyses/1?tab=attack&f=1").text
    assert "T1566" in with_negated


def test_mapping_verdict_rescores_and_refreshes_the_summary(client, repo):
    analysed(client, data=ATTACK_REPORT)
    view = stored(repo)
    mapping_id = view.mapping_ids["T1558.003"]
    before = view.risk.score
    response = client.post(f"/analyses/1/mappings/{mapping_id}/verdict?tab=attack",
                           data={"verdict": "rejected", "note": "  false positive "},
                           headers={**HX, "HX-Target": "tab-area"})
    assert response.status_code == 200
    assert "Saved verdict &#39;rejected&#39;" in response.text
    assert 'id="summary"' in response.text and 'hx-swap-oob="true"' in response.text
    after = stored(repo)
    assert after.mapping_notes[mapping_id] == "false positive"
    assert after.risk.score < before
    history = client.get("/analyses/1?tab=metadata").text
    assert "false positive" in history and "rejected" in history


def test_indicator_verdict_without_htmx_redirects_back_with_filters(client, repo):
    analysed(client)
    view = stored(repo)
    indicator_id = next(iter(view.indicator_ids.values()))
    response = client.post(f"/analyses/1/indicators/{indicator_id}/verdict?tab=iocs&f=1&q=198",
                           data={"verdict": "malicious"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/analyses/1?tab=iocs&f=1&q=198"
    assert "malicious" in {i.verification.value for i in stored(repo).indicators}


def test_verdict_on_a_finding_of_another_analysis_is_refused(client, repo):
    analysed(client, data=ATTACK_REPORT)
    analysed(client, data=REPORT + b" Second document.", name="second.txt")
    other_mapping = stored(repo, 1).mapping_ids["T1558.003"]
    other_indicator = next(iter(stored(repo, 1).indicator_ids.values()))
    assert client.post(f"/analyses/2/mappings/{other_mapping}/verdict",
                       data={"verdict": "confirmed"}).status_code == 404
    assert client.post(f"/analyses/2/indicators/{other_indicator}/verdict",
                       data={"verdict": "malicious"}).status_code == 404
    assert client.post("/analyses/99/mappings/1/verdict",
                       data={"verdict": "confirmed"}).status_code == 404


def test_invalid_verdict_values_are_rejected(client, repo):
    analysed(client, data=ATTACK_REPORT)
    view = stored(repo)
    mapping_id = view.mapping_ids["T1558.003"]
    indicator_id = next(iter(view.indicator_ids.values()))
    assert client.post(f"/analyses/1/mappings/{mapping_id}/verdict",
                       data={"verdict": "pwned"}).status_code == 400
    assert client.post(f"/analyses/1/indicators/{indicator_id}/verdict",
                       data={"verdict": "pwned"}).status_code == 400


def test_cross_site_verdicts_are_refused(client, repo):
    analysed(client, data=ATTACK_REPORT)
    mapping_id = stored(repo).mapping_ids["T1558.003"]
    response = client.post(f"/analyses/1/mappings/{mapping_id}/verdict",
                           data={"verdict": "rejected"}, headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403
    assert stored(repo).mappings[0].verdict.value == "unverified"


def test_ioc_filters(client):
    analysed(client)
    everything = client.get("/analyses/1?tab=iocs").text
    assert "198.51.100.7" in everything and "CVE-2021-44228" in everything
    only_cves = client.get("/analyses/1?tab=iocs&f=1&type=cve").text
    assert "CVE-2021-44228" in only_cves and "198.51.100.7" not in only_cves
    unflagged = client.get("/analyses/1?tab=iocs&f=1&type=cve&type=ipv4&hide_flagged=1").text
    assert "198.51.100.7" not in unflagged
    by_context = client.get("/analyses/1?tab=iocs&f=1&type=ipv4&q=contacted").text
    assert "198.51.100.7" in by_context


def test_unsaved_analysis_has_no_verdict_forms(analyzer):
    client = TestClient(create_app(lambda: analyzer, lambda: None))
    location = analysed(client, data=ATTACK_REPORT)
    ref = location.split("/")[-1]
    page = client.get(f"/analyses/{ref}?tab=attack").text
    assert "requires a saved analysis" in page and "Analyst verdict for" not in page
    assert "not saved, so reports carry no analyst verdicts" in client.get(
        f"/analyses/{ref}?tab=export").text
    assert client.get(f"/analyses/{ref}/export/json").status_code == 200


def test_reports_download_with_safe_names_and_current_verdicts(client, repo):
    import io
    import json
    import zipfile

    analysed(client, data=ATTACK_REPORT, name='weird "name"; x.txt')
    mapping_id = stored(repo).mapping_ids["T1558.003"]
    client.post(f"/analyses/1/mappings/{mapping_id}/verdict", data={"verdict": "confirmed"})
    export_tab = client.get("/analyses/1?tab=export").text
    assert "/analyses/1/export/pdf" in export_tab

    pdf = client.get("/analyses/1/export/pdf")
    assert pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF")
    # The upload name contained quotes and a semicolon; only [A-Za-z0-9_-] survive.
    assert re.fullmatch(r'attachment; filename="cybersleuth_[A-Za-z0-9_-]+_1\.pdf"',
                        pdf.headers["content-disposition"])
    data = json.loads(client.get("/analyses/1/export/json").content)
    assert "confirmed" in json.dumps(data)
    archive = zipfile.ZipFile(io.BytesIO(client.get("/analyses/1/export/zip").content))
    assert archive.namelist()


@pytest.mark.parametrize("url", ["/analyses/1/export/exe", "/analyses/9/export/pdf"])
def test_unknown_exports_are_404(client, url):
    analysed(client)
    assert client.get(url).status_code == 404


# --- step 3: history, dashboard, explorers -------------------------------------------------

COLLECTION_PAGES = ["/history", "/dashboard", "/explorer/iocs", "/explorer/entities",
                    "/explorer/attack"]


@pytest.mark.parametrize("url", COLLECTION_PAGES)
def test_collection_pages_explain_when_empty(client, analyzer, url):
    assert "No analyses saved yet" in client.get(url).text
    no_db = TestClient(create_app(lambda: analyzer, lambda: None))
    assert "database is unavailable, so there are no saved" in no_db.get(url).text


@pytest.fixture
def two_reports(client):
    """Two documents sharing an IP, one with an explicit technique, one hostile name."""
    analysed(client, data=ATTACK_REPORT, name="first.txt")
    analysed(client, data=REPORT + b" Seen again later.", name="</script><img src=x>.txt")
    return client


@pytest.mark.parametrize("url", COLLECTION_PAGES)
def test_collection_pages_render(two_reports, url):
    response = two_reports.get(url)
    assert response.status_code == 200
    assert "<img src=x>" not in response.text


def test_history_lists_and_links_analyses(two_reports):
    text = two_reports.get("/history").text
    assert 'href="/analyses/1"' in text and 'href="/analyses/2"' in text
    # "/" in the upload name is treated as a path separator, so only the tail is kept.
    assert "first.txt" in text and "script&gt;&lt;img src=x&gt;.txt" in text


def test_delete_requires_confirmation_and_removes_the_document(two_reports, repo):
    assert two_reports.post("/documents/1/delete").status_code == 400
    assert repo.stats().documents == 2
    response = two_reports.post("/documents/1/delete", data={"confirm": "yes"},
                                follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/history"
    assert repo.stats().documents == 1
    htmx = two_reports.post("/documents/2/delete", data={"confirm": "yes"}, headers=HX)
    assert htmx.headers["hx-redirect"] == "/history"
    assert repo.stats().documents == 0


def test_cross_site_delete_is_refused(two_reports, repo):
    response = two_reports.post("/documents/1/delete", data={"confirm": "yes"},
                                headers={"Origin": "https://evil.example"})
    assert response.status_code == 403 and repo.stats().documents == 2


def test_delete_without_a_database(analyzer):
    client = TestClient(create_app(lambda: analyzer, lambda: None))
    assert client.post("/documents/1/delete", data={"confirm": "yes"}).status_code == 503


def test_dashboard_embeds_escaped_chart_data(two_reports):
    import json

    text = two_reports.get("/dashboard").text
    assert '<script src="/vendor/plotly.min.js" defer></script>' in text
    specs = re.findall(r'<script type="application/json" class="chart-spec">(.*?)</script>',
                       text, re.S)
    assert len(specs) == 4
    for spec in specs:
        assert "<" not in spec and ">" not in spec
        assert json.loads(spec)["data"]
    assert "Recent analyses" in text and "Table view" in text


def test_plotly_is_served_locally(client):
    response = client.get("/vendor/plotly.min.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert len(response.content) > 1_000_000


def test_ioc_explorer_filters(two_reports):
    everything = two_reports.get("/explorer/iocs").text
    assert "198.51.100.7" in everything and "CVE-2021-44228" in everything
    shared = two_reports.get("/explorer/iocs?f=1&type=IPV4&type=CVE&verdict=unverified"
                             "&shared=1").text
    assert "198.51.100.7" in shared and "first.txt" in shared
    nothing = two_reports.get("/explorer/iocs?f=1&type=IPV4&verdict=unverified&q=10.0").text
    assert "No indicators match the filter." in nothing


def test_entity_explorer_filters_and_links(two_reports):
    text = two_reports.get("/explorer/entities?f=1&type=Tool&q=mimi").text
    assert "Mimikatz" in text
    assert 'href="https://attack.mitre.org/software/S0002/"' in text
    assert "No entities match" in two_reports.get("/explorer/entities?f=1&q=zzz").text


def test_attack_explorer_filter_and_heatmap(two_reports):
    text = two_reports.get("/explorer/attack").text
    assert "T1558.003" in text and "chart-spec" in text
    explicit = two_reports.get("/explorer/attack?f=1&explicit=1").text
    assert "T1558.003" in explicit


def test_chart_json_cannot_close_its_script_element():
    import pandas as pd
    import plotly.graph_objects as go

    from src.web.pages import chart

    figure = go.Figure(go.Bar(x=["</script><b>&"], y=[1]))
    c = chart(figure, pd.DataFrame({"A": [1]}), "t")
    assert "<" not in c.spec and ">" not in c.spec and "&" not in c.spec
    assert "\\u003c" in c.spec and "\\u0026" in c.spec
