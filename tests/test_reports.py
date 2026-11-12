"""Tests for JSON / CSV / PDF report exports and their safety properties."""

from __future__ import annotations

import csv
import io
import json
import zipfile

import pymupdf
import pytest

from src.database.db_manager import AnalysisRepository, make_engine
from src.database.views import hydrate, view_from_result
from src.intelligence.analyzer import Analyzer
from src.nlp.ioc_models import Indicator, IOCOccurrence, IOCType
from src.reporting import csv_report, json_report, pdf_report
from src.reporting.common import TextDefanger, csv_safe, defang, report_stem

TEXT = (
    "=HYPERLINK(\"http://x\") Ops contacted 203.0.113.9 first.\n"
    "The actor APT28 used Kerberoasting (T1558.003) against the domain controller. "
    "The payload was fetched from https://evil-host.example.com/a.b/payload.exe and the "
    "implant beaconed to 198.51.100.7. Phishing mail came from bad@phish.example.org. "
    "The dropper hash was 44d88612fea8a8f36de82e1278abb02f. CVE-2024-3400 was exploited. "
    "Кириллица — “quoted” text… with a dash."
)
LIVE_URL = "https://evil-host.example.com/a.b/payload.exe"


@pytest.fixture(scope="module")
def analyzer() -> Analyzer:
    return Analyzer(use_models=False)


@pytest.fixture
def stored(tmp_path, analyzer):
    """A saved analysis with one IOC verdict + note, reloaded from the database."""
    repo = AnalysisRepository(make_engine(f"sqlite:///{(tmp_path / 'r.db').as_posix()}"))
    analysis_id = repo.save(analyzer.analyze(TEXT.encode(), "report.txt"),
                            store_full_text=True).analysis_id
    view = hydrate(repo.get_analysis(analysis_id))
    ip_id = view.indicator_ids[(IOCType.IPV4, "198.51.100.7")]
    repo.set_indicator_verdict(ip_id, "malicious", note="Seen in our proxy logs")
    view = hydrate(repo.get_analysis(analysis_id))
    return repo, view, repo.verification_events(analysis_id)


# --- helpers ------------------------------------------------------------------


@pytest.mark.parametrize(("ioc_type", "value", "expected"), [
    (IOCType.URL, "https://evil.example.com/a.b/x.exe", "hxxps://evil[.]example[.]com/a.b/x.exe"),
    (IOCType.URL, "HTTP://a.example/", "hxxp://a[.]example/"),
    (IOCType.DOMAIN, "evil.example.net", "evil[.]example[.]net"),
    (IOCType.IPV4, "198.51.100.7", "198[.]51[.]100[.]7"),
    (IOCType.EMAIL, "bad@phish.example.org", "bad[@]phish[.]example[.]org"),
    (IOCType.MD5, "44d88612fea8a8f36de82e1278abb02f", "44d88612fea8a8f36de82e1278abb02f"),
    (IOCType.CVE, "CVE-2024-3400", "CVE-2024-3400"),
])
def test_defang(ioc_type, value, expected):
    assert defang(ioc_type, value) == expected


def test_text_defanger_prefers_longest_form_and_skips_defanged():
    url = Indicator(IOCType.URL, "https://a.example.com/x",
                    [IOCOccurrence("https://a.example.com/x", 1, 0, 1, False, 0, "")])
    domain = Indicator(IOCType.DOMAIN, "a.example.com",
                       [IOCOccurrence("a[.]example[.]com", 1, 0, 1, True, 0, "")])
    clean = TextDefanger([url, domain])
    assert clean("Get https://a.example.com/x or a.example.com") == \
        "Get hxxps://a[.]example[.]com/x or a[.]example[.]com"
    assert clean("already a[.]example[.]com") == "already a[.]example[.]com"
    assert TextDefanger([])("unchanged") == "unchanged"


@pytest.mark.parametrize("cell", ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tx", "\rx"])
def test_csv_safe_neutralises_formulas(cell):
    assert csv_safe(cell) == "'" + cell


def test_csv_safe_leaves_other_values():
    assert csv_safe("normal") == "normal"
    assert csv_safe(-0.5) == -0.5  # numbers stay numeric (model scores can be negative)
    assert csv_safe(None) is None


def test_report_stem_is_filesystem_safe(analyzer):
    view = view_from_result(analyzer.analyze(b"Some text about nothing.", "../..\\a b;rm.txt"))
    stem = report_stem(view)
    assert stem.startswith("cybersleuth_")
    assert all(c.isalnum() or c in "_-" for c in stem)


# --- JSON ---------------------------------------------------------------------


def test_json_report_carries_verdicts_notes_and_history(stored):
    _, view, events = stored
    report = json.loads(json_report.to_json(view, events))
    assert report["report"]["schema_version"] == "1.1"
    ip = next(i for i in report["indicators"] if i["value"] == "198.51.100.7")
    assert ip["verification"] == "malicious" and ip["analyst_note"] == "Seen in our proxy logs"
    assert ip["value_defanged"] == "198[.]51[.]100[.]7"
    others = [i for i in report["indicators"] if i["value"] != "198.51.100.7"]
    assert {i["verification"] for i in others} == {"unverified"}  # nothing invented
    assert report["verification_history"][0]["to"] == "malicious"
    assert report["analysis"]["id"] == view.analysis_id


def test_json_report_never_contains_full_text_or_live_evidence(stored):
    _, view, events = stored
    assert view.full_text  # stored in the DB for this test, yet must not be exported
    report = json_report.build_report(view, events)
    for indicator in report["indicators"]:
        indicator.pop("value")  # the one field that is canonical by design
    dumped = json.dumps(report, ensure_ascii=False)
    assert view.full_text not in dumped
    assert LIVE_URL not in dumped and "198.51.100.7" not in dumped
    assert "hxxps://evil-host[.]example[.]com/a.b/payload.exe" in dumped


def test_json_report_keeps_unicode(stored):
    _, view, _ = stored
    assert "Кириллица" in json_report.to_json(view).decode("utf-8")


# --- CSV ----------------------------------------------------------------------


def _read_zip(data: bytes) -> dict[str, list[dict]]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {name: list(csv.DictReader(io.StringIO(archive.read(name).decode("utf-8-sig"))))
                for name in archive.namelist() if name.endswith(".csv")} | {
            "README.txt": archive.read("README.txt").decode("utf-8")}


def test_csv_zip_contents_match_json(stored):
    _, view, events = stored
    files = _read_zip(csv_report.to_csv_zip(view, events))
    report = json_report.build_report(view, events)
    assert len(files["indicators.csv"]) == len(report["indicators"])
    assert len(files["attack_techniques.csv"]) == len(report["attack_techniques"])
    assert len(files["verification_history.csv"]) == 1
    assert "Limitations:" in files["README.txt"]


def test_csv_is_defanged_and_formula_safe(stored):
    _, view, events = stored
    files = _read_zip(csv_report.to_csv_zip(view, events))
    values = {row["value_defanged"] for row in files["indicators.csv"]}
    assert "hxxps://evil-host[.]example[.]com/a.b/payload.exe" in values
    assert "value" not in files["indicators.csv"][0]  # canonical values only in JSON
    raw = csv_report.to_csv_zip(view, events)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        everything = "".join(archive.read(n).decode("utf-8-sig") for n in archive.namelist())
    assert LIVE_URL not in everything
    first = next(r for r in files["indicators.csv"] if r["value_defanged"].startswith("203"))
    assert first["first_context"].startswith("'=HYPERLINK")


# --- PDF ----------------------------------------------------------------------


def test_pdf_report_content_and_links(stored):
    _, view, events = stored
    data = pdf_report.to_pdf(view, events)
    assert data.startswith(b"%PDF")
    document = pymupdf.open(stream=data, filetype="pdf")
    text = " ".join(page.get_text() for page in document)
    assert "198[.]51[.]100[.]7" in text and "malicious" in text
    assert LIVE_URL not in text
    assert "Limitations and provenance" in text and "Seen in our proxy logs" in text
    uris = [link.get("uri", "") for page in document for link in page.get_links()]
    assert uris and all(u.startswith("https://attack.mitre.org/techniques/") for u in uris)


def test_pdf_caps_long_tables(stored, monkeypatch):
    _, view, _ = stored
    monkeypatch.setattr(pdf_report, "MAX_ROWS", 2)
    document = pymupdf.open(stream=pdf_report.to_pdf(view), filetype="pdf")
    text = " ".join(page.get_text() for page in document)
    assert f"Showing the first 2 of {len(view.indicators)}" in text


def test_latin1_transliteration():
    assert pdf_report.latin1("a — “b” …") == 'a - "b" ...'
    assert pdf_report.latin1("Кир") == "???"
    assert pdf_report.latin1("café") == "café"
    assert pdf_report.latin1(None) == ""


def test_reports_for_unsaved_and_empty_analysis(analyzer):
    view = view_from_result(analyzer.analyze(b"Nothing of interest happened today.", "e.txt"))
    assert pdf_report.to_pdf(view).startswith(b"%PDF")
    assert json.loads(json_report.to_json(view))["analysis"]["id"] is None
    assert "indicators.csv" in _read_zip(csv_report.to_csv_zip(view))


# --- web export ---------------------------------------------------------------


def test_export_tab_offers_three_downloads(stored):
    from fastapi.testclient import TestClient

    from src.web.app import create_app

    repo, view, _ = stored
    client = TestClient(create_app(lambda: None, lambda: repo))
    text = client.get(f"/analyses/{view.analysis_id}?tab=export").text
    for ext in ("pdf", "json", "zip"):
        assert f'href="/analyses/{view.analysis_id}/export/{ext}"' in text
        assert client.get(f"/analyses/{view.analysis_id}/export/{ext}").status_code == 200
