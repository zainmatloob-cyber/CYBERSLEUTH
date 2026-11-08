"""Security regression tests (see docs/security.md).

Each test pins down one rule from the security review, so a later change can't quietly
undo it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pandas as pd
import pymupdf
import pytest

from config.settings import IngestionSettings
from src.ingestion.pipeline import ingest
from src.utils.exceptions import FileTooLargeError

ROOT = Path(__file__).resolve().parent.parent
APP_FILES = [ROOT / "app.py", *sorted((ROOT / "src").rglob("*.py"))]

# --- the application never contacts the network or renders raw HTML ----------------

NETWORK_MODULES = {"requests", "httpx", "aiohttp", "urllib.request", "http.client", "socket",
                   "ftplib", "smtplib", "telnetlib", "webbrowser", "urllib3"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names |= {node.module} | {f"{node.module}.{a.name}" for a in node.names}
    return names


@pytest.mark.parametrize("path", APP_FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_application_code_has_no_network_client(path):
    """Extracted URLs and IPs are never contacted: the app has no way to make requests."""
    found = {name for name in _imports(path)
             if any(name == m or name.startswith(m + ".") for m in NETWORK_MODULES)}
    assert not found, f"{path.name} imports {found}"


@pytest.mark.parametrize("path", APP_FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_application_code_never_renders_raw_html_or_executes_code(path):
    source = path.read_text(encoding="utf-8")
    for forbidden in ("unsafe_allow_html", "components.html", "st.html(", "eval(", "exec(",
                      "subprocess", "os.system"):
        assert forbidden not in source, f"{path.name} uses {forbidden}"


# --- untrusted text in charts ------------------------------------------------------------

LINK = '<a href="https://evil.example">report</a>.pdf'


def test_chart_labels_are_escaped():
    from src.visualization import dashboard

    assert dashboard.plain(LINK) == '&lt;a href="https://evil.example"&gt;report&lt;/a&gt;.pdf'
    assert dashboard.plain("R&D <b>") == "R&amp;D &lt;b&gt;"

    matrix = pd.DataFrame([[1]], index=[LINK], columns=["execution"])
    heatmap = dashboard.tactic_heatmap(matrix)
    bars = dashboard.horizontal_bar(pd.DataFrame({"Name": [LINK], "N": [1]}), "Name", "N",
                                    "t", "x")
    for labels in (heatmap.data[0].y, bars.data[0].y):
        assert all("<" not in str(label) for label in labels)


# --- size limits on untrusted documents -----------------------------------------------------


def _pdf(pages: int, text: str) -> bytes:
    doc = pymupdf.open()
    for _ in range(pages):
        doc.new_page().insert_text((72, 72), text)
    return doc.tobytes()


def test_pdf_text_cap_stops_extraction():
    limits = IngestionSettings(max_text_chars=200)
    with pytest.raises(FileTooLargeError, match="exceeds 200 characters by page"):
        ingest(_pdf(20, "Lateral movement used RDP and PsExec. " * 2), "big.pdf", limits=limits)
    assert ingest(_pdf(1, "Short report."), "ok.pdf", limits=limits).char_count < 200


def test_text_cap_applies_to_every_format():
    limits = IngestionSettings(max_text_chars=100)
    with pytest.raises(FileTooLargeError, match="limit 100"):
        ingest(b"The actors used Mimikatz. " * 20, "big.txt", limits=limits)


def test_default_text_cap():
    assert IngestionSettings().max_text_chars == 1_000_000


# --- indicator length --------------------------------------------------------------------


def test_overlong_urls_are_not_extracted():
    from src.nlp.ioc_extractor import MAX_URL_LENGTH, IOCExtractor
    from src.nlp.ioc_models import IOCType

    extractor = IOCExtractor()
    ok = "http://evil.example.com/" + "a" * (MAX_URL_LENGTH - 24)
    too_long = "http://evil.example.com/" + "a" * MAX_URL_LENGTH
    assert [m.ioc_type for m in extractor.find(ok)] == [IOCType.URL]
    assert IOCType.URL not in {m.ioc_type for m in extractor.find(too_long)}


# --- evaluation manifests ---------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["../escape", "a/b", "C:\\x", "/abs", "", "UPPER", "a" * 65])
def test_manifest_ids_cannot_name_other_paths(bad, tmp_path):
    from src.evaluation import manifest as rm

    with pytest.raises(ValueError, match="invalid advisory id"):
        rm.manifest_files({"id": bad, "pdf_name": "x.pdf"}, tmp_path)


# --- XML ------------------------------------------------------------------------------------


def _docx_with_entity(secret_path: Path) -> bytes:
    import io
    import zipfile

    import docx

    buffer = io.BytesIO()
    document = docx.Document()
    document.add_paragraph("Report body MARKER")
    document.save(buffer)
    source = zipfile.ZipFile(io.BytesIO(buffer.getvalue()))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename == "word/document.xml":
                text = data.decode("utf-8")
                declaration = (f'<!DOCTYPE w:document [<!ENTITY xxe SYSTEM '
                               f'"{secret_path.as_uri()}">]>')
                text = text.replace("?>", "?>" + declaration, 1).replace("MARKER", "&xxe;")
                data = text.encode("utf-8")
            target.writestr(item, data)
    return out.getvalue()


def test_docx_external_entities_are_not_resolved(tmp_path):
    """No XXE: a DOCX can't make the reader include a local file in the extracted text."""
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-CONTENT", encoding="utf-8")
    try:
        document = ingest(_docx_with_entity(secret), "xxe.docx")
    except Exception as exc:  # rejecting the file is also safe
        assert "TOP-SECRET" not in str(exc)
        return
    assert "TOP-SECRET" not in " ".join(page.text for page in document.pages)


# --- regular-expression denial of service ---------------------------------------------------

HOSTILE = {
    "no-spaces": "a" * 200_000,
    "hyphen-runs": "a-" * 100_000,
    "dots": "a." * 100_000,
    "digit-dots": "1." * 100_000,
    "url-path": "http://evil.example.com/" + "a/" * 100_000,
    "at-signs": "a@" * 100_000,
    "brackets": "[.]" * 66_000,
}


@pytest.mark.parametrize("text", HOSTILE.values(), ids=HOSTILE.keys())
def test_text_stages_stay_linear_on_hostile_input(text):
    """200,000 hostile characters through every regex-heavy stage in well under a few
    seconds. The old hyphen-rejoin pattern took ~6 s for 20,000 characters (quadratic)."""
    import time

    from src.ingestion.models import PageText
    from src.ingestion.text_cleaner import clean_pages
    from src.nlp.ioc_extractor import IOCExtractor
    from src.nlp.preprocessing import split_sentences

    extractor = IOCExtractor()
    started = time.perf_counter()
    pages = clean_pages([PageText(1, text)])
    split_sentences(pages)
    extractor.find(pages[0].text)
    assert time.perf_counter() - started < 5


def test_hyphen_rejoin_fix_changes_no_output():
    """The token-start anchor only removes wasted attempts: same output as the old pattern."""
    import random
    import re

    from src.ingestion import text_cleaner

    old = re.compile(r"(\S+)-[ \t]*\n[ \t]*(\S+)")
    rng = random.Random(20261108)
    for _ in range(20_000):
        s = "".join(rng.choice("ab-\n \t.1[]/X") for _ in range(rng.randint(0, 30)))
        assert (old.sub(text_cleaner._rejoin_hyphenated, s)
                == text_cleaner._LINE_BREAK_HYPHEN.sub(text_cleaner._rejoin_hyphenated, s))
