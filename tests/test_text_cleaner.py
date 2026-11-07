"""Tests for src/ingestion/text_cleaner.py."""

from __future__ import annotations

import pytest

from src.ingestion.models import PageText
from src.ingestion.text_cleaner import clean_pages, clean_text

# Indicators that must survive cleaning byte-for-byte.
IOC_SAMPLES = [
    "hxxp://malicious-example[.]com/payload.exe",
    "hxxps://evil[.]example[.]org/a?b=c",
    "192.168.1[.]1",
    "10[.]0[.]0[.]5",
    "198.51.100.7:8443",
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "CVE-2024-3400",
    "attacker[@]example[.]com",
    "C:\\Windows\\Temp\\svch0st.exe",
    "update-service.example.net",
]


@pytest.mark.parametrize("ioc", IOC_SAMPLES)
def test_iocs_survive_cleaning(ioc):
    assert clean_text(f"Observed {ioc} in traffic.") == f"Observed {ioc} in traffic."


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ﬁle ﬂow", "file flow"),  # ligatures
        ("ＡＰＴ２９", "APT29"),  # full-width
        ("non\u00a0breaking", "non breaking"),
        ("\u201cquoted\u201d and \u2018single\u2019", "\"quoted\" and 'single'"),
        ("non\u2011breaking-hyphen", "non-breaking-hyphen"),
    ],
)
def test_unicode_normalisation(raw, expected):
    assert clean_text(raw) == expected


def test_invisible_characters_removed_from_hash():
    broken = "d41d8cd98f00\u200bb204e98\u00ad00998ecf8427e"
    assert clean_text(broken) == "d41d8cd98f00b204e9800998ecf8427e"


def test_bom_and_control_characters_removed():
    assert clean_text("\ufeffhello\x00\x07 world\x1b") == "hello world"


def test_line_endings_normalised():
    assert clean_text("a\r\nb\rc") == "a\nb\nc"
    assert clean_text("page one\fpage two") == "page one\n\npage two"


def test_whitespace_collapsed_but_paragraphs_kept():
    raw = "  first   line \t here  \n\n\n\n\nsecond\t\tparagraph   "
    assert clean_text(raw) == "first line here\n\nsecond paragraph"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("the mal-\nware spread", "the malware spread"),  # prose word split
        ("the mal- \n  ware spread", "the malware spread"),  # stray spaces
        ("new mal-\nware.", "new malware."),  # trailing punctuation is not an IOC hint
        ("visit evil-\nsite.com now", "visit evil-site.com now"),  # domain keeps hyphen
        ("track CVE-\n2024-3400 now", "track CVE-2024-3400 now"),  # CVE keeps hyphen
        ("group Sandworm-\nTeam", "group Sandworm-Team"),  # capitalised → keep hyphen
        ("list item -\nnext", "list item -\nnext"),  # detached dash is not a split word
    ],
)
def test_line_break_hyphenation(raw, expected):
    assert clean_text(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "\n\n\t"])
def test_empty_input(raw):
    assert clean_text(raw) == ""


@pytest.mark.parametrize(
    "raw",
    ["ﬁle  mal-\nware\r\n\n\n\nhxxp://a[.]b","  “x”\u200b\x00 ", "evil-\nsite.com\f\fz"],
)
def test_idempotent(raw):
    once = clean_text(raw)
    assert clean_text(once) == once


def test_clean_pages_preserves_page_numbers():
    pages = [PageText(1, "  a  "), PageText(2, ""), PageText(3, "ﬁ")]
    assert clean_pages(pages) == [PageText(1, "a"), PageText(2, ""), PageText(3, "fi")]
