"""Tests for IOC extraction (src/nlp/ioc_extractor.py)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from src.ingestion.models import ExtractedDocument, FileType, PageText
from src.ingestion.pipeline import ingest
from src.nlp.ioc_extractor import IOCExtractor, load_tlds, refang
from src.nlp.ioc_models import IOCFlag, IOCType, VerificationStatus
from src.nlp.preprocessing import split_sentences

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
MD5 = "44d88612fea8a8f36de82e1278abb02f"
SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture(scope="module")
def extractor() -> IOCExtractor:
    return IOCExtractor(today=lambda: date(2026, 11, 7))


def found(extractor: IOCExtractor, text: str) -> list[tuple[IOCType, str]]:
    return [(m.ioc_type, m.value) for m in extractor.find(text)]


# --- IPv4 ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "text", ["8.8.4.4", "8[.]8[.]4[.]4", "8(.)8(.)4(.)4", "8[dot]8[dot]4[dot]4", "8{.}8{.}4{.}4"]
)
def test_ipv4_plain_and_defanged(extractor, text):
    assert found(extractor, f"C2 at {text} today.") == [(IOCType.IPV4, "8.8.4.4")]


@pytest.mark.parametrize(
    "text",
    ["256.1.1.1", "01.2.3.4", "1.2.3.4.5", "version 1.2.3.4", "v1.2.3.4", "build 10.0.19041.1"],
)
def test_ipv4_rejections(extractor, text):
    assert not [m for m in extractor.find(text) if m.ioc_type is IOCType.IPV4]


@pytest.mark.parametrize(
    ("ip", "flag"),
    [
        ("198.51.100.7", IOCFlag.DOCUMENTATION_RANGE),
        ("10.1.2.3", IOCFlag.PRIVATE),
        ("192.168.1.1", IOCFlag.PRIVATE),
        ("127.0.0.1", IOCFlag.LOOPBACK),
        ("169.254.1.1", IOCFlag.LINK_LOCAL),
        ("100.64.0.1", IOCFlag.SHARED),
        ("224.0.0.1", IOCFlag.MULTICAST),
        ("0.0.0.0", IOCFlag.RESERVED),
    ],
)
def test_ipv4_flags(extractor, ip, flag):
    (match,) = extractor.find(ip)
    assert flag in match.flags


def test_public_ip_has_no_flags(extractor):
    assert extractor.find("8.8.8.8")[0].flags == frozenset()


# --- domains ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("evil-site.com", "evil-site.com"),
        ("cdn.update.evil-site.co.uk", "cdn.update.evil-site.co.uk"),
        ("EVIL.COM", "evil.com"),
        ("evil[.]com", "evil.com"),
        ("evil(dot)com", "evil.com"),
        ("invoice[.]zip", "invoice.zip"),  # defanged → analyst says it is a domain
        ("asp.net", "asp.net"),
    ],
)
def test_domains(extractor, text, value):
    assert found(extractor, f"Beacon to {text}.") == [(IOCType.DOMAIN, value)]


@pytest.mark.parametrize(
    "text",
    [
        "svch0st.exe", "payload.dll", "invoice.zip", "loader.py", "readme.md", "run.sh",
        "System.Management.Automation", "Microsoft.Exchange", "e.g. this", "i.e. that",
        "host.local", "report.pdf", "Node.js", "C:\\Temp\\evil.zip", "files/invoice.zip",
    ],
)
def test_domain_false_positives_rejected(extractor, text):
    assert not [m for m in extractor.find(f"Saw {text} here") if m.ioc_type is IOCType.DOMAIN]


@pytest.mark.parametrize("domain", ["example.com", "sub.example.org", "evil.test", "a.invalid"])
def test_reserved_domain_flag(extractor, domain):
    (match,) = extractor.find(domain)
    assert IOCFlag.RESERVED_DOMAIN in match.flags


# --- URLs ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("hxxp://evil[.]com/a.php", "http://evil.com/a.php"),
        ("hxxps[:]//evil[.]com/x", "https://evil.com/x"),
        ("hXXps[://]evil[.]com", "https://evil.com"),
        ("https://EVIL.com/Path/File.PHP?id=1", "https://evil.com/Path/File.PHP?id=1"),
        ("http://198.51.100.7:8080/gate", "http://198.51.100.7:8080/gate"),
        ("fxp://files[.]evil[.]com/drop", "ftp://files.evil.com/drop"),
    ],
)
def test_urls(extractor, text, value):
    assert found(extractor, f"Download {text} now") == [(IOCType.URL, value)]


@pytest.mark.parametrize(
    ("text", "raw"),
    [
        ("Visit http://evil.com/a.", "http://evil.com/a"),
        ("(see http://evil.com/a)", "http://evil.com/a"),
        ('"http://evil.com/x",', "http://evil.com/x"),
        ("http://evil.com/wiki/Foo_(bar)", "http://evil.com/wiki/Foo_(bar)"),  # balanced kept
    ],
)
def test_url_trailing_punctuation(extractor, text, raw):
    (match,) = extractor.find(text)
    assert match.raw == raw


def test_url_host_not_double_counted(extractor):
    assert found(extractor, "Fetched https://evil.com/198.51.100.7/" + MD5) == [
        (IOCType.URL, "https://evil.com/198.51.100.7/" + MD5)
    ]


def test_url_with_ip_host_flags(extractor):
    (match,) = extractor.find("http://10.0.0.5/admin")
    assert IOCFlag.PRIVATE in match.flags


# --- emails -------------------------------------------------------------------


@pytest.mark.parametrize(
    "text", ["Bob.Smith@Evil.com", "bob.smith[@]evil[.]com", "bob.smith[at]evil[.]com"]
)
def test_emails(extractor, text):
    assert found(extractor, f"From {text} today") == [(IOCType.EMAIL, "bob.smith@evil.com")]


def test_email_with_invalid_tld_rejected(extractor):
    assert found(extractor, "admin@server.local") == []


# --- hashes -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "ioc_type"), [(MD5, IOCType.MD5), (SHA1, IOCType.SHA1), (SHA256, IOCType.SHA256)]
)
def test_hashes(extractor, value, ioc_type):
    assert found(extractor, f"Hash {value.upper()} seen") == [(ioc_type, value)]


@pytest.mark.parametrize(
    "text",
    [
        "a" * 32,  # no digits
        "1" * 32,  # long number
        "12345678901234567890123456789012",  # digits only
        "0" * 64,
        "ab" * 64,  # 128 hex chars (SHA-512): no 32/40/64 window with clean boundaries
        MD5 + "f",  # 33 hex chars
    ],
)
def test_hash_rejections(extractor, text):
    assert found(extractor, f"x {text} y") == []


# --- CVEs ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("CVE-2024-3400", "CVE-2024-3400"),
        ("cve-2021-44228", "CVE-2021-44228"),
        ("CVE 2024 12345", "CVE-2024-12345"),
        ("CVE-2027-0001", "CVE-2027-0001"),  # next year: IDs are reserved ahead of time
    ],
)
def test_cves(extractor, text, value):
    assert found(extractor, f"Exploited {text} today") == [(IOCType.CVE, value)]


@pytest.mark.parametrize(
    "text", ["CVE-1990-1234", "CVE-2030-1234", "CVE-2024-123", "XCVE-2024-1234"]
)
def test_cve_rejections(extractor, text):
    assert found(extractor, text) == []


# --- helpers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "literal"),
    [
        ("hxxp://a[.]b", "http://a.b"),
        ("a[at]b(dot)c", "a@b.c"),
        ("hxxps[:]//x", "https://x"),
        ("plain.com", "plain.com"),
    ],
)
def test_refang(raw, literal):
    assert refang(raw) == literal


def test_load_tlds_bundled_snapshot():
    tlds = load_tlds()
    assert {"com", "uk", "zip", "xn--p1ai"} <= tlds
    assert not any(t.startswith("#") for t in tlds)


def test_load_tlds_rejects_empty_file(tmp_path):
    empty = tmp_path / "tlds.txt"
    empty.write_text("# Version 1\n", encoding="ascii")
    with pytest.raises(ValueError):
        load_tlds(empty)


# --- document-level extraction ------------------------------------------------


def _document(*pages: str) -> ExtractedDocument:
    page_list = [PageText(i + 1, text) for i, text in enumerate(pages)]
    return ExtractedDocument(
        "x.txt", FileType.TXT, "0" * 64, 1, page_list, sentences=split_sentences(page_list)
    )


def test_deduplication_and_evidence(extractor):
    doc = _document("First seen 8.8.4.4 here. Unrelated text.", "Again 8[.]8[.]4[.]4 on page two.")
    (indicator,) = extractor.extract(doc)
    assert (indicator.ioc_type, indicator.value, indicator.count) == (IOCType.IPV4, "8.8.4.4", 2)
    assert indicator.defanged and indicator.pages == [1, 2]
    assert indicator.verification is VerificationStatus.UNVERIFIED
    assert indicator.source == "rule:regex"

    first, second = indicator.occurrences
    assert first.context == "First seen 8.8.4.4 here."
    assert (first.sentence_index, second.sentence_index) == (0, 2)
    assert second.raw == "8[.]8[.]4[.]4" and second.context == "Again 8[.]8[.]4[.]4 on page two."
    for occurrence in indicator.occurrences:
        page = doc.pages[occurrence.page_number - 1]
        assert page.text[occurrence.char_start : occurrence.char_end] == occurrence.raw


def test_same_value_different_types_kept_separate(extractor):
    """Output is grouped in IOCType declaration order, then by first position."""
    doc = _document("Domain evil.com and URL http://evil.com/x and mail a@evil.com.")
    assert [(i.ioc_type, i.value) for i in extractor.extract(doc)] == [
        (IOCType.DOMAIN, "evil.com"),
        (IOCType.URL, "http://evil.com/x"),
        (IOCType.EMAIL, "a@evil.com"),
    ]


def test_context_falls_back_without_sentences(extractor):
    doc = ExtractedDocument("x", FileType.TXT, "0" * 64, 1, [PageText(1, "IP 8.8.4.4 seen")])
    (indicator,) = extractor.extract(doc)
    assert indicator.occurrences[0].sentence_index is None
    assert indicator.occurrences[0].context == "IP 8.8.4.4 seen"


def test_document_without_iocs(extractor):
    assert extractor.extract(_document("Nothing to see here. Just prose.")) == []


@pytest.mark.parametrize("name", ["synthetic_advisory.txt", "synthetic_advisory.docx",
                                  "synthetic_advisory.pdf"])
def test_sample_advisory_exact_extraction(extractor, name):
    """Exact expected set: guards precision (nothing extra) and recall (nothing missed)."""
    doc = ingest((SAMPLES / name).read_bytes(), name)
    assert {(i.ioc_type, i.value) for i in extractor.extract(doc)} == {
        (IOCType.URL, "https://invoice-portal.example.com/download.php"),
        (IOCType.EMAIL, "billing@invoice-portal.example.com"),
        (IOCType.CVE, "CVE-2024-3400"),
        (IOCType.IPV4, "198.51.100.23"),
        (IOCType.IPV4, "203.0.113.77"),
        (IOCType.DOMAIN, "update-service.example.net"),
        (IOCType.MD5, MD5),
        (IOCType.SHA256, SHA256),
    }


# --- robustness on PDF-extracted text (synthetic examples only) ------------------------

ONION_V3 = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"  # 56 base32 chars


def _found(text: str) -> list[tuple[str, str, list[str]]]:
    return [(m.ioc_type.value, m.value, sorted(f.value for f in m.flags))
            for m in IOCExtractor().find(text)]


def test_url_wrapped_at_line_break_is_rejoined_and_flagged():
    text = "Fetched https://cdn.bad-host.com/stage/loader.reques\nts.php?id=7 at noon."
    matches = IOCExtractor().find(text)
    assert [(m.value, sorted(f.value for f in m.flags)) for m in matches] == [
        ("https://cdn.bad-host.com/stage/loader.requests.php?id=7", ["rejoined_line_break"])]
    assert text[matches[0].char_start:matches[0].char_end] == matches[0].raw  # exact slice


@pytest.mark.parametrize(("text", "expected"), [
    ("See https://bad-host.com/a/b\nThe actor then left.", ["https://bad-host.com/a/b"]),
    ("See https://bad-host.com/a/b\nand then left.", ["https://bad-host.com/a/b"]),
    ("Two https://a-host.com/x\nhttps://b-host.com/y here.",
     ["https://a-host.com/x", "https://b-host.com/y"]),
], ids=["sentence", "plain-word", "new-url"])
def test_url_not_joined_with_unrelated_next_line(text, expected):
    found = _found(text)
    assert [v for _, v, _ in found] == expected
    assert all(not flags for _, _, flags in found)


def test_trailing_nbsp_residue_is_removed_but_query_entities_kept():
    found = {v for _, v, _ in _found("Get https://bad-host.com/js/app.js&nbsp; and "
                                     "https://bad-host.com/q?a=1&copy=2 too.")}
    assert found == {"https://bad-host.com/js/app.js", "https://bad-host.com/q?a=1&copy=2"}


@pytest.mark.parametrize("text", [
    "C2 at xxx.xxx.xxx.xxx was redacted.",
    "Request to http://XXX.XXX.XXX.XXX:80/index.html was redacted.",
], ids=["domain", "url-host"])
def test_placeholders_are_rejected(text):
    assert _found(text) == []


def test_real_xxx_domains_are_still_accepted():
    assert _found("Traffic to bad-site.xxx was seen.") == [("domain", "bad-site.xxx", [])]


def test_onion_names_need_a_valid_tor_label():
    found = _found(f"Leak site {ONION_V3}.onion and http://abcdefghijklmnop.onion/x "
                   "but not shop.onion or http://bad-1.onion/")
    assert found == [("domain", f"{ONION_V3}.onion", ["tor_onion_service"]),
                     ("url", "http://abcdefghijklmnop.onion/x", ["tor_onion_service"])]
