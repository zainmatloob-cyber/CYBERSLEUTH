"""Rule-based Indicator of Compromise extraction.

Pipeline per page:
1. **Candidate matching** with regexes that accept common defanging directly
   (``[.]``, ``(.)``, ``[dot]``, ``[@]``, ``[at]``, ``hxxp``, ``[:]``). Matching the
   original text, rather than refanging it first, keeps character offsets exact.
2. **Validation** for each type (IP parsing, IANA TLD list, hash sanity, CVE year).
3. **Normalisation** to a canonical, refanged value.
4. **Overlap resolution** by priority: URL > email > CVE > IPv4 > domain > hashes.
   A domain inside a URL is therefore not counted twice.

Then, per document: **de-duplication** by ``(type, value)`` and **evidence
linking** of every occurrence to its sentence.

This module never resolves, fetches, or contacts any extracted value.
"""

from __future__ import annotations

import bisect
import ipaddress
import logging
import re
from collections.abc import Callable, Iterable
from datetime import date
from functools import lru_cache
from pathlib import Path

from config.settings import settings
from src.ingestion.models import ExtractedDocument, Sentence
from src.nlp.ioc_models import Indicator, IOCFlag, IOCMatch, IOCOccurrence, IOCType

logger = logging.getLogger(__name__)

TLD_FILE: Path = settings.knowledge_base_dir / "iana_tlds.txt"

# Real TLDs that collide with common file extensions (derived from the bundled
# IANA list). "invoice.zip" or "loader.py" is usually a filename, so such a
# domain is only accepted when written defanged (an explicit analyst signal).
FILE_EXTENSION_TLDS: frozenset[str] = frozenset(
    {"app", "cab", "md", "mov", "one", "pl", "py", "rs", "sh", "so", "zip"}
)
_RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost"})
_RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
_PRIVATE_NETS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_SHARED_NET = ipaddress.ip_network("100.64.0.0/10")
_FIRST_CVE_YEAR = 1999

# --- regex building blocks ----------------------------------------------------

_DOT = r"(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\.)"
_AT = r"(?:\[@\]|\(@\)|\[at\]|\(at\)|@)"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_TLD = r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_BODY = rf"(?:{_LABEL}{_DOT})+{_TLD}"
_IPV4_BODY = rf"\d{{1,3}}(?:{_DOT}\d{{1,3}}){{3}}"
_SCHEME = r"(?:h(?:tt|xx)ps?|f[tx]p)(?:://|\[://\]|\[:\]//)"
_PORT = r"(?:(?::|\[:\])\d{1,5})?"

_URL_RE = re.compile(
    rf"(?<!\w){_SCHEME}(?:{_IPV4_BODY}|{_DOMAIN_BODY}|localhost){_PORT}"
    r"(?:[/?#][^\s<>\"'`]*)?",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    rf"(?<![\w.%+-])[a-z0-9._%+-]{{1,64}}{_AT}{_DOMAIN_BODY}(?![\w-])", re.IGNORECASE
)
_CVE_RE = re.compile(r"(?<![\w-])CVE[- ]?(\d{4})[- ](\d{4,7})(?!\d)", re.IGNORECASE)
_IPV4_RE = re.compile(rf"(?<![\w.]){_IPV4_BODY}(?!\d|{_DOT}\d)", re.IGNORECASE)
_DOMAIN_RE = re.compile(rf"(?<![\w@.\-/\\]){_DOMAIN_BODY}(?![\w-])", re.IGNORECASE)
_HASH_RES = {
    IOCType.SHA256: re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.IGNORECASE),
    IOCType.SHA1: re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.IGNORECASE),
    IOCType.MD5: re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.IGNORECASE),
}
_VERSION_PREFIX = re.compile(r"(?:\bv|\bver\.?|\bversion|\bbuild)\s*$", re.IGNORECASE)

_REFANG_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"^fxp", re.IGNORECASE), "ftp"),
)
_URL_TRAILING = ".,;:!?'\""
_BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}


@lru_cache(maxsize=4)
def load_tlds(path: Path = TLD_FILE) -> frozenset[str]:
    """Load the bundled IANA TLD snapshot (lower-cased, comments skipped)."""
    with path.open(encoding="ascii") as handle:
        tlds = frozenset(
            line.strip().lower() for line in handle if line.strip() and not line.startswith("#")
        )
    if not tlds:
        raise ValueError(f"TLD list at {path} is empty")
    return tlds


def refang(raw: str) -> str:
    """Convert a defanged indicator to its literal form (``hxxp://a[.]b`` → ``http://a.b``)."""
    value = raw
    for pattern, replacement in _REFANG_RULES:
        value = pattern.sub(replacement, value)
    return value


def _is_defanged(raw: str) -> bool:
    return refang(raw).lower() != raw.lower()


def _trim_url(raw: str) -> str:
    """Drop sentence punctuation and unbalanced closing brackets from a URL's end."""
    def removable(last: str) -> bool:
        unbalanced = last in _BRACKET_PAIRS and raw.count(last) > raw.count(_BRACKET_PAIRS[last])
        return last in _URL_TRAILING or unbalanced

    while raw and removable(raw[-1]):
        raw = raw[:-1]
    return raw


def _domain_flags(domain: str) -> frozenset[IOCFlag]:
    tld = domain.rsplit(".", 1)[-1]
    reserved = tld in _RESERVED_TLDS or any(
        domain == d or domain.endswith("." + d) for d in _RESERVED_DOMAINS
    )
    return frozenset({IOCFlag.RESERVED_DOMAIN}) if reserved else frozenset()


def _ip_flags(ip: ipaddress.IPv4Address) -> frozenset[IOCFlag]:
    flags: set[IOCFlag] = set()
    if any(ip in net for net in _DOCUMENTATION_NETS):
        flags.add(IOCFlag.DOCUMENTATION_RANGE)
    elif any(ip in net for net in _PRIVATE_NETS):
        flags.add(IOCFlag.PRIVATE)
    elif ip in _SHARED_NET:
        flags.add(IOCFlag.SHARED)
    if ip.is_loopback:
        flags.add(IOCFlag.LOOPBACK)
    if ip.is_link_local:
        flags.add(IOCFlag.LINK_LOCAL)
    if ip.is_multicast:
        flags.add(IOCFlag.MULTICAST)
    if ip.is_unspecified or ip.is_reserved:
        flags.add(IOCFlag.RESERVED)
    return frozenset(flags)


def _is_title_case_namespace(raw: str) -> bool:
    """``System.Management`` / ``Microsoft.Exchange``: .NET-style names, not domains."""
    labels = refang(raw).split(".")
    return all(label[:1].isupper() and label[1:] != label[1:].upper() for label in labels)


class IOCExtractor:
    """Deterministic, regex-based IOC extractor."""

    def __init__(
        self,
        tlds: Iterable[str] | None = None,
        file_extension_tlds: Iterable[str] = FILE_EXTENSION_TLDS,
        today: Callable[[], date] = date.today,
    ) -> None:
        self.tlds = frozenset(t.lower() for t in tlds) if tlds is not None else load_tlds()
        self.file_extension_tlds = frozenset(file_extension_tlds)
        self._today = today

    # --- per-type validation + normalisation ---------------------------------

    def _valid_domain(self, domain: str) -> bool:
        # RFC 6761 special-use names are not delegated (absent from the IANA list) but
        # are unambiguous; they are accepted and always carry RESERVED_DOMAIN.
        tld = domain.rsplit(".", 1)[-1]
        return len(domain) <= 253 and (tld in self.tlds or tld in _RESERVED_TLDS)

    def _url(self, raw: str) -> tuple[str, frozenset[IOCFlag]] | None:
        literal = refang(raw)
        scheme, _, rest = literal.partition("://")
        host_end = len(rest)
        for sep in "/?#":
            index = rest.find(sep)
            if index != -1:
                host_end = min(host_end, index)
        host_port, path = rest[:host_end], rest[host_end:]
        host = host_port.rsplit(":", 1)[0] if ":" in host_port else host_port
        host = host.lower().rstrip(".")
        if not host:
            return None
        value = f"{scheme.lower()}://{host_port.lower()}{path}"
        try:
            flags = _ip_flags(ipaddress.IPv4Address(host))
        except ValueError:
            flags = _domain_flags(host)
        return value, flags

    def _email(self, raw: str) -> tuple[str, frozenset[IOCFlag]] | None:
        value = refang(raw).lower()
        domain = value.rsplit("@", 1)[-1].rstrip(".")
        if not self._valid_domain(domain):
            return None
        return value, _domain_flags(domain)

    def _cve(self, match: re.Match[str]) -> tuple[str, frozenset[IOCFlag]] | None:
        year, number = int(match.group(1)), match.group(2)
        if not _FIRST_CVE_YEAR <= year <= self._today().year + 1:
            return None
        return f"CVE-{year}-{number}", frozenset()

    def _ipv4(self, raw: str, text: str, start: int) -> tuple[str, frozenset[IOCFlag]] | None:
        if _VERSION_PREFIX.search(text[max(0, start - 12) : start]):
            return None  # "version 1.2.3.4" is a version number, not an address
        try:
            ip = ipaddress.IPv4Address(refang(raw))  # rejects >255 and leading zeros
        except ValueError:
            return None
        return str(ip), _ip_flags(ip)

    def _domain(self, raw: str) -> tuple[str, frozenset[IOCFlag]] | None:
        defanged = _is_defanged(raw)
        domain = refang(raw).lower().rstrip(".")
        if not self._valid_domain(domain):
            return None
        tld = domain.rsplit(".", 1)[-1]
        if not defanged and tld in self.file_extension_tlds:
            return None  # "invoice.zip", "loader.py": probably a filename
        if not defanged and _is_title_case_namespace(raw):
            return None  # "System.Management": a .NET namespace
        return domain, _domain_flags(domain)

    @staticmethod
    def _hash(raw: str) -> tuple[str, frozenset[IOCFlag]] | None:
        # Real digests mix digits and letters; reject long numbers and filler like "0000…".
        if raw.isdigit() or not any(c.isdigit() for c in raw) or len(set(raw.lower())) == 1:
            return None
        return raw.lower(), frozenset()

    # --- matching -------------------------------------------------------------

    def find(self, text: str) -> list[IOCMatch]:
        """Return validated, non-overlapping IOC matches in ``text``, ordered by position."""
        covered = bytearray(len(text))
        accepted: list[IOCMatch] = []

        def accept(ioc_type: IOCType, start: int, raw: str, result) -> None:
            end = start + len(raw)
            if result is None or any(covered[start:end]):
                return
            covered[start:end] = b"\x01" * (end - start)
            value, flags = result
            accepted.append(
                IOCMatch(ioc_type, raw, value, start, end, _is_defanged(raw), flags)
            )

        for m in _URL_RE.finditer(text):
            raw = _trim_url(m.group())
            accept(IOCType.URL, m.start(), raw, self._url(raw))
        for m in _EMAIL_RE.finditer(text):
            accept(IOCType.EMAIL, m.start(), m.group(), self._email(m.group()))
        for m in _CVE_RE.finditer(text):
            accept(IOCType.CVE, m.start(), m.group(), self._cve(m))
        for m in _IPV4_RE.finditer(text):
            accept(IOCType.IPV4, m.start(), m.group(), self._ipv4(m.group(), text, m.start()))
        for m in _DOMAIN_RE.finditer(text):
            accept(IOCType.DOMAIN, m.start(), m.group(), self._domain(m.group()))
        for ioc_type, pattern in _HASH_RES.items():
            for m in pattern.finditer(text):
                accept(ioc_type, m.start(), m.group(), self._hash(m.group()))

        return sorted(accepted, key=lambda match: match.char_start)

    def extract(self, document: ExtractedDocument) -> list[Indicator]:
        """Extract, de-duplicate and evidence-link every IOC in a document."""
        locator = _SentenceLocator(document.sentences)
        indicators: dict[tuple[IOCType, str], Indicator] = {}

        for page in document.pages:
            for match in self.find(page.text):
                sentence_index, context = locator.locate(
                    page.page_number, match.char_start, page.text
                )
                key = (match.ioc_type, match.value)
                indicator = indicators.setdefault(
                    key, Indicator(match.ioc_type, match.value, flags=match.flags)
                )
                indicator.occurrences.append(
                    IOCOccurrence(
                        raw=match.raw,
                        page_number=page.page_number,
                        char_start=match.char_start,
                        char_end=match.char_end,
                        defanged=match.defanged,
                        sentence_index=sentence_index,
                        context=context,
                    )
                )

        type_order = {t: i for i, t in enumerate(IOCType)}
        result = sorted(
            indicators.values(),
            key=lambda i: (type_order[i.ioc_type], i.occurrences[0].page_number,
                           i.occurrences[0].char_start),
        )
        logger.info(
            "Extracted %d unique IOCs (%d occurrences) from %s",
            len(result), sum(i.count for i in result), document.filename,
        )
        return result


class _SentenceLocator:
    """Maps a (page, offset) position to the sentence that contains it."""

    _FALLBACK_WINDOW = 80

    def __init__(self, sentences: list[Sentence]) -> None:
        self._by_page: dict[int, tuple[list[int], list[tuple[int, Sentence]]]] = {}
        for index, sentence in enumerate(sentences):
            starts, entries = self._by_page.setdefault(sentence.page_number, ([], []))
            starts.append(sentence.char_start)
            entries.append((index, sentence))

    def locate(self, page_number: int, offset: int, page_text: str) -> tuple[int | None, str]:
        starts, entries = self._by_page.get(page_number, ([], []))
        position = bisect.bisect_right(starts, offset) - 1
        if position >= 0:
            index, sentence = entries[position]
            if sentence.char_start <= offset < sentence.char_end:
                return index, " ".join(sentence.text.split())
        # No sentence covers the offset (e.g. sentences not computed): use a text window.
        window = page_text[
            max(0, offset - self._FALLBACK_WINDOW) : offset + self._FALLBACK_WINDOW
        ]
        return None, " ".join(window.split())
