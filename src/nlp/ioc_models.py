"""Data contracts for Indicators of Compromise.

Extraction is not a verdict. Every indicator starts as
``VerificationStatus.UNVERIFIED``; ``flags`` describe *what* a value is
(e.g. a private IP or a documentation range), never whether it is malicious.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class IOCType(StrEnum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


class VerificationStatus(StrEnum):
    """Analyst verdict. Only a human (or a future, explicit enrichment step) changes this."""

    UNVERIFIED = "unverified"
    MALICIOUS = "malicious"
    BENIGN = "benign"
    FALSE_POSITIVE = "false_positive"


class IOCFlag(StrEnum):
    """Descriptive properties of an indicator. Not maliciousness judgements."""

    DOCUMENTATION_RANGE = "documentation_range"  # RFC 5737 test networks
    PRIVATE = "private"  # RFC 1918
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    SHARED = "shared_address_space"  # RFC 6598 carrier-grade NAT
    RESERVED = "reserved"
    RESERVED_DOMAIN = "reserved_domain"  # RFC 2606 / 6761 example & test names
    TOR_ONION = "tor_onion_service"  # RFC 7686 .onion name (reachable only over Tor)
    REJOINED = "rejoined_line_break"  # URL reconstructed across a line break in the source


@dataclass(frozen=True)
class IOCMatch:
    """One raw regex hit inside a single page's text, already validated and normalised."""

    ioc_type: IOCType
    raw: str  # exactly as written in the document (may be defanged)
    value: str  # normalised, refanged canonical form
    char_start: int
    char_end: int
    defanged: bool
    flags: frozenset[IOCFlag] = frozenset()


@dataclass(frozen=True)
class IOCOccurrence:
    """Evidence: where an indicator appeared and the sentence around it."""

    raw: str
    page_number: int
    char_start: int
    char_end: int
    defanged: bool
    sentence_index: int | None
    context: str


@dataclass
class Indicator:
    """A unique (type, value) indicator with every occurrence that supports it."""

    ioc_type: IOCType
    value: str
    occurrences: list[IOCOccurrence] = field(default_factory=list)
    flags: frozenset[IOCFlag] = frozenset()
    verification: VerificationStatus = VerificationStatus.UNVERIFIED
    # Provenance: distinguishes deterministic rules from future model output.
    source: str = "rule:regex"

    @property
    def count(self) -> int:
        return len(self.occurrences)

    @property
    def defanged(self) -> bool:
        """True if any occurrence was written in defanged form."""
        return any(o.defanged for o in self.occurrences)

    @property
    def pages(self) -> list[int]:
        return sorted({o.page_number for o in self.occurrences})
