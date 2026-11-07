"""Text normalisation that is safe for threat-intelligence content.

Design rule: cleaning must never destroy Indicators of Compromise. Defanged
forms such as ``hxxp://``, ``evil[.]com`` and ``192.168.1[.]1`` must pass through
unchanged so the Phase 2 IOC extractor can find them.

Steps (order matters):
1. Normalise line endings (``\\r\\n``, ``\\r``, form feed).
2. Unicode NFKC: ligatures (``ﬁ`` → ``fi``), full-width characters, NBSP → space.
3. Remove invisible characters (zero-width spaces, soft hyphens, BOM) that
   are often inserted inside hashes/domains and break pattern matching.
4. Map typographic quotes and hyphens to ASCII.
5. Remove remaining control characters.
6. Re-join words hyphenated across line breaks, keeping the hyphen when the
   token looks like an indicator (domain, CVE, path, number).
7. Collapse runs of spaces and excess blank lines.
"""

from __future__ import annotations

import re
import unicodedata

from src.ingestion.models import PageText

_INVISIBLE_CHARS = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
_TYPOGRAPHIC_MAP = str.maketrans({
    "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "“": '"', "”": '"', "„": '"', "‟": '"',
    "‐": "-", "‑": "-",
})
# C0/C1 control characters except tab and newline.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_LINE_BREAK_HYPHEN = re.compile(r"(\S+)-[ \t]*\n[ \t]*(\S+)")
# Characters that suggest a token is an indicator or identifier, not prose.
_INDICATOR_HINT = re.compile(r"[\d.\[\]/\\@:_=]")
_EDGE_PUNCTUATION = "\"'([{)]},.;:!?"
_SPACE_RUNS = re.compile(r"[ \t]+")
_EXCESS_BLANK_LINES = re.compile(r"\n{3,}")


def _rejoin_hyphenated(match: re.Match[str]) -> str:
    left, right = match.group(1), match.group(2)
    left_core = left.lstrip(_EDGE_PUNCTUATION)
    right_core = right.rstrip(_EDGE_PUNCTUATION)
    is_prose_split = (
        left_core[-1:].islower()
        and right_core[:1].islower()
        and not _INDICATOR_HINT.search(left_core)
        and not _INDICATOR_HINT.search(right_core)
    )
    # "mali-\nware" → "malware";  "evil-\nsite.com" → "evil-site.com";
    # "CVE-\n2024-3400" → "CVE-2024-3400"
    return f"{left}{right}" if is_prose_split else f"{left}-{right}"


def clean_text(text: str) -> str:
    """Return normalised text. Idempotent: ``clean_text(clean_text(x)) == clean_text(x)``."""
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\f", "\n\n")
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_INVISIBLE_CHARS).translate(_TYPOGRAPHIC_MAP)
    text = _CONTROL_CHARS.sub("", text)
    text = _LINE_BREAK_HYPHEN.sub(_rejoin_hyphenated, text)
    lines = (_SPACE_RUNS.sub(" ", line).strip() for line in text.split("\n"))
    text = "\n".join(lines)
    text = _EXCESS_BLANK_LINES.sub("\n\n", text)
    return text.strip()


def clean_pages(pages: list[PageText]) -> list[PageText]:
    """Clean every page, preserving page numbers (including now-empty pages)."""
    return [PageText(page_number=p.page_number, text=clean_text(p.text)) for p in pages]
