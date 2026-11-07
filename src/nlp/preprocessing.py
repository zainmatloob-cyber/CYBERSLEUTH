"""Sentence segmentation with exact source offsets.

Phase 1 uses a transparent rule-based splitter. It sits behind the
``SentenceSplitter`` protocol so a spaCy-based splitter can replace it in
Phase 2 without changing any caller.

Rules:
* Blank lines are hard paragraph boundaries.
* Single line breaks are soft wraps (typical in PDFs) and do not end a sentence.
* ``.``, ``!``, ``?`` end a sentence only when followed by whitespace and then
  an uppercase letter, digit, or opening quote/bracket. Periods inside tokens
  (``192.168.1.1``, ``evil.com``, ``v2.4.1``) are never followed by
  whitespace, so indicators are never split.
* Common abbreviations (``e.g.``, ``Inc.``, ``U.S.``) and single-letter
  initials do not end a sentence.
* Over-long spans (e.g. an unpunctuated IOC list) are split at line breaks,
  then at whitespace, so each sentence stays a usable evidence snippet.

Invariant: ``page.text[s.char_start:s.char_end] == s.text`` for every sentence.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Protocol

from src.ingestion.models import PageText, Sentence

DEFAULT_MAX_SENTENCE_CHARS = 1000

_PARAGRAPH_BREAK = re.compile(r"\n[ \t]*\n\s*")
_SENTENCE_END = re.compile(r"[.!?]+[\"')\]]*(?=\s+[\"'(\[]?[A-Z0-9])")
_ABBREVIATIONS = frozenset({
    "e.g", "i.e", "vs", "cf", "al", "approx", "dept", "est", "fig", "figs", "no", "nos",
    "vol", "p", "pp", "sec", "ch", "ref", "mr", "mrs", "ms", "dr", "prof", "sr", "jr", "st",
    "inc", "ltd", "corp", "co", "llc", "gov", "u.s", "u.k", "u.n", "e.u",
    "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec",
})


class SentenceSplitter(Protocol):
    """Anything that turns one page into offset-preserving sentences."""

    def split(self, page: PageText) -> list[Sentence]: ...


def _is_abbreviation(text: str, period_index: int) -> bool:
    start = period_index
    while start > 0 and not text[start - 1].isspace():
        start -= 1
    token = text[start:period_index].lstrip("\"'([").lower()
    return token in _ABBREVIATIONS or (len(token) == 1 and token.isalpha())


def _paragraph_spans(text: str) -> Iterator[tuple[int, int]]:
    position = 0
    for match in _PARAGRAPH_BREAK.finditer(text):
        yield position, match.start()
        position = match.end()
    yield position, len(text)


def _sentence_spans(text: str, start: int, end: int) -> Iterator[tuple[int, int]]:
    position = start
    for match in _SENTENCE_END.finditer(text, start, end):
        punctuation = match.group().rstrip("\"')]")
        if punctuation == "." and _is_abbreviation(text, match.start()):
            continue
        yield position, match.end()
        position = match.end()
    yield position, end


def _limit_length(text: str, start: int, end: int, max_chars: int) -> Iterator[tuple[int, int]]:
    if end - start <= max_chars:
        yield start, end
        return
    # First preference: an over-long block with line breaks is almost always a
    # list (IOC tables, bullet points), so every line becomes its own unit.
    if "\n" in text[start:end]:
        line_start = start
        for offset, char in enumerate(text[start:end], start):
            if char == "\n":
                yield from _limit_length(text, line_start, offset, max_chars)
                line_start = offset + 1
        yield from _limit_length(text, line_start, end, max_chars)
        return
    # Last resort: split at the last whitespace before the limit (or hard cut).
    cut = text.rfind(" ", start, start + max_chars)
    cut = cut if cut > start else start + max_chars
    yield start, cut
    yield from _limit_length(text, cut, end, max_chars)


def _strip_span(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


class RegexSentenceSplitter:
    """Rule-based, dependency-free sentence splitter (Phase 1 default)."""

    def __init__(self, max_sentence_chars: int = DEFAULT_MAX_SENTENCE_CHARS) -> None:
        if max_sentence_chars <= 0:
            raise ValueError("max_sentence_chars must be positive")
        self.max_sentence_chars = max_sentence_chars

    def split(self, page: PageText) -> list[Sentence]:
        text = page.text
        sentences: list[Sentence] = []
        for p_start, p_end in _paragraph_spans(text):
            for s_start, s_end in _sentence_spans(text, p_start, p_end):
                for c_start, c_end in _limit_length(text, s_start, s_end, self.max_sentence_chars):
                    start, end = _strip_span(text, c_start, c_end)
                    if start < end:
                        sentences.append(Sentence(text[start:end], page.page_number, start, end))
        return sentences


def split_sentences(
    pages: list[PageText], splitter: SentenceSplitter | None = None
) -> list[Sentence]:
    """Segment every page into sentences, in page order."""
    splitter = splitter or RegexSentenceSplitter()
    return [sentence for page in pages for sentence in splitter.split(page)]
