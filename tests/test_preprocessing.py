"""Tests for sentence segmentation (src/nlp/preprocessing.py)."""

from __future__ import annotations

import pytest

from src.ingestion.models import PageText, Sentence
from src.nlp.preprocessing import RegexSentenceSplitter, split_sentences


def _texts(text: str, **kwargs) -> list[str]:
    return [s.text for s in RegexSentenceSplitter(**kwargs).split(PageText(1, text))]


def _assert_offsets(page: PageText, sentences: list[Sentence]) -> None:
    for s in sentences:
        assert page.text[s.char_start : s.char_end] == s.text
        assert s.page_number == page.page_number


def test_basic_split():
    assert _texts("First sentence. Second one! Third? Fourth.") == [
        "First sentence.", "Second one!", "Third?", "Fourth.",
    ]


@pytest.mark.parametrize(
    "sentence",
    [
        "The C2 server was 192.168.10.45 and it responded.",
        "Traffic went to update.example-cdn.net over TLS.",
        "Defanged as hxxp://evil[.]com/x.php in the report.",
        "Version 2.4.1 of the loader was observed.",
        "The sample 44d88612fea8a8f36de82e1278abb02f was dropped.",
        "It exploited CVE-2024-3400 on exposed devices.",
    ],
)
def test_indicators_are_not_split(sentence):
    assert _texts(f"{sentence} Next sentence here.") == [sentence, "Next sentence here."]


@pytest.mark.parametrize(
    "text",
    [
        "Tools, e.g. Mimikatz, were used.",
        "Acme Inc. Was targeted by the group.",
        "The U.S. Government issued an advisory.",
        "Analyst J. Smith reviewed the case.",
        "See Fig. 3 for the timeline.",
        "Reported on Jan. 15 by the vendor.",
    ],
)
def test_abbreviations_do_not_split(text):
    assert _texts(text) == [text]


def test_sentence_ending_with_domain():
    assert _texts("Beacons went to evil.com. Then exfiltration began.") == [
        "Beacons went to evil.com.", "Then exfiltration began.",
    ]


def test_closing_quote_and_bracket_stay_with_sentence():
    assert _texts('He said "stop." Then left. (See note.) Done.') == [
        'He said "stop."', "Then left.", "(See note.)", "Done.",
    ]


def test_soft_line_wrap_is_not_a_boundary():
    assert _texts("The actor used\nspear-phishing emails.") == [
        "The actor used\nspear-phishing emails."
    ]


def test_blank_line_is_a_boundary_even_without_punctuation():
    assert _texts("Indicator | Type\n\n198.51.100.7 | IPv4") == [
        "Indicator | Type", "198.51.100.7 | IPv4",
    ]


def test_lowercase_after_period_does_not_split():
    assert _texts("See section 4. the actor then moved.") == [
        "See section 4. the actor then moved."
    ]


def test_long_unpunctuated_block_split_at_line_breaks():
    lines = [f"198.51.100.{i}" for i in range(50)]
    result = _texts("\n".join(lines), max_sentence_chars=60)
    assert result == lines


def test_long_single_line_split_at_whitespace():
    text = " ".join(["word"] * 100)
    result = _texts(text, max_sentence_chars=50)
    assert all(len(s) <= 50 for s in result)
    assert " ".join(result) == text


def test_long_token_hard_cut():
    result = _texts("a" * 120, max_sentence_chars=50)
    assert [len(s) for s in result] == [50, 50, 20]


def test_offsets_round_trip_on_messy_text():
    page = PageText(7, "  Intro.  Second line\nwraps here.\n\n\nNew para e.g. this! Last?  ")
    sentences = RegexSentenceSplitter().split(page)
    _assert_offsets(page, sentences)
    assert [s.text for s in sentences] == [
        "Intro.", "Second line\nwraps here.", "New para e.g. this!", "Last?",
    ]


def test_empty_page_yields_no_sentences():
    assert RegexSentenceSplitter().split(PageText(1, "")) == []
    assert RegexSentenceSplitter().split(PageText(1, "  \n\n ")) == []


def test_split_sentences_across_pages_keeps_page_numbers():
    pages = [PageText(1, "One. Two."), PageText(2, ""), PageText(3, "Three.")]
    sentences = split_sentences(pages)
    assert [(s.page_number, s.text) for s in sentences] == [(1, "One."), (1, "Two."), (3, "Three.")]
    for page in pages:
        _assert_offsets(page, [s for s in sentences if s.page_number == page.page_number])


def test_custom_splitter_is_used():
    class OneSentencePerPage:
        def split(self, page):
            return [Sentence(page.text, page.page_number, 0, len(page.text))]

    assert len(split_sentences([PageText(1, "A. B. C.")], OneSentencePerPage())) == 1


def test_invalid_max_length_rejected():
    with pytest.raises(ValueError):
        RegexSentenceSplitter(max_sentence_chars=0)
