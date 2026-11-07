"""Cybersecurity named-entity recognition: knowledge base + rules + spaCy NER.

Per sentence (sentences come from Phase 1, so every mention carries evidence):

1. **ATT&CK knowledge base**: case-sensitive phrase matching on every name and alias,
   plus case-insensitive matching for distinctive names (``mimikatz`` → Mimikatz).
2. **Curated knowledge base**: case-insensitive tools, named vulnerabilities and
   attack-technique terms.
3. **Actor naming patterns**: vendor conventions such as APT41, FIN7, UNC4841,
   Storm-0558, DEV-0537, TA505 and "<Adjective> Bear/Panda/Typhoon/...".
4. **spaCy NER**: ORG → organization, GPE/LOC → location.

Overlaps are resolved by that priority order, so the model never relabels a
known entity (e.g. "Cobalt Strike" is a tool, not an ORG). Ambiguous names
(common words, short acronyms) need a type keyword in the same sentence.
Forms shared by several KB entries are disambiguated by context, and the other
candidates are recorded in ``Entity.alternatives``.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache

import spacy
from spacy.language import Language
from spacy.matcher import PhraseMatcher
from spacy.tokens import Doc

from config.settings import settings
from src.ingestion.models import ExtractedDocument, Sentence
from src.nlp.entity_kb import EntityKnowledgeBase, KBEntry, default_knowledge_base
from src.nlp.entity_models import Entity, EntityMention, EntitySource, EntityType
from src.nlp.preprocessing import split_sentences
from src.utils.exceptions import ModelNotAvailableError

logger = logging.getLogger(__name__)

_UNUSED_PIPES = ["parser", "lemmatizer", "tagger", "attribute_ruler", "senter"]
_MODEL_LABELS = {"ORG": EntityType.ORGANIZATION, "GPE": EntityType.LOCATION,
                 "LOC": EntityType.LOCATION}
# Lower number wins when spans overlap.
_PRIORITY = {"attack": 0, "attack_lower": 1, "curated": 2, "pattern": 3, "model": 4}

_ACTOR_CODE_RE = re.compile(
    r"(?<![\w-])(APT|FIN|TA|UNC|DEV|Storm|UAC|TAG)[- ]?(\d{2,5})(?![\w-])"
)
_ACTOR_CODE_DIGITS = {"APT": (1, 3), "FIN": (1, 2), "TA": (3, 4), "UNC": (3, 5),
                      "DEV": (4, 4), "Storm": (4, 4), "UAC": (4, 4), "TAG": (2, 3)}
_ACTOR_CODE_SEPARATOR = {"DEV": "-", "Storm": "-", "UAC": "-", "TAG": "-"}
_ACTOR_ANIMAL_RE = re.compile(
    r"(?<![\w-])((?:[A-Z][a-z]+|[A-Z]{3,}) (?i:Bear|Panda|Kitten|Chollima|Spider|Jackal|Tiger"
    r"|Buffalo|Leopard|Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Cyclone))(?![\w-])"
)
# Identifier-like text the statistical NER sometimes labels as ORG/GPE.
_IOC_LIKE_RE = re.compile(
    r"[/@\\\[\]]"  # URLs, emails, paths, defanged forms
    r"|^[\w-]+(?:\.[\w-]+)+$"  # domains, IPs, dotted identifiers
    r"|\bCVE-\d"  # vulnerability IDs
    r"|\b[0-9a-f]{32,}\b",  # hashes
    re.IGNORECASE,
)
_TRAILING_PUNCTUATION = ".:;!?"


@dataclass(frozen=True)
class _Candidate:
    start: int  # offsets relative to the sentence
    end: int
    priority: int
    entity_type: EntityType
    name: str
    source: EntitySource
    kb_id: str | None = None
    attributes: tuple[tuple[str, str], ...] = ()
    alternatives: tuple[str, ...] = ()


@lru_cache(maxsize=2)
def load_spacy_model(name: str) -> Language:
    """Load a spaCy pipeline once, keeping only what NER needs."""
    try:
        return spacy.load(name, exclude=_UNUSED_PIPES)
    except OSError as exc:
        raise ModelNotAvailableError(
            f"spaCy model {name!r} is not installed. Run: python -m spacy download {name}"
        ) from exc


class EntityExtractor:
    """Extracts cybersecurity entities from an ``ExtractedDocument``."""

    def __init__(
        self,
        knowledge_base: EntityKnowledgeBase | None = None,
        model: str | None = settings.nlp.spacy_model,
        batch_size: int = settings.nlp.spacy_batch_size,
    ) -> None:
        """``model=None`` runs the deterministic rules only (blank English tokenizer)."""
        self.kb = knowledge_base or default_knowledge_base()
        self.nlp = load_spacy_model(model) if model else spacy.blank("en")
        self.model_name = model
        self.batch_size = batch_size
        self._exact, self._lower = self._build_matchers()

    # --- setup ----------------------------------------------------------------

    def _build_matchers(self) -> tuple[PhraseMatcher, PhraseMatcher]:
        exact = PhraseMatcher(self.nlp.vocab, attr="ORTH")
        lower = PhraseMatcher(self.nlp.vocab, attr="LOWER")
        self._lower_attack: dict[str, list[KBEntry]] = {}
        for form, entries in self.kb.attack_forms.items():
            if form in self.kb.blocked:
                continue
            exact.add(f"attack|{form}", [self.nlp.make_doc(form)])
            if not self.kb.requires_context(form):
                self._lower_attack.setdefault(form.lower(), []).extend(entries)
        for key in self._lower_attack:
            lower.add(f"attack_lower|{key}", [self.nlp.make_doc(key)])
        for key in self.kb.curated_forms:
            lower.add(f"curated|{key}", [self.nlp.make_doc(key)])
        return exact, lower

    # --- candidate generation ---------------------------------------------------

    def _choose(self, form: str, entries: list[KBEntry], sentence: str) -> KBEntry | None:
        """Pick the KB entry for a surface form; ``None`` if context is required but absent."""
        unique = list({e.kb_id: e for e in entries}.values())
        with_context = [e for e in unique if self.kb.has_context(e.entity_type, sentence)]
        if self.kb.requires_context(form) and not with_context:
            return None
        pool = with_context or unique
        # Prefer the entry whose primary name is this form, then the lowest ATT&CK id.
        return min(pool, key=lambda e: (e.name != form, e.kb_id or ""))

    def _kb_candidates(self, doc: Doc) -> Iterator[_Candidate]:
        sentence = doc.text
        for matcher in (self._exact, self._lower):
            for match_id, start, end in matcher(doc):
                kind, _, key = self.nlp.vocab.strings[match_id].partition("|")
                span = doc[start:end]
                if kind == "curated":
                    entry = self.kb.curated_forms[key]
                    yield _Candidate(span.start_char, span.end_char, _PRIORITY[kind],
                                     entry.entity_type, entry.name, entry.source,
                                     attributes=entry.attributes)
                    continue
                entries = self.kb.attack_forms[key] if kind == "attack" else self._lower_attack[key]
                chosen = self._choose(span.text, entries, sentence)
                if chosen is None:
                    continue
                others = tuple(sorted({e.kb_id for e in entries if e.kb_id != chosen.kb_id}))
                yield _Candidate(span.start_char, span.end_char, _PRIORITY[kind],
                                 chosen.entity_type, chosen.name, chosen.source,
                                 kb_id=chosen.kb_id, alternatives=others)

    def _pattern_candidates(self, sentence: str) -> Iterator[_Candidate]:
        for match in _ACTOR_CODE_RE.finditer(sentence):
            prefix, digits = match.group(1), match.group(2)
            low, high = _ACTOR_CODE_DIGITS[prefix]
            if not low <= len(digits) <= high:
                continue
            name = f"{prefix}{_ACTOR_CODE_SEPARATOR.get(prefix, '')}{digits}"
            yield self._actor_candidate(match.start(), match.end(), name)
        for match in _ACTOR_ANIMAL_RE.finditer(sentence):
            name = " ".join(word.capitalize() for word in match.group(1).split())
            yield self._actor_candidate(match.start(), match.end(), name)

    def _actor_candidate(self, start: int, end: int, name: str) -> _Candidate:
        # A normalised pattern hit that is a known ATT&CK form ("APT 41" → APT41)
        # is upgraded to the knowledge-base entity.
        known = [e for e in self.kb.attack_forms.get(name, [])
                 if e.entity_type is EntityType.THREAT_ACTOR]
        if known:
            entry = min(known, key=lambda e: e.kb_id or "")
            return _Candidate(start, end, _PRIORITY["pattern"], entry.entity_type, entry.name,
                              entry.source, kb_id=entry.kb_id)
        return _Candidate(start, end, _PRIORITY["pattern"], EntityType.THREAT_ACTOR, name,
                          EntitySource.ACTOR_PATTERN)

    @staticmethod
    def _model_candidates(doc: Doc) -> Iterator[_Candidate]:
        whole_sentence = doc.text.strip().rstrip(_TRAILING_PUNCTUATION).strip()
        for ent in doc.ents:
            # An entity spanning the entire sentence is almost always a heading
            # ("Technical Details.") that the model mislabels as ORG.
            if ent.text.strip() == whole_sentence:
                continue
            entity_type = _MODEL_LABELS.get(ent.label_)
            if entity_type is None:
                continue
            start, end = ent.start_char, ent.end_char
            if doc.text[start:end].endswith("'s"):  # possessive is not part of the name
                end -= 2
            text = " ".join(doc.text[start:end].split())
            if (
                len(text) < 2
                or not any(c.isalpha() for c in text)
                or text.islower()
                or _IOC_LIKE_RE.search(text)
            ):
                continue
            yield _Candidate(start, end, _PRIORITY["model"], entity_type, text,
                             EntitySource.MODEL)

    @staticmethod
    def _resolve(candidates: list[_Candidate], length: int) -> list[_Candidate]:
        """Greedy non-overlapping selection: priority first, then longer spans."""
        covered = bytearray(length)
        chosen: list[_Candidate] = []
        for cand in sorted(candidates, key=lambda c: (c.priority, c.start - c.end, c.start)):
            if any(covered[cand.start : cand.end]):
                continue
            covered[cand.start : cand.end] = b"\x01" * (cand.end - cand.start)
            chosen.append(cand)
        return sorted(chosen, key=lambda c: c.start)

    # --- public API -------------------------------------------------------------

    def find(self, doc: Doc) -> list[_Candidate]:
        """All resolved entity candidates in one processed sentence."""
        candidates = [*self._kb_candidates(doc), *self._pattern_candidates(doc.text)]
        if self.model_name:
            candidates.extend(self._model_candidates(doc))
        return self._resolve(candidates, len(doc.text))

    def extract(self, document: ExtractedDocument) -> list[Entity]:
        sentences: list[Sentence] = document.sentences or split_sentences(document.pages)
        entities: dict[tuple[EntityType, str], Entity] = {}

        docs = self.nlp.pipe((s.text for s in sentences), batch_size=self.batch_size)
        for index, (sentence, doc) in enumerate(zip(sentences, docs, strict=True)):
            context = " ".join(sentence.text.split())
            for cand in self.find(doc):
                key = (cand.entity_type, cand.name.casefold())
                entity = entities.setdefault(key, Entity(
                    entity_type=cand.entity_type,
                    name=cand.name,
                    source=cand.source,
                    kb_id=cand.kb_id,
                    attributes=dict(cand.attributes),
                ))
                # A later mention via an ambiguous alias ("Sofacy") adds alternatives.
                entity.alternatives = tuple(sorted({*entity.alternatives, *cand.alternatives}))
                entity.mentions.append(EntityMention(
                    text=sentence.text[cand.start : cand.end],
                    page_number=sentence.page_number,
                    char_start=sentence.char_start + cand.start,
                    char_end=sentence.char_start + cand.end,
                    sentence_index=index,
                    context=context,
                ))

        type_order = {t: i for i, t in enumerate(EntityType)}
        result = sorted(entities.values(),
                        key=lambda e: (type_order[e.entity_type], -e.count, e.name.casefold()))
        logger.info("Extracted %d unique entities from %s (model=%s)",
                    len(result), document.filename, self.model_name)
        return result
