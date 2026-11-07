"""Evidence views that join indicators and entities back to their source sentences.

Two views:
* ``build_sentence_evidence``: for every sentence, the indicators and entities found in
  it, so an analyst can read each finding in context.
* ``link_vulnerabilities``: merges CVE identifiers (from IOC extraction) with named
  vulnerabilities (from entity recognition, e.g. "Log4Shell" → CVE-2021-44228), so a
  vulnerability mentioned both ways is reported once.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from src.ingestion.models import ExtractedDocument, Sentence
from src.nlp.entity_models import Entity, EntityMention, EntityType
from src.nlp.ioc_models import Indicator, IOCOccurrence, IOCType


@dataclass(frozen=True)
class SentenceEvidence:
    sentence_index: int
    sentence: Sentence
    indicators: tuple[tuple[Indicator, IOCOccurrence], ...] = ()
    entities: tuple[tuple[Entity, EntityMention], ...] = ()

    @property
    def has_findings(self) -> bool:
        return bool(self.indicators or self.entities)


@dataclass(frozen=True)
class VulnerabilityRecord:
    cve_id: str
    names: tuple[str, ...]  # named-vulnerability labels, e.g. ("Log4Shell",)
    id_mentions: int  # times the CVE identifier itself appears
    name_mentions: int  # times a name for it appears
    pages: tuple[int, ...]

    @property
    def mentioned_by(self) -> str:
        if self.id_mentions and self.name_mentions:
            return "id+name"
        return "id" if self.id_mentions else "name"


def build_sentence_evidence(
    document: ExtractedDocument, indicators: list[Indicator], entities: list[Entity]
) -> list[SentenceEvidence]:
    """One ``SentenceEvidence`` per sentence, findings ordered by position."""
    iocs_by_sentence: dict[int, list[tuple[Indicator, IOCOccurrence]]] = defaultdict(list)
    for indicator in indicators:
        for occurrence in indicator.occurrences:
            if occurrence.sentence_index is not None:
                iocs_by_sentence[occurrence.sentence_index].append((indicator, occurrence))

    entities_by_sentence: dict[int, list[tuple[Entity, EntityMention]]] = defaultdict(list)
    for entity in entities:
        for mention in entity.mentions:
            entities_by_sentence[mention.sentence_index].append((entity, mention))

    return [
        SentenceEvidence(
            sentence_index=index,
            sentence=sentence,
            indicators=tuple(sorted(iocs_by_sentence[index], key=lambda p: p[1].char_start)),
            entities=tuple(sorted(entities_by_sentence[index], key=lambda p: p[1].char_start)),
        )
        for index, sentence in enumerate(document.sentences)
    ]


def link_vulnerabilities(
    indicators: list[Indicator], entities: list[Entity]
) -> list[VulnerabilityRecord]:
    """Merge CVE indicators and named-vulnerability entities into one record per CVE."""
    id_mentions: dict[str, int] = defaultdict(int)
    name_mentions: dict[str, int] = defaultdict(int)
    names: dict[str, set[str]] = defaultdict(set)
    pages: dict[str, set[int]] = defaultdict(set)

    for indicator in indicators:
        if indicator.ioc_type is IOCType.CVE:
            id_mentions[indicator.value] += indicator.count
            pages[indicator.value].update(indicator.pages)

    for entity in entities:
        if entity.entity_type is not EntityType.VULNERABILITY:
            continue
        for cve in filter(None, (c.strip() for c in entity.attributes.get("cve", "").split(","))):
            names[cve].add(entity.name)
            name_mentions[cve] += entity.count
            pages[cve].update(m.page_number for m in entity.mentions)

    return [
        VulnerabilityRecord(
            cve_id=cve,
            names=tuple(sorted(names[cve])),
            id_mentions=id_mentions[cve],
            name_mentions=name_mentions[cve],
            pages=tuple(sorted(pages[cve])),
        )
        for cve in sorted(id_mentions.keys() | names.keys())
    ]
