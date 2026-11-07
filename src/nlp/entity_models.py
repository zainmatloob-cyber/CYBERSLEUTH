"""Data contracts for cybersecurity named entities.

``confidence`` is ``None`` unless a component produces a genuinely calibrated
score. Knowledge-base and pattern matches are deterministic, and spaCy's
``en_core_web_sm`` NER does not expose per-entity probabilities, so no score is
invented for either.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EntityType(StrEnum):
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"
    ATTACK_TECHNIQUE = "attack_technique"
    ORGANIZATION = "organization"
    LOCATION = "location"


class EntitySource(StrEnum):
    """Provenance of an entity: separates deterministic rules from model predictions."""

    ATTACK_KB = "kb:mitre-attack"
    CURATED_KB = "kb:curated"
    ACTOR_PATTERN = "rule:actor-pattern"
    MODEL = "model:spacy"


@dataclass(frozen=True)
class EntityMention:
    """One occurrence of an entity, with its evidence sentence."""

    text: str  # exactly as written (may be an alias)
    page_number: int
    char_start: int
    char_end: int
    sentence_index: int
    context: str


@dataclass
class Entity:
    """A unique entity (type + canonical name) and every mention supporting it."""

    entity_type: EntityType
    name: str  # canonical name (e.g. ATT&CK primary name for an alias)
    source: EntitySource
    kb_id: str | None = None  # e.g. ATT&CK "G0007" / "S0154"
    attributes: dict[str, str] = field(default_factory=dict)  # e.g. {"cve": "CVE-2021-44228"}
    alternatives: tuple[str, ...] = ()  # other KB ids the same surface form could denote
    mentions: list[EntityMention] = field(default_factory=list)
    confidence: float | None = None

    @property
    def count(self) -> int:
        return len(self.mentions)

    @property
    def aliases_seen(self) -> list[str]:
        """Distinct surface forms used in the document (excluding the canonical name)."""
        return sorted({m.text for m in self.mentions} - {self.name})
