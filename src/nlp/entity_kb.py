"""Loader for the versioned entity knowledge base in data/knowledge_base/.

Sources:
* ``attack_entities.json``  groups, malware and tools derived from MITRE ATT&CK.
* ``curated_entities.json`` hand-curated tools, named vulnerabilities, technique terms.
* ``entity_rules.json``     hand-reviewed disambiguation rules.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from config.settings import settings
from src.nlp.entity_models import EntitySource, EntityType
from src.utils.exceptions import KnowledgeBaseError

KB_DIR: Path = settings.knowledge_base_dir
_ATTACK_TYPES = {
    "threat_actor": EntityType.THREAT_ACTOR,
    "malware": EntityType.MALWARE,
    "tool": EntityType.TOOL,
}
_CURATED_SECTIONS = {
    "tools": EntityType.TOOL,
    "vulnerabilities": EntityType.VULNERABILITY,
    "attack_techniques": EntityType.ATTACK_TECHNIQUE,
}
# Short forms ("Net", "RTM", "TVT") collide with ordinary words and acronyms.
SHORT_FORM_MAX_LENGTH = 3


@dataclass(frozen=True)
class KBEntry:
    kb_id: str | None
    entity_type: EntityType
    name: str
    source: EntitySource
    attributes: tuple[tuple[str, str], ...] = ()


@dataclass
class EntityKnowledgeBase:
    """Surface form → candidate entries, plus disambiguation rules."""

    attack_forms: dict[str, list[KBEntry]]
    curated_forms: dict[str, KBEntry]  # keyed by lower-cased variant
    context_required: frozenset[str]
    blocked: frozenset[str]
    context_patterns: dict[EntityType, re.Pattern[str]]
    versions: dict[str, str] = field(default_factory=dict)

    def requires_context(self, form: str) -> bool:
        return form in self.context_required or len(form) <= SHORT_FORM_MAX_LENGTH

    def has_context(self, entity_type: EntityType, sentence: str) -> bool:
        pattern = self.context_patterns.get(entity_type)
        return bool(pattern and pattern.search(sentence))


def _read_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise KnowledgeBaseError(f"Cannot load knowledge base file {path.name}: {exc}") from exc


def _keyword_pattern(words: list[str]) -> re.Pattern[str]:
    alternatives = "|".join(sorted((re.escape(w.lower()) for w in words), key=len, reverse=True))
    return re.compile(rf"(?<![\w-])(?:{alternatives})(?![\w-])", re.IGNORECASE)


def load_knowledge_base(directory: Path = KB_DIR) -> EntityKnowledgeBase:
    """Load and cross-validate all knowledge-base files."""
    attack = _read_json(directory / "attack_entities.json")
    curated = _read_json(directory / "curated_entities.json")
    rules = _read_json(directory / "entity_rules.json")

    attack_forms: dict[str, list[KBEntry]] = defaultdict(list)
    for item in attack["entries"]:
        entry = KBEntry(item["id"], _ATTACK_TYPES[item["type"]], item["name"],
                        EntitySource.ATTACK_KB)
        for form in {item["name"], *item["aliases"]}:
            attack_forms[form].append(entry)

    curated_forms: dict[str, KBEntry] = {}
    for section, entity_type in _CURATED_SECTIONS.items():
        for item in curated[section]:
            attributes = (("cve", ", ".join(item["cve"])),) if item.get("cve") else ()
            entry = KBEntry(None, entity_type, item["name"], EntitySource.CURATED_KB, attributes)
            for variant in item["variants"]:
                key = variant.lower()
                if key in curated_forms:
                    raise KnowledgeBaseError(f"Duplicate curated variant {variant!r}")
                curated_forms[key] = entry

    context_required = frozenset(rules["context_required_forms"])
    blocked = frozenset(rules["blocked_forms"])
    unknown = sorted((context_required | blocked) - attack_forms.keys())
    if unknown:  # guards the hand-reviewed rule file against typos
        raise KnowledgeBaseError(f"Rule forms not found in ATT&CK data: {unknown}")

    context_patterns = {
        EntityType(kind): _keyword_pattern(words)
        for kind, words in rules["context_keywords"].items()
    }
    versions = {
        "attack": str(attack.get("attack_version")),
        "curated": curated.get("version", ""),
        "rules": rules.get("version", ""),
    }
    return EntityKnowledgeBase(
        attack_forms=dict(attack_forms),
        curated_forms=curated_forms,
        context_required=context_required,
        blocked=blocked,
        context_patterns=context_patterns,
        versions=versions,
    )


@lru_cache(maxsize=1)
def default_knowledge_base() -> EntityKnowledgeBase:
    return load_knowledge_base()
