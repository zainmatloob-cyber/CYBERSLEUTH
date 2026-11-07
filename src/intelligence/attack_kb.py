"""ATT&CK technique knowledge base (v20.1), with translation of revoked IDs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from config.settings import settings
from src.utils.exceptions import KnowledgeBaseError

TECHNIQUES_PATH: Path = settings.knowledge_base_dir / "attack_techniques.json"
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MAX_REVOCATION_CHAIN = 10


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    is_subtechnique: bool
    description: str

    @property
    def parent_id(self) -> str:
        return self.id.split(".")[0]

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


class TechniqueKB:
    def __init__(self, techniques: dict[str, Technique], revoked_to: dict[str, str],
                 version: str) -> None:
        self.techniques = techniques
        self.revoked_to = revoked_to
        self.version = version

    def resolve(self, technique_id: str) -> str | None:
        """Return the active ID for ``technique_id`` (following revocations), or ``None``."""
        current = technique_id
        for _ in range(_MAX_REVOCATION_CHAIN):
            if current in self.techniques:
                return current
            if current not in self.revoked_to:
                return None
            current = self.revoked_to[current]
        return None  # cyclic or too long a chain: treat as unknown

    def get(self, technique_id: str) -> Technique | None:
        resolved = self.resolve(technique_id)
        return self.techniques.get(resolved) if resolved else None

    def parent(self, technique_id: str) -> str | None:
        """Active parent technique ID (a sub-technique's parent, or the technique itself)."""
        resolved = self.resolve(technique_id)
        if resolved is None:
            return None
        return self.resolve(resolved.split(".")[0]) or resolved.split(".")[0]


def load_technique_kb(path: Path = TECHNIQUES_PATH) -> TechniqueKB:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KnowledgeBaseError(f"Cannot load {path.name}: {exc}") from exc
    techniques = {}
    for item in data["techniques"]:
        if not TECHNIQUE_ID_RE.match(item["id"]):
            raise KnowledgeBaseError(f"Invalid technique id {item['id']!r} in {path.name}")
        techniques[item["id"]] = Technique(item["id"], item["name"], tuple(item["tactics"]),
                                           item["is_subtechnique"], item["description"])
    return TechniqueKB(techniques, dict(data["revoked_to"]), str(data["attack_version"]))


@lru_cache(maxsize=1)
def default_technique_kb() -> TechniqueKB:
    return load_technique_kb()
