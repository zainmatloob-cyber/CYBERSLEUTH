"""Threat-category dataset built from technique-labelled ATT&CK procedure examples.

Source: Hugging Face ``sarahwei/cyber_MITRE_technique_CTI_dataset_v16`` (Apache-2.0),
i.e. MITRE ATT&CK v16 Enterprise procedure examples, each labelled with one technique.

Steps:
1. **Verify** the pinned raw file by SHA-256.
2. **Clean** markup (``<code>``, citation markers) and **merge** rows that have identical
   text but different techniques (multi-label).
3. **Map** techniques to threat categories using the versioned
   ``technique_category_map.json``. "other" applies only when no category does.
4. **Group** each sentence by the actor, software or campaign it describes, and
   **split by group** (train/val/test). Near-identical sentences about the same
   actor can therefore never appear on both sides of a split.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from config.settings import settings
from src.nlp.entity_kb import EntityKnowledgeBase, default_knowledge_base
from src.utils.exceptions import CyberSleuthError

DATASET_ID = "sarahwei/cyber_MITRE_technique_CTI_dataset_v16"
DATASET_REVISION = "9e52a7fb9400097cfe09756ce09256279dfa8d82"
DATASET_FILE = "dataset.csv"
DATASET_SHA256 = "bcac09a30da335f59957ac9e7581749f4040d9857d057a70390baac4371c8855"
DATASET_URL = (
    f"https://huggingface.co/datasets/{DATASET_ID}/resolve/{DATASET_REVISION}/{DATASET_FILE}"
)
CATEGORY_MAP_PATH = settings.knowledge_base_dir / "technique_category_map.json"
OTHER = "other"
SPLITS = ("train", "val", "test")
SPLIT_SEED = "cybersleuth-v1"
_SPLIT_BOUNDS = (70, 85)  # hash bucket < 70 → train, < 85 → val, else test

_TECHNIQUE_RE = re.compile(r"^(T\d{4})(\.\d{3})?\b")
_CAMPAIGN_PREFIX = re.compile(r"^(?:During|For|In) (?:the )?(?P<campaign>[^,]{2,80}?),\s+")
_ARTICLE_PREFIX = re.compile(r"^(?:A|An|The)\s+")
_SUBJECT_END = re.compile(
    r"\s(?:has|have|had|can|could|uses|used|is|was|were|will|may|might|involved|involves"
    r"|leverages|leveraged|employs|employed|performs|performed|attempts|attempted)\b"
)
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_HTML_TAG = re.compile(r"</?[a-zA-Z][^>]*>")


class DatasetError(CyberSleuthError):
    """The raw dataset is missing, corrupted, or does not match the pinned version."""


@dataclass(frozen=True)
class CategoryMap:
    version: str
    technique_to_categories: dict[str, frozenset[str]]
    categories: tuple[str, ...]

    def categorize(self, techniques: Iterable[str]) -> frozenset[str]:
        found: set[str] = set()
        for technique in techniques:
            found |= self.technique_to_categories.get(parent_technique(technique), frozenset())
        return frozenset(found) or frozenset({OTHER})


def load_category_map(path: Path = CATEGORY_MAP_PATH) -> CategoryMap:
    data = json.loads(path.read_text(encoding="utf-8"))
    mapping: dict[str, set[str]] = {}
    for category, spec in data["categories"].items():
        for technique in spec["techniques"]:
            if not re.fullmatch(r"T\d{4}", technique):
                raise DatasetError(f"Invalid parent technique id {technique!r} in {path.name}")
            mapping.setdefault(technique, set()).add(category)
    return CategoryMap(
        version=data["version"],
        technique_to_categories={t: frozenset(c) for t, c in mapping.items()},
        categories=tuple(data["categories"]),
    )


def parent_technique(technique: str) -> str:
    """``T1566.001`` → ``T1566``."""
    match = _TECHNIQUE_RE.match(technique)
    if not match:
        raise DatasetError(f"Not an ATT&CK technique id: {technique!r}")
    return match.group(1)


def technique_from_label(label: str) -> str:
    """``"T1562.001: Impair Defenses- ..."`` → ``"T1562.001"``."""
    match = _TECHNIQUE_RE.match(label.strip())
    if not match:
        raise DatasetError(f"Label without a technique id: {label!r}")
    return match.group(1) + (match.group(2) or "")


def clean_text(text: str) -> str:
    text = _CITATION.sub("", text)
    text = _HTML_TAG.sub("", text)
    return " ".join(text.split())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_raw_file(path: Path, expected_sha256: str = DATASET_SHA256) -> None:
    if not path.is_file():
        raise DatasetError(f"{path} not found. Run: python scripts/prepare_threat_dataset.py")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise DatasetError(
            f"{path.name} SHA-256 mismatch (expected {expected_sha256[:12]}…, "
            f"got {actual[:12]}…). The file is corrupted or not the pinned revision."
        )


class GroupKeyer:
    """Assigns each sentence to the actor/software/campaign it describes."""

    def __init__(self, kb: EntityKnowledgeBase | None = None) -> None:
        kb = kb or default_knowledge_base()
        # Longest first, so "Lazarus Group" wins over "Lazarus".
        self._forms = sorted(
            ((form, entries[0].kb_id) for form, entries in kb.attack_forms.items()
             if len(form) >= 3),
            key=lambda item: -len(item[0]),
        )

    def _kb_prefix(self, text: str) -> str | None:
        for form, kb_id in self._forms:
            if text.startswith(form) and (len(text) == len(form) or not text[len(form)].isalnum()):
                return f"attack:{kb_id}"
        return None

    def key(self, text: str) -> str:
        campaign = _CAMPAIGN_PREFIX.match(text)
        rest = text[campaign.end():] if campaign else text
        rest = _ARTICLE_PREFIX.sub("", rest)
        known = self._kb_prefix(rest)
        if known:
            return known
        if campaign:
            return "campaign:" + campaign.group("campaign").strip().lower()
        end = _SUBJECT_END.search(rest)
        subject = rest[: end.start()] if end and end.start() <= 60 else " ".join(rest.split()[:2])
        return "subject:" + subject.strip().lower()


def assign_split(group: str, seed: str = SPLIT_SEED) -> str:
    """Deterministic, order-independent split assignment by hashing the group key."""
    bucket = int(hashlib.sha256(f"{seed}:{group}".encode()).hexdigest(), 16) % 100
    if bucket < _SPLIT_BOUNDS[0]:
        return "train"
    return "val" if bucket < _SPLIT_BOUNDS[1] else "test"


def build_dataset(
    raw: pd.DataFrame, category_map: CategoryMap, keyer: GroupKeyer | None = None
) -> pd.DataFrame:
    """Return one row per unique cleaned sentence: text, techniques, categories, group, split."""
    if not {"text", "label"} <= set(raw.columns):
        raise DatasetError(f"Expected columns 'text' and 'label', got {list(raw.columns)}")
    keyer = keyer or GroupKeyer()
    frame = raw.dropna(subset=["text", "label"]).copy()
    frame["text"] = frame["text"].map(clean_text)
    frame = frame[frame["text"].str.len() > 0]
    frame["technique"] = frame["label"].map(technique_from_label)

    merged = (
        frame.groupby("text", sort=True)["technique"]
        .agg(lambda values: tuple(sorted(set(values))))
        .reset_index(name="techniques")
    )
    merged["categories"] = merged["techniques"].map(
        lambda ts: tuple(sorted(category_map.categorize(ts)))
    )
    merged["group"] = merged["text"].map(keyer.key)
    merged["split"] = merged["group"].map(assign_split)
    return merged[["text", "techniques", "categories", "group", "split"]]


PROCESSED_PATH = settings.data_dir / "processed" / "threat_categories.jsonl"


def load_processed(split: str, path: Path = PROCESSED_PATH) -> list[dict]:
    """Rows of one split from the processed JSONL (built by prepare_threat_dataset.py)."""
    if split not in SPLITS:
        raise DatasetError(f"Unknown split {split!r}")
    if not path.is_file():
        raise DatasetError(f"{path} not found. Run: python scripts/prepare_threat_dataset.py")
    with path.open(encoding="utf-8") as handle:
        rows = [row for row in map(json.loads, handle) if row["split"] == split]
    if not rows:
        raise DatasetError(f"No {split} rows in {path.name}")
    return rows


def dataset_statistics(dataset: pd.DataFrame, categories: Iterable[str]) -> dict:
    """Counts per split and category, plus multi-label and grouping figures."""
    labels = [*categories, OTHER]
    per_split = {}
    for split in SPLITS:
        part = dataset[dataset["split"] == split]
        per_split[split] = {
            "sentences": len(part),
            "groups": part["group"].nunique(),
            "categories": {c: int(part["categories"].map(lambda cs, c=c: c in cs).sum())
                           for c in labels},
        }
    splits_per_group = dataset.groupby("group")["split"].nunique()
    return {
        "sentences": len(dataset),
        "groups": dataset["group"].nunique(),
        "multi_technique_sentences": int((dataset["techniques"].map(len) > 1).sum()),
        "multi_category_sentences": int((dataset["categories"].map(len) > 1).sum()),
        "groups_in_multiple_splits": int((splits_per_group > 1).sum()),  # must be 0
        "largest_groups": dataset["group"].value_counts().head(10).to_dict(),
        "splits": per_split,
    }
