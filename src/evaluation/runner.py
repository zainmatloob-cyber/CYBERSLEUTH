"""Evaluate IOC and entity extraction against hand-annotated gold files.

A split directory contains ``<name>.txt`` documents and ``<name>.gold.json`` labels
(see data/evaluation/ANNOTATION_GUIDELINES.md). Matching is exact on canonical values:
* IOCs: the refanged, normalised value (e.g. ``http://evil.example.com/x``).
* Entities: case-insensitive, whitespace-collapsed, ignoring a leading "the".
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from src.evaluation.metrics import Counts, macro_f1, micro, score
from src.intelligence.analyzer import Analyzer
from src.nlp.entity_models import EntityType
from src.nlp.ioc_models import IOCType
from src.utils.exceptions import CyberSleuthError

TASKS = ("iocs", "entities")
_VALID_TYPES = {"iocs": {t.value for t in IOCType}, "entities": {t.value for t in EntityType}}
_LEADING_THE = re.compile(r"^the\s+", re.IGNORECASE)


class GoldFileError(CyberSleuthError):
    """A gold annotation file is malformed."""


def normalise(task: str, value: str) -> str:
    if task == "iocs":
        return value
    return _LEADING_THE.sub("", " ".join(value.split())).casefold()


@dataclass
class GoldDocument:
    path: Path
    labels: dict[str, set[tuple[str, str]]]  # task → {(type, normalised value)}
    display: dict[tuple[str, str, str], str]  # (task, type, normalised) → value as annotated


def load_gold(gold_path: Path) -> GoldDocument:
    try:
        data = json.loads(gold_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldFileError(f"{gold_path.name}: {exc}") from exc
    document = gold_path.with_name(data.get("document", ""))
    if not document.is_file():
        raise GoldFileError(f"{gold_path.name}: document {data.get('document')!r} not found")

    labels: dict[str, set[tuple[str, str]]] = {}
    display: dict[tuple[str, str, str], str] = {}
    for task in TASKS:
        labels[task] = set()
        for item in data.get(task, []):
            kind, value = item.get("type"), item.get("value")
            if kind not in _VALID_TYPES[task] or not isinstance(value, str) or not value:
                raise GoldFileError(f"{gold_path.name}: invalid {task} label {item!r}")
            key = (kind, normalise(task, value))
            if key in labels[task]:
                raise GoldFileError(f"{gold_path.name}: duplicate {task} label {item!r}")
            labels[task].add(key)
            display[(task, *key)] = value
    return GoldDocument(document, labels, display)


@dataclass
class EvaluationReport:
    split: str
    mode: str
    documents: list[str] = field(default_factory=list)
    per_type: dict[str, dict[str, Counts]] = field(default_factory=dict)
    errors: list[dict[str, str]] = field(default_factory=list)

    def overall(self, task: str) -> Counts:
        return micro(self.per_type.get(task, {}).values())

    def as_dict(self) -> dict:
        return {
            "split": self.split,
            "mode": self.mode,
            "documents": self.documents,
            "tasks": {
                task: {
                    "micro": self.overall(task).as_dict(),
                    "macro_f1": macro_f1(self.per_type.get(task, {})),
                    "per_type": {t: c.as_dict() for t, c in sorted(self.per_type[task].items())},
                }
                for task in TASKS
            },
            "errors": self.errors,
        }


def evaluate_split(split_dir: Path, analyzer: Analyzer, mode: str) -> EvaluationReport:
    gold_files = sorted(split_dir.glob("*.gold.json"))
    if not gold_files:
        raise GoldFileError(f"No *.gold.json files in {split_dir}")

    report = EvaluationReport(split=split_dir.name, mode=mode)
    counts: dict[str, dict[str, Counts]] = {task: defaultdict(Counts) for task in TASKS}

    for gold_path in gold_files:
        gold = load_gold(gold_path)
        result = analyzer.analyze(gold.path.read_bytes(), gold.path.name)
        report.documents.append(gold.path.name)
        predicted = {
            "iocs": {(i.ioc_type.value, normalise("iocs", i.value)) for i in result.indicators},
            "entities": {(e.entity_type.value, normalise("entities", e.name))
                         for e in result.entities},
        }
        shown = {("entities", e.entity_type.value, normalise("entities", e.name)): e.name
                 for e in result.entities}

        for task in TASKS:
            types = {t for t, _ in gold.labels[task] | predicted[task]}
            for kind in types:
                g = {v for t, v in gold.labels[task] if t == kind}
                p = {v for t, v in predicted[task] if t == kind}
                counts[task][kind] = counts[task][kind] + score(g, p)
                for value in sorted(p - g):
                    report.errors.append({"document": gold.path.name, "task": task,
                                          "type": kind, "error": "false_positive",
                                          "value": shown.get((task, kind, value), value)})
                for value in sorted(g - p):
                    report.errors.append({"document": gold.path.name, "task": task,
                                          "type": kind, "error": "false_negative",
                                          "value": gold.display[(task, kind, value)]})

    report.per_type = {task: dict(c) for task, c in counts.items()}
    return report
