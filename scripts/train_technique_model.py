"""Train and evaluate the ATT&CK technique model and the explicit technique matcher.

Usage:
    python scripts/train_technique_model.py           # model selection on val (test untouched)
    python scripts/train_technique_model.py --final   # train, score test ONCE, save

Protocol: train → fit; val → choose C (top-1 accuracy) and the abstention threshold (smallest
threshold whose val selective precision ≥ TARGET_PRECISION); test → final report.
Gold labels are v16 techniques translated to active v20.1 parent techniques.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402

from src.intelligence.assertion import assertion_status  # noqa: E402
from src.intelligence.attack_kb import default_technique_kb  # noqa: E402
from src.intelligence.mitre_mapper import (  # noqa: E402
    TECHNIQUE_MODEL_PATH,
    ExplicitTechniqueMatcher,
    TechniqueModel,
    load_term_technique_ids,
)
from src.ml.dataset import DATASET_REVISION, load_processed  # noqa: E402
from src.nlp.entity_extractor import EntityExtractor  # noqa: E402
from src.nlp.entity_models import EntityType  # noqa: E402
from src.utils.logging_config import configure_logging  # noqa: E402

REPORT_DIR = ROOT / "docs" / "evaluation"
# Log-spaced; widened once because the first optimum (C = 2) sat on the upper edge.
C_GRID = (0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0)
TARGET_PRECISION = 0.80  # fixed before looking at any results
BOOTSTRAP = 1000


def gold(rows: list[dict]) -> tuple[list[str], list[frozenset[str]], list[str]]:
    kb = default_technique_kb()
    texts, labels, groups = [], [], []
    for row in rows:
        parents = frozenset(p for t in row["techniques"] if (p := kb.parent(t)))
        if parents:
            texts.append(row["text"])
            labels.append(parents)
            groups.append(row["group"])
    return texts, labels, groups


def expand(texts: list[str], labels: list[frozenset[str]]) -> tuple[list[str], list[str]]:
    pairs = [(t, label) for t, ls in zip(texts, labels, strict=True) for label in sorted(ls)]
    return [p[0] for p in pairs], [p[1] for p in pairs]


def topk_hits(ranked: list[list[tuple[str, float]]], labels: list[frozenset[str]],
              k: int) -> np.ndarray:
    return np.array([any(t in gold_set for t, _ in r[:k]) for r, gold_set in
                     zip(ranked, labels, strict=True)])


def choose_threshold(top1_scores: np.ndarray, correct: np.ndarray) -> tuple[float, float, float]:
    """Smallest threshold with selective precision ≥ target (max coverage); else best precision."""
    candidates = np.unique(np.quantile(top1_scores, np.linspace(0, 0.99, 100)))
    best_fallback = (float(candidates[0]), -1.0, 0.0)
    for t in candidates:
        kept = top1_scores >= t
        if not kept.any():
            continue
        precision, coverage = float(correct[kept].mean()), float(kept.mean())
        if precision >= TARGET_PRECISION:
            return float(t), precision, coverage
        if precision > best_fallback[1]:
            best_fallback = (float(t), precision, coverage)
    return best_fallback


def group_bootstrap(groups: list[str], values: dict[str, np.ndarray],
                    kept: np.ndarray) -> dict[str, tuple[float, float]]:
    index: dict[str, list[int]] = {}
    for i, g in enumerate(groups):
        index.setdefault(g, []).append(i)
    rows = list(index.values())
    rng = np.random.default_rng(13)
    samples: dict[str, list[float]] = {k: [] for k in [*values, "selective_precision",
                                                        "coverage"]}
    for _ in range(BOOTSTRAP):
        pick = np.array([i for g in rng.integers(0, len(rows), len(rows)) for i in rows[g]])
        for name, v in values.items():
            samples[name].append(float(v[pick].mean()))
        k = kept[pick]
        samples["coverage"].append(float(k.mean()))
        if k.any():
            samples["selective_precision"].append(float(values["top1"][pick][k].mean()))
    return {k: (float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5)))
            for k, v in samples.items() if v}


def explicit_eval(texts: list[str], labels: list[frozenset[str]]) -> dict:
    kb = default_technique_kb()
    matcher = ExplicitTechniqueMatcher(kb)
    term_ids = load_term_technique_ids()
    entities = EntityExtractor(model=None)
    from src.ingestion.models import ExtractedDocument, FileType, PageText, Sentence

    predicted_pairs = correct_pairs = sentences_with_match = 0
    for text, gold_set in zip(texts, labels, strict=True):
        found = {kb.parent(t) for t, *_ in matcher.find(text)}
        doc = ExtractedDocument("s", FileType.TXT, "0" * 64, 1, [PageText(1, text)],
                                sentences=[Sentence(text, 1, 0, len(text))])
        for entity in entities.extract(doc):
            if entity.entity_type is EntityType.ATTACK_TECHNIQUE:
                found |= {kb.parent(t) for t in term_ids.get(entity.name, ())}
        found.discard(None)
        if found:
            sentences_with_match += 1
            predicted_pairs += len(found)
            correct_pairs += len(found & gold_set)
    return {"coverage": sentences_with_match / len(texts),
            "precision": correct_pairs / predicted_pairs if predicted_pairs else None,
            "predicted": predicted_pairs, "correct": correct_pairs}


def revision() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--final", action="store_true")
    args = parser.parse_args()
    configure_logging("WARNING")

    train_x, train_y, _ = gold(load_processed("train"))
    val_x, val_y, _ = gold(load_processed("val"))
    fit_x, fit_y = expand(train_x, train_y)
    print(f"train {len(train_x)} sentences / {len(set(fit_y))} parent techniques; "
          f"val {len(val_x)}")

    best = None
    for c in C_GRID:
        model = TechniqueModel(C=c).fit(fit_x, fit_y)
        top1 = topk_hits(model.top_k(val_x, 1), val_y, 1).mean()
        print(f"C={c:<5} val top-1 accuracy {top1:.3f}")
        if best is None or top1 > best[0]:
            best = (top1, c, model)
    _, best_c, model = best
    if best_c in (C_GRID[0], C_GRID[-1]):
        print(f"WARNING: selected C={best_c} is on the edge of the grid.")

    val_ranked = model.top_k(val_x, 5)
    val_scores = np.array([r[0][1] for r in val_ranked])
    val_correct = topk_hits(val_ranked, val_y, 1)
    threshold, val_precision, val_coverage = choose_threshold(val_scores, val_correct)
    model.threshold = threshold
    print(f"Selected C={best_c}; threshold {threshold:.3f} → val selective precision "
          f"{val_precision:.3f} at coverage {val_coverage:.3f}")

    if not args.final:
        print("Test split not touched. Re-run with --final to score it once.")
        return

    test_x, test_y, test_g = gold(load_processed("test"))
    ranked = model.top_k(test_x, 5)
    scores = np.array([r[0][1] for r in ranked])
    hits = {f"top{k}": topk_hits(ranked, test_y, k) for k in (1, 3, 5)}
    kept = scores >= threshold
    unseen = sum(1 for ls in test_y if not ls & set(model.classes))
    results = {
        "n": len(test_x),
        **{name: float(v.mean()) for name, v in hits.items()},
        "coverage": float(kept.mean()),
        "selective_precision": float(hits["top1"][kept].mean()) if kept.any() else None,
        "sentences_with_gold_technique_unseen_in_train": unseen,
        "ci95": group_bootstrap(test_g, hits, kept),
        "explicit": explicit_eval(test_x, test_y),
        "assertion_status": dict(Counter(assertion_status(t).value for t in test_x)),
    }
    model.save(TECHNIQUE_MODEL_PATH, dataset_revision=DATASET_REVISION, selected_C=str(best_c),
               code_revision=revision())
    meta = {"date": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"), "revision": revision(),
            "selected_C": best_c, "threshold": threshold, "target_precision": TARGET_PRECISION,
            "val": {"selective_precision": val_precision, "coverage": val_coverage},
            "classes": len(model.classes)}
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "technique_mapping_test.json").write_text(
        json.dumps({**meta, "test": results}, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({**meta, "test": results}, indent=1))
    print(f"Saved model to {TECHNIQUE_MODEL_PATH}")


if __name__ == "__main__":
    main()
