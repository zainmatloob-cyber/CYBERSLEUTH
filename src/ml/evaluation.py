"""Multi-label evaluation with group-level bootstrap confidence intervals.

* Per category: binary precision, recall and F1, using the same ``Counts`` as
  extraction evaluation (undefined values → ``None``).
* Macro F1 over the evaluated categories (categories with no support count as F1 0 if
  they were predicted, and are excluded if they have neither support nor predictions).
* Confusion matrix: every row has exactly one true category (multi-category rows are
  absent from this dataset). The prediction is reduced to one category, the
  highest-priority predicted label, so the matrix shows *which* categories get confused.
* Bootstrap: groups (actors/software) are resampled with replacement, not sentences,
  because sentences within a group are correlated.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

from src.evaluation.metrics import Counts
from src.ml.dataset import OTHER


def per_category_counts(
    truth: Sequence[frozenset[str]], predicted: Sequence[frozenset[str]],
    categories: Sequence[str],
) -> dict[str, Counts]:
    result = {}
    for category in categories:
        tp = sum(1 for t, p in zip(truth, predicted, strict=True)
                 if category in t and category in p)
        fp = sum(1 for t, p in zip(truth, predicted, strict=True)
                 if category not in t and category in p)
        fn = sum(1 for t, p in zip(truth, predicted, strict=True)
                 if category in t and category not in p)
        result[category] = Counts(tp, fp, fn)
    return result


def macro_f1(counts: dict[str, Counts]) -> float | None:
    values = [c.f1 if c.f1 is not None else 0.0
              for c in counts.values() if c.support or c.fp]
    return sum(values) / len(values) if values else None


def primary(labels: frozenset[str], order: Sequence[str]) -> str:
    """Reduce a label set to one label: first category in ``order``, else ``other``."""
    for category in order:
        if category in labels:
            return category
    return OTHER


def confusion(
    truth: Sequence[frozenset[str]], predicted: Sequence[frozenset[str]],
    order: Sequence[str],
) -> tuple[list[str], list[list[int]]]:
    labels = [*order, OTHER]
    index = {label: i for i, label in enumerate(labels)}
    matrix = [[0] * len(labels) for _ in labels]
    for t, p in zip(truth, predicted, strict=True):
        matrix[index[primary(t, order)]][index[primary(p, order)]] += 1
    return labels, matrix


def bootstrap_ci(
    truth: Sequence[frozenset[str]], predicted: Sequence[frozenset[str]],
    groups: Sequence[str], categories: Sequence[str],
    iterations: int = 1000, seed: int = 13, alpha: float = 0.05,
) -> dict[str, tuple[float, float]]:
    """Percentile CIs for per-category F1 and macro F1, resampling groups."""
    by_group: dict[str, list[int]] = {}
    for i, group in enumerate(groups):
        by_group.setdefault(group, []).append(i)
    group_rows = list(by_group.values())
    rng = np.random.default_rng(seed)
    samples: dict[str, list[float]] = {c: [] for c in [*categories, "macro_f1"]}

    for _ in range(iterations):
        chosen = rng.integers(0, len(group_rows), len(group_rows))
        rows = [i for g in chosen for i in group_rows[g]]
        counts = per_category_counts([truth[i] for i in rows], [predicted[i] for i in rows],
                                     categories)
        for category, c in counts.items():
            if c.support:  # F1 is only meaningful when the resample contains positives
                samples[category].append(c.f1 if c.f1 is not None else 0.0)
        macro = macro_f1(counts)
        if macro is not None:
            samples["macro_f1"].append(macro)

    low, high = 100 * alpha / 2, 100 * (1 - alpha / 2)
    return {k: (float(np.percentile(v, low)), float(np.percentile(v, high)))
            for k, v in samples.items() if v}


def evaluate(
    truth: Sequence[frozenset[str]], predicted: Sequence[frozenset[str]],
    groups: Sequence[str], categories: Sequence[str], bootstrap: int = 1000,
) -> dict:
    counts = per_category_counts(truth, predicted, categories)
    labels, matrix = confusion(truth, predicted, categories)
    exact = sum(1 for t, p in zip(truth, predicted, strict=True) if t == p) / len(truth)
    return {
        "n": len(truth),
        "per_category": {c: counts[c].as_dict() for c in categories},
        "macro_f1": macro_f1(counts),
        "exact_match": exact,
        "confusion": {"labels": labels, "matrix": matrix},
        "ci95": bootstrap_ci(truth, predicted, groups, categories, bootstrap) if bootstrap else {},
    }
