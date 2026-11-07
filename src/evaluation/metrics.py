"""Set-based precision / recall / F1.

Undefined values are reported as ``None`` rather than 0 or 1. With no predictions,
precision is undefined. Reporting 0 would hide that, and reporting 1 would flatter it.
"""

from __future__ import annotations

from collections.abc import Hashable, Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def __add__(self, other: Counts) -> Counts:
        return Counts(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    @property
    def support(self) -> int:
        """Number of gold items."""
        return self.tp + self.fn

    @property
    def precision(self) -> float | None:
        predicted = self.tp + self.fp
        return self.tp / predicted if predicted else None

    @property
    def recall(self) -> float | None:
        return self.tp / self.support if self.support else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None:
            return None
        return 0.0 if p + r == 0 else 2 * p * r / (p + r)

    def as_dict(self) -> dict[str, float | int | None]:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "support": self.support,
                "precision": self.precision, "recall": self.recall, "f1": self.f1}


def score(gold: Iterable[Hashable], predicted: Iterable[Hashable]) -> Counts:
    gold_set, predicted_set = set(gold), set(predicted)
    return Counts(
        tp=len(gold_set & predicted_set),
        fp=len(predicted_set - gold_set),
        fn=len(gold_set - predicted_set),
    )


def micro(counts: Iterable[Counts]) -> Counts:
    total = Counts()
    for c in counts:
        total = total + c
    return total


def macro_f1(per_type: dict[str, Counts]) -> float | None:
    """Unweighted mean F1 over types that have gold support (rare types count equally)."""
    values = [c.f1 for c in per_type.values() if c.support and c.f1 is not None]
    return sum(values) / len(values) if values else None
