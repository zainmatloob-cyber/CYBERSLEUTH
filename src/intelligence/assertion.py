"""Assertion status: does a sentence report that a behaviour *happened*?

A NegEx-style heuristic over cue phrases near the mention, within the same clause:

* ``negated``     "Phishing was **not** involved", "**no evidence** of lateral movement"
* ``possible``    hedges and advice: "**may** have used", "defenders **should** block"
* ``capability``  "X **can** dump credentials", "has the **ability to**" (not observed use)
* ``observed``    everything else ("X used / has used / exfiltrated …")

Priority when several apply: negated > possible > capability > observed.
This is a transparent heuristic; it is unit-tested but has no annotated evaluation set.
"""

from __future__ import annotations

import re
from enum import StrEnum


class AssertionStatus(StrEnum):
    OBSERVED = "observed"
    CAPABILITY = "capability"
    POSSIBLE = "possible"
    NEGATED = "negated"


# Strength order for aggregating several evidence sentences (best first).
STATUS_RANK = {AssertionStatus.OBSERVED: 0, AssertionStatus.CAPABILITY: 1,
               AssertionStatus.POSSIBLE: 2, AssertionStatus.NEGATED: 3}

_NEGATION = re.compile(
    # "without" is deliberately absent: "executed without user interaction" is not a negation.
    r"\b(?:not|never|no|none of|neither|nor"
    r"|did not|does not|do not|was not|were not|is not|are not|has not|have not"
    r"|didn't|doesn't|wasn't|weren't|isn't|aren't|hasn't|haven't|ruled out|unrelated)\b",
    re.IGNORECASE,
)
_HEDGE = re.compile(
    r"\b(?:may|might|could|possibly|possible|potentially|potential|likely|suspected"
    r"|appears? to|believed to|should|recommend\w*|consider|mitigat\w*|prevent\w*"
    r"|if an? attackers?|in order to detect)\b",
    re.IGNORECASE,
)
_CAPABILITY = re.compile(
    r"\b(?:can|is able to|are able to|capable of|has the ability to|have the ability to"
    r"|ability to|supports?|is designed to|contains functionality)\b",
    re.IGNORECASE,
)
_CLAUSE_BREAK = re.compile(r"[;:]|\bbut\b|\bhowever\b|\bwhereas\b|\balthough\b", re.IGNORECASE)
WINDOW = 80  # characters on each side of the mention


def _clause(sentence: str, start: int, end: int) -> str:
    """The text around [start, end) that lies in the same clause, within ``WINDOW``."""
    left = sentence[max(0, start - WINDOW):start]
    right = sentence[end:end + WINDOW]
    breaks = list(_CLAUSE_BREAK.finditer(left))
    if breaks:
        left = left[breaks[-1].end():]
    first = _CLAUSE_BREAK.search(right)
    if first:
        right = right[: first.start()]
    return f"{left} {sentence[start:end]} {right}"


def assertion_status(sentence: str, start: int = 0, end: int | None = None) -> AssertionStatus:
    """Status of the mention at ``sentence[start:end]`` (the whole sentence by default)."""
    end = len(sentence) if end is None else end
    scope = _clause(sentence, start, end)
    if _NEGATION.search(scope):
        return AssertionStatus.NEGATED
    if _HEDGE.search(scope):
        return AssertionStatus.POSSIBLE
    if _CAPABILITY.search(scope):
        return AssertionStatus.CAPABILITY
    return AssertionStatus.OBSERVED
