"""Rule-based threat-category baseline.

Transparent keyword rules for every category, including two the ML model cannot
learn from the training data: ``ddos`` (too few examples) and ``malware`` (not
derivable per sentence). Every prediction carries the exact terms that triggered it.

The rules were written from domain knowledge before looking at the dataset, and are
assessed on the validation split only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.ml.dataset import OTHER

# Word-boundary patterns; matched case-insensitively.
RULES: dict[str, tuple[str, ...]] = {
    "phishing": (
        r"phish\w*", r"spear[- ]?phish\w*", r"malicious (?:e-?mail|attachment|link)s?",
        r"lure (?:document|e-?mail)s?", r"e-?mail attachments?", r"smishing", r"vishing",
    ),
    "ransomware": (
        r"ransom\w*", r"encrypt(?:s|ed|ing)? (?:the )?(?:victim'?s? )?files", r"file encryption",
        r"shadow cop(?:y|ies)", r"vssadmin", r"decrypt(?:or|ion key)s?", r"double extortion",
    ),
    "vulnerability_exploitation": (
        r"exploit(?:s|ed|ing|ation)?", r"CVE-\d{4}-\d{4,7}", r"vulnerabilit(?:y|ies)",
        r"zero[- ]day", r"0-day", r"remote code execution", r"buffer overflow",
    ),
    "credential_theft": (
        r"credentials?", r"passwords?", r"mimikatz", r"lsass", r"keylog\w*", r"brute[- ]?forc\w*",
        r"password spray\w*", r"kerberoast\w*", r"hash(?:es)? dump\w*", r"NTLM hash\w*",
        r"SAM (?:database|hive)", r"session cookies?", r"access tokens?",
    ),
    "data_breach": (
        r"exfiltrat\w*", r"data leak\w*", r"leak site", r"stolen data", r"data theft",
        r"(?:upload|transferr?)(?:s|ed|ing)? (?:the )?(?:stolen|collected|harvested)"
        r" (?:data|files)",
    ),
    "ddos": (
        r"d?dos attacks?", r"ddos", r"denial[- ]of[- ]service", r"(?:syn|udp|http) flood\w*",
        r"flooding attacks?",
    ),
    "malware": (
        r"malware", r"trojan\w*", r"backdoors?", r"\bRATs?\b", r"loaders?", r"droppers?",
        r"implants?", r"worms?", r"infostealers?", r"stealers?", r"botnets?", r"rootkits?",
    ),
}

_COMPILED = {
    category: re.compile("|".join(rf"(?<![\w-])(?:{p})(?![\w-])" for p in patterns),
                         re.IGNORECASE)
    for category, patterns in RULES.items()
}


@dataclass(frozen=True)
class RulePrediction:
    categories: frozenset[str]
    evidence: dict[str, tuple[str, ...]]  # category → matched terms (as written)


class RuleBasedClassifier:
    """Deterministic keyword classifier. Not trained, so it has no confidence scores."""

    categories: tuple[str, ...] = tuple(RULES)

    def explain(self, text: str) -> RulePrediction:
        evidence = {}
        for category, pattern in _COMPILED.items():
            hits = tuple(dict.fromkeys(m.group(0) for m in pattern.finditer(text)))
            if hits:
                evidence[category] = hits
        categories = frozenset(evidence) or frozenset({OTHER})
        return RulePrediction(categories, evidence)

    def predict(self, texts: list[str]) -> list[frozenset[str]]:
        return [self.explain(text).categories for text in texts]
