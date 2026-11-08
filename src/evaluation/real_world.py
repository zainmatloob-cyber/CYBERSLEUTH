"""Real-world evaluation against public CISA advisories.

Gold labels come from CISA, not from the project author:

* **Techniques**: every ATT&CK technique ID the advisory cites (in the narrative and in its
  ATT&CK appendix tables), resolved to ATT&CK v20.1 (revoked IDs follow ``revoked_by``).
  IDs that no longer resolve are reported, not silently dropped.
* **Indicators**: the values in CISA's own STIX 2.1 bundle for the advisory.

Two conditions:

* **As published.** The advisory is analysed as-is. Explicit-ID matches are close to
  tautological here (CISA prints the IDs), so predictions are broken down by how they were
  found, and the interesting figure is how often *non-ID* predictions (names, terms, model)
  agree with CISA's list.
* **IDs masked.** Every ``Txxxx(.yyy)`` / ``TAxxxx`` string is removed before analysis. This
  measures what the name/term matcher and the model recover without the answer key.
  Technique *names* in CISA's tables remain, which is stated in the report.

"Not cited by CISA" does not prove a prediction wrong: advisories don't list every
behaviour they describe. Those figures are labelled agreement, not precision.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from src.evaluation.metrics import Counts, score
from src.intelligence.attack_kb import TechniqueKB
from src.intelligence.mitre_mapper import MappingMethod, TechniqueMapping
from src.nlp.ioc_models import Indicator, IOCType

TECHNIQUE_ID_RE = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![0-9])")
MASK_RE = re.compile(r"(?<![A-Za-z0-9])(?:TA\d{4}|T\d{4}(?:\.\d{3})?)(?![0-9])")
COMPARED_IOC_TYPES = (IOCType.IPV4, IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL, IOCType.MD5,
                      IOCType.SHA1, IOCType.SHA256)

_PATTERN_RULES = (
    (re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'"), None),
    (re.compile(r"domain-name:value\s*=\s*'([^']+)'"), IOCType.DOMAIN),
    (re.compile(r"url:value\s*=\s*'([^']+)'"), IOCType.URL),
    (re.compile(r"email-addr:value\s*=\s*'([^']+)'"), IOCType.EMAIL),
    (re.compile(r"hashes\.'?(MD5|SHA-1|SHA-256|SHA1|SHA256)'?\s*=\s*'([^']+)'", re.I), "hash"),
)
_HASH_TYPES = {"md5": IOCType.MD5, "sha-1": IOCType.SHA1, "sha1": IOCType.SHA1,
               "sha-256": IOCType.SHA256, "sha256": IOCType.SHA256}
_SCO_TYPES = {"ipv4-addr": None, "domain-name": IOCType.DOMAIN, "url": IOCType.URL,
              "email-addr": IOCType.EMAIL}


# --- gold: techniques ----------------------------------------------------------------


@dataclass
class CitedTechniques:
    resolved: set[str] = field(default_factory=set)  # v20.1 IDs
    unresolved: list[str] = field(default_factory=list)  # cited IDs absent from v20.1
    translated: dict[str, str] = field(default_factory=dict)  # revoked/deprecated → current


def cited_techniques(text: str, kb: TechniqueKB) -> CitedTechniques:
    cited = CitedTechniques()
    for raw in sorted(set(TECHNIQUE_ID_RE.findall(text))):
        current = kb.resolve(raw)
        if current is None:
            cited.unresolved.append(raw)
            continue
        cited.resolved.add(current)
        if current != raw:
            cited.translated[raw] = current
    return cited


def mask_technique_ids(text: str) -> str:
    return MASK_RE.sub("", text)


def parents(ids: Iterable[str], kb: TechniqueKB) -> set[str]:
    return {kb.parent(i) or i.split(".")[0] for i in ids}


# --- predictions -----------------------------------------------------------------------


def prediction_group(mapping: TechniqueMapping) -> str:
    """How a technique was found: by its ID, by name/term only, or by the model only."""
    methods = {e.method for e in mapping.evidence}
    if MappingMethod.EXPLICIT_ID in methods:
        return "id"
    if methods & {MappingMethod.EXPLICIT_NAME, MappingMethod.EXPLICIT_TERM}:
        return "name_or_term"
    return "model_only"


def asserted(mappings: Iterable[TechniqueMapping]) -> list[TechniqueMapping]:
    """Mappings the system presents as present (negated ones are excluded)."""
    return [m for m in mappings if m.status.value != "negated"]


@dataclass
class GroupAgreement:
    predicted: int = 0
    cited_exact: int = 0
    cited_parent: int = 0

    def as_dict(self) -> dict[str, float | int | None]:
        def rate(n: int) -> float | None:
            return None if not self.predicted else round(n / self.predicted, 4)
        return {"predicted": self.predicted, "cited_exact": self.cited_exact,
                "cited_parent": self.cited_parent, "agreement_exact": rate(self.cited_exact),
                "agreement_parent": rate(self.cited_parent)}


def group_agreement(mappings: Iterable[TechniqueMapping], gold: set[str],
                    kb: TechniqueKB) -> dict[str, GroupAgreement]:
    gold_parents = parents(gold, kb)
    groups = {g: GroupAgreement() for g in ("id", "name_or_term", "model_only")}
    for mapping in asserted(mappings):
        group = groups[prediction_group(mapping)]
        group.predicted += 1
        group.cited_exact += mapping.technique_id in gold
        group.cited_parent += (kb.parent(mapping.technique_id) or mapping.technique_id) \
            in gold_parents
    return groups


def technique_counts(mappings: Iterable[TechniqueMapping], gold: set[str],
                     kb: TechniqueKB, groups: set[str] | None = None) -> dict[str, Counts]:
    """Set-based counts at exact and parent level, optionally for some groups only."""
    predicted = {m.technique_id for m in asserted(mappings)
                 if groups is None or prediction_group(m) in groups}
    return {"exact": score(gold, predicted),
            "parent": score(parents(gold, kb), parents(predicted, kb))}


# --- gold: indicators (STIX) ---------------------------------------------------------------


def _ip_or_none(value: str) -> IOCType | None:
    import ipaddress
    try:
        return IOCType.IPV4 if ipaddress.ip_address(value).version == 4 else None
    except ValueError:
        return None


def normalise(ioc_type: IOCType, value: str) -> str:
    """Comparison form: case-folded (URL paths too, a documented simplification)."""
    value = value.strip()
    if ioc_type is IOCType.URL:
        return value.lower().rstrip("/")
    return value.lower().rstrip(".")


def stix_indicators(bundle: dict) -> dict[IOCType, set[str]]:
    """Indicator values from STIX 2.x indicator patterns and cyber-observable objects."""
    found: dict[IOCType, set[str]] = {t: set() for t in COMPARED_IOC_TYPES}

    def add(ioc_type: IOCType | None, value: str) -> None:
        if ioc_type is None:  # ipv4-addr may hold a CIDR range; keep single addresses only
            ioc_type = _ip_or_none(value)
        if ioc_type in found:
            found[ioc_type].add(normalise(ioc_type, value))

    for obj in bundle.get("objects", []):
        kind = obj.get("type")
        if kind == "indicator":
            pattern = obj.get("pattern", "")
            for regex, ioc_type in _PATTERN_RULES:
                for match in regex.finditer(pattern):
                    if ioc_type == "hash":
                        add(_HASH_TYPES[match.group(1).lower()], match.group(2))
                    else:
                        add(ioc_type, match.group(1))
        elif kind in _SCO_TYPES and "value" in obj:
            add(_SCO_TYPES[kind], obj["value"])
        elif kind == "file":
            for name, value in obj.get("hashes", {}).items():
                if name.lower() in _HASH_TYPES:
                    add(_HASH_TYPES[name.lower()], value)
    return found


def extracted_indicators(indicators: Iterable[Indicator]) -> dict[IOCType, set[str]]:
    found: dict[IOCType, set[str]] = {t: set() for t in COMPARED_IOC_TYPES}
    for indicator in indicators:
        if indicator.ioc_type in found:
            found[indicator.ioc_type].add(normalise(indicator.ioc_type, indicator.value))
    return found


@dataclass
class IOCAgreement:
    """Agreement between extracted indicators and CISA's STIX bundle, per type.

    ``in_text`` counts STIX values whose literal (refanged) form appears in the document, so
    recall can be reported both against all STIX values and against the printed ones.
    """

    extracted: int = 0
    stix: int = 0
    in_text: int = 0
    matched: int = 0  # extracted ∩ STIX

    def as_dict(self) -> dict[str, float | int | None]:
        def rate(n: int, d: int) -> float | None:
            return None if not d else round(n / d, 4)
        return {"extracted": self.extracted, "stix": self.stix, "stix_in_text": self.in_text,
                "matched": self.matched,
                "extracted_in_stix": rate(self.matched, self.extracted),
                "stix_found": rate(self.matched, self.stix),
                "printed_stix_found": rate(self.matched, self.in_text)}


_TEXT_REFANG = (
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\bhxxp", re.IGNORECASE), "http"),
    (re.compile(r"\bfxp", re.IGNORECASE), "ftp"),
)


def refang_text(text: str) -> str:
    """Refang a whole document (used only to check whether a STIX value is printed)."""
    for pattern, replacement in _TEXT_REFANG:
        text = pattern.sub(replacement, text)
    return text


def ioc_agreement(extracted: dict[IOCType, set[str]], stix: dict[IOCType, set[str]],
                  refanged_text: str) -> dict[str, IOCAgreement]:
    text = refanged_text.lower()
    result = {}
    for ioc_type in COMPARED_IOC_TYPES:
        ours, theirs = extracted[ioc_type], stix[ioc_type]
        if not ours and not theirs:
            continue
        result[ioc_type.value] = IOCAgreement(
            extracted=len(ours), stix=len(theirs),
            in_text=sum(1 for v in theirs if v in text),
            matched=len(ours & theirs))
    return result
