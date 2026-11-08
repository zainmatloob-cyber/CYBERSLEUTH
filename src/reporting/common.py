"""Shared helpers for report exports (JSON, CSV, PDF).

Report safety rules, applied by every exporter:

* **Defanged output.** Network indicators (URLs, domains, IPv4, e-mail) are written in
  defanged form (``hxxps://evil[.]example/``) in human-facing reports, and evidence
  sentences are defanged the same way, so a report can't be clicked through to
  attacker infrastructure. The JSON export also carries the canonical value
  (``value``) for machine ingestion, clearly separated from ``value_defanged``.
* **No live links except references.** The only URLs written as URLs are ATT&CK and
  NVD reference pages, which are validated against fixed patterns.
* **CSV formula injection.** A cell that starts with ``= + - @`` (or a tab/CR) is
  prefixed with ``'`` so spreadsheet software treats it as text, not a formula.
* **Privacy.** Reports contain findings and their evidence sentences, never the full
  document text.
* **No verdicts invented.** Indicators and mappings carry the analyst verdict as stored
  ("unverified" unless an analyst changed it).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime

from src.database.views import StoredAnalysis
from src.nlp.ioc_models import Indicator, IOCType
from src.visualization.aggregations import category_label

REPORT_SCHEMA_VERSION = "1.1"
GENERATOR = "CyberSleuth"

_NETWORK_TYPES = {IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.EMAIL}
_SCHEME_RE = re.compile(r"^(https?|ftp)://", re.IGNORECASE)
_SCHEME_DEFANG = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

REPORT_LIMITATIONS = (
    "This report was produced automatically. Every finding is a lead for an analyst to "
    "check, not a conclusion.",
    "Extracted indicators are not classified as malicious. Their verification status is "
    "the analyst verdict recorded in CyberSleuth (\"unverified\" unless changed).",
    "Indicators were not contacted, resolved or enriched; flags such as "
    "\"documentation_range\" describe the value, not its maliciousness.",
    "Model-suggested ATT&CK techniques and threat categories have a measured error rate on "
    "the project's held-out test split (see docs/models); their false-positive rate on "
    "real-world reports has not been measured.",
    "Entity recognition was evaluated on a small synthetic, author-annotated corpus; "
    "results on real reports may be lower.",
    "Assertion status (observed / capability / possible / negated) comes from a rule-based "
    "cue detector and can be wrong for complex sentences.",
)


def generated_at() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# --- defanging ----------------------------------------------------------------------


def defang(ioc_type: IOCType, value: str) -> str:
    """Defanged form of a canonical indicator value. Hashes and CVE ids are unchanged."""
    if ioc_type not in _NETWORK_TYPES:
        return value
    if ioc_type is IOCType.URL:
        match = _SCHEME_RE.match(value)
        scheme, rest = (match.group(1), value[match.end():]) if match else ("", value)
        host, sep, path = rest.partition("/")
        defanged = host.replace(".", "[.]") + sep + path
        if scheme:
            return f"{_SCHEME_DEFANG[scheme.lower()]}://{defanged}"
        return defanged
    if ioc_type is IOCType.EMAIL:
        local, _, domain = value.rpartition("@")
        return f"{local}[@]{domain.replace('.', '[.]')}"
    return value.replace(".", "[.]")


class TextDefanger:
    """Defangs the analysis' own network indicators wherever they appear in a sentence.

    Rather than guessing at arbitrary text, it replaces the exact surface forms the
    extractor found (each occurrence's ``raw`` text and the canonical value), longest
    first, so overlapping forms (a domain inside a URL) are handled correctly.
    """

    def __init__(self, indicators: Iterable[Indicator]) -> None:
        replacements: dict[str, str] = {}
        for indicator in indicators:
            if indicator.ioc_type not in _NETWORK_TYPES:
                continue
            target = defang(indicator.ioc_type, indicator.value)
            replacements.setdefault(indicator.value, target)
            for occurrence in indicator.occurrences:
                if not occurrence.defanged:
                    replacements.setdefault(occurrence.raw, target)
        self._replacements = replacements
        forms = sorted(replacements, key=len, reverse=True)
        self._pattern = (re.compile("|".join(map(re.escape, forms)), re.IGNORECASE)
                         if forms else None)
        self._lookup = {k.lower(): v for k, v in replacements.items()}

    def __call__(self, text: str) -> str:
        if not self._pattern or not text:
            return text
        return self._pattern.sub(lambda m: self._lookup[m.group(0).lower()], text)


# --- CSV safety ---------------------------------------------------------------------


def csv_safe(value: object) -> object:
    """Neutralise spreadsheet formula injection in a single cell (strings only)."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


# --- small shared facts ---------------------------------------------------------------


def report_stem(view: StoredAnalysis) -> str:
    """Safe download filename stem: no path separators or shell-special characters."""
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", view.filename.rsplit(".", 1)[0]).strip("_")
    suffix = f"_{view.analysis_id}" if view.analysis_id else ""
    return f"cybersleuth_{stem[:40] or 'document'}{suffix}"


def executive_summary(view: StoredAnalysis) -> list[str]:
    """Deterministic, template-based summary sentences. Nothing here is generated freely."""
    risk = view.risk
    lines = [
        f"Risk score {risk.score:.1f}/100 ({risk.band}), confidence {risk.confidence.level}. "
        "Severity and confidence are assessed separately.",
        f"{len(view.indicators)} unique indicators, {len(view.entities)} entities, "
        f"{len(view.mappings)} ATT&CK techniques and {len(view.categories)} threat categories "
        f"were extracted from {view.page_count} page(s).",
    ]
    asserted = [c for c in view.categories if c.asserted]
    if asserted:
        lines.append("Threat categories with non-negated evidence: "
                     + ", ".join(category_label(c.category) for c in asserted) + ".")
    explicit = [m for m in view.mappings if m.explicit and m.status.value != "negated"]
    if explicit:
        shown = ", ".join(f"{m.technique_id} {m.name}" for m in explicit[:5])
        more = f" and {len(explicit) - 5} more" if len(explicit) > 5 else ""
        lines.append(f"Techniques named explicitly in the text: {shown}{more}.")
    leads = [m for m in view.mappings if m.is_unverified_lead]
    if leads:
        lines.append(f"{len(leads)} technique(s) were suggested by the model only. They are "
                     "unverified leads, listed separately and excluded from the risk score "
                     "until an analyst confirms them.")
    verified = sum(1 for i in view.indicators if i.verification.value != "unverified")
    reviewed = sum(1 for m in view.mappings if m.verdict.value != "unverified")
    lines.append(f"Analyst review so far: {verified} of {len(view.indicators)} indicators and "
                 f"{reviewed} of {len(view.mappings)} techniques have a verdict.")
    return lines
