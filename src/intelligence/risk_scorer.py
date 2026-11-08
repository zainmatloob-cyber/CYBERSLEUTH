"""Explainable risk scoring: R = w_V·V + w_M·M + w_A·A + w_E·E (components on 0–100).

The weights, bands and every parameter come from ``config/risk_model.json``. They are
heuristics chosen by the project author, not cybersecurity standards.

Design rules:
* **Explain everything.** Each component returns its value, weighted contribution, the
  reasoning lines, and the evidence it used.
* **No inflation by volume.** V and A use the *maximum* plus a small capped breadth bonus.
  E uses *diversity* of IOC types, never counts. A report with 500 IPs is not riskier than
  one with 5.
* **No double counting.** CVE IDs and named vulnerabilities are already merged per CVE.
  Each ATT&CK technique counts once (its strongest evidence). Hashes add a fixed bonus.
* **Missing evidence** gives 0 for that component with the explanation "no evidence". Weights
  are not redistributed: a report without vulnerability evidence is less
  vulnerability-driven.
* **Confidence is separate from severity.** It reflects data quality (fallback modes, OCR
  gaps, very short text), not how dangerous the content is.
* **Analyst verdicts count.** A rejected mapping contributes nothing. An unverified model-only
  suggestion contributes nothing either (its factor is 0 since the real-world evaluation,
  see docs/evaluation/real_world_analysis.md). Once an analyst confirms it, it counts like an
  explicit match. :meth:`RiskScorer.rescore` recomputes a stored assessment after verdicts
  change.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from config.settings import PROJECT_ROOT, settings
from src.ingestion.models import ExtractedDocument
from src.intelligence.assertion import AssertionStatus
from src.intelligence.evidence_manager import VulnerabilityRecord
from src.intelligence.mitre_mapper import AnalystVerdict, MappingMethod, TechniqueMapping
from src.intelligence.threat_assessment import ThreatCategoryFinding
from src.nlp.entity_models import Entity, EntitySource, EntityType
from src.nlp.ioc_models import Indicator, IOCType
from src.utils.exceptions import CyberSleuthError

RISK_CONFIG_PATH = PROJECT_ROOT / "config" / "risk_model.json"
KEV_PATH = settings.knowledge_base_dir / "cisa_kev.json"
_HASH_TYPES = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}
COMPONENTS = ("vulnerability", "malware", "attack_behaviour", "evidence")
LABELS = {"vulnerability": "Vulnerability severity (V)", "malware": "Malware evidence (M)",
          "attack_behaviour": "Attack behaviour severity (A)", "evidence": "Evidence strength (E)"}
LIMITATIONS = (
    "Weights, bands and parameters are author-chosen heuristics, not an industry standard.",
    "The score reflects what the report describes, not the risk to a specific organisation.",
    "Model-suggested techniques and categories are unverified until an analyst confirms them.",
    "CVE severity uses CISA KEV membership only; CVSS scores are not used (offline).",
)


class RiskConfigError(CyberSleuthError):
    """The risk model configuration is invalid."""


@dataclass(frozen=True)
class RiskComponent:
    key: str
    label: str
    weight: float
    value: float  # 0–100
    explanation: tuple[str, ...]

    @property
    def contribution(self) -> float:
        return self.weight * self.value


@dataclass(frozen=True)
class Confidence:
    level: str  # high | medium | low
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    band: str
    components: tuple[RiskComponent, ...]
    confidence: Confidence
    config_version: str
    limitations: tuple[str, ...] = LIMITATIONS


def load_risk_config(path: Path = RISK_CONFIG_PATH) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RiskConfigError(f"Cannot load {path.name}: {exc}") from exc
    weights = config.get("weights", {})
    if set(weights) != set(COMPONENTS):
        raise RiskConfigError(f"Weights must be defined exactly for {COMPONENTS}")
    if any(not 0 <= w <= 1 for w in weights.values()) or abs(sum(weights.values()) - 1) > 1e-9:
        raise RiskConfigError("Weights must be between 0 and 1 and sum to 1.")
    mins = [band["min"] for band in config.get("bands", [])]
    if not mins or mins[0] != 0 or mins != sorted(set(mins)) or mins[-1] > 100:
        raise RiskConfigError("Bands must start at 0 and increase strictly up to 100.")
    return config


@lru_cache(maxsize=2)
def load_kev(path: Path = KEV_PATH) -> dict[str, dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))["vulnerabilities"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        raise RiskConfigError(f"Cannot load KEV snapshot {path.name}: {exc}") from exc


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


class RiskScorer:
    def __init__(self, config: dict | None = None, kev: dict[str, dict] | None = None) -> None:
        self.config = config or load_risk_config()
        self.kev = load_kev() if kev is None else kev

    # --- components -----------------------------------------------------------------

    def _vulnerability(self, records: Sequence[VulnerabilityRecord]) -> tuple[float, list[str]]:
        cfg = self.config["vulnerability"]
        if not records:
            return 0.0, ["No vulnerability evidence (no CVE IDs or named vulnerabilities)."]
        scored = []
        for record in records:
            kev = self.kev.get(record.cve_id)
            names = f" ({', '.join(record.names)})" if record.names else ""
            if kev and kev["ransomware_use"]:
                scored.append((cfg["known_exploited_ransomware"],
                               f"{record.cve_id}{names}: in CISA KEV with known ransomware use"))
            elif kev:
                scored.append((cfg["known_exploited"],
                               f"{record.cve_id}{names}: in CISA KEV (known exploited)"))
            elif record.names:
                scored.append((cfg["named_vulnerability"],
                               f"{record.cve_id}{names}: well-known named vulnerability"))
            else:
                scored.append((cfg["mentioned_cve"], f"{record.cve_id}: mentioned"))
        scored.sort(key=lambda item: -item[0])
        bonus = min(cfg["breadth_bonus_cap"],
                    cfg["breadth_bonus_per_extra_cve"] * (len(scored) - 1))
        lines = [f"{text} → {value}" for value, text in scored[:5]]
        if len(scored) > 5:
            lines.append(f"… and {len(scored) - 5} more CVEs")
        lines.append(f"Highest CVE score {scored[0][0]} + breadth bonus {bonus} "
                     f"({len(scored)} distinct CVEs, capped at {cfg['breadth_bonus_cap']}).")
        return _clamp(scored[0][0] + bonus), lines

    def _malware(self, entities: Sequence[Entity], indicators: Sequence[Indicator],
                 categories: Sequence[ThreatCategoryFinding]) -> tuple[float, list[str]]:
        cfg = self.config["malware"]
        malware = [e for e in entities if e.entity_type is EntityType.MALWARE]
        ransomware = next((c for c in categories if c.category == "ransomware" and c.asserted),
                          None)
        lines, value = [], 0.0
        if malware:
            known = [e.name for e in malware if e.source is EntitySource.ATTACK_KB]
            value = cfg["known_malware_family"] if known else cfg["malware_mentioned"]
            lines.append(f"Malware named: {', '.join(e.name for e in malware[:6])}"
                         + (f" (ATT&CK-known: {', '.join(known[:6])})" if known else "")
                         + f" → {value}")
        if ransomware:
            value = max(value, cfg["ransomware_evidence"])
            lines.append(f"Ransomware behaviour in {ransomware.sentence_count} non-negated "
                         f"sentence(s) via {'/'.join(ransomware.sources)} → "
                         f"{cfg['ransomware_evidence']}")
        hashes = sorted({i.ioc_type.value for i in indicators if i.ioc_type in _HASH_TYPES})
        if value and hashes:
            value += cfg["file_hash_bonus"]
            lines.append(f"File hashes present ({', '.join(hashes)}): +{cfg['file_hash_bonus']}")
        if not lines:
            lines.append("No malware evidence (no malware names or ransomware behaviour).")
        return _clamp(value), lines

    def _effective(self, mapping: TechniqueMapping) -> float:
        """Best status × method factor over a mapping's evidence.

        0 if every sentence is negated, if an analyst rejected the mapping, or if it is an
        unverified model-only suggestion (model factor 0).
        """
        if mapping.verdict is AnalystVerdict.REJECTED:
            return 0.0
        cfg = self.config["attack_behaviour"]
        confirmed = mapping.verdict is AnalystVerdict.CONFIRMED

        def method_factor(method: MappingMethod) -> float:
            if method is not MappingMethod.MODEL:
                return cfg["method_factor"]["explicit"]
            return cfg["method_factor"]["confirmed_model" if confirmed else "model"]

        return max(cfg["status_factor"][e.status.value] * method_factor(e.method)
                   for e in mapping.evidence)

    @staticmethod
    def _corroborated(mapping: TechniqueMapping) -> bool:
        return (mapping.explicit or mapping.verdict is AnalystVerdict.CONFIRMED
                or len({e.sentence_index for e in mapping.evidence}) >= 2)

    @staticmethod
    def _excluded_leads(mappings: Sequence[TechniqueMapping]) -> int:
        return sum(1 for m in mappings if m.is_unverified_lead and m.status.value != "negated")

    def _attack(self, mappings: Sequence[TechniqueMapping]) -> tuple[float, list[str]]:
        cfg = self.config["attack_behaviour"]
        severity = cfg["tactic_severity"]
        scored = []
        for mapping in mappings:
            factor = self._effective(mapping)
            if factor <= 0:
                continue
            tactic = max(mapping.tactics, key=lambda t: severity.get(t, 0), default=None)
            base = severity.get(tactic, 0) if tactic else 0
            scored.append((base * factor, mapping, tactic, factor))
        leads = self._excluded_leads(mappings)
        lead_line = (f"{leads} unverified model suggestion(s) excluded until an analyst "
                     "confirms them." if leads else None)
        if not scored:
            return 0.0, ["No scoring ATT&CK technique evidence (explicit, or confirmed by an "
                         "analyst).", *([lead_line] if lead_line else [])]
        scored.sort(key=lambda item: -item[0])
        # Kill-chain breadth counts only techniques that are explicit or supported by several
        # sentences: single unverified model suggestions must not inflate breadth.
        tactics = {t for _, m, _, _ in scored if self._corroborated(m) for t in m.tactics}
        bonus = min(cfg["breadth_bonus_cap"],
                    cfg["breadth_bonus_per_extra_tactic"] * max(0, len(tactics) - 1))
        lines = [f"{m.technique_id} {m.name} [{tactic}, factor {factor:.2f}] → {value:.0f}"
                 for value, m, tactic, factor in scored[:5]]
        lines.append(f"Highest technique score {scored[0][0]:.0f} + kill-chain breadth bonus "
                     f"{bonus} ({len(tactics)} tactics from explicit or multi-sentence "
                     f"techniques, capped at {cfg['breadth_bonus_cap']}).")
        if lead_line:
            lines.append(lead_line)
        return _clamp(scored[0][0] + bonus), lines

    def _evidence(self, mappings: Sequence[TechniqueMapping],
                  categories: Sequence[ThreatCategoryFinding],
                  indicators: Sequence[Indicator]) -> tuple[float, list[str]]:
        cfg = self.config["evidence"]
        active = [m for m in mappings if self._effective(m) > 0]
        corroborated = [m for m in active
                        if m.status is AssertionStatus.OBSERVED and self._corroborated(m)]
        share = len(corroborated) / len(active) if active else 0.0
        sentences = {e.sentence_index for m in active for e in m.evidence}
        sentences |= {e.sentence_index for c in categories if c.asserted for e in c.evidence
                      if e.status is not AssertionStatus.NEGATED}
        ioc_types = {i.ioc_type for i in indicators}
        parts = (
            cfg["corroborated_share_points"] * share,
            cfg["evidence_sentences_points"] * min(1.0, len(sentences)
                                                   / cfg["evidence_sentences_full_at"]),
            cfg["ioc_type_diversity_points"] * min(1.0, len(ioc_types)
                                                   / cfg["ioc_type_diversity_full_at"]),
        )
        lines = [
            f"{len(corroborated)}/{len(active)} techniques observed and explicit or "
            f"multi-sentence → {parts[0]:.1f}/{cfg['corroborated_share_points']}",
            f"{len(sentences)} distinct evidence sentences → {parts[1]:.1f}/"
            f"{cfg['evidence_sentences_points']}",
            f"{len(ioc_types)} IOC types "
            f"({', '.join(sorted(t.value for t in ioc_types)) or 'none'}) → {parts[2]:.1f}/"
            f"{cfg['ioc_type_diversity_points']} (types, not counts)",
        ]
        return _clamp(sum(parts)), lines

    # --- confidence -----------------------------------------------------------------

    def _confidence(self, document: ExtractedDocument, mappings: Sequence[TechniqueMapping],
                    components: Sequence[RiskComponent], degraded: Sequence[str]) -> Confidence:
        cfg = self.config["confidence"]
        reasons = list(degraded)
        if document.needs_ocr:
            reasons.append("Some pages are scanned images; their text was not analysed.")
        if len(document.sentences) < cfg["min_sentences"]:
            reasons.append(f"Very little text ({len(document.sentences)} sentences).")
        if all(c.value == 0 for c in components if c.key != "evidence"):
            return Confidence("low", (*reasons, "No substantive threat evidence was found."))
        level = "high" if not reasons else "medium" if len(reasons) <= 2 else "low"
        return Confidence(level, tuple(reasons) or ("No data-quality issues detected.",))

    # --- public -------------------------------------------------------------------

    def band(self, score: float) -> str:
        return [b["name"] for b in self.config["bands"] if score >= b["min"]][-1]

    def score(
        self, document: ExtractedDocument, indicators: Sequence[Indicator],
        entities: Sequence[Entity], vulnerabilities: Sequence[VulnerabilityRecord],
        mappings: Sequence[TechniqueMapping], categories: Sequence[ThreatCategoryFinding],
        degraded: Sequence[str] = (),
    ) -> RiskAssessment:
        components = self._components(indicators, entities, vulnerabilities, mappings,
                                      categories)
        return self._assessment(
            components, self._confidence(document, mappings, components, degraded))

    def rescore(
        self, previous: RiskAssessment, indicators: Sequence[Indicator],
        entities: Sequence[Entity], vulnerabilities: Sequence[VulnerabilityRecord],
        mappings: Sequence[TechniqueMapping], categories: Sequence[ThreatCategoryFinding],
    ) -> RiskAssessment:
        """Recompute severity after analyst verdicts change.

        Confidence is kept: it describes data quality, which a verdict does not change.
        """
        components = self._components(indicators, entities, vulnerabilities, mappings,
                                      categories)
        return self._assessment(components, previous.confidence)

    def _assessment(self, components: tuple[RiskComponent, ...],
                    confidence: Confidence) -> RiskAssessment:
        total = round(sum(c.contribution for c in components), 1)
        return RiskAssessment(score=total, band=self.band(total), components=components,
                              confidence=confidence, config_version=self.config["version"])

    def _components(
        self, indicators: Sequence[Indicator], entities: Sequence[Entity],
        vulnerabilities: Sequence[VulnerabilityRecord], mappings: Sequence[TechniqueMapping],
        categories: Sequence[ThreatCategoryFinding],
    ) -> tuple[RiskComponent, ...]:
        weights = self.config["weights"]
        values = {
            "vulnerability": self._vulnerability(vulnerabilities),
            "malware": self._malware(entities, indicators, categories),
            "attack_behaviour": self._attack(mappings),
            "evidence": self._evidence(mappings, categories, indicators),
        }
        return tuple(
            RiskComponent(key, LABELS[key], weights[key], round(values[key][0], 1),
                          tuple(values[key][1]))
            for key in COMPONENTS
        )
