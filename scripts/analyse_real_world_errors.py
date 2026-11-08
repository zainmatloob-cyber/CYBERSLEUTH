"""Error analysis for the real-world (CISA) evaluation. Read-only: it changes nothing.

Usage:  python scripts/analyse_real_world_errors.py

Prints the most frequent model-only technique suggestions, agreement with CISA by model
score band, the most common name/term-only matches, and indicator misses/extras versus
CISA's STIX. Findings are written up in docs/evaluation/real_world_analysis.md. Nothing
here is used to tune the system: the real-world set is a test set.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.evaluation import real_world as rw  # noqa: E402
from src.intelligence.analyzer import Analyzer  # noqa: E402
from src.intelligence.attack_kb import default_technique_kb  # noqa: E402

BANDS = ((float("-inf"), 0.25), (0.25, 0.5), (0.5, 0.75), (0.75, float("inf")))


def main() -> None:
    kb, analyzer = default_technique_kb(), Analyzer()
    gold = json.loads((ROOT / "data" / "real_world" / "gold.json").read_text())
    raw = ROOT / "data" / "raw" / "cisa"
    model_tech: collections.Counter = collections.Counter()
    name_only: collections.Counter = collections.Counter()
    scored: list[tuple[float, bool]] = []
    missed, extra = collections.defaultdict(list), collections.defaultdict(list)
    for doc_id, entry in gold["documents"].items():
        result = analyzer.analyze((raw / f"{doc_id}.pdf").read_bytes(), f"{doc_id}.pdf")
        truth = rw.parents(entry["techniques"], kb)
        if truth:  # same rule as the evaluation: no ATT&CK section, no technique scoring
            for m in rw.asserted(result.mappings):
                group = rw.prediction_group(m)
                if group == "model_only":
                    ok = (kb.parent(m.technique_id) or m.technique_id) in truth
                    model_tech[(m.technique_id, m.name, ok)] += 1
                    scored.append((m.max_score, ok))
                elif group == "name_or_term":
                    terms = sorted({e.matched_text for e in m.evidence if e.matched_text})
                    name_only[(m.technique_id, m.name, tuple(terms[:2]))] += 1
        if "stix" in entry:
            text = rw.refang_text("\n\n".join(p.text for p in result.document.pages)).lower()
            ours = rw.extracted_indicators(result.indicators)
            for t in ("domain", "url", "email"):
                stix, found = set(entry["stix"].get(t, [])), ours[rw.IOCType(t)]
                missed[t] += sorted(v for v in stix - found if v in text)
                extra[t] += sorted(found - stix)
    print(f"Model-only suggestions: {len(scored)}; most frequent:")
    for (tid, name, ok), n in model_tech.most_common(15):
        print(f"  {n:3d}  {tid:10s} {name}  (cited by CISA: {ok})")
    print("Agreement with CISA (parent level) by model decision score:")
    for lo, hi in BANDS:
        band = [ok for s, ok in scored if s is not None and lo <= s < hi]
        rate = f"{sum(band) / len(band):.2f}" if band else "n/a"
        print(f"  [{lo}, {hi}): n={len(band):4d}  agreement={rate}")
    print("Most common name/term-only matches:")
    for key, n in name_only.most_common(12):
        print(f"  {n:3d}  {key}")
    for t in ("domain", "url", "email"):
        print(f"Printed STIX {t} values not extracted ({len(missed[t])}): {missed[t][:12]}")
        print(f"Extracted {t} values not in STIX ({len(extra[t])}): {extra[t][:12]}")


if __name__ == "__main__":
    main()
