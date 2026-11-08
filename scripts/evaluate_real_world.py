"""Evaluate CyberSleuth on public CISA advisories (see src/evaluation/real_world.py).

Usage:
    python scripts/fetch_real_world.py              # get and verify the documents first
    python scripts/evaluate_real_world.py           # verify files + write gold labels only
    python scripts/evaluate_real_world.py --final   # score once; writes docs/evaluation/

Without --final no predictions are computed, so the gold labels can be inspected before
the code is frozen and scored. Scoring requires both trained models.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.evaluation import real_world as rw  # noqa: E402
from src.evaluation.metrics import Counts, micro  # noqa: E402
from src.ingestion.pipeline import ingest  # noqa: E402
from src.intelligence.attack_kb import default_technique_kb  # noqa: E402

MANIFEST = ROOT / "data" / "real_world" / "manifest.json"
GOLD_PATH = ROOT / "data" / "real_world" / "gold.json"
RAW_DIR = ROOT / "data" / "raw" / "cisa"
OUT_JSON = ROOT / "docs" / "evaluation" / "real_world.json"
OUT_MD = ROOT / "docs" / "evaluation" / "real_world.md"
GROUPS = ("id", "name_or_term", "model_only")


def local_suffix(kind: str, published_name: str) -> str:
    """``pdf``, ``stix.json`` (STIX 2.x) or ``stix.xml`` (STIX 1.x)."""
    if kind == "pdf":
        return "pdf"
    return "stix.xml" if published_name.lower().endswith(".xml") else "stix.json"


def load_documents() -> list[dict]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    problems = []
    for doc in manifest["documents"]:
        for kind in ("pdf", "stix"):
            if not doc.get(f"{kind}_name"):
                continue
            path = RAW_DIR / f"{doc['id']}.{local_suffix(kind, doc[f'{kind}_name'])}"
            if not path.exists():
                problems.append(f"missing {path.name}")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != doc.get(f"{kind}_sha256"):
                problems.append(f"hash mismatch {path.name}")
            doc[f"{kind}_path"] = path
    if problems:
        raise SystemExit("Run scripts/fetch_real_world.py first: " + "; ".join(problems))
    return manifest["documents"]


def document_text(pdf_path: Path) -> str:
    document = ingest(pdf_path.read_bytes(), pdf_path.name)
    return "\n\n".join(page.text for page in document.pages)


def build_gold(documents: list[dict], kb) -> dict:
    gold = {"attack_version": kb.version, "documents": {}}
    for doc in documents:
        cited = rw.cited_techniques(document_text(doc["pdf_path"]), kb)
        entry = {"techniques": sorted(cited.resolved), "translated": cited.translated,
                 "unresolved": cited.unresolved}
        if doc.get("stix_path"):
            stix = rw.load_stix(doc["stix_path"])
            entry["stix"] = {t.value: sorted(v) for t, v in stix.items() if v}
        gold["documents"][doc["id"]] = entry
    return gold


def _counts(c: Counts) -> dict:
    return c.as_dict()


def evaluate(documents: list[dict], gold: dict, kb) -> dict:
    from src.intelligence.analyzer import Analyzer

    analyzer = Analyzer()
    results: dict = {"documents": {}, "attack_version": kb.version}
    totals = {"published": {g: rw.GroupAgreement() for g in GROUPS},
              "published_counts": [], "masked_counts": {k: [] for k in
                                                        ("all", "name_or_term", "model_only")},
              "ioc": {}}
    for doc in documents:
        truth = set(gold["documents"][doc["id"]]["techniques"])
        published = analyzer.analyze(doc["pdf_path"].read_bytes(), doc["pdf_path"].name)
        if published.components.get("technique_mapping") != "explicit+model":
            raise SystemExit("The technique model is not loaded; train it before scoring.")
        text = "\n\n".join(page.text for page in published.document.pages)
        masked = analyzer.analyze(rw.mask_technique_ids(text).encode("utf-8"),
                                  f"{doc['id']}_masked.txt")

        entry = {
            "title": doc["title"], "group": doc["group"], "pages": published.document.page_count,
            "gold_techniques": len(truth), "techniques_evaluated": bool(truth),
            "analysis_seconds": round(published.timings_ms.get("total", 0) / 1000, 2),
            "risk": [round(published.risk.score, 1), published.risk.band],
        }
        # An advisory without an ATT&CK section gives no technique gold: scoring it would
        # count every prediction as "not cited". Such documents count for IOCs only.
        if truth:
            groups = rw.group_agreement(published.mappings, truth, kb)
            for name, group in groups.items():
                total = totals["published"][name]
                total.predicted += group.predicted
                total.cited_exact += group.cited_exact
                total.cited_parent += group.cited_parent
            published_counts = rw.technique_counts(published.mappings, truth, kb)
            totals["published_counts"].append(published_counts)
            masked_counts = {
                "all": rw.technique_counts(masked.mappings, truth, kb),
                "name_or_term": rw.technique_counts(masked.mappings, truth, kb,
                                                    {"name_or_term"}),
                "model_only": rw.technique_counts(masked.mappings, truth, kb, {"model_only"}),
            }
            for key, value in masked_counts.items():
                totals["masked_counts"][key].append(value)
            entry |= {
                "published_groups": {k: v.as_dict() for k, v in groups.items()},
                "published": {lvl: _counts(c) for lvl, c in published_counts.items()},
                "masked": {k: {lvl: _counts(c) for lvl, c in v.items()}
                           for k, v in masked_counts.items()},
            }
        if doc.get("stix_path"):
            stix = {rw.IOCType(t): set(v) for t, v in gold["documents"][doc["id"]]["stix"].items()}
            stix = {t: stix.get(t, set()) for t in rw.COMPARED_IOC_TYPES}
            agreement = rw.ioc_agreement(rw.extracted_indicators(published.indicators), stix,
                                         rw.refang_text(text))
            entry["ioc"] = {t: a.as_dict() for t, a in agreement.items()}
            for t, a in agreement.items():
                total = totals["ioc"].setdefault(t, rw.IOCAgreement())
                total.extracted += a.extracted
                total.stix += a.stix
                total.in_text += a.in_text
                total.matched += a.matched
        results["documents"][doc["id"]] = entry
        print(f"{doc['id']}: {len(truth)} cited techniques, "
              f"{entry['analysis_seconds']} s")

    results["overall"] = {
        "published_groups": {k: v.as_dict() for k, v in totals["published"].items()},
        "published": {lvl: _counts(micro(c[lvl] for c in totals["published_counts"]))
                      for lvl in ("exact", "parent")},
        "masked": {k: {lvl: _counts(micro(c[lvl] for c in v)) for lvl in ("exact", "parent")}
                   for k, v in totals["masked_counts"].items()},
        "ioc": {t: a.as_dict() for t, a in totals["ioc"].items()},
    }
    results["components"] = dict(published.components)
    return results


def _pct(value) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def render_markdown(results: dict, gold: dict) -> str:
    overall = results["overall"]
    technique_docs = sum(d["techniques_evaluated"] for d in results["documents"].values())
    lines = [
        "# Real-world evaluation: CISA joint advisories",
        "",
        "Generated by `scripts/evaluate_real_world.py --final`, scored **once** with the code "
        "frozen. Documents and gold derivation: `data/real_world/` and "
        "`src/evaluation/real_world.py`.",
        "",
        f"* {len(results['documents'])} public CISA advisories (TLP:CLEAR); ATT&CK "
        f"{results['attack_version']}.",
        "* **Technique gold** = every technique ID CISA cites in the advisory, resolved to "
        "v20.1. **IOC gold** = CISA's STIX bundle for the advisory.",
        "* Negated mappings are excluded from predictions. Parent level counts a sub-technique "
        "as its parent technique.",
        f"* Technique metrics use the {technique_docs} advisories that have an ATT&CK "
        "section; the others count for indicators only.",
        "",
        "## 1. As published: agreement with CISA's technique list, by how it was found",
        "",
        "\"Agreement\" = share of predictions that CISA also cites. A prediction CISA does not "
        "cite is not necessarily wrong (advisories do not list every behaviour), so this is a "
        "lower bound on precision, not precision.",
        "",
        "| Found by | Predicted | Agreement (exact) | Agreement (parent) |",
        "|---|---|---|---|",
    ]
    for group, label in (("id", "Technique ID in text"), ("name_or_term", "Name / term only"),
                         ("model_only", "Model only")):
        g = overall["published_groups"][group]
        lines.append(f"| {label} | {g['predicted']} | {_pct(g['agreement_exact'])} | "
                     f"{_pct(g['agreement_parent'])} |")
    p = overall["published"]
    lines += [
        "",
        f"All methods together (micro): exact P {_pct(p['exact']['precision'])} / "
        f"R {_pct(p['exact']['recall'])}; parent P {_pct(p['parent']['precision'])} / "
        f"R {_pct(p['parent']['recall'])}. Recall here is mostly the ID matcher reading "
        "CISA's own IDs.",
        "",
        "## 2. IDs masked: what is recovered without the answer key",
        "",
        "Technique IDs are removed from the text before analysis. Technique *names* in CISA's "
        "appendix tables remain, which favours the name matcher.",
        "",
        "| Predictions from | Exact P | Exact R | Parent P | Parent R |",
        "|---|---|---|---|---|",
    ]
    for key, label in (("all", "All methods"), ("name_or_term", "Name / term matcher"),
                       ("model_only", "Model only")):
        m = overall["masked"][key]
        lines.append(f"| {label} | {_pct(m['exact']['precision'])} | "
                     f"{_pct(m['exact']['recall'])} | {_pct(m['parent']['precision'])} | "
                     f"{_pct(m['parent']['recall'])} |")
    lines += [
        "",
        "## 3. Indicators vs CISA STIX",
        "",
        "`Extracted in STIX` = share of our indicators that CISA's STIX also lists. "
        "`STIX found` = share of STIX values we extracted; `printed STIX found` restricts that "
        "to STIX values that actually appear in the PDF text (STIX often lists more than the "
        "PDF prints).",
        "",
        "| Type | Extracted | STIX | STIX printed in PDF | Matched | Extracted in STIX | "
        "STIX found | Printed STIX found |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for t, a in sorted(overall["ioc"].items()):
        lines.append(f"| {t} | {a['extracted']} | {a['stix']} | {a['stix_in_text']} | "
                     f"{a['matched']} | {_pct(a['extracted_in_stix'])} | "
                     f"{_pct(a['stix_found'])} | {_pct(a['printed_stix_found'])} |")
    lines += [
        "",
        "## 4. Per document",
        "",
        "| Advisory | Group | Pages | CISA techniques | Model-only predicted | Model-only "
        "agreement (parent) | Masked recall (parent) | Analysis time (s) | Risk |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for doc_id, d in results["documents"].items():
        if not d["techniques_evaluated"]:
            lines.append(f"| {doc_id} | {d['group']} | {d['pages']} | none (no ATT&CK "
                         f"section; IOCs only) | - | - | - | {d['analysis_seconds']} | "
                         f"{d['risk'][0]} {d['risk'][1]} |")
            continue
        mo = d["published_groups"]["model_only"]
        lines.append(f"| {doc_id} | {d['group']} | {d['pages']} | {d['gold_techniques']} | "
                     f"{mo['predicted']} | {_pct(mo['agreement_parent'])} | "
                     f"{_pct(d['masked']['all']['parent']['recall'])} | "
                     f"{d['analysis_seconds']} | {d['risk'][0]} {d['risk'][1]} |")
    unresolved = {k: v["unresolved"] for k, v in gold["documents"].items() if v["unresolved"]}
    translated = {k: v["translated"] for k, v in gold["documents"].items() if v["translated"]}
    lines += [
        "",
        "## 5. Gold-label notes",
        "",
        f"* Cited IDs translated from revoked/deprecated to v20.1: {translated or 'none'}.",
        f"* Cited IDs not in v20.1 (excluded from gold): {unresolved or 'none'}.",
        "",
        "## 6. Limitations",
        "",
        f"* {len(results['documents'])} advisories is a small sample; per-document numbers "
        "vary widely. No confidence intervals are claimed.",
        "* The set was chosen by the project owner and is weighted towards ransomware "
        "(#StopRansomware) and state-sponsored advisories.",
        "* CISA's technique list is incomplete by design, so agreement understates precision "
        "and recall against it measures coverage of *CISA's* labels only.",
        "* All are US-government joint advisories with a consistent structure; vendor "
        "reports and blogs may behave differently.",
        "* Gold IDs are read from the same PyMuPDF text extraction the system uses; text the "
        "extractor misses is missing from both.",
        "* IOC comparison case-folds values (URL paths included) and ignores CIDR ranges.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final", action="store_true", help="score once and write reports")
    args = parser.parse_args()
    kb = default_technique_kb()
    documents = load_documents()
    gold = build_gold(documents, kb)
    GOLD_PATH.write_text(json.dumps(gold, indent=2) + "\n", encoding="utf-8")
    for doc_id, entry in gold["documents"].items():
        stix = {t: len(v) for t, v in entry.get("stix", {}).items()}
        print(f"{doc_id}: {len(entry['techniques'])} techniques, translated "
              f"{entry['translated']}, unresolved {entry['unresolved']}, STIX {stix}")
    if not args.final:
        print(f"Gold written to {GOLD_PATH.relative_to(ROOT)}. Re-run with --final to score.")
        return 0
    results = evaluate(documents, gold, kb)
    OUT_JSON.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    OUT_MD.write_text(render_markdown(results, gold), encoding="utf-8")
    print(f"Wrote {OUT_JSON.relative_to(ROOT)} and {OUT_MD.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
