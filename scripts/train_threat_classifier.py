"""Train and evaluate the threat-category classifier.

Usage:
    python scripts/train_threat_classifier.py            # model selection on val (test untouched)
    python scripts/train_threat_classifier.py --final    # train, then score test ONCE and save

Protocol: train → fit; val → choose C and per-category thresholds; test → final report.
Requires data/processed/threat_categories.jsonl (python scripts/prepare_threat_dataset.py).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.ml.dataset import DATASET_REVISION, DATASET_SHA256, OTHER  # noqa: E402
from src.ml.evaluation import evaluate  # noqa: E402
from src.ml.rule_classifier import RuleBasedClassifier  # noqa: E402
from src.ml.threat_classifier import ThreatClassifier  # noqa: E402
from src.utils.logging_config import configure_logging  # noqa: E402

DATA_PATH = ROOT / "data" / "processed" / "threat_categories.jsonl"
MODEL_PATH = ROOT / "models" / "threat_classifier.joblib"
REPORT_DIR = ROOT / "docs" / "evaluation"
# Log-spaced. If the best C lands on an edge, widen the grid (it was 0.25–8 at first,
# and the optimum sat on the upper edge).
C_GRID = (0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0)


def load(split: str) -> tuple[list[str], list[frozenset[str]], list[str]]:
    texts, labels, groups = [], [], []
    with DATA_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row["split"] == split:
                texts.append(row["text"])
                labels.append(frozenset(row["categories"]))
                groups.append(row["group"])
    if not texts:
        raise SystemExit(f"No {split} rows in {DATA_PATH}. Run prepare_threat_dataset.py.")
    return texts, labels, groups


def fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"


def table(name: str, result: dict, categories: list[str]) -> str:
    ci = result.get("ci95", {})
    lines = [f"### {name}", "", "| Category | Support | Precision | Recall | F1 | F1 95% CI |",
             "|---|---:|---:|---:|---:|---|"]
    for c in categories:
        m = result["per_category"][c]
        interval = f"{ci[c][0]:.2f}–{ci[c][1]:.2f}" if c in ci else "n/a"
        lines.append(f"| {c} | {m['support']} | {fmt(m['precision'])} | {fmt(m['recall'])} | "
                     f"{fmt(m['f1'])} | {interval} |")
    macro_ci = ci.get("macro_f1")
    interval = f" (95% CI {macro_ci[0]:.2f}–{macro_ci[1]:.2f})" if macro_ci else ""
    lines += ["", f"Macro F1: **{fmt(result['macro_f1'])}**{interval} · exact match "
              f"{result['exact_match']:.2f} · n = {result['n']}", ""]
    return "\n".join(lines)


def confusion_table(result: dict) -> str:
    labels, matrix = result["confusion"]["labels"], result["confusion"]["matrix"]
    short = [label[:10] for label in labels]
    lines = ["| true ↓ / predicted → | " + " | ".join(short) + " |",
             "|---|" + "---:|" * len(labels)]
    lines += [f"| {labels[i]} | " + " | ".join(str(v) for v in row) + " |"
              for i, row in enumerate(matrix)]
    return "\n".join(lines)


def revision() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--final", action="store_true",
                        help="score the test split once and save the model and reports")
    args = parser.parse_args()
    configure_logging("WARNING")

    train_x, train_y, _ = load("train")
    val_x, val_y, val_g = load("val")
    rules = RuleBasedClassifier()

    # --- model selection on validation ---------------------------------------
    print("C    val macro F1 (after threshold tuning on val)")
    best: tuple[float, float, ThreatClassifier] | None = None
    for c in C_GRID:
        model = ThreatClassifier(C=c).fit(train_x, train_y)
        model.tune_thresholds(val_x, val_y)
        score = evaluate(val_y, model.predict(val_x), val_g, model.categories, 0)["macro_f1"]
        print(f"{c:<5} {score:.3f}")
        if best is None or score > best[0]:
            best = (score, c, model)
    _, best_c, model = best
    categories = list(model.categories)
    print(f"Selected C = {best_c}; learned categories: {categories}")
    print("Thresholds:", model.thresholds)

    rule_categories = [*categories, "ddos"]
    val_model = evaluate(val_y, model.predict(val_x), val_g, categories, 1000)
    val_rules = evaluate(val_y, rules.predict(val_x), val_g, rule_categories, 1000)
    val_majority = evaluate(val_y, [frozenset({OTHER})] * len(val_y), val_g, categories, 0)
    print(table("Validation: TF-IDF + Logistic Regression", val_model, categories))
    print(table("Validation: rule baseline", val_rules, rule_categories))
    print(f"Validation: majority baseline (always 'other') macro F1 = "
          f"{fmt(val_majority['macro_f1'])}\n")

    if not args.final:
        print("Test split not touched. Re-run with --final to score it once.")
        return

    # --- final, one-time test evaluation ----------------------------------------
    test_x, test_y, test_g = load("test")
    test_model = evaluate(test_y, model.predict(test_x), test_g, categories, 1000)
    test_rules = evaluate(test_y, rules.predict(test_x), test_g, rule_categories, 1000)
    test_majority = evaluate(test_y, [frozenset({OTHER})] * len(test_y), test_g, categories, 0)

    meta = {"date": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"), "revision": revision(),
            "dataset_revision": DATASET_REVISION, "dataset_sha256": DATASET_SHA256,
            "selected_C": best_c, "thresholds": model.thresholds,
            "learned_categories": categories}
    model.save(MODEL_PATH, dataset_revision=DATASET_REVISION, selected_C=str(best_c),
               code_revision=meta["revision"])

    markdown = "\n".join([
        "# Threat classifier: test-split evaluation (scored once)", "",
        f"* Date: {meta['date']} · code `{meta['revision']}` · dataset revision "
        f"`{DATASET_REVISION[:7]}`",
        f"* Model: TF-IDF (word 1–2 + char 3–5) + one-vs-rest Logistic Regression, "
        f"C = {best_c}, thresholds tuned on val: {model.thresholds}",
        "* Labels are **derived** from ATT&CK technique labels (see the dataset card), and the "
        "texts are ATT&CK procedure examples. Expect lower performance on real reports.",
        "* 95% CIs: percentile bootstrap over actor/software groups (1,000 resamples).", "",
        table("TF-IDF + Logistic Regression", test_model, categories),
        table("Rule baseline", test_rules, rule_categories),
        f"Majority baseline (always `other`): macro F1 = {fmt(test_majority['macro_f1'])}", "",
        "### Confusion matrix (model, primary label)", "", confusion_table(test_model), "",
        "### Confusion matrix (rules, primary label)", "", confusion_table(test_rules), "",
    ])
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "threat_classifier_test.md").write_text(markdown, encoding="utf-8",
                                                          newline="\n")
    (REPORT_DIR / "threat_classifier_test.json").write_text(json.dumps({
        **meta, "validation": {"model": val_model, "rules": val_rules},
        "test": {"model": test_model, "rules": test_rules, "majority": test_majority},
    }, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(markdown)
    print(f"Saved model to {MODEL_PATH} and reports to {REPORT_DIR}")


if __name__ == "__main__":
    main()
