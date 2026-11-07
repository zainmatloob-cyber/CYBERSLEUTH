"""Measure IOC and entity extraction quality on the annotated evaluation set.

Usage:
    python scripts/evaluate_extraction.py --split dev            # rules + spaCy model
    python scripts/evaluate_extraction.py --split dev --rules-only
    python scripts/evaluate_extraction.py --split test --save    # writes docs/evaluation/

The test split must be scored only once, after development is finished
(see data/evaluation/ANNOTATION_GUIDELINES.md).
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

from src.evaluation.runner import TASKS, EvaluationReport, evaluate_split  # noqa: E402
from src.intelligence.analyzer import Analyzer  # noqa: E402
from src.nlp.entity_extractor import EntityExtractor  # noqa: E402
from src.utils.logging_config import configure_logging  # noqa: E402

EVAL_DIR = ROOT / "data" / "evaluation"
OUT_DIR = ROOT / "docs" / "evaluation"


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _git_revision() -> str:
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "src", "data"], cwd=ROOT,
                               capture_output=True, text=True, check=True).stdout.strip()
        return f"{rev}{'+uncommitted' if dirty else ''}"
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def render_markdown(report: EvaluationReport, meta: dict) -> str:
    lines = [
        f"# Extraction evaluation: `{report.split}` split, {report.mode}",
        "",
        f"* Date: {meta['date']} · Code revision: `{meta['revision']}` · "
        f"ATT&CK KB v{meta['attack_version']}",
        f"* Documents ({len(report.documents)}): {', '.join(report.documents)}",
        "* Data: **synthetic documents annotated by the project author**. These numbers "
        "describe behaviour on this small set only and are not an estimate of real-world accuracy.",
        "",
    ]
    for task in TASKS:
        overall = report.overall(task)
        data = report.as_dict()["tasks"][task]
        lines += [
            f"## {task.upper()}",
            "",
            "| Type | Support | TP | FP | FN | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for kind, c in sorted(report.per_type[task].items()):
            lines.append(f"| {kind} | {c.support} | {c.tp} | {c.fp} | {c.fn} | "
                         f"{_fmt(c.precision)} | {_fmt(c.recall)} | {_fmt(c.f1)} |")
        lines += [
            f"| **micro** | {overall.support} | {overall.tp} | {overall.fp} | {overall.fn} | "
            f"**{_fmt(overall.precision)}** | **{_fmt(overall.recall)}** | "
            f"**{_fmt(overall.f1)}** |",
            "",
            f"Macro F1 (types with support): **{_fmt(data['macro_f1'])}**",
            "",
        ]
    lines += ["## Errors", "", "| Document | Task | Type | Error | Value |",
              "|---|---|---|---|---|"]
    lines += [f"| {e['document']} | {e['task']} | {e['type']} | {e['error']} | `{e['value']}` |"
              for e in report.errors] or ["| — | — | — | — | none |"]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=["dev", "test"], required=True)
    parser.add_argument("--rules-only", action="store_true", help="disable the spaCy model")
    parser.add_argument("--save", action="store_true", help="write JSON + Markdown reports")
    args = parser.parse_args()

    configure_logging("WARNING")
    analyzer = (Analyzer(entity_extractor=EntityExtractor(model=None)) if args.rules_only
                else Analyzer())
    mode = "rules-only" if analyzer.entity_extractor.model_name is None \
        else f"rules+{analyzer.entity_extractor.model_name}"
    report = evaluate_split(EVAL_DIR / args.split, analyzer, mode)
    meta = {
        "date": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "revision": _git_revision(),
        "attack_version": analyzer.entity_extractor.kb.versions.get("attack"),
    }
    markdown = render_markdown(report, meta)
    print(markdown)

    if args.save:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        stem = f"{args.split}_{'rules_only' if args.rules_only else 'full'}"
        (OUT_DIR / f"{stem}.json").write_text(
            json.dumps({**meta, **report.as_dict()}, indent=1) + "\n", encoding="utf-8",
            newline="\n")
        (OUT_DIR / f"{stem}.md").write_text(markdown, encoding="utf-8", newline="\n")
        print(f"Saved {stem}.json / {stem}.md to {OUT_DIR}")


if __name__ == "__main__":
    main()
