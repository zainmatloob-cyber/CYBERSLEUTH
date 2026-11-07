"""Download, verify and build the threat-category dataset.

Usage:  python scripts/prepare_threat_dataset.py [--offline]

* Downloads the pinned Hugging Face revision to data/raw/ (skipped if already present)
  and verifies its SHA-256 before use.
* Writes data/processed/threat_categories.jsonl (one sentence per line).
* Writes docs/datasets/threat_categories.md (the dataset card with statistics).

Raw and processed data are git-ignored and can be rebuilt with this script.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from src.ml.dataset import (  # noqa: E402
    DATASET_FILE,
    DATASET_ID,
    DATASET_REVISION,
    DATASET_SHA256,
    DATASET_URL,
    OTHER,
    SPLITS,
    build_dataset,
    dataset_statistics,
    load_category_map,
    verify_raw_file,
)

RAW_PATH = ROOT / "data" / "raw" / "sarahwei_technique_v16" / DATASET_FILE
OUT_PATH = ROOT / "data" / "processed" / "threat_categories.jsonl"
CARD_PATH = ROOT / "docs" / "datasets" / "threat_categories.md"
_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024


def download(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "CyberSleuth-dataset-builder"})
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 (pinned https URL)
        data = response.read(_MAX_DOWNLOAD_BYTES + 1)
    if len(data) > _MAX_DOWNLOAD_BYTES:
        raise SystemExit("Download exceeds the size limit; refusing to continue.")
    target.write_bytes(data)


def render_card(stats: dict, categories: tuple[str, ...], map_version: str) -> str:
    labels = [*categories, OTHER]
    rows = "\n".join(
        f"| {c} | " + " | ".join(str(stats["splits"][s]["categories"][c]) for s in SPLITS) + " |"
        for c in labels
    )
    sizes = " | ".join(f"{stats['splits'][s]['sentences']:,} ({stats['splits'][s]['groups']:,} groups)"
                       for s in SPLITS)
    return f"""# Dataset card: threat categories

| | |
|---|---|
| Source | Hugging Face [`{DATASET_ID}`](https://huggingface.co/datasets/{DATASET_ID}), revision `{DATASET_REVISION}` |
| Content | MITRE ATT&CK v16 Enterprise procedure examples (one sentence each), labelled with an ATT&CK technique |
| License | Apache-2.0 (dataset). Content derived from MITRE ATT&CK®, used under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |
| Raw file SHA-256 | `{DATASET_SHA256}` |
| Category labels | **Derived** from technique labels with `data/knowledge_base/technique_category_map.json` (version {map_version}) |
| Build | `python scripts/prepare_threat_dataset.py` |

## Processing
1. Citation markers and HTML tags removed; whitespace collapsed.
2. Rows with identical text merged (union of techniques → multi-label).
3. Techniques mapped to categories (sub-techniques inherit their parent). `other` = no category applies.
4. Each sentence grouped by the actor, software or campaign it describes, using longest-prefix
   matching against the ATT&CK knowledge base, so aliases share a group. The split is
   assigned by hashing the group: about 70/15/15, with no group in more than one split.

## Statistics
* Unique sentences: **{stats['sentences']:,}** in {stats['groups']:,} groups
* Sentences with more than one technique: {stats['multi_technique_sentences']}; with more
  than one category: {stats['multi_category_sentences']}
* Groups appearing in more than one split: **{stats['groups_in_multiple_splits']}** (must be 0)
* Train | Val | Test: {sizes}

| Category | Train | Val | Test |
|---|---:|---:|---:|
{rows}

## Known limitations
* **Derived labels.** Categories come from a heuristic mapping, not from annotators labelling
  categories. The model can only be as right as that mapping.
* **Sentence level.** Each example is one procedure sentence. Report-level categories in
  CyberSleuth are aggregated from sentence predictions, and that aggregation is not
  validated by this dataset.
* **ATT&CK-style language.** Procedure examples are short, edited and formulaic
  ("X has used Y to …"). Real reports are longer and noisier, so performance is expected to
  be lower on them.
* **Category gaps.** `ddos` has too few examples to learn from. `malware` cannot be derived
  per sentence. Both are handled by the rule-based baseline only.
* **Severe imbalance.** `other` dominates. Use macro-averaged metrics.
* **Version gap.** The dataset is ATT&CK v16; the category map was checked against v20.1.
  Technique IDs used in the map are stable across these versions.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--offline", action="store_true", help="never download")
    args = parser.parse_args()

    if not RAW_PATH.exists():
        if args.offline:
            raise SystemExit(f"{RAW_PATH} missing and --offline given.")
        print(f"Downloading {DATASET_URL}")
        download(DATASET_URL, RAW_PATH)
    verify_raw_file(RAW_PATH)

    category_map = load_category_map()
    dataset = build_dataset(pd.read_csv(RAW_PATH), category_map)
    stats = dataset_statistics(dataset, category_map.categories)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8", newline="\n") as handle:
        for row in dataset.itertuples(index=False):
            handle.write(json.dumps({"text": row.text, "techniques": list(row.techniques),
                                     "categories": list(row.categories), "group": row.group,
                                     "split": row.split}, ensure_ascii=False) + "\n")
    CARD_PATH.parent.mkdir(parents=True, exist_ok=True)
    CARD_PATH.write_text(render_card(stats, category_map.categories, category_map.version),
                         encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in stats.items() if k != "largest_groups"}, indent=1))
    print("largest groups:", stats["largest_groups"])
    print(f"Wrote {OUT_PATH} and {CARD_PATH}")


if __name__ == "__main__":
    main()
