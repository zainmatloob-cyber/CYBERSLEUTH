"""Split a real-world set into development and test advisories, once.

Usage:  python scripts/split_real_world.py --manifest data/real_world/batch2/manifest.json

The split is stratified by publication period, with a fixed allocation and seed declared
here before the split was run:

* 2022: 4 development, 3 test
* 2023: 4 development, 3 test
* 2024 and later: 1 development, 2 test. The test side gets more recent advisories because
  the result should describe documents written in the current style.

Within each period the advisory IDs are sorted and then shuffled with ``random.Random(SEED)``,
so the assignment is reproducible and doesn't depend on file order. The script writes
``"split"`` into every document and refuses to run on a manifest that already has one: a
split is made once and never redrawn after looking at results.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

SEED = 20261108
# period -> (development, test)
ALLOCATION = {"2022": (4, 3), "2023": (4, 3), "2024+": (1, 2)}


def period(published: str) -> str:
    year = int(published[:4])
    return str(year) if year < 2024 else "2024+"


def split(documents: list[dict], seed: int = SEED,
          allocation: dict[str, tuple[int, int]] = ALLOCATION) -> dict[str, str]:
    """Advisory ID -> ``"dev"`` or ``"test"``."""
    strata: dict[str, list[str]] = {}
    for doc in documents:
        strata.setdefault(period(doc["published"]), []).append(doc["id"])
    if set(strata) != set(allocation):
        raise ValueError(f"periods {sorted(strata)} don't match {sorted(allocation)}")
    rng = random.Random(seed)
    assignment = {}
    for name in sorted(allocation):
        ids = sorted(strata[name])
        dev, test = allocation[name]
        if len(ids) != dev + test:
            raise ValueError(f"{name}: {len(ids)} advisories, allocation is {dev}+{test}")
        rng.shuffle(ids)
        assignment |= {doc_id: "dev" for doc_id in ids[:dev]}
        assignment |= {doc_id: "test" for doc_id in ids[dev:]}
    return assignment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if any("split" in doc for doc in manifest["documents"]):
        raise SystemExit("This manifest is already split; a split is never redrawn.")
    assignment = split(manifest["documents"])
    for doc in manifest["documents"]:
        doc["split"] = assignment[doc["id"]]
    manifest["split"] = {
        "method": "stratified by publication period, fixed allocation, seeded shuffle "
                  "(scripts/split_real_world.py)",
        "seed": SEED,
        "allocation": {k: {"dev": v[0], "test": v[1]} for k, v in ALLOCATION.items()},
    }
    # Only the test split may be scored with --final; dev is for choosing the threshold.
    manifest["final_scoring"] = "test"
    manifest["report_stem"] = f"real_world_{args.manifest.parent.name}_test"
    args.manifest.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    for label in ("dev", "test"):
        ids = [d["id"] for d in manifest["documents"] if d["split"] == label]
        print(f"{label} ({len(ids)}): {', '.join(ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
