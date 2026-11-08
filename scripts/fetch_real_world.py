"""Verify a real-world evaluation set (public CISA advisories).

Usage:  python scripts/fetch_real_world.py                      # verify the first set
        python scripts/fetch_real_world.py --manifest data/real_world/batch2/manifest.json
        python scripts/fetch_real_world.py --record             # first time only

The documents are not redistributed and are downloaded by hand: cisa.gov's CDN refuses
automated clients, and this project does not try to get around that. For each advisory in
the manifest, open the advisory page, download the PDF (and the STIX files when listed),
and save them in the manifest's ``raw_dir`` under the local names described in
``src/evaluation/manifest.py`` (``<id>.pdf``, ``<id>.stix.json``, ...).
Every file must match the recorded SHA-256, so the evaluation always runs on exactly the
documents it was scored on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.evaluation import manifest as rm  # noqa: E402

MANIFEST = ROOT / "data" / "real_world" / "manifest.json"
PAGE_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories/{id}"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--record", action="store_true",
                        help="record hashes of the files in the manifest")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    raw_dir = rm.raw_dir(manifest, ROOT)
    failures = 0
    for doc in manifest["documents"]:
        for file in rm.manifest_files(doc, raw_dir):
            if not file.path.exists():
                print(f"MISSING {file.path.name}: download '{file.published_name}' from "
                      f"{PAGE_URL.format(id=doc['id'])}\n  and save it as {file.path}")
                failures += 1
                continue
            digest = sha256(file.path)
            if args.record:
                rm.record_hash(doc, file, digest)
            elif file.sha256 != digest:
                print(f"HASH MISMATCH {file.path.name}: expected {file.sha256}, got {digest}")
                failures += 1
            else:
                print(f"OK {file.path.name}")
    if args.record and not failures:
        args.manifest.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8")
        print("Hashes recorded.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
