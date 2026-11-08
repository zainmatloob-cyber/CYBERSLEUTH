"""Verify the real-world evaluation set (public CISA advisories).

Usage:  python scripts/fetch_real_world.py            # verify files against the manifest
        python scripts/fetch_real_world.py --record   # first time only: record SHA-256s

The documents are not redistributed and are downloaded by hand: cisa.gov's CDN refuses
automated clients, and this project does not try to get around that. For each advisory in
data/real_world/manifest.json, open the advisory page, download the PDF (and the STIX JSON
when listed), and save them in data/raw/cisa/ as ``<id>.pdf`` and ``<id>.stix.json``.
Every file must match the recorded SHA-256, so the evaluation always runs on exactly the
documents it was scored on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data" / "real_world" / "manifest.json"
RAW_DIR = ROOT / "data" / "raw" / "cisa"
PAGE_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories/{id}"
SUFFIXES = {"pdf": "pdf", "stix": "stix.json"}


def local_path(doc_id: str, kind: str) -> Path:
    return RAW_DIR / f"{doc_id}.{SUFFIXES[kind]}"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true",
                        help="record hashes of the files in the manifest")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failures = 0
    for doc in manifest["documents"]:
        for kind in SUFFIXES:
            published_name = doc.get(f"{kind}_name")
            if not published_name:
                continue
            path = local_path(doc["id"], kind)
            if not path.exists():
                print(f"MISSING {path.name}: download '{published_name}' from "
                      f"{PAGE_URL.format(id=doc['id'])}\n  and save it as {path}")
                failures += 1
                continue
            digest = sha256(path)
            key = f"{kind}_sha256"
            if args.record:
                doc[key] = digest
            elif doc.get(key) != digest:
                print(f"HASH MISMATCH {path.name}: expected {doc.get(key)}, got {digest}")
                failures += 1
            else:
                print(f"OK {path.name}")
    if args.record and not failures:
        MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
        print("Hashes recorded.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
