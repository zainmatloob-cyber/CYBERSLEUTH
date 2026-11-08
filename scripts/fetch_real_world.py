"""Fetch and verify the real-world evaluation set (public CISA advisories).

Usage:  python scripts/fetch_real_world.py            # fetch missing files, verify hashes
        python scripts/fetch_real_world.py --record   # first run only: record SHA-256s

Files go to data/raw/cisa/ (git-ignored). Only https URLs under www.cisa.gov listed in
data/real_world/manifest.json are fetched, with an honest user agent. cisa.gov's CDN may
refuse automated clients; the script does not try to get around that. Instead it prints
each URL and the filename to save it as, so you can download the files in a browser.
Every file must match the SHA-256 recorded in the manifest, so the evaluation always runs
on exactly the documents it was scored on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data" / "real_world" / "manifest.json"
RAW_DIR = ROOT / "data" / "raw" / "cisa"
MAX_BYTES = 30 * 1024 * 1024
ALLOWED_PREFIX = "https://www.cisa.gov/"
USER_AGENT = "CyberSleuth-evaluation"


def local_path(doc_id: str, kind: str) -> Path:
    return RAW_DIR / f"{doc_id}.{'pdf' if kind == 'pdf' else 'stix.json'}"


def download(url: str, target: Path) -> None:
    if not url.startswith(ALLOWED_PREFIX):
        raise SystemExit(f"Refusing non-CISA URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 (allow-listed)
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise SystemExit(f"{url} exceeds the size limit.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true",
                        help="record hashes of the downloaded files in the manifest")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failures = 0
    for doc in manifest["documents"]:
        for kind in ("pdf", "stix"):
            url = doc.get(kind)
            if not url:
                continue
            path = local_path(doc["id"], kind)
            if not path.exists():
                try:
                    download(url, path)
                    print(f"Downloaded {path.name}")
                except urllib.error.HTTPError as exc:
                    print(f"MISSING {path.name}: the server refused ({exc.code}). Download it "
                          f"in a browser and save it as\n    {path}\n  from {url}")
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
    if args.record:
        MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
        print("Hashes recorded.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
