"""Download the trained model files from the project's GitHub release and verify them.

Usage:
    python scripts/fetch_models.py           # download any missing or changed file
    python scripts/fetch_models.py --verify  # check local files only, no network

The expected SHA-256 and size of every file are pinned in config/model_files.json. Model
files are pickles, and loading one runs code, so a file is moved into models/ only after its
hash matches. A wrong file is deleted, never loaded. This script is the only place that
downloads models; the application itself never makes network requests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config" / "model_files.json"
MODELS_DIR = ROOT / "models"
URL = "https://github.com/{repository}/releases/download/{tag}/{name}"
CHUNK = 1 << 20


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, target: Path, expected_bytes: int, opener=urllib.request.urlopen) -> None:
    """Stream ``url`` to ``target``; refuse anything larger than ``expected_bytes``."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-HTTPS URL: {url}")
    written = 0
    with opener(url, timeout=60) as response, target.open("wb") as out:
        for block in iter(lambda: response.read(CHUNK), b""):
            written += len(block)
            if written > expected_bytes:
                raise ValueError(f"{target.name}: larger than the expected {expected_bytes} bytes")
            out.write(block)


def fetch(config: dict, models_dir: Path, verify_only: bool = False,
          opener=urllib.request.urlopen) -> list[str]:
    """Bring every model file up to date. Returns the problems found (empty = all good)."""
    problems = []
    models_dir.mkdir(parents=True, exist_ok=True)
    for name, spec in config["files"].items():
        path = models_dir / name
        if path.exists() and sha256(path) == spec["sha256"]:
            print(f"OK {name}")
            continue
        if verify_only:
            problems.append(f"{name}: {'hash mismatch' if path.exists() else 'missing'}")
            continue
        url = URL.format(repository=config["repository"], tag=config["release_tag"], name=name)
        partial = path.with_name(path.name + ".part")
        try:
            print(f"Downloading {url}")
            download(url, partial, spec["bytes"], opener)
            if sha256(partial) != spec["sha256"]:
                raise ValueError(f"{name}: SHA-256 does not match config/model_files.json")
        except (OSError, ValueError) as exc:
            partial.unlink(missing_ok=True)
            problems.append(f"{name}: {exc}")
            continue
        partial.replace(path)
        print(f"OK {name} (downloaded)")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="check local files only")
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    problems = fetch(config, MODELS_DIR, verify_only=args.verify)
    for problem in problems:
        print(f"PROBLEM {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
