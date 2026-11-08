"""Manifests for the real-world evaluation sets (public CISA advisories).

A manifest lists each advisory's published file names and SHA-256 hashes. Its files are
downloaded by hand and saved under the manifest's ``raw_dir`` (default ``data/raw/cisa``)
with local names derived from the advisory ID:

* ``<id>.pdf``
* ``<id>.stix.json`` / ``<id>.stix.xml`` when there is one STIX file;
* ``<id>.stix-1.xml``, ``<id>.stix-2.json``, ... when there are several (some advisories
  publish their indicators in more than one bundle).

Two formats are accepted for the STIX files. The current one is a list,
``"stix": [{"name": ..., "sha256": ...}]``. The first manifest's form
(``stix_name`` / ``stix_sha256``) is still read so its recorded hashes stay valid.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_RAW_DIR = Path("data") / "raw" / "cisa"


@dataclass(frozen=True)
class ManifestFile:
    kind: str  # "pdf" or "stix"
    published_name: str
    path: Path
    sha256: str | None


def stix_entries(doc: dict) -> list[dict]:
    """The advisory's STIX files as ``[{"name", "sha256"}]``, in either manifest format."""
    if "stix" in doc:
        return list(doc["stix"])
    if doc.get("stix_name"):
        return [{"name": doc["stix_name"], "sha256": doc.get("stix_sha256")}]
    return []


def _stix_suffix(published_name: str) -> str:
    """``xml`` for STIX 1.x, ``json`` for STIX 2.x, from the published file name."""
    return "xml" if published_name.lower().endswith(".xml") else "json"


def manifest_files(doc: dict, raw_dir: Path) -> list[ManifestFile]:
    """Every file of one advisory, with its local path and recorded hash."""
    files = []
    if doc.get("pdf_name"):
        files.append(ManifestFile("pdf", doc["pdf_name"], raw_dir / f"{doc['id']}.pdf",
                                  doc.get("pdf_sha256")))
    entries = stix_entries(doc)
    for n, entry in enumerate(entries, start=1):
        number = "" if len(entries) == 1 else f"-{n}"
        local = f"{doc['id']}.stix{number}.{_stix_suffix(entry['name'])}"
        files.append(ManifestFile("stix", entry["name"], raw_dir / local, entry.get("sha256")))
    return files


def record_hash(doc: dict, file: ManifestFile, digest: str) -> None:
    """Store ``digest`` for ``file`` in ``doc``, keeping the manifest's own format."""
    if file.kind == "pdf":
        doc["pdf_sha256"] = digest
    elif "stix" in doc:
        next(e for e in doc["stix"] if e["name"] == file.published_name)["sha256"] = digest
    else:
        doc["stix_sha256"] = digest


def verified_documents(manifest: dict, raw_dir: Path) -> list[dict]:
    """The documents with ``pdf_path`` and ``stix_paths`` set, every file hash-checked.

    Raises ``SystemExit`` listing every missing or changed file.
    """
    import hashlib

    problems = []
    for doc in manifest["documents"]:
        doc["stix_paths"] = []
        for file in manifest_files(doc, raw_dir):
            if not file.path.exists():
                problems.append(f"missing {file.path.name}")
            elif hashlib.sha256(file.path.read_bytes()).hexdigest() != file.sha256:
                problems.append(f"hash mismatch {file.path.name}")
            if file.kind == "pdf":
                doc["pdf_path"] = file.path
            else:
                doc["stix_paths"].append(file.path)
    if problems:
        raise SystemExit("Run scripts/fetch_real_world.py first: " + "; ".join(problems))
    return manifest["documents"]


SPLITS = ("dev", "test")


def in_split(manifest: dict, documents: list[dict], split: str | None) -> list[dict]:
    """The documents of ``split``. A split manifest must be used one split at a time."""
    is_split = "split" in manifest
    if not is_split:
        if split is not None:
            raise SystemExit("This manifest has no development/test split.")
        return documents
    if split not in SPLITS:
        raise SystemExit("This manifest is split: choose --split dev or --split test.")
    return [doc for doc in documents if doc.get("split") == split]


def check_final_scoring(manifest: dict, split: str | None) -> None:
    """Refuse ``--final`` unless the manifest allows scoring this split."""
    allowed = manifest.get("final_scoring", True)
    if allowed is False:
        raise SystemExit("This manifest is not open for final scoring: split it into "
                         "development and test documents first.")
    if allowed is not True and split != allowed:
        raise SystemExit(f"Final scoring is allowed only on --split {allowed}.")


def raw_dir(manifest: dict, root: Path, default: Path | None = None) -> Path:
    """Where the manifest's files are saved: its ``raw_dir`` (relative to ``root``)."""
    if manifest.get("raw_dir"):
        return root / manifest["raw_dir"]
    return default if default is not None else root / DEFAULT_RAW_DIR
