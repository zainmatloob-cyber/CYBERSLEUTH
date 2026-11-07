"""Build the ATT&CK knowledge-base files from a MITRE ATT&CK Enterprise STIX bundle.

Outputs (data/knowledge_base/):
* ``attack_entities.json``   active groups, malware and tools with ATT&CK IDs and aliases.
* ``attack_techniques.json`` active techniques and sub-techniques (ID, name, tactics,
  short description), plus a map of revoked or deprecated technique IDs to their
  replacements, so labels from older ATT&CK versions can be translated.

The raw bundle (~55 MB) is not committed; only these compact derivatives are.
Download the bundle from
https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json)

Usage:  python scripts/build_attack_kb.py path/to/enterprise-attack.json

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. ATT&CK data is
used under the ATT&CK Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB_DIR = ROOT / "data" / "knowledge_base"
STIX_TYPES = {"intrusion-set": "threat_actor", "malware": "malware", "tool": "tool"}
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_MAX_DESCRIPTION = 300


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _short_description(text: str) -> str:
    text = _MARKDOWN_LINK.sub(r"\1", _CITATION.sub("", text or ""))
    text = " ".join(text.split())
    first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    return first if len(first) <= _MAX_DESCRIPTION else first[: _MAX_DESCRIPTION - 1] + "…"


def _header(objects: list[dict]) -> dict:
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    return {
        "source": "MITRE ATT&CK Enterprise (https://attack.mitre.org/)",
        "attack_version": collection.get("x_mitre_version"),
        "attack_modified": collection.get("modified"),
        "terms_of_use": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
    }


def build_entities(objects: list[dict]) -> dict:
    entries = []
    for obj in objects:
        kind = STIX_TYPES.get(obj["type"])
        if kind is None or not _active(obj):
            continue
        attack_id = _attack_id(obj)
        if attack_id is None:
            continue
        aliases = obj.get("aliases") or obj.get("x_mitre_aliases") or []
        names = sorted({a.strip() for a in aliases if a.strip()} - {obj["name"]})
        entries.append({"id": attack_id, "type": kind, "name": obj["name"], "aliases": names})
    entries.sort(key=lambda e: e["id"])
    return {**_header(objects), "entries": entries}


def build_techniques(objects: list[dict]) -> dict:
    by_stix = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
    techniques, inactive = [], {}
    for obj in by_stix.values():
        attack_id = _attack_id(obj)
        if attack_id is None:
            continue
        if not _active(obj):
            inactive[obj["id"]] = attack_id
            continue
        techniques.append({
            "id": attack_id,
            "name": obj["name"],
            "tactics": sorted(p["phase_name"] for p in obj.get("kill_chain_phases", [])
                              if p.get("kill_chain_name") == "mitre-attack"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "description": _short_description(obj.get("description", "")),
        })

    # Revoked techniques point to their replacement through "revoked-by" relationships.
    replacements: dict[str, str] = {}
    for rel in objects:
        if rel["type"] == "relationship" and rel.get("relationship_type") == "revoked-by":
            source, target = by_stix.get(rel["source_ref"]), by_stix.get(rel["target_ref"])
            if source and target and _attack_id(source) and _attack_id(target):
                replacements[_attack_id(source)] = _attack_id(target)
    deprecated = sorted(set(inactive.values()) - set(replacements))

    techniques.sort(key=lambda t: t["id"])
    return {**_header(objects), "techniques": techniques,
            "revoked_to": dict(sorted(replacements.items())),
            "deprecated_without_replacement": deprecated}


def _write(name: str, data: dict) -> None:
    path = KB_DIR / name
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8",
                    newline="\n")
    print(f"Wrote {path}")


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python scripts/build_attack_kb.py path/to/enterprise-attack.json")
    with Path(sys.argv[1]).open(encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]
    entities = build_entities(objects)
    techniques = build_techniques(objects)
    _write("attack_entities.json", entities)
    _write("attack_techniques.json", techniques)
    print(f"{len(entities['entries'])} entities, {len(techniques['techniques'])} techniques, "
          f"{len(techniques['revoked_to'])} revoked->replacement, "
          f"{len(techniques['deprecated_without_replacement'])} deprecated "
          f"(ATT&CK v{techniques['attack_version']})")


if __name__ == "__main__":
    main()
