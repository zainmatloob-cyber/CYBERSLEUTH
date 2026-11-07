"""Build data/knowledge_base/attack_entities.json from a MITRE ATT&CK Enterprise STIX bundle.

Extracts active (not revoked, not deprecated) groups, malware and tools with
their ATT&CK IDs and aliases. The raw bundle (~55 MB) is not committed; only
this compact derivative is.

Download the bundle from
https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json)

Usage:  python scripts/build_attack_kb.py path/to/enterprise-attack.json

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. ATT&CK data is
used under the ATT&CK Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "data" / "knowledge_base" / "attack_entities.json"
STIX_TYPES = {"intrusion-set": "threat_actor", "malware": "malware", "tool": "tool"}


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build(bundle_path: Path) -> dict:
    with bundle_path.open(encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]

    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    entries = []
    for obj in objects:
        kind = STIX_TYPES.get(obj["type"])
        if kind is None or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_id = _attack_id(obj)
        if attack_id is None:
            continue
        aliases = obj.get("aliases") or obj.get("x_mitre_aliases") or []
        names = sorted({a.strip() for a in aliases if a.strip()} - {obj["name"]})
        entries.append({"id": attack_id, "type": kind, "name": obj["name"], "aliases": names})

    entries.sort(key=lambda e: e["id"])
    return {
        "source": "MITRE ATT&CK Enterprise (https://attack.mitre.org/)",
        "attack_version": collection.get("x_mitre_version"),
        "attack_modified": collection.get("modified"),
        "terms_of_use": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        "entries": entries,
    }


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python scripts/build_attack_kb.py path/to/enterprise-attack.json")
    data = build(Path(sys.argv[1]))
    OUTPUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8",
                      newline="\n")
    print(f"Wrote {len(data['entries'])} entries (ATT&CK v{data['attack_version']}) to {OUTPUT}")


if __name__ == "__main__":
    main()
