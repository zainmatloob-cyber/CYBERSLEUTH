"""Build data/knowledge_base/cisa_kev.json from the CISA KEV catalogue.

Usage:  python scripts/build_kev_snapshot.py path/to/known_exploited_vulnerabilities.json

Download the catalogue from
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
CISA KEV is a U.S. Government work. Only the fields CyberSleuth uses are kept.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "data" / "knowledge_base" / "cisa_kev.json"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def build(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = {}
    for item in data["vulnerabilities"]:
        cve = item["cveID"].strip()
        if not _CVE.match(cve):
            raise SystemExit(f"Unexpected CVE id {cve!r}")
        entries[cve] = {
            "vendor": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "name": item.get("vulnerabilityName", ""),
            "date_added": item.get("dateAdded", ""),
            "ransomware_use": item.get("knownRansomwareCampaignUse") == "Known",
        }
    return {
        "source": "CISA Known Exploited Vulnerabilities Catalog "
                  "(https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
        "catalog_version": data["catalogVersion"],
        "date_released": data["dateReleased"],
        "count": len(entries),
        "vulnerabilities": dict(sorted(entries.items())),
    }


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python scripts/build_kev_snapshot.py path/to/kev.json")
    data = build(Path(sys.argv[1]))
    OUTPUT.write_text(json.dumps(data, indent=0, ensure_ascii=False) + "\n", encoding="utf-8",
                      newline="\n")
    print(f"Wrote {data['count']} KEV entries (catalog {data['catalog_version']}) to {OUTPUT}")


if __name__ == "__main__":
    main()
