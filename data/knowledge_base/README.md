# Knowledge base

Versioned reference data bundled with CyberSleuth. Nothing here is fetched at runtime.

| File | Source | Version | License / terms |
|---|---|---|---|
| `iana_tlds.txt` | https://data.iana.org/TLD/tlds-alpha-by-domain.txt | see first line (`# Version ...`) | IANA public data |
| `attack_entities.json` | Derived from MITRE ATT&CK Enterprise STIX ([attack-stix-data](https://github.com/mitre-attack/attack-stix-data)) by `scripts/build_attack_kb.py` | `attack_version` field (v20.1) | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |
| `curated_entities.json` | Hand-curated: abused admin tools, named vulnerabilities → CVE, attack-technique terms | `version` field | Project (MIT) |
| `entity_rules.json` | Hand-reviewed disambiguation rules for ambiguous ATT&CK names | `version` field | Project (MIT) |

MITRE ATT&CK® is a registered trademark of The MITRE Corporation.

## Refreshing

* **TLDs**: download the new list, review the diff, commit it.
* **ATT&CK**: download `enterprise-attack.json` and run
  `python scripts/build_attack_kb.py path/to/enterprise-attack.json`. Then run
  `pytest tests/test_ner.py`: loading fails if a reviewed rule refers to a name
  that no longer exists, and a test fails if a curated entry now duplicates ATT&CK.
* **Rules**: when adding a name to `context_required_forms`, add a test case to
  `tests/test_ner.py::test_ambiguous_names_need_context`.
