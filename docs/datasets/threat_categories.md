# Dataset card: threat categories

| | |
|---|---|
| Source | Hugging Face [`sarahwei/cyber_MITRE_technique_CTI_dataset_v16`](https://huggingface.co/datasets/sarahwei/cyber_MITRE_technique_CTI_dataset_v16), revision `9e52a7fb9400097cfe09756ce09256279dfa8d82` |
| Content | MITRE ATT&CK v16 Enterprise procedure examples (one sentence each), labelled with an ATT&CK technique |
| License | Apache-2.0 (dataset). Content derived from MITRE ATT&CK®, used under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |
| Raw file SHA-256 | `bcac09a30da335f59957ac9e7581749f4040d9857d057a70390baac4371c8855` |
| Category labels | **Derived** from technique labels with `data/knowledge_base/technique_category_map.json` (version 2026-11-07) |
| Build | `python scripts/prepare_threat_dataset.py` |

## Processing
1. Citation markers and HTML tags removed; whitespace collapsed.
2. Rows with identical text merged (union of techniques → multi-label).
3. Techniques mapped to categories (sub-techniques inherit their parent). `other` = no category applies.
4. Each sentence grouped by the actor, software or campaign it describes, using longest-prefix
   matching against the ATT&CK knowledge base, so aliases share a group. The split is
   assigned by hashing the group: about 70/15/15, with no group in more than one split.

## Statistics
* Unique sentences: **13,918** in 1,082 groups
* Sentences with more than one technique: 75; with more
  than one category: 0
* Groups appearing in more than one split: **0** (must be 0)
* Train | Val | Test: 10,313 (779 groups) | 1,456 (141 groups) | 2,149 (162 groups)

| Category | Train | Val | Test |
|---|---:|---:|---:|
| phishing | 207 | 17 | 36 |
| ransomware | 79 | 14 | 14 |
| vulnerability_exploitation | 118 | 16 | 30 |
| credential_theft | 486 | 59 | 104 |
| data_breach | 234 | 34 | 50 |
| ddos | 6 | 0 | 1 |
| other | 9183 | 1316 | 1914 |

## Known limitations
* **Derived labels.** Categories come from a heuristic mapping, not from annotators labelling
  categories. The model can only be as right as that mapping.
* **Sentence level.** Each example is one procedure sentence. Report-level categories in
  CyberSleuth are aggregated from sentence predictions, and that aggregation is not
  validated by this dataset.
* **ATT&CK-style language.** Procedure examples are short, edited and formulaic
  ("X has used Y to …"). Real reports are longer and noisier, so performance is expected to
  be lower on them.
* **Category gaps.** `ddos` has too few examples to learn from. `malware` cannot be derived
  per sentence. Both are handled by the rule-based baseline only.
* **Severe imbalance.** `other` dominates. Use macro-averaged metrics.
* **Version gap.** The dataset is ATT&CK v16; the category map was checked against v20.1.
  Technique IDs used in the map are stable across these versions.
