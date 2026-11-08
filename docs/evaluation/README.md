# Extraction Evaluation

> **Read this first.** The evaluation set is **8 synthetic documents written and annotated
> by the project author** (4 dev, 4 test). The numbers describe behaviour on this small,
> self-made set. They are **not** an estimate of real-world accuracy. They are useful for
> regression tracking and for finding systematic errors.

## Protocol
1. The [annotation guidelines](../../data/evaluation/ANNOTATION_GUIDELINES.md) were written
   before the documents. Gold labels were written from the text, not from extractor output.
2. **Dev split**: scored repeatedly. Three general fixes were made from dev errors (a
   `tooling` tool keyword, dropping model entities inside dotted identifiers, and stripping
   leading articles).
3. **Test split**: scored **once**, after the extractor code was frozen at commit `08fc805`.
   The test errors below were not used to change the extractors.
4. Unit of evaluation: unique `(type, canonical value)` pairs per document, micro-averaged.

One correction after the test run: the **metric code** had a bug. Macro F1 skipped types
with gold items but no predictions, which inflated the rules-only macro F1 from 0.64 to 0.90.
It was fixed in a separate commit and all reports were regenerated. The extractors were not
changed.

## Results (test split, scored once)

| Task | Mode | Support | Precision | Recall | Micro F1 | Macro F1 |
|---|---|---:|---:|---:|---:|---:|
| IOCs | rules | 18 | 1.00 | 1.00 | 1.00 | 1.00 |
| Entities | rules + `en_core_web_sm` | 47 | 0.87 | 0.83 | **0.85** | 0.87 |
| Entities | rules only | 47 | 1.00 | 0.55 | 0.71 | 0.64 |

Dev split for comparison: entities 0.93 / 0.93 / 0.93 (full pipeline). The drop from dev to
test is the expected effect of tuning on dev.

### Per entity type (test, full pipeline)
| Type | Support | P | R | F1 | Main error source |
|---|---:|---:|---:|---:|---|
| attack_technique | 14 | 1.00 | 1.00 | 1.00 | — |
| location | 7 | 1.00 | 1.00 | 1.00 | — |
| threat_actor | 3 | 1.00 | 1.00 | 1.00 | — |
| vulnerability | 1 | 1.00 | 1.00 | 1.00 | — |
| malware | 7 | 1.00 | 0.71 | 0.83 | Names outside ATT&CK (`POWERSTAR`, bare `LockBit`) |
| tool | 6 | 1.00 | 0.50 | 0.67 | Not in the KB (`Evilginx`, `wbadmin`); lowercase `net user` |
| organization | 9 | 0.50 | 0.67 | 0.57 | The model labels protocols and products (HTTPS, SSH, MFA, Group Policy) as ORG |

## What this shows
* **Knowledge-base and rule output is precise** (1.00 precision in rules-only mode). Its
  weakness is **coverage**: entities absent from ATT&CK and the curated list are missed.
* **The statistical model adds recall but most of the errors.** It is the only source of
  organisations and locations (recall 0 without it), and the source of every entity false
  positive on the test set.
* **IOC extraction made no errors here.** The documents contain the traps the extractor was
  designed for (filenames on TLD-like extensions, version strings, namespaces), so this is
  weak evidence. Real reports will contain patterns not anticipated here.

## Improvement directions (not yet implemented)
* An ORG stop-list for protocols and technologies (HTTPS, SSH, MFA, RDP), validated on dev.
* KB coverage: a curated list of common Windows administration binaries (`wbadmin`, `net`).
* Real public advisories (e.g. CISA), independently annotated, to replace self-made data.

## Reports
`dev_full`, `dev_rules_only`, `test_full`, `test_rules_only` (`.md` and `.json`) in this
folder. Reproduce with `python scripts/evaluate_extraction.py --split test [--rules-only]`.

## Real-world evaluation (CISA advisories, Phase 5)
Fourteen public CISA advisories chosen by the project owner: six ransomware, four
state-sponsored, one red-team assessment, one malware, one RMM tool abuse and one exploitation
advisory. Two have no ATT&CK section, so they count for indicators only. Older STIX 1.x XML
bundles are parsed too, and any DTD or entity declaration is refused. **The gold labels come from CISA, not the author:** technique labels are the
ATT&CK IDs each advisory cites, and indicator labels are CISA's STIX bundle. The documents
aren't redistributed. `data/real_world/manifest.json` pins every file by URL and SHA-256.

```text
python scripts/fetch_real_world.py              # verify hand-downloaded files (lists any missing)
python scripts/fetch_real_world.py --record     # first time only: record hashes
python scripts/evaluate_real_world.py           # write gold labels only (inspect first)
python scripts/evaluate_real_world.py --final   # score once -> real_world.md / .json
```

**Results:** [real_world.md](real_world.md) (scored once at `0f1e6e9`) and
[real_world_analysis.md](real_world_analysis.md) (error analysis). Model-only technique
suggestions agree with CISA only 10% of the time; IP and hash extraction are near-perfect.

Method and caveats are in `src/evaluation/real_world.py`. The main question is how often
model-only technique suggestions agree with what CISA cites. A suggestion CISA doesn't cite
isn't necessarily wrong, so this is reported as agreement, not precision.
