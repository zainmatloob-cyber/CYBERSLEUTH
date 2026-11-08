# Model card: ATT&CK technique mapper

| | |
|---|---|
| Task | Map a CTI sentence to MITRE ATT&CK (v20.1) techniques, with an assertion status |
| Explicit mapping | Technique IDs in the text (revoked IDs translated), multi-word ATT&CK technique names, and curated technique terms with hand-assigned IDs. Deterministic, no score |
| Model mapping | TF-IDF (word 1–2 + char 3–5) → LinearSVC over **196 parent techniques**, C = 2, `class_weight="balanced"`. Suggests the top technique when its decision score ≥ −0.647 (chosen on val as the smallest threshold with selective precision ≥ 0.80, a target fixed beforehand). Runner-up techniques are kept as alternatives. Scores are SVM margins, **not probabilities** |
| Assertion status | NegEx-style cues within the clause: `observed` / `capability` / `possible` / `negated` |
| Verification | Every mapping starts `unverified` (analyst review in Phase 4) |
| Training data | Train split of the [threat-category dataset](../datasets/threat_categories.md). v16 labels translated to active v20.1 parents (15 revoked labels; 254 sentences affected) |
| Artifact | `models/technique_model.joblib` (git-ignored; `python scripts/train_technique_model.py --final`) |

## Test results (2,149 sentences, 162 unseen actor/software groups, scored once at `53c514b`)

| Metric | Value (95% group-bootstrap CI) |
|---|---|
| Model top-1 accuracy | **0.82** (0.80–0.83) |
| Model top-3 accuracy | 0.93 (0.92–0.94) |
| Model top-5 accuracy | 0.95 (0.94–0.96) |
| Coverage at threshold | 0.97 (0.96–0.98) |
| Selective precision (top-1 correct when not abstaining) | 0.83 (0.81–0.84) |
| Explicit matcher: sentences with ≥1 match | 9.6% |
| Explicit matcher: precision vs. gold | 0.63 (lower bound, see below) |

Validation (used for choosing C and the threshold): top-1 0.79, selective precision 0.81 at
coverage 0.97.

## Findings
* **Abstention barely matters on this data.** Top-1 accuracy (0.82) is already close to the
  precision target, so the model abstains on only 3% of sentences. Every ATT&CK sentence
  describes some technique. Real reports contain headings, background and recommendations
  that describe none, and the dataset has **no "no technique" examples**, so the
  **false-positive rate on real reports is unmeasured**. Model mappings are presented as
  suggestions.
* **Explicit precision is understated.** Gold has one technique per sentence, while sentences
  often involve several. For example, "Briba uses rundll32 within Registry Run Keys / Startup
  Folder entries" correctly matches T1547.001, but gold lists only T1218.
* **Explicit matcher error source (structural, fixable without test data).** Some ATT&CK
  names are generic phrases or shared between techniques: "Web Services" (T1583.006 and
  T1584.006), "Social Media" (T1593.001), "Spearphishing Link" (T1566.002 and T1598.003).
  Candidate fix: drop names shared by two or more techniques, and require context for
  Resource Development names. To be validated on val.
* **Assertion status on ATT&CK text:** 65% observed, 33% capability ("X can …"), 1.5%
  possible, 0.3% negated. The 7 negated sentences are all false negations: conditions ("will
  terminate if they are *not* present"), "not only", and purpose clauses ("so they could
  *not* be modified"). Not fixed here, because the examples come from the test split.

## Limitations
* **It doesn't transfer to real reports at the current threshold.** On 14 CISA advisories,
  only 10% of model-only suggestions (55 of 550) match a technique CISA cites. Below a decision
  score of 0.25 (85% of suggestions), agreement is 3%; at 0.75 or above it is 65%. See
  [real-world analysis](../evaluation/real_world_analysis.md).
* Trained on ATT&CK procedure prose. Real reports differ in style and length.
* Parent-technique level only for the model. Sub-techniques come only from explicit matches.
* Assertion detection is a cue heuristic without an annotated evaluation set.
* The model file is a pickle. Load only files produced by this project.
