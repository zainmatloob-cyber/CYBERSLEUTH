# Model card: threat-category classifier

| | |
|---|---|
| Task | Multi-label classification of a CTI **sentence** into threat categories |
| Model | TF-IDF (word 1–2-grams + character 3–5-grams) → one-vs-rest Logistic Regression (`class_weight="balanced"`, liblinear, C = 16) |
| Categories learned | `credential_theft`, `data_breach`, `phishing`, `ransomware`, `vulnerability_exploitation`. `other` is predicted when no category reaches its threshold |
| Categories left to rules | `ddos` (7 examples in the whole dataset), `malware` (cannot be derived per sentence) |
| Thresholds (tuned on val) | credential_theft 0.35 · data_breach 0.75 · phishing 0.85 · ransomware 0.80 · vulnerability_exploitation 0.40 |
| Training data | [Threat-category dataset](../datasets/threat_categories.md): 10,313 train sentences from ATT&CK procedure examples, with **derived** labels |
| Artifact | `models/threat_classifier.joblib` (git-ignored; rebuilt by `python scripts/train_threat_classifier.py --final`, deterministically) |

## Evaluation (test split, 2,149 sentences, 162 unseen actor/software groups, scored once)

| Category | Support | Model F1 (95% CI) | Rules F1 (95% CI) |
|---|---:|---|---|
| credential_theft | 104 | **0.90** (0.85–0.94) | 0.71 (0.63–0.78) |
| vulnerability_exploitation | 30 | **0.89** (0.78–0.96) | 0.67 (0.53–0.78) |
| phishing | 36 | **0.87** (0.78–0.95) | 0.57 (0.48–0.67) |
| data_breach | 50 | **0.83** (0.74–0.90) | 0.54 (0.42–0.64) |
| ransomware | 14 | 0.67 (0.18–0.88) | **0.73** (0.55–0.86) |
| **Macro F1** | | **0.83** (0.73–0.88) | 0.64 (0.59–0.69) |

Majority baseline (always `other`): macro F1 0.00. Validation macro F1 was 0.89. The drop
on test is expected, because C and the thresholds were chosen on val.

Full report with the confusion matrices: [threat_classifier_test.md](../evaluation/threat_classifier_test.md).

## Findings
* **The model beats the rules on 4 of 5 categories.** Rules have high recall but low
  precision. They fire on any *mention* (e.g. "Ryuk ransomware has used `net view`"), while
  labels mark the *behaviour* a sentence describes.
* **Ransomware is the exception.** Model recall is 0.50 (7 of 14) with a very wide CI. At
  threshold 0.80 the model misses half of the test cases; rules find 12 of 14. A hybrid
  (rules OR model for ransomware) is a plausible improvement, and must be chosen on val, not test.
* **No cross-category confusion.** In the confusion matrix every error is between a category
  and `other`. The errors are coverage and threshold errors, not mix-ups between categories.
* **Learned features are mostly behavioural**: "keystrokes", "passwords", "dump" →
  credential theft; "encrypt files", "shadow copies", "vssadmin" → ransomware; "cve",
  "exploited", "sql injection" → exploitation.
  * **Spurious signal:** "sleep" / "can sleep" → data_breach (exfiltration over C2 co-occurs
    with beaconing language).
  * **Some name memorisation:** the char n-gram "cry" in ransomware (WannaCry-style names).

## Scores are not probabilities
Outputs are Logistic Regression scores trained with class re-weighting. They are useful for
ranking and thresholding but **not calibrated**. The UI and reports call them "scores".

## Limitations and intended use
* Trained and tested on short, edited ATT&CK procedure sentences. Real reports are longer
  and noisier, so expect lower performance.
* Labels come from a heuristic technique-to-category mapping. The model inherits its errors.
* Report-level categories (aggregated from sentences) are not validated by this dataset.
* Intended to support analysts by flagging likely categories with evidence sentences.
  Not for automated decisions.
* The model file is a pickle. Load only files produced by this project.
