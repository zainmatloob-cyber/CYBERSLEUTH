# Threat classifier: test-split evaluation (scored once)

* Date: 2026-11-07 15:51 UTC · code `daf5fca` · dataset revision `9e52a7f`
* Model: TF-IDF (word 1–2 + char 3–5) + one-vs-rest Logistic Regression, C = 16.0, thresholds tuned on val: {'credential_theft': 0.35, 'data_breach': 0.75, 'phishing': 0.85, 'ransomware': 0.8, 'vulnerability_exploitation': 0.4}
* Labels are **derived** from ATT&CK technique labels (see the dataset card), and the texts are ATT&CK procedure examples. Expect lower performance on real reports.
* 95% CIs: percentile bootstrap over actor/software groups (1,000 resamples).

### TF-IDF + Logistic Regression

| Category | Support | Precision | Recall | F1 | F1 95% CI |
|---|---:|---:|---:|---:|---|
| credential_theft | 104 | 0.88 | 0.91 | 0.90 | 0.85–0.94 |
| data_breach | 50 | 0.82 | 0.84 | 0.83 | 0.74–0.90 |
| phishing | 36 | 0.91 | 0.83 | 0.87 | 0.78–0.95 |
| ransomware | 14 | 1.00 | 0.50 | 0.67 | 0.18–0.88 |
| vulnerability_exploitation | 30 | 0.83 | 0.97 | 0.89 | 0.78–0.96 |

Macro F1: **0.83** (95% CI 0.73–0.88) · exact match 0.97 · n = 2149

### Rule baseline (same categories as the model)

| Category | Support | Precision | Recall | F1 | F1 95% CI |
|---|---:|---:|---:|---:|---|
| credential_theft | 104 | 0.63 | 0.82 | 0.71 | 0.63–0.78 |
| data_breach | 50 | 0.42 | 0.74 | 0.54 | 0.42–0.64 |
| phishing | 36 | 0.47 | 0.75 | 0.57 | 0.48–0.67 |
| ransomware | 14 | 0.63 | 0.86 | 0.73 | 0.55–0.86 |
| vulnerability_exploitation | 30 | 0.51 | 0.97 | 0.67 | 0.53–0.78 |

Macro F1: **0.64** (95% CI 0.59–0.69) · exact match 0.84 · n = 2149

Rule-only categories:

* `ddos` (rules only): support 1, TP 1, FP 0, FN 0. Too few examples for a meaningful score.

Majority baseline (always `other`): macro F1 = 0.00

_Report revision note: the first version of this report computed the rules' macro F1 including `ddos` (1 test example), giving 0.70 instead of the comparable 0.64. The model is unchanged (retraining is deterministic)._

### Confusion matrix (model, primary label)

| true ↓ / predicted → | credential | data_breac | phishing | ransomware | vulnerabil | other |
|---|---:|---:|---:|---:|---:|---:|
| credential_theft | 95 | 0 | 0 | 0 | 0 | 9 |
| data_breach | 0 | 42 | 0 | 0 | 0 | 8 |
| phishing | 0 | 0 | 30 | 0 | 0 | 6 |
| ransomware | 0 | 0 | 0 | 7 | 0 | 7 |
| vulnerability_exploitation | 0 | 0 | 0 | 0 | 29 | 1 |
| other | 13 | 9 | 3 | 0 | 6 | 1884 |

### Confusion matrix (rules, primary label)

| true ↓ / predicted → | credential | data_breac | phishing | ransomware | vulnerabil | other |
|---|---:|---:|---:|---:|---:|---:|
| credential_theft | 85 | 2 | 0 | 0 | 0 | 17 |
| data_breach | 0 | 37 | 0 | 0 | 0 | 13 |
| phishing | 2 | 0 | 25 | 0 | 1 | 8 |
| ransomware | 0 | 0 | 0 | 12 | 0 | 2 |
| vulnerability_exploitation | 1 | 0 | 0 | 0 | 28 | 1 |
| other | 46 | 46 | 29 | 5 | 25 | 1764 |
