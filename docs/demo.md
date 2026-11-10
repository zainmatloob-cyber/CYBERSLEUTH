# Demo guide

A 10-minute walkthrough using only the synthetic files in `data/samples/`. Every indicator
in them is fictional or from a reserved range (RFC 5737 IPs, `example.com` domains), so the
demo is safe to show anywhere.

Start the app (`streamlit run app.py`, or the Docker image) and open the **Document
Analysis** page.

## 1. Analyse a report (3 min)

Upload `data/samples/synthetic_advisory.pdf`, a two-page advisory about the fictional actor
GLASS PANTHER.

* **Summary:** 8 indicators of 7 types, entities (the tool PowerShell plus technique terms
  such as "Spearphishing"), ATT&CK techniques and a risk score, all in about a second.
  GLASS PANTHER isn't recognised as an actor: it is fictional and not in the knowledge base,
  and the app doesn't guess.
* **🎯 IOCs:** the defanged forms in the text (`hxxps://invoice-portal[.]example[.]com`,
  `203.0.113[.]77`, `billing[@]…`) are refanged to canonical values. The original form and
  page are kept as evidence. The RFC 5737 addresses carry the `documentation_range` flag,
  and the `example.com` names `reserved_domain`.
  **Every indicator starts "unverified":** extraction never claims something is malicious.
* **🗺️ ATT&CK:** Phishing (T1566) and Data Encrypted for Impact (T1486), found from the
  text. Each one shows the sentence it came from and its assertion status (observed /
  capability / possible / negated).
* **⚠️ Risk:** every component of the score with its weight and a plain-language reason,
  plus a separate confidence level and the score's limitations.

## 2. Analyst verification (3 min)

Upload `data/samples/synthetic_advisory.txt` (the same report as plain text). It adds
**Multi-Factor Authentication (T1556.006)**, matched from the recommendation "enforce
multi-factor authentication". This is a real weakness of name matching: an ATT&CK technique
name used as everyday advice. The real-world evaluation found the same pattern
([real_world_analysis.md](evaluation/real_world_analysis.md)).

1. In **🗺️ ATT&CK**, select T1556.006 and set the verdict to **rejected**. Add a note
   ("mitigation advice, not attacker behaviour") and click **Save verdict**.
2. The **risk score is recalculated at once,** from 95.2 to 94.5: rejected techniques count
   for nothing. The ATT&CK count in the summary drops from 3 to 2.
3. In **🎯 IOCs**, set the verdict for `198.51.100.23` to **malicious**. Each verdict is
   written to an audit trail with the analyst name and time.

**Model suggestions:** in real reports, model-only ATT&CK suggestions are hidden by default
behind "Show N unverified model suggestion(s)". They don't count towards risk until an
analyst confirms them. Only suggestions above the score cut-off chosen on real advisories are
shown ([model card](models/technique_mapper.md)).

## 3. Edge cases (1 min)

* **Scanned PDF:** upload `data/samples/synthetic_scanned.pdf`. It is rejected with "No
  extractable text: the document appears to be scanned images. OCR is not supported yet."
  The app says what happened rather than returning an empty analysis.
* **Disguised file:** rename any `.exe` to `.pdf` and upload it. The type is detected from
  the content, not the name, so it is rejected.
* **Duplicate:** upload the same PDF again under another name. The stored analysis reopens,
  with its verdicts.

## 4. Cross-document views (2 min)

After analysing all three sample formats (`.pdf`, `.txt`, `.docx`):
* **History:** every analysis, reopenable, with delete-with-confirmation.
* **Dashboard:** documents by risk band, top categories and tactics, and a tactic ×
  document heatmap. Every chart has a table view.
* **IOC Explorer:** indicators seen in two or more documents, with a verdict filter.
* **ATT&CK Explorer:** for each technique, the documents where it counts (explicit or
  confirmed) and where it was only a model lead.

## 5. Export (1 min)

**📤 Export** on any analysis:
* **JSON:** the full structured report, schema 1.1 ([reports.md](reports.md)).
* **CSV:** a ZIP of 10 tables plus a README, with a formula-injection guard.
* **PDF:** an executive summary with evidence.

Network indicators are defanged in every format, so a report can be mailed without creating
live links.

## Talking points

* **Rules and models are kept apart,** and every finding shows its evidence and how it was
  found.
* **Measured on real advisories,** not only on synthetic text: IP and hash extraction are
  near-perfect. Model suggestions only became usable after a cut-off chosen on separate
  development advisories, and that cut-off was tested once on unseen ones
  ([README § Evaluation](../README.md#evaluation)).
* **Security by design:** untrusted uploads, no network access, escaped output and a
  documented review ([security.md](security.md)).
