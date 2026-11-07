# CyberSleuth Methodology

This document records how each stage works, why it was designed that way, and
its known limitations. It grows with each phase. Every claim here reflects
implemented and tested behaviour.

## 1. Document ingestion (Phase 1)

### 1.1 Validation
Files are identified by their content, not their extension:

| Type | Rule |
|---|---|
| PDF | `%PDF-` within the first 1 KiB (the PDF format allows leading bytes) |
| DOCX | ZIP signature, plus `[Content_Types].xml` and `word/document.xml` in the archive |
| TXT | UTF-16 BOM, or no NUL bytes and ≤ 5 % non-whitespace control bytes in the first 8 KiB |
| Legacy `.doc` (OLE) | Rejected with a hint to save as `.docx` |

The extension must match the detected content type.

### 1.2 Extraction
* **PDF** (PyMuPDF): text extracted per page in reading order (`sort=True`).
  * A page with fewer than 20 extractable characters that contains an image is
    treated as scanned.
  * PDFs that need a password to open are rejected. PDFs restricted only by an
    owner password (copy/print permissions) are still read.
  * Damaged PDFs that MuPDF can repair are accepted with a warning.
* **DOCX** (python-docx): paragraphs and tables in document order.
  * Each table row is written as one line, with cells separated by ` | `.
  * Horizontally merged cells are de-duplicated.
* **TXT**: encodings are tried in this order:
  1. An encoding declared by a BOM (UTF-8 or UTF-16).
  2. Strict UTF-8.
  3. Windows-1252.

  Undecodable bytes become U+FFFD and produce a warning.

### 1.3 Cleaning
Design rule: **cleaning must never change an Indicator of Compromise.** The
tests check that defanged URLs, bracketed IPs, hashes, CVE IDs, Windows paths
and `ip:port` values pass through byte-for-byte.

Steps, in order:
1. Normalise line endings.
2. Unicode NFKC (ligatures, full-width characters, non-breaking spaces).
3. Remove invisible characters (zero-width characters, soft hyphen, BOM).
4. Map typographic quotes and hyphens to ASCII.
5. Remove control characters.
6. Rejoin words hyphenated across lines.
7. Collapse whitespace.

Rejoining (step 6) drops the hyphen only for lowercase prose fragments
(`mal-\nware` → `malware`). It keeps the hyphen when either fragment contains
digits, dots, slashes, brackets, `@`, `:`, `_`, `=`, or starts with an uppercase
letter (`evil-\nsite.com` → `evil-site.com`, `CVE-\n2024-3400` → `CVE-2024-3400`).

### 1.4 Sentence segmentation
A rule-based splitter, chosen because it is predictable on IOC-heavy text:
* A blank line always ends a sentence. A single line break is treated as a wrapped line.
* `.`, `!` or `?` ends a sentence only when followed by whitespace and then an
  uppercase letter, digit, or opening quote/bracket. Indicators such as
  `192.168.1.1` and `evil.com` never contain whitespace after a dot, so they
  are never split.
* A fixed list of abbreviations (`e.g.`, `Inc.`, `U.S.`, `Jan.`, …) and
  single-letter initials do not end a sentence.
* Sentences longer than 1,000 characters are split at every line break, then at
  spaces. This mainly affects unpunctuated IOC lists.
* Each sentence stores its page number and character positions.

## 2. IOC extraction (Phase 2)

Implemented in `src/nlp/ioc_extractor.py`. It never resolves or contacts any value.

1. **Matching on the original text.** The regexes accept common defanging directly
   (`[.]`, `(.)`, `{.}`, `[dot]`, `[@]`, `[at]`, `hxxp`, `fxp`, `[:]`, `[://]`), so character
   positions stay exact. The refanged value is stored separately from the text as written.
2. **Validation for each type.**
   * IPv4 is parsed with `ipaddress`, which rejects octets over 255 and leading zeros.
     Matches preceded by `v`, `ver`, `version` or `build` are rejected.
   * Domains need a TLD from the bundled IANA snapshot (or an RFC 6761 special-use name).
   * Hashes must be bounded by non-hex characters and mix digits and letters.
   * CVE years must be between 1999 and next year.
3. **False-positive guards, derived from data.**
   * 11 real TLDs collide with file extensions (`zip py md sh app cab mov one pl rs so`).
     These are accepted as domains only when written defanged.
   * Title-case dotted names (`System.Management`) are rejected because `.management`,
     `.exchange` and `.security` are real TLDs.
4. **Overlap priority:** URL > email > CVE > IPv4 > domain > hash. A host inside a URL is
   not counted twice.
5. **De-duplication** by `(type, value)`. Every occurrence keeps its page, position,
   sentence index and sentence text.

Flags (`documentation_range`, `private`, `reserved_domain`, …) describe what a value is.
Every indicator is `unverified`: being extracted is not a verdict.

## 3. Entity recognition (Phase 2)

Implemented in `src/nlp/entity_extractor.py`. When spans overlap, the earlier source wins:

| Priority | Source | Provenance label |
|---|---|---|
| 1 | MITRE ATT&CK v20.1 groups, malware and tools with aliases (1,716 names) | `kb:mitre-attack` |
| 2 | Curated tools, named vulnerabilities (→ CVE), attack-technique terms | `kb:curated` |
| 3 | Actor naming patterns (APT/FIN/UNC/TA/DEV/Storm/UAC/TAG, vendor animal and weather names) | `rule:actor-pattern` |
| 4 | spaCy `en_core_web_sm` ORG / GPE / LOC | `model:spacy` |

**Disambiguation.**
* 132 hand-reviewed ATT&CK names that are ordinary words (`Cuba`, `Royal`, `Silence`), plus
  every name of 3 characters or fewer, count only when the same sentence contains a keyword
  for their type.
* Names shared by several entries (e.g. `Sofacy`: group or malware) are resolved by
  context. The other candidates are kept in `alternatives`.

**Model output filtering.** Model entities are dropped when they:
* look like identifiers (domains, CVE IDs, hashes, paths);
* span a whole sentence (usually a heading);
* are part of a dotted identifier.

A leading "the" is removed from model entity names.

**Confidence.** None. The rules are deterministic, and `en_core_web_sm` does not expose
calibrated per-entity probabilities, so no score is invented.

Entities are **mentions**: "Phishing was not involved" still yields Phishing. Deciding
whether a behaviour actually occurred belongs to the ATT&CK mapping stage (Phase 3).

## 4. Evaluation (Phase 2)

8 synthetic, author-annotated documents, split 4 dev and 4 test. The test split was scored
once, with the extractor code frozen. Full protocol, per-type results and every error are
in [evaluation/README.md](evaluation/README.md).

| Task (test split) | Precision | Recall | F1 |
|---|---:|---:|---:|
| IOCs | 1.00 | 1.00 | 1.00 |
| Entities (rules + model) | 0.87 | 0.83 | 0.85 |
| Entities (rules only) | 1.00 | 0.55 | 0.71 |

These numbers describe a small, self-made set, not real-world accuracy.

## 5. Known limitations

| Area | Limitation | Possible mitigation |
|---|---|---|
| IOC | No IPv6, SHA-512, file paths, registry keys or cryptocurrency addresses | More patterns with the same validation approach |
| IOC | Title-case real domains (`Evil.Com`) are rejected by the namespace guard | Context-aware guard |
| IOC | `evil.com.zz` (an invalid TLD after a valid one) is rejected as a whole | Fall back to the longest valid suffix |
| IOC | The part of an email before `@` is lowercased | Keep the original case |
| NER | Entities absent from ATT&CK and the curated list are missed (test recall: tools 0.50) | Broader curated lists; a trained NER model with labelled data |
| NER | Ambiguous names without a context keyword in the same sentence are missed (`Tor`, lowercase `net`) | Context window wider than one sentence |
| NER | The model labels protocols and products as ORG (test ORG precision 0.50) | Stop-list validated on dev; a larger model |
| NER | About 730 sentences/s; a 20 MB text file takes minutes | Parallel `nlp.pipe`, background jobs |
| Evaluation | Small, synthetic, self-annotated set | Independently annotated public advisories |
| OCR | Scanned pages are detected but not read | Optional Tesseract integration |
| DOCX | Headers, footers, footnotes, comments and text boxes are not extracted | Read the extra document parts |
| DOCX | Nested tables are flattened into their cell text | Walk tables recursively |
| PDF | Complex multi-column layouts and tables can be read in the wrong order | Block-level layout analysis |
| PDF | Headings without punctuation merge into the following sentence | Line-length and font heuristics, or spaCy |
| Cleaning | A word already containing a hyphen loses it if the line breaks there (`pre-\nauthentication` → `preauthentication`) | Dictionary lookup |
| Segmentation | `Appendix A. The…` is not split (the single capital letter is treated as an initial) | Context-aware initial detection |
| Segmentation | The abbreviation list is English-only and fixed | Statistical splitter (Phase 2 evaluation) |
| TXT | Windows-1252 fallback can mis-decode other single-byte encodings | Statistical charset detection |

## 6. Data used

| Data | Origin | Purpose |
|---|---|---|
| `data/samples/` | Synthetic, generated by `scripts/make_samples.py` (RFC 5737 IPs, `example.*` domains, EICAR MD5, fictional actor) | Demos, end-to-end tests |
| `data/evaluation/` | Synthetic, author-written and author-annotated | Extraction evaluation (section 4) |
| `data/knowledge_base/iana_tlds.txt` | IANA TLD list, version 2026110700 | Domain validation |
| `data/knowledge_base/attack_entities.json` | Derived from MITRE ATT&CK Enterprise v20.1 | Entity knowledge base |
| `data/knowledge_base/curated_entities.json`, `entity_rules.json` | Hand-curated and reviewed | Curated entities, disambiguation |

No real incident data or real live indicators are used anywhere in the project.

## 7. Threat classification (Phase 3)

**Data.** Hugging Face `sarahwei/cyber_MITRE_technique_CTI_dataset_v16` @ `9e52a7f`
(SHA-256 verified). It contains ATT&CK v16 procedure sentences labelled with techniques.
Categories are **derived** with the versioned `technique_category_map.json`; Data Breach
is defined as the ATT&CK Exfiltration tactic. The split is grouped by actor/software
through the ATT&CK knowledge base (no group in more than one split). See the
[dataset card](datasets/threat_categories.md).

**Models.**
* A keyword rule baseline with evidence terms for every category. It is the only source
  for `ddos` and `malware`.
* TF-IDF (word + char n-grams) with one-vs-rest balanced Logistic Regression. C and the
  per-category thresholds are chosen on val; the test split is scored once.

**Results (test).** Macro F1 0.83 (95% CI 0.73–0.88) vs. 0.64 for the rules. The model wins
on 4 of 5 categories; the rules win on ransomware, where model recall is 0.50 with a very
wide CI. Details and confusion matrices are in the [model card](models/threat_classifier.md).

**Reporting corrections.** The first version of the report averaged the rules' macro F1
over a different category set: it included `ddos`, which has one test sentence. It was
corrected to the comparable value, and the model was unchanged (retraining is
deterministic).

**Distinction to keep in mind.** The rules detect *mentions*, while the labels describe
*behaviour*. This is the same mention-vs-evidence problem the ATT&CK mapping stage
must handle.

## 8. ATT&CK technique mapping (Phase 3)

`src/intelligence/mitre_mapper.py` combines **explicit** mappings and **model** mappings:
* Explicit (deterministic) mappings come from technique IDs (revoked IDs translated through
  `attack_techniques.json`), multi-word ATT&CK names, and curated terms with verified IDs.
* Model mappings come from a LinearSVC over 196 parent techniques, with an abstention
  threshold chosen on val.

Each piece of evidence carries an assertion status
(`observed`/`capability`/`possible`/`negated`, from `src/intelligence/assertion.py`), and
each mapping starts `unverified`. This is the **mention vs. evidence** distinction: "Phishing
was not involved" yields a *negated* T1566 mapping, not evidence of phishing.

Test results (scored once): model top-1 0.82 (95% CI 0.80–0.83) and top-5 0.95. The explicit
matcher's precision of 0.63 is a lower bound because the gold labels are single-label.
Abstention cannot be evaluated properly, because the data has no "no technique" sentences.
Details, error analysis and open fixes are in the [model card](models/technique_mapper.md).
