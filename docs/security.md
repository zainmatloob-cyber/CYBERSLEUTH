# Security review

Review of CyberSleuth against the security rules in the project brief, carried out on
2026-11-08 (Phase 5 hardening). Each control is pinned by a test; most are in
`tests/test_security.py`.

**Scope:** the Streamlit app (`app.py`, `src/`). The evaluation scripts in `scripts/` run
only on files the project owner downloads and are outside the threat model, except where
noted.

## Threat model

* **The main threat is an uploaded document.** It may be malformed, hostile or huge. Its
  text, file name and metadata are attacker-controlled, and the text is displayed, stored
  and exported.
* **The app is a single-user analyst tool.** It has no login. If it is deployed for several
  people, put it behind an authenticating proxy (see [Deployment limits](#deployment-limits)).
* **Model files and knowledge bases are trusted project files.** They are never accepted
  from users.

## Controls

| Rule from the brief | How it's enforced | Test |
|---|---|---|
| Treat uploads as untrusted; validate content and size | Size cap (20 MB, plus Streamlit's 25 MB hard cap); type detected from magic bytes, not the extension; DOCX ZIP-bomb guard (100 MB uncompressed, 2,000 entries); PDF page cap (500); encrypted PDFs rejected; file names stripped of directories and control characters | `test_validator.py`, `test_readers.py` |
| | **New:** extracted text capped at 2,000,000 characters (`CYBERSLEUTH_MAX_TEXT_CHARS`). Compressed PDF streams can expand far beyond the file size; the PDF reader stops at the first page over the cap | `test_security.py` |
| Never execute uploaded content | PyMuPDF only extracts text: no PDF JavaScript, embedded files or links are acted on. DOCX XML is parsed without entity resolution (no XXE). STIX 1.x XML in the evaluation refuses any DTD or entity declaration. No `eval`, `exec` or `subprocess` in the app | `test_security.py` (XXE payload; static check), `test_real_world.py` (DTD refusal) |
| Do not contact extracted URLs or IPs | The app has no network client at all. A static test fails if one is ever imported in `app.py` or `src/` | `test_security.py` |
| An extracted indicator is not automatically malicious | Every indicator and technique starts `unverified`; only an analyst changes that, with an audit trail. Reserved and documentation ranges are flagged | `test_ioc.py`, `test_database.py` |
| Never expose secrets or credentials | No secrets in the repository: `.env`, `.streamlit/secrets.toml` and `*.db` are git-ignored, and a scan of tracked files found none. Configuration comes from environment variables. Unexpected errors show a generic message; details go to the log only | `test_app.py` |
| Avoid storing sensitive contents unnecessarily | The database stores the evidence sentences behind each finding, not the document. Full text is stored only with `CYBERSLEUTH_STORE_FULL_TEXT=1`. Logs contain file names and counts, never document text. Reports never include the full text | `test_database.py`, `test_reports.py` |
| (Output safety) | All untrusted text shown through Markdown is escaped (`md_escape`); no `unsafe_allow_html`. Network IOCs and evidence sentences are defanged in reports. CSV cells get a formula-injection guard. Only ATT&CK and validated NVD links are clickable | `test_app.py`, `test_reports.py`, `test_security.py` |
| | **New:** chart labels are escaped. Plotly renders `<a href>` and a few other tags in labels, so a file name such as `<a href="https://…">x</a>.pdf` would have become a clickable link in the dashboard heatmap | `test_security.py` |
| Do not implement offensive operations | The app reads documents and nothing else: no scanning, enrichment lookups or exploitation | static network check |

## Findings and fixes

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | **No cap on extracted text.** A PDF under 20 MB could expand into very large text and keep the NLP stages busy for a long time (denial of service) | Medium | `max_text_chars` (default 2,000,000), checked page by page while reading a PDF and after every reader |
| 2 | **Link injection in charts.** Document names were passed to Plotly unescaped | Low (Plotly blocks `javascript:` links, so this allowed a misleading link, not script execution) | `dashboard.plain()` escapes `& < >` in chart labels |
| 3 | **Unbounded URL length.** Indicator values longer than the 2,048-character database column would fail on databases that enforce lengths (SQLite doesn't) | Low | URLs over 2,048 characters aren't extracted (`MAX_URL_LENGTH`) |
| 4 | **Manifest IDs used as file names.** An ID like `../x` could name a path outside the raw-data folder | Low (manifests are project files) | IDs must be lower-case slugs |
| 5 | **pytest 8.4.2 advisory** PYSEC-2026-1845: an insecure shared temporary directory on multi-user Unix systems. Development dependency only | Low | pytest 9.0.3 |
| 6 | **Model loader inconsistency.** The technique model didn't warn when loaded under another scikit-learn version | Low (correctness) | Warning added (fixed in the coverage step, `3184cea`) |

## Dependency audit

```text
pip install pip-audit
pip-audit -r requirements.lock.txt
```

2026-11-08, after the fixes: **no known vulnerabilities**. `en-core-web-sm` can't be
audited because it isn't on PyPI; it is a model package from spaCy's GitHub releases.

## Accepted risks and limits

* **Model files are pickles.** Loading one runs code. Loaders check the object type and
  format version, but that only catches a wrong or stale file, not a malicious one. The real
  control is that model paths are fixed and only the project's own files are loaded.
* **Parser vulnerabilities.** PyMuPDF (MuPDF, written in C) parses hostile PDFs in the app's
  own process. Keep it updated, and for a shared deployment run the app in a container with
  limited memory and no outbound network.
* **ReDoS.** The IOC patterns were written to avoid nested quantifiers. Their run time on
  large documents is measured in the performance step, not here.
* **No authentication or per-user separation.** Anyone who can reach the app can see every
  stored analysis and change verdicts. Streamlit's XSRF protection is on by default and is
  left enabled.

## Deployment limits

For anything beyond local use:
* Put the app behind an authenticating reverse proxy.
* Run it in a container with memory and CPU limits and outbound network disabled. The app
  needs no outbound access.
* Keep the database file out of the web root, and back it up. It holds evidence sentences
  from every analysed document.
