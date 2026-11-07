# CyberSleuth

**AI-Powered Cyber Threat Intelligence Extraction and Analysis Platform**

CyberSleuth turns unstructured cybersecurity reports (PDF, DOCX, TXT) into
structured, explainable, evidence-backed threat intelligence. It runs entirely
locally with free and open-source tools and needs no paid API.

> **Status: Phase 3 complete, v0.3.0.** Ingestion, IOC extraction, entity recognition,
> threat classification (TF-IDF + Logistic Regression), MITRE ATT&CK technique mapping and
> explainable risk scoring work and are tested. The database, dashboard and report exports
> (Phase 4) are **not yet implemented**. See the [Roadmap](#roadmap).

## Problem

Threat intelligence arrives as long, unstructured advisories and vendor reports.
Analysts pull out indicators, actors and techniques by hand, which is slow,
inconsistent and hard to audit. CyberSleuth automates the extraction and keeps
an evidence trail for every finding: document, page and character position.

## Features (implemented)

* **Safe document ingestion**
  * File type detected from the content, so the extension isn't trusted.
  * Limits on file size and PDF pages.
  * Protection against DOCX zip bombs.
  * Encrypted PDFs rejected.
* **Text extraction**
  * PDF page by page, with document metadata.
  * DOCX paragraphs and tables in document order.
  * TXT with automatic encoding detection.
* **Clear handling of hard documents**
  * Scanned PDF pages flagged as needing OCR.
  * Damaged PDFs repaired with a warning.
  * Undecodable bytes reported.
* **Text cleaning that leaves indicators unchanged**: Unicode normalisation that
  keeps `hxxp://`, `evil[.]com`, `10[.]0[.]0[.]5`, hashes and CVE IDs exactly as written.
* **Sentence segmentation with exact source positions**, the base for
  evidence-backed findings.
* **IOC extraction** of IPv4, domains, URLs, emails, MD5/SHA-1/SHA-256 and CVE IDs.
  * Handles defanged forms (`hxxp`, `[.]`, `[at]`).
  * Validated against an IANA TLD snapshot and Python's IP parser.
  * Guards against filenames, version strings and .NET namespaces.
  * De-duplicated, with page, position and sentence for every occurrence.
  * Flags such as private IP or documentation range. Indicators are **never** treated
    as malicious by default.
* **Cybersecurity entity recognition** of malware, threat actors, tools, named
  vulnerabilities, attack techniques, organisations and locations.
  * Uses a MITRE ATT&CK v20.1 knowledge base with aliases (`Fancy Bear` → APT28, G0007),
    curated lists, actor naming patterns and spaCy.
  * Resolves ambiguous names from context (`Cuba` ransomware vs. the country).
  * Records the source of every entity, and invents no confidence scores.
* **Threat classification**: report categories from a TF-IDF + Logistic Regression model
  (trained on Hugging Face ATT&CK procedure data) plus a keyword rule baseline, with evidence
  sentences and negation handling.
* **MITRE ATT&CK mapping** (v20.1): explicit matches (IDs, technique names, curated terms) and
  model suggestions, each with an assertion status (observed / capability / possible /
  negated). Every mapping starts unverified.
* **Explainable risk score**: R = 0.30V + 0.25M + 0.25A + 0.20E, with a reasoned breakdown for
  each component. It uses the CISA KEV catalogue, guards against inflation and double
  counting, and reports a separate confidence level ([methodology](docs/methodology.md#10-risk-scoring-phase-3)).
* **Persistence and analyst verification**: SQLite + SQLAlchemy store every analysis.
  * Documents are de-duplicated by SHA-256, and re-analyses are kept as history.
  * Analysts can mark IOCs (malicious / benign / false positive) and ATT&CK mappings
    (confirmed / rejected) with notes. Every change goes into an append-only audit log.
  * Only findings and their evidence sentences are stored; the full text is opt-in.
* **Dashboard and cross-document explorers** (Plotly):
  * Charts of risk bands, threat categories, ATT&CK tactics and IOC types.
  * An **IOC Explorer** showing which reports share an indicator, an **Entity Explorer**, and an
    **ATT&CK Explorer** with verification coverage and a tactic × document heatmap.
  * Counts use documents, not mentions, and only the latest analysis per document.
* **Evidence views**: findings for each sentence, and CVE IDs merged with named
  vulnerabilities (Log4Shell ↔ CVE-2021-44228).
* **Streamlit interface**: IOC, Entity and Evidence explorers with filters and search,
  and ATT&CK/NVD reference links. Document text, sentence and metadata views.

## Evaluation

8 synthetic, author-annotated documents, split dev/test. The test split was scored once,
with the code frozen ([details and every error](docs/evaluation/README.md)):

| Test split | Precision | Recall | F1 |
|---|---:|---:|---:|
| IOC extraction | 1.00 | 1.00 | 1.00 |
| Entity recognition (rules + spaCy) | 0.87 | 0.83 | 0.85 |
| Entity recognition (rules only) | 1.00 | 0.55 | 0.71 |

This is a small, self-made set. The numbers are **not** a real-world accuracy claim.

### Threat-category classifier
TF-IDF + Logistic Regression, trained on 10,313 ATT&CK procedure sentences from the Hugging
Face dataset [`sarahwei/cyber_MITRE_technique_CTI_dataset_v16`](https://huggingface.co/datasets/sarahwei/cyber_MITRE_technique_CTI_dataset_v16).
Category labels are derived from technique labels. Results are on a test split of
**unseen actors**, scored once ([model card](docs/models/threat_classifier.md)):

| Test split (2,149 sentences) | Macro F1 (95% CI) |
|---|---|
| TF-IDF + Logistic Regression | **0.83** (0.73–0.88) |
| Rule baseline | 0.64 (0.59–0.69) |
| Majority baseline | 0.00 |

### ATT&CK technique mapping
Explicit matching (technique IDs, ATT&CK names, curated terms) plus a LinearSVC suggesting one
of 196 parent techniques. Each mapping gets an assertion status (observed / capability /
possible / negated) and starts unverified ([model card](docs/models/technique_mapper.md)):

| Test split (2,149 sentences, unseen actors) | Value (95% CI) |
|---|---|
| Model top-1 / top-5 accuracy | **0.82** (0.80–0.83) / 0.95 |
| Explicit matcher precision (lower bound) | 0.63 |

Sentence-level results on ATT&CK-style text. Expect lower performance on real reports.

## Architecture

```text
Upload → Validation → Extraction → Cleaning → Sentences → IOCs & Entities → Evidence
       → Threat Classification → MITRE ATT&CK → Risk Scoring → [Database → Reports]   (bracketed: planned)
```

Details: [docs/architecture.md](docs/architecture.md) · Methodology and
limitations: [docs/methodology.md](docs/methodology.md)

## Technology stack

| Area | Phase 1 | Planned |
|---|---|---|
| Language | Python 3.12 | |
| UI | Streamlit, Plotly | |
| Documents | PyMuPDF, python-docx | |
| Data | pandas | NumPy, SQLite + SQLAlchemy |
| NLP / ML | spaCy 3.8 (`en_core_web_sm`), regex extraction, MITRE ATT&CK KB | TF-IDF, scikit-learn |
| Quality | pytest, pytest-cov, ruff | |

## Installation (Windows)

```powershell
git clone https://github.com/zainmatloob-cyber/CYBERSLEUTH.git
cd CYBERSLEUTH
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1   # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

On macOS/Linux, use `python3.12 -m venv .venv` and `source .venv/bin/activate`.
`requirements.lock.txt` pins the exact versions the tests last passed with.

## Train the models (once, about 2 minutes)

The trained models are not committed (they are git-ignored and rebuilt deterministically):

```powershell
python scripts/prepare_threat_dataset.py   # downloads the pinned Hugging Face dataset, verifies SHA-256
python scripts/train_threat_classifier.py --final
python scripts/train_technique_model.py --final
```

Without them the app still runs. Threat categories then come from rules only, ATT&CK mapping
from explicit matches only, and the analysis shows a warning and lowers its confidence.

## Usage

```powershell
streamlit run app.py
```

Open http://localhost:8501 and upload a report. Synthetic demo documents are in
[`data/samples/`](data/samples/); regenerate them with `python scripts/make_samples.py`.

Programmatic use:

```python
from src.intelligence.analyzer import Analyzer

result = Analyzer().analyze(open("report.pdf", "rb").read(), "report.pdf")
for indicator in result.indicators:
    print(indicator.ioc_type, indicator.value, indicator.count, sorted(indicator.flags))
for entity in result.entities:
    print(entity.entity_type, entity.name, entity.kb_id, entity.source)
```

Evaluate extraction quality: `python scripts/evaluate_extraction.py --split dev`.

## Configuration

Limits are defined in [`config/settings.py`](config/settings.py). Override them
with environment variables:

| Variable | Default |
|---|---|
| `CYBERSLEUTH_MAX_FILE_SIZE_MB` | 20 |
| `CYBERSLEUTH_MAX_PDF_PAGES` | 500 |
| `CYBERSLEUTH_MAX_DOCX_UNCOMPRESSED_MB` | 100 |
| `CYBERSLEUTH_MAX_DOCX_ZIP_ENTRIES` | 2000 |
| `CYBERSLEUTH_MIN_CHARS_PER_TEXT_PAGE` | 20 |
| `CYBERSLEUTH_LOG_LEVEL` | INFO |
| `CYBERSLEUTH_SPACY_MODEL` | en_core_web_sm |
| `CYBERSLEUTH_SPACY_BATCH_SIZE` | 64 |
| `CYBERSLEUTH_DB_URL` | `sqlite:///data/cybersleuth.db` |
| `CYBERSLEUTH_STORE_FULL_TEXT` | 0 (store evidence sentences only) |
| `CYBERSLEUTH_ANALYST` | analyst (name recorded in the audit log) |

## Testing

```powershell
pytest                                          # full suite
pytest --cov=src --cov=app --cov-report=term-missing
ruff check .
```

The suite covers:
* validation and attack cases (disguised executables, zip bombs, path traversal,
  Markdown injection);
* every reader's edge cases;
* cleaning that leaves IOCs intact, and the sentence-position invariant;
* IOC false-positive traps and defanging variants;
* entity disambiguation and knowledge-base integrity;
* the evaluation metrics;
* end-to-end analysis, and the UI through Streamlit's `AppTest`.

Model-dependent tests are skipped automatically if `en_core_web_sm` is not installed.

## Project structure

```text
app.py                  Streamlit entry point
config/settings.py      Limits and paths (environment overrides)
src/ingestion/          Validation, readers, cleaning, pipeline, data models
src/nlp/                Sentence segmentation, IOC extraction, entity recognition, KB loader
src/intelligence/       Analysis orchestrator, evidence views (MITRE mapping, risk: planned)
src/evaluation/         Precision/recall/F1 and the gold-file evaluation runner
src/ml/                 Threat-category dataset, rule baseline, classifier, evaluation
src/visualization/      Table builders, cross-document aggregations, Plotly figures
src/ui/                 Streamlit pages (Analysis, History, Dashboard, IOC/Entity/ATT&CK explorers)
src/database/           SQLAlchemy schema, repository, hydration of stored analyses
src/reporting/          PDF/JSON/CSV export (planned)
data/knowledge_base/    Versioned IANA TLDs, ATT&CK-derived entities, curated lists, rules
data/evaluation/        Annotation guidelines and the annotated dev/test documents
scripts/                Sample generator, ATT&CK KB builder, evaluation runner
tests/                  pytest suite
docs/                   Architecture, methodology, evaluation reports
```

## Roadmap

- [x] **Phase 1:** Foundation and document ingestion
- [x] **Phase 2:** IOC extraction, cybersecurity named-entity recognition, evidence views, evaluation
- [x] **Phase 3:** Threat classification (rule baseline + TF-IDF/Logistic Regression), MITRE ATT&CK mapping, explainable risk scoring
- [ ] **Phase 4:** SQLite persistence, dashboard, explorers, PDF/JSON/CSV reports
- [ ] **Phase 5:** Evaluation on a manually verified dataset, hardening, deployment

## Known limitations

OCR is not supported. DOCX headers, footers and text boxes are not extracted.
Complex PDF layouts may be read in the wrong order. The full list is in
[docs/methodology.md](docs/methodology.md#2-known-limitations-phase-1).

## Responsible use

CyberSleuth extracts and organises intelligence. It never contacts, resolves or
scans extracted URLs, domains or IPs. An extracted indicator is not, by itself,
proof that something is malicious.

## License

[MIT](LICENSE)
