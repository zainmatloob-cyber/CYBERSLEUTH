# CyberSleuth

**AI-Powered Cyber Threat Intelligence Extraction and Analysis Platform**

CyberSleuth turns unstructured cybersecurity reports (PDF, DOCX, TXT) into
structured, explainable, evidence-backed threat intelligence. It runs entirely
locally with free and open-source tools and needs no paid API.

> **Status: Phase 1 complete, v0.1.0.** Document ingestion works and is tested.
> IOC extraction, entity recognition, classification, MITRE ATT&CK mapping and
> risk scoring are planned and **not yet implemented**. See the [Roadmap](#roadmap).

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
  evidence-backed findings in later phases.
* **Streamlit interface** with a dark theme, upload progress, warnings, a
  per-page text view, a searchable sentence table and metadata.

## Architecture

```text
Upload → Validation → Extraction → Cleaning → Sentences → [IOCs & Entities → Classification
       → MITRE ATT&CK → Risk Scoring → Database → Dashboard & Reports]   (bracketed: planned)
```

Details: [docs/architecture.md](docs/architecture.md) · Methodology and
limitations: [docs/methodology.md](docs/methodology.md)

## Technology stack

| Area | Phase 1 | Planned |
|---|---|---|
| Language | Python 3.12 | |
| UI | Streamlit | Plotly |
| Documents | PyMuPDF, python-docx | |
| Data | pandas | NumPy, SQLite + SQLAlchemy |
| NLP / ML | Rule-based cleaning and segmentation | spaCy, TF-IDF, scikit-learn |
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

## Usage

```powershell
streamlit run app.py
```

Open http://localhost:8501 and upload a report. Synthetic demo documents are in
[`data/samples/`](data/samples/); regenerate them with `python scripts/make_samples.py`.

Programmatic use:

```python
from src.ingestion.pipeline import ingest

doc = ingest(open("report.pdf", "rb").read(), "report.pdf")
print(doc.page_count, len(doc.sentences), doc.warnings)
for s in doc.sentences[:3]:
    print(s.page_number, s.char_start, s.text)
```

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

## Testing

```powershell
pytest                                          # full suite
pytest --cov=src --cov=app --cov-report=term-missing
ruff check .
```

The suite covers validation and attack cases (disguised executables, zip bombs,
path traversal, Markdown injection), every reader's edge cases, cleaning that
leaves IOCs intact, the sentence-position invariant, end-to-end ingestion, and
the UI through Streamlit's `AppTest`.

## Project structure

```text
app.py                  Streamlit entry point
config/settings.py      Limits and paths (environment overrides)
src/ingestion/          Validation, readers, cleaning, pipeline, data models
src/nlp/                Sentence segmentation (IOC/NER/classification: planned)
src/intelligence/       MITRE mapping, risk scoring (planned)
src/database/           SQLAlchemy models (planned)
src/reporting/          PDF/JSON/CSV export (planned)
scripts/make_samples.py Synthetic demo-document generator
tests/                  pytest suite
docs/                   Architecture and methodology
```

## Roadmap

- [x] **Phase 1:** Foundation and document ingestion
- [ ] **Phase 2:** IOC extraction and cybersecurity named-entity recognition
- [ ] **Phase 3:** Threat classification (rule-based baseline + TF-IDF/Logistic Regression), MITRE ATT&CK mapping, risk scoring
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
