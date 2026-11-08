# Performance

Measured on 2026-11-08 with `scripts/benchmark.py`, on a 4-core Intel laptop (Windows 10,
Python 3.12, CPU only). Each run is a fresh process. Raw results:
[performance.json](performance.json).

```text
python scripts/benchmark.py --sizes 100000 250000 500000 1000000
python scripts/benchmark.py --file path/to/report.pdf
```

**Read the numbers as ranges.** The same benchmark ran about **2.2× slower** in an earlier
run on the same machine (for example, 7.2 s against 2.9 s for 100,000 characters), with no
change to the measured code. Laptop CPU boost and background load vary. Both runs are
reported.

## Real advisories

| Document | Pages | Characters | Sentences | Analysis (s) | Peak memory (MB) |
|---|---|---|---|---|---|
| aa23-278a (top-ten misconfigurations) | 44 | 91,048 | 827 | 3.7 (8.7 in the slower run) | 389 |
| aa25-141a (GRU logistics) | 33 | 62,845 | 749 | 2.8 | 385 |
| aa24-109a (Akira) | 31 | 62,652 | 602 | 2.8 | 387 |
| aa23-165a (LockBit) | 30 | 57,427 | 509 | 2.5 | 389 |

**Model loading** (spaCy, both trained models and the knowledge bases) takes about 1.5 s and
about 354 MB. The app does it once per server process (`st.cache_resource`).

## Scaling with document length (synthetic TXT)

| Characters | Total (s) | Entities | Classification | ATT&CK mapping | IOCs | Ingestion | Peak MB |
|---|---|---|---|---|---|---|---|
| 100,000 | 2.9 (7.2) | 1.6 | 0.8 | 0.4 | 0.07 | 0.02 | 373 |
| 250,000 | 7.1 (16.7) | 3.7 | 2.0 | 0.9 | 0.4 | 0.1 | 379 |
| 500,000 | 14.6 (33.5) | 7.5 | 4.0 | 2.6 | 0.4 | 0.1 | 397 |
| 1,000,000 | 30.1 | 15.3 | 8.8 | 5.0 | 0.8 | 0.2 | 429 |

The slower run's totals are in brackets.
* **Time grows linearly with text length:** about 30–67 s per million characters, depending
  on the machine state.
* **Where the time goes:** entity recognition (spaCy) is about half, threat classification a
  quarter and ATT&CK mapping a sixth. IOC extraction and risk scoring are negligible.
* **Memory is dominated by the loaded models.** One analysis adds about 75 MB per million
  characters.
* **PDF reading adds about 24 ms per page,** almost all of it PyMuPDF's `sort=True` reading
  order (pure Python). Unsorted extraction is about 6× faster, but it changes the text and so
  every recorded evaluation result, which isn't worth about 1 s per 44 pages.

## Limits chosen from these numbers

* **Extracted text: 1,000,000 characters** (`CYBERSLEUTH_MAX_TEXT_CHARS`). This keeps the
  worst case at about 0.5–1.2 minutes plus PDF reading. It roughly matches the 500-page PDF
  limit at about 2,000 characters per dense page. The security review first set
  2,000,000, which would have allowed up to about 2.5 minutes.
* The largest real advisory in either evaluation set has about 91,000 characters, a tenth of
  the cap.

## Regular-expression denial of service (ReDoS)

Every regex-heavy stage was timed on 21 hostile inputs of 100,000 characters: long runs
without spaces, repeated `a.`, `1.`, `a-`, `a@`, `[.]`, defanged URL fragments, colons,
unterminated URLs and long query strings.

**Finding: the text cleaner was quadratic.** The pattern that rejoins words hyphenated
across line breaks, `(\S+)-[ \t]*\n[ \t]*(\S+)`, retried from every position inside a long
unbroken run, and each retry backtracked through the rest of the run. 20,000 characters
without spaces took 4–12 s, and the 100,000-character inputs didn't finish within 10 minutes.
Any upload containing a long unbroken run, such as a base64 blob, would have stalled the
analysis.

**Fix:** only start a match at a token boundary, `(?<!\S)(\S+)-…`. Leftmost matches already
started at a token boundary, so the output is unchanged:
* identical on 200,000 random strings;
* identical on all 62 real advisory PDFs on disk (the 31 in the two evaluation sets plus the
  original downloads);
* a seeded equivalence test is kept in the suite.

| Input | Before | After |
|---|---|---|
| 20,000 characters without spaces | 4–12 s | 0.002 s |
| 1,000,000 characters without spaces | did not finish (estimated hours) | 0.14 s |
| Worst of all 21 hostile inputs (100,000 characters, all stages) | did not finish | 0.25 s |

IOC extraction, refanging, sentence splitting and assertion detection were already linear:
all under 0.1 s on every hostile input.

**End-to-end on hostile documents,** entity recognition is the slowest stage. On `a-a-a-…`
spaCy makes one token per character, about 65 s per million characters. That's linear (3.4,
6.7 and 12.9 s for 50,000, 100,000 and 200,000 characters), and the text cap bounds it.

`tests/test_security.py` sends 200,000 hostile characters through cleaning, splitting and
IOC extraction with a 5-second limit. A quadratic regression would take minutes, so the
limit is generous rather than flaky.

## Not optimised (deliberately)

* **No parallelism.** Analyses run one at a time per Streamlit session, and spaCy's batch size
  is configurable (`CYBERSLEUTH_SPACY_BATCH_SIZE`). For a shared deployment, scale by running
  more app processes behind the proxy.
* **No caching of results across identical uploads beyond the database:** a re-upload of a
  stored document reopens the stored analysis, but it is still analysed again first.
