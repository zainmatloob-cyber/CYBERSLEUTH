# Report exports

Every analysis can be exported from the **📤 Export** tab, for fresh and reopened analyses
alike. Each file is generated when its button is clicked, so it includes every verdict
recorded up to that moment.

| Format | Module | Audience | Indicator values |
|---|---|---|---|
| PDF | `src/reporting/pdf_report.py` | Analysts, managers | Defanged |
| JSON | `src/reporting/json_report.py` | Tools, archives (complete record) | Canonical **and** defanged |
| CSV (ZIP) | `src/reporting/csv_report.py` | Spreadsheets, quick filtering | Defanged |

All three formats are built from one dictionary, `json_report.build_report()`. The CSV and PDF
are views of the JSON, so the formats can't disagree.

## Safety rules

| Risk | Control |
|---|---|
| A reader clicks attacker infrastructure in a report | Network IOCs (URL, domain, IPv4, e-mail) are defanged (`hxxps://evil[.]example/`). Evidence sentences are defanged by replacing the analysis' own extracted forms, longest first. The PDF links only to ATT&CK technique pages |
| CSV formula injection (`=HYPERLINK(...)` in a sentence) | Every string cell starting with `= + - @`, a tab or CR gets a leading `'`. Numbers stay numeric |
| Leaking the source document | Reports contain findings and evidence sentences only, never `full_text`, even when it is stored (a test checks this) |
| Invented verdicts | Verdicts and notes are exported as stored. Unreviewed findings say `unverified` |
| Unsafe download filename | `report_stem()` keeps only `[A-Za-z0-9_-]` from the uploaded name |
| Overstating the analysis | Every format carries the limitations list. The PDF repeats it in section 9 and marks model-only techniques |

**Known gap:** sentence defanging covers the indicators the extractor found. A URL the
extractor rejected (for example, an invalid TLD) stays as written in the evidence sentence.

## JSON schema (version 1.0)

```text
report              generator, schema_version, generated_at, limitations[]
document            filename, sha256, file_type, size_bytes, page_count, sentence_count,
                    needs_ocr, embedded_metadata{}
analysis            id (null if unsaved), analysed_at, risk_model_version,
                    components{}, knowledge_bases{}, warnings[]
summary[]           template-based executive summary sentences
risk                score, band, confidence{level, reasons[]},
                    components[]{key, label, weight, value, contribution, explanation[]}
indicators[]        type, value, value_defanged, flags[], verification, analyst_note,
                    source, pages[], occurrences[]{page, as_written, was_defanged,
                    sentence_index, context}
entities[]          type, name, attack_id, reference, source, aliases_seen[],
                    alternatives[], attributes{}, confidence (always null), mentions[]
vulnerabilities[]   cve, names[], mentioned_by, id_mentions, name_mentions, pages[], reference
threat_categories[] category, status, sources[], sentence_count, max_model_score,
                    evidence[]{page, sentence_index, source, status, score, terms[], sentence}
attack_techniques[] technique_id, name, tactics[], reference, status, methods[], explicit,
                    max_model_score, verification, analyst_note,
                    evidence[]{page, sentence_index, method, status, matched_text, score,
                    alternatives[[id, score]], sentence}
verification_history[]  time, target_type, target_id, from, to, analyst, note
```

Model scores are decision-function values, **not probabilities**. Adding a field is a minor
version change. Renaming or removing one is a major change.

## CSV bundle

`README.txt` (provenance and limitations), `indicators.csv`, `indicator_occurrences.csv`,
`entities.csv`, `vulnerabilities.csv`, `attack_techniques.csv`, `attack_evidence.csv`,
`threat_categories.csv`, `category_evidence.csv`, `risk_components.csv`,
`verification_history.csv`. The files are UTF-8 with a BOM, so Excel opens non-ASCII text
correctly.

## PDF layout

1. Executive summary
2. Risk assessment (formula, component table, confidence reasons)
3. Threat categories, with up to 2 distinct evidence sentences each
4. ATT&CK techniques: status, method and verification, with up to 2 distinct evidence sentences each
5. Indicators
6. Vulnerabilities
7. Entities
8. Analyst verification history
9. Limitations and provenance

The document details are on the first page, before section 1.

Tables are capped at 300 rows, and the PDF says so ("Showing the first N of M"). The JSON and
CSV exports are never truncated. The PDF uses fpdf2's built-in fonts, so it needs no network
access or bundled fonts. The cost is that characters outside Latin-1 print as `?`; dashes,
quotes and accented Latin letters are transliterated. This limitation is stated in the report
itself.
