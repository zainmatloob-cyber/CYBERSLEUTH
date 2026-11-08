"""CSV export: one flat table per finding type, bundled in a ZIP.

Built from :func:`src.reporting.json_report.build_report`, so the CSV and JSON exports
cannot disagree. Spreadsheet-facing, so:

* network indicators are written defanged only (the canonical value is in the JSON);
* every string cell passes through :func:`csv_safe` (formula-injection guard);
* files are UTF-8 with a BOM so Excel detects the encoding.
"""

from __future__ import annotations

import csv
import io
import zipfile
from collections.abc import Sequence

from src.database.models import VerificationEvent
from src.database.views import StoredAnalysis
from src.reporting.common import REPORT_SCHEMA_VERSION, csv_safe
from src.reporting.json_report import build_report


def _join(values) -> str:
    return "; ".join(str(v) for v in values)


def _csv(rows: list[dict], columns: list[str]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: csv_safe(row.get(k)) for k in columns})
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def build_tables(report: dict) -> dict[str, tuple[list[str], list[dict]]]:
    """File name → (columns, rows). Pure, for testing."""
    tables: dict[str, tuple[list[str], list[dict]]] = {}
    tables["indicators.csv"] = (
        ["type", "value_defanged", "occurrences", "pages", "flags", "verification",
         "analyst_note", "source", "first_context"],
        [{**i, "occurrences": len(i["occurrences"]), "pages": _join(i["pages"]),
          "flags": _join(i["flags"]),
          "first_context": i["occurrences"][0]["context"] if i["occurrences"] else ""}
         for i in report["indicators"]])
    tables["indicator_occurrences.csv"] = (
        ["type", "value_defanged", "page", "as_written", "was_defanged", "context"],
        [{"type": i["type"], "value_defanged": i["value_defanged"], **o}
         for i in report["indicators"] for o in i["occurrences"]])
    tables["entities.csv"] = (
        ["type", "name", "attack_id", "source", "mentions", "aliases_seen", "alternatives",
         "reference"],
        [{**e, "mentions": len(e["mentions"]), "aliases_seen": _join(e["aliases_seen"]),
          "alternatives": _join(e["alternatives"])} for e in report["entities"]])
    tables["vulnerabilities.csv"] = (
        ["cve", "names", "mentioned_by", "id_mentions", "name_mentions", "pages", "reference"],
        [{**v, "names": _join(v["names"]), "pages": _join(v["pages"])}
         for v in report["vulnerabilities"]])
    tables["attack_techniques.csv"] = (
        ["technique_id", "name", "tactics", "status", "methods", "explicit",
         "unverified_model_lead",
         "max_model_score", "verification", "analyst_note", "evidence_count", "reference"],
        [{**m, "tactics": _join(m["tactics"]), "methods": _join(m["methods"]),
          "evidence_count": len(m["evidence"])} for m in report["attack_techniques"]])
    tables["attack_evidence.csv"] = (
        ["technique_id", "page", "method", "status", "matched_text", "score", "sentence"],
        [{"technique_id": m["technique_id"], **e}
         for m in report["attack_techniques"] for e in m["evidence"]])
    tables["threat_categories.csv"] = (
        ["category", "status", "sources", "sentence_count", "max_model_score"],
        [{**c, "sources": _join(c["sources"])} for c in report["threat_categories"]])
    tables["category_evidence.csv"] = (
        ["category", "page", "source", "status", "score", "terms", "sentence"],
        [{"category": c["category"], **e, "terms": _join(e["terms"])}
         for c in report["threat_categories"] for e in c["evidence"]])
    tables["risk_components.csv"] = (
        ["key", "label", "weight", "value", "contribution", "explanation"],
        [{**c, "explanation": " ".join(c["explanation"])}
         for c in report["risk"]["components"]])
    tables["verification_history.csv"] = (
        ["time", "target_type", "target_id", "from", "to", "analyst", "note"],
        report["verification_history"])
    return tables


def _readme(report: dict, files: list[str]) -> bytes:
    doc, risk = report["document"], report["risk"]
    lines = [
        f"CyberSleuth CSV export (report schema {REPORT_SCHEMA_VERSION})",
        f"Generated: {report['report']['generated_at']}",
        f"Document: {doc['filename']} (SHA-256 {doc['sha256']})",
        f"Risk: {risk['score']}/100 ({risk['band']}), confidence {risk['confidence']['level']}",
        "",
        "Network indicators and evidence sentences are defanged. Cells that would start a",
        "spreadsheet formula are prefixed with an apostrophe.",
        "",
        "Files:", *(f"  {name}" for name in files),
        "",
        "Limitations:", *(f"  - {item}" for item in report["report"]["limitations"]),
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def to_csv_zip(view: StoredAnalysis, events: Sequence[VerificationEvent] = ()) -> bytes:
    report = build_report(view, events)
    tables = build_tables(report)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", _readme(report, list(tables)))
        for name, (columns, rows) in tables.items():
            archive.writestr(name, _csv(rows, columns))
    return buffer.getvalue()
