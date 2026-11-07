"""Analyst-facing PDF report (fpdf2, built-in fonts, no network access).

Sections: document, executive summary, risk assessment, threat categories, ATT&CK
techniques, indicators, vulnerabilities, entities, verification history, limitations and
provenance.

Design notes:

* Built from :func:`build_report`, the same data as the JSON/CSV exports.
* Indicators and evidence are defanged. The only clickable links are ATT&CK technique
  pages (validated URLs from the knowledge base).
* Built-in PDF fonts cover Latin-1 only. Text is transliterated (dashes, quotes, ellipsis)
  and anything else becomes ``?``. This is a known limitation, stated in the report; the
  JSON and CSV exports keep full Unicode.
* Long tables are capped (:data:`MAX_ROWS`) with an explicit "showing N of M" note.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence

from fpdf import FPDF
from fpdf.enums import WrapMode, XPos, YPos
from fpdf.fonts import FontFace

from src.database.models import VerificationEvent
from src.database.views import StoredAnalysis
from src.reporting.json_report import build_report
from src.visualization.aggregations import category_label

MAX_ROWS = 300
EVIDENCE_PER_FINDING = 2
_PUNCTUATION = str.maketrans({
    "—": "-", "–": "-", "‒": "-", "−": "-", "‘": "'", "’": "'",
    "“": '"', "”": '"', "…": "...", "•": "*", " ": " ",
    "→": "->", "×": "x", "​": "",
})
INK, MUTED, RULE, HEAD_FILL = (25, 25, 25), (100, 100, 100), (200, 200, 200), (235, 238, 243)
FONT_LIMITATION = ("PDF text uses built-in Latin-1 fonts: characters outside Latin-1 are "
                   "shown as '?'. The JSON and CSV exports keep the original text.")


def latin1(text: object) -> str:
    """Make text safe for the built-in PDF fonts."""
    value = "" if text is None else str(text)
    value = value.translate(_PUNCTUATION)
    try:
        value.encode("latin-1")
        return value
    except UnicodeEncodeError:
        decomposed = unicodedata.normalize("NFKD", value)
        stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
        return stripped.encode("latin-1", errors="replace").decode("latin-1")


class _Report(FPDF):
    def __init__(self, title: str) -> None:
        super().__init__(format="A4")
        self._title = title
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=16)
        self.set_title(title)
        self.set_creator("CyberSleuth")

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 5, latin1(self._title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 5, "Machine-assisted analysis - verify findings before acting on them.")
        self.cell(0, 5, f"Page {self.page_no()}/{{nb}}", align="R")

    # --- building blocks ------------------------------------------------------------

    def heading(self, text: str) -> None:
        if self.will_page_break(30):
            self.add_page()
        self.ln(3)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*INK)
        self.cell(0, 8, latin1(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*RULE)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def para(self, text: str, size: float = 10, style: str = "", color=INK) -> None:
        self.set_font("Helvetica", style, size)
        self.set_text_color(*color)
        self.multi_cell(0, size * 0.5, latin1(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def bullets(self, items: Sequence[str], size: float = 10) -> None:
        for item in items:
            self.para(f"- {item}", size=size)

    def note(self, text: str) -> None:
        self.para(text, size=8.5, style="I", color=MUTED)

    def data_table(self, headings: Sequence[str], rows: Sequence[Sequence[object]],
              widths: Sequence[float], links: Sequence[str | None] | None = None,
              link_column: int = 0, total: int | None = None,
              wrap: WrapMode = WrapMode.WORD) -> None:
        if not rows:
            self.note("None found.")
            return
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*INK)
        self.set_draw_color(*RULE)
        with super().table(col_widths=widths, line_height=4, padding=1,
                           headings_style=_heading_style(), wrapmode=wrap,
                           text_align="LEFT", first_row_as_headings=True) as grid:
            grid.row([latin1(h) for h in headings])
            for i, values in enumerate(rows):
                row = grid.row()
                for j, value in enumerate(values):
                    link = links[i] if links and j == link_column else None
                    row.cell(latin1(value), link=link)
        if total is not None and total > len(rows):
            self.note(f"Showing the first {len(rows)} of {total}. The JSON and CSV exports "
                      "contain every row.")
        self.ln(2)


def _heading_style() -> FontFace:
    return FontFace(emphasis="BOLD", fill_color=HEAD_FILL)


def _fmt(value: float | None, digits: int = 2) -> str:
    return "" if value is None else f"{value:.{digits}f}"


def _evidence_lines(evidence: list[dict]) -> list[str]:
    """Distinct evidence sentences (rules and model often cite the same one), capped."""
    distinct = list(dict.fromkeys(
        f'p.{e["page"]} [{e["status"]}] "{e["sentence"]}"' for e in evidence))
    lines = distinct[:EVIDENCE_PER_FINDING]
    if len(distinct) > len(lines):
        lines.append(f"... {len(distinct) - len(lines)} more sentence(s) in the JSON export.")
    return lines


def to_pdf(view: StoredAnalysis, events: Sequence[VerificationEvent] = ()) -> bytes:
    report = build_report(view, events)
    doc, analysis, risk = report["document"], report["analysis"], report["risk"]
    pdf = _Report(f"CyberSleuth threat intelligence report - {doc['filename']}")
    pdf.alias_nb_pages()
    pdf.add_page()

    # --- title & document ---------------------------------------------------------
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*INK)
    pdf.cell(0, 10, "CyberSleuth threat intelligence report", new_x=XPos.LMARGIN,
             new_y=YPos.NEXT)
    pdf.note(f"Generated {report['report']['generated_at']} (UTC) - report schema "
             f"{report['report']['schema_version']} - "
             + (f"analysis #{analysis['id']}" if analysis["id"] else "unsaved analysis")
             + f", analysed {analysis['analysed_at']}")
    pdf.data_table(["Field", "Value"], [
        ("Document", doc["filename"]), ("SHA-256", doc["sha256"]),
        ("Type / size", f"{doc['file_type'].upper()} / {doc['size_bytes']:,} bytes"),
        ("Pages / sentences", f"{doc['page_count']} / {doc['sentence_count']:,}"),
        ("Needs OCR", "Yes" if doc["needs_ocr"] else "No"),
    ], widths=(35, 145), wrap=WrapMode.CHAR)

    pdf.heading("1. Executive summary")
    pdf.bullets(report["summary"])
    if analysis["warnings"]:
        pdf.para("Warnings", size=10, style="B")
        pdf.bullets(analysis["warnings"], size=9)

    # --- risk -----------------------------------------------------------------------
    pdf.heading("2. Risk assessment")
    pdf.para(f"{risk['score']}/100 - {risk['band']} (confidence {risk['confidence']['level']},"
             f" risk model {analysis['risk_model_version']})", size=11, style="B")
    weights = {c["key"]: c["weight"] for c in risk["components"]}
    pdf.note("R = " + " + ".join(f"{w:.2f}*{k[0].upper()}" for k, w in weights.items())
             + ". Severity and confidence are reported separately.")
    pdf.data_table(["Component", "Weight", "Value", "Contribution", "Why"], [
        (c["label"], f"{c['weight']:.2f}", f"{c['value']:.0f}", f"{c['contribution']:.1f}",
         " ".join(c["explanation"])) for c in risk["components"]],
        widths=(32, 14, 13, 20, 101))
    pdf.para("Confidence reasons", size=10, style="B")
    pdf.bullets(risk["confidence"]["reasons"], size=9)

    # --- threat categories ------------------------------------------------------------
    pdf.heading("3. Threat categories")
    categories = report["threat_categories"]
    pdf.data_table(["Category", "Status", "Sources", "Sentences", "Max model score"], [
        (category_label(c["category"]), c["status"], ", ".join(c["sources"]),
         c["sentence_count"], _fmt(c["max_model_score"])) for c in categories],
        widths=(50, 30, 40, 25, 35))
    for c in categories:
        pdf.para(category_label(c["category"]), size=9, style="B")
        pdf.bullets(_evidence_lines(c["evidence"]), size=8.5)

    # --- ATT&CK -----------------------------------------------------------------------
    pdf.heading("4. MITRE ATT&CK techniques")
    pdf.note("Status is the strongest assertion across the evidence. 'model' means suggested "
             "by the classifier only; these are unverified until an analyst confirms them. "
             "Technique IDs link to attack.mitre.org.")
    techniques = report["attack_techniques"]
    shown = techniques[:MAX_ROWS]
    pdf.data_table(["ID", "Name", "Tactics", "Status", "Method", "Verification"], [
        (m["technique_id"], m["name"], ", ".join(m["tactics"]), m["status"],
         ", ".join(m["methods"]), m["verification"]) for m in shown],
        widths=(20, 48, 38, 22, 30, 22), links=[m["reference"] for m in shown],
        total=len(techniques))
    for m in shown:
        pdf.para(f"{m['technique_id']} {m['name']}", size=9, style="B")
        if m["analyst_note"]:
            pdf.note(f"Analyst note: {m['analyst_note']}")
        pdf.bullets(_evidence_lines(m["evidence"]), size=8.5)

    # --- indicators -------------------------------------------------------------------
    pdf.heading("5. Indicators of compromise")
    pdf.note("Defanged. Not contacted or enriched. Flags describe the value, not whether it "
             "is malicious. Verification is the recorded analyst verdict.")
    indicators = report["indicators"]
    pdf.data_table(["Type", "Value (defanged)", "Count", "Pages", "Flags", "Verification"], [
        (i["type"].upper(), i["value_defanged"], len(i["occurrences"]),
         ", ".join(map(str, i["pages"])), ", ".join(i["flags"]), i["verification"])
        for i in indicators[:MAX_ROWS]],
        widths=(16, 74, 13, 17, 35, 25), total=len(indicators), wrap=WrapMode.CHAR)

    # --- vulnerabilities & entities ------------------------------------------------------
    pdf.heading("6. Vulnerabilities")
    pdf.data_table(["CVE", "Known as", "Mentioned by", "Pages"], [
        (v["cve"], ", ".join(v["names"]), v["mentioned_by"], ", ".join(map(str, v["pages"])))
        for v in report["vulnerabilities"]], widths=(40, 70, 35, 35))

    pdf.heading("7. Entities")
    entities = report["entities"]
    pdf.data_table(["Type", "Name", "ATT&CK ID", "Mentions", "Source"], [
        (e["type"].replace("_", " "), e["name"], e["attack_id"] or "", len(e["mentions"]),
         e["source"]) for e in entities[:MAX_ROWS]],
        widths=(30, 60, 25, 20, 45), total=len(entities))

    # --- verification & limitations ---------------------------------------------------------
    pdf.heading("8. Analyst verification history")
    pdf.data_table(["When (UTC)", "Target", "From", "To", "Analyst", "Note"], [
        (e["time"], f"{e['target_type']} #{e['target_id']}", e["from"], e["to"], e["analyst"],
         e["note"] or "") for e in report["verification_history"]],
        widths=(34, 26, 22, 22, 24, 52))

    pdf.heading("9. Limitations and provenance")
    pdf.bullets([*report["report"]["limitations"], FONT_LIMITATION], size=9)
    pdf.data_table(["Item", "Version / value"], [
        *((f"Component: {k}", v) for k, v in analysis["components"].items()),
        *((f"Knowledge base: {k}", v) for k, v in analysis["knowledge_bases"].items()),
    ], widths=(60, 120))
    return bytes(pdf.output())
