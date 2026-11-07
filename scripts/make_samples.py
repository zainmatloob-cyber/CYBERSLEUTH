"""Generate SYNTHETIC sample threat reports in data/samples/ for demos and manual testing.

Every indicator uses reserved documentation ranges (RFC 5737 IPs, example.* domains)
or well-known test values (the EICAR test-file MD5), so nothing here is a real,
live indicator. The threat actor "GLASS PANTHER" is fictional.

Usage:  python scripts/make_samples.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import docx
import pymupdf

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import settings  # noqa: E402

# ASCII only: PyMuPDF's built-in Helvetica is Latin-1, so an em dash would become "?".
BANNER = "SYNTHETIC SAMPLE - FOR TESTING ONLY. All indicators are fictional or reserved."

PARAGRAPHS = [
    "Threat Advisory: GLASS PANTHER Phishing Campaign",
    "Executive Summary. In March 2026 the fictional actor GLASS PANTHER targeted "
    "finance organisations with spear-phishing emails. Victims received a message from "
    "billing[@]invoice-portal.example.com containing a link to "
    "hxxps://invoice-portal[.]example[.]com/download.php.",
    "Technical Details. The downloaded archive executed a PowerShell script that "
    "contacted 198.51.100.23 and 203.0.113[.]77 over port 443. The loader, version 2.4.1, "
    "then deployed a ransomware payload that encrypted files on network shares.",
    "Initial access was achieved by exploiting CVE-2024-3400 on exposed VPN gateways, "
    "e.g. devices that had not been patched since Jan. 2026.",
    "Indicators of Compromise",
    "MD5: 44d88612fea8a8f36de82e1278abb02f",
    "SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "Domain: update-service.example.net",
    "Recommendations. Block the listed indicators, patch VPN appliances, and enforce "
    "multi-factor authentication for remote access.",
]


def write_txt(path: Path) -> None:
    # newline="\n": stop Windows translating to CRLF, so the file matches the repo copy.
    path.write_text("\n\n".join([BANNER, *PARAGRAPHS]) + "\n", encoding="utf-8", newline="\n")


def write_docx(path: Path) -> None:
    document = docx.Document()
    document.core_properties.title = "GLASS PANTHER Advisory (synthetic)"
    document.core_properties.author = "CyberSleuth sample generator"
    document.add_paragraph(BANNER)
    document.add_heading(PARAGRAPHS[0], level=1)
    for text in PARAGRAPHS[1:4]:
        document.add_paragraph(text)
    document.add_heading(PARAGRAPHS[4], level=2)
    table = document.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text, table.rows[0].cells[1].text = "Type", "Indicator"
    for line in PARAGRAPHS[5:8]:
        kind, value = line.split(": ", 1)
        row = table.add_row().cells
        row[0].text, row[1].text = kind, value
    document.add_paragraph(PARAGRAPHS[8])
    document.save(path)


def write_pdf(path: Path) -> None:
    pdf = pymupdf.open()
    pdf.set_metadata({"title": "GLASS PANTHER Advisory (synthetic)",
                      "author": "CyberSleuth sample generator"})
    pages = [[BANNER, *PARAGRAPHS[:4]], PARAGRAPHS[4:]]
    for blocks in pages:
        page = pdf.new_page()
        rect = pymupdf.Rect(56, 56, page.rect.width - 56, page.rect.height - 56)
        page.insert_textbox(rect, "\n\n".join(blocks), fontsize=11, fontname="helv")
    pdf.save(path)
    pdf.close()


def write_scanned_pdf(path: Path) -> None:
    """A PDF whose only page is an image: exercises the 'needs OCR' path."""
    pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 300, 100), False)
    pix.clear_with(235)
    pdf = pymupdf.open()
    pdf.new_page().insert_image(pymupdf.Rect(72, 72, 372, 172), stream=pix.tobytes("png"))
    pdf.save(path)
    pdf.close()


def main() -> None:
    out = settings.samples_dir
    out.mkdir(parents=True, exist_ok=True)
    write_txt(out / "synthetic_advisory.txt")
    write_docx(out / "synthetic_advisory.docx")
    write_pdf(out / "synthetic_advisory.pdf")
    write_scanned_pdf(out / "synthetic_scanned.pdf")
    print(f"Wrote samples to {out}")  # CLI script: print is appropriate here


if __name__ == "__main__":
    main()
