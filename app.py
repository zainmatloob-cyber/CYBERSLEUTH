"""CyberSleuth Streamlit entry point.

Run with:  streamlit run app.py

Pages live in ``src/ui/pages.py``; shared helpers and the security notes on rendering
untrusted content are in ``src/ui/common.py``.
"""

from __future__ import annotations

import streamlit as st

from config.settings import settings
from src.ui import pages
from src.ui.common import get_analyzer, get_repository, md_escape
from src.utils.logging_config import configure_logging

__all__ = ["main", "md_escape"]

configure_logging()


def _sidebar() -> None:
    with st.sidebar:
        st.caption("Cyber Threat Intelligence Extraction & Analysis")
        limits = settings.ingestion
        st.caption(
            f"Accepted: PDF, DOCX, TXT · max {limits.max_file_size_bytes // 1_048_576} MB · "
            f"max {limits.max_pdf_pages} PDF pages. Uploads are processed in memory; only "
            "findings and their evidence sentences are saved. Extracted indicators are never "
            "contacted."
        )


def main() -> None:
    st.set_page_config(page_title=settings.app_name, page_icon="🛡️", layout="wide")
    repo = get_repository()
    navigation = st.navigation([
        st.Page(lambda: pages.analysis_page(get_analyzer(), repo), title="Document Analysis",
                icon="🔍", url_path="analysis", default=True),
        st.Page(lambda: pages.history_page(repo), title="History", icon="🗂️",
                url_path="history"),
        st.Page(lambda: pages.dashboard_page(repo), title="Dashboard", icon="📊",
                url_path="dashboard"),
        st.Page(lambda: pages.ioc_explorer_page(repo), title="IOC Explorer", icon="🎯",
                url_path="iocs"),
        st.Page(lambda: pages.entity_explorer_page(repo), title="Entity Explorer", icon="🧬",
                url_path="entities"),
        st.Page(lambda: pages.attack_explorer_page(repo), title="ATT&CK Explorer", icon="🗺️",
                url_path="attack"),
    ])
    with st.sidebar:
        st.title(f"🛡️ {settings.app_name}")
    _sidebar()
    navigation.run()


if __name__ == "__main__":
    main()
