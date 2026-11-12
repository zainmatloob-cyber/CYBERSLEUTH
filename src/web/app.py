"""FastAPI application: routes for uploading, analysing and viewing threat reports.

Pages are server-rendered with Jinja2. HTMX swaps fragments for tab changes and filters;
every page also works as a plain full-page request.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path, PurePath

from fastapi import FastAPI, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

from config.settings import settings
from src.database.db_manager import AnalysisRepository, DatabaseError
from src.database.views import StoredAnalysis, hydrate, view_from_result
from src.intelligence.analyzer import AnalysisResult, Analyzer
from src.utils.exceptions import CyberSleuthError
from src.web import tabs
from src.web.security import SecurityMiddleware
from src.web.state import UNSAVED_PREFIX, AppState, default_repository, new_unsaved_ref

logger = logging.getLogger("cybersleuth.web")

WEB_DIR = Path(__file__).resolve().parent
BAND_CLASS = {"Low": "low", "Moderate": "moderate", "High": "high", "Critical": "critical"}
SAVE_NOTES = {
    "new": "Saved as analysis #{id}.",
    "existing": "This document was already analysed with the same components: showing "
                "stored analysis #{id} with its analyst verdicts.",
}
NAV = (("analyze", "Analyze", "/"),)


def _templates() -> Jinja2Templates:
    # Autoescaping is explicit and unconditional: all document content is untrusted.
    env = Environment(loader=FileSystemLoader(WEB_DIR / "templates"), autoescape=True,
                      trim_blocks=True, lstrip_blocks=True)
    env.globals.update(app_name=settings.app_name, nav=NAV, band_class=BAND_CLASS)
    return Jinja2Templates(env=env)


FRAGMENT_TARGETS = frozenset({"tab-area", "tab-results"})


def _is_fragment(request: Request) -> bool:
    """An HTMX tab change or filter: answer with the tab area only, not the whole page."""
    return (request.headers.get("hx-request") == "true"
            and request.headers.get("hx-target") in FRAGMENT_TARGETS)


def _safe_filename(name: str | None) -> str:
    """Browsers send a bare name, but strip any path a client might add."""
    return PurePath((name or "upload").replace("\\", "/")).name or "upload"


def create_app(analyzer_factory: Callable[[], Analyzer] = Analyzer,
               repository_factory: Callable[[], AnalysisRepository | None] = default_repository,
               cache_size: int = 8) -> FastAPI:
    app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityMiddleware)
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
    state = AppState(analyzer_factory, repository_factory, cache_size)
    app.state.cs = state
    templates = _templates()

    def page(request: Request, name: str, context: dict, status_code: int = 200,
             active: str | None = None) -> HTMLResponse:
        context = {"db_available": state.repo is not None, "active": active, **context}
        return templates.TemplateResponse(request, name, context, status_code=status_code)

    # --- analyze ------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def analyze_form(request: Request) -> HTMLResponse:
        limits = settings.ingestion
        return page(request, "analyze.html", {
            "max_mb": limits.max_file_size_bytes // 1_048_576,
            "max_pages": limits.max_pdf_pages,
            "accept": ",".join(sorted(limits.allowed_extensions)),
        }, active="analyze")

    @app.post("/analyze")
    def analyze(request: Request, file: UploadFile) -> Response:
        # Sync endpoint: FastAPI runs it in a worker thread, so analysis doesn't block
        # the event loop.
        filename = _safe_filename(file.filename)
        limit = settings.ingestion.max_file_size_bytes
        data = file.file.read(limit + 1)
        error = None
        if len(data) > limit:
            error = f"the file is larger than {limit // 1_048_576} MB."
        elif not data:
            error = "the file is empty."
        result = None
        if error is None:
            result, error = _run(state.analyzer, data, filename)
        if error is not None:
            fragment = request.headers.get("hx-request") == "true"
            return page(request, "_upload_error.html" if fragment else "analyze.html",
                        {"error": error, "filename": filename,
                         "max_mb": limit // 1_048_576,
                         "max_pages": settings.ingestion.max_pdf_pages,
                         "accept": ",".join(sorted(settings.ingestion.allowed_extensions))},
                        status_code=200 if fragment else 422, active="analyze")
        ref, note = _store(state, result)
        url = f"/analyses/{ref}" + (f"?saved={note}" if note else "")
        if request.headers.get("hx-request") == "true":
            return Response(status_code=204, headers={"HX-Redirect": url})
        return RedirectResponse(url, status_code=303)

    # --- one analysis -----------------------------------------------------------------

    @app.get("/analyses/{ref}", response_class=HTMLResponse)
    def analysis(request: Request, ref: str, tab: str = "risk",
                 saved: str | None = None) -> HTMLResponse:
        view, result = _load(state, ref)
        if view is None:
            message = ("This unsaved analysis is no longer in memory (the server keeps only "
                       "the most recent ones). Analyse the document again."
                       if ref.startswith(UNSAVED_PREFIX) else "Analysis not found.")
            return page(request, "not_found.html", {"message": message}, status_code=404)
        available = tabs.available_tabs(result is not None)
        if tab not in {t.key for t in available}:
            tab = "risk"
        ctx = tabs.TabContext(view, result, request.query_params, state.repo)
        context = {"ref": ref, "view": view, "tab": tab, "tabs": available,
                   "data": tabs.BUILDERS[tab](ctx)}
        if _is_fragment(request):
            return page(request, "_tab_area.html", context)
        note = SAVE_NOTES.get(saved or "")
        context.update(summary=tabs.summary(view),
                       save_note=note.format(id=view.analysis_id) if note else None,
                       unsaved=ref.startswith(UNSAVED_PREFIX))
        return page(request, "analysis.html", context)

    @app.get("/healthz")
    def health() -> dict:
        return {"status": "ok"}

    return app


def _run(analyzer: Analyzer, data: bytes,
         filename: str) -> tuple[AnalysisResult | None, str | None]:
    """Return ``(result, error_message)``; exactly one of them is ``None``."""
    try:
        return analyzer.analyze(data, filename), None
    except CyberSleuthError as exc:
        return None, str(exc)
    except Exception:  # unexpected bug: log full details, show a generic message
        logger.exception("Unexpected failure analysing %s", filename)
        return None, "an unexpected error occurred while processing this file. See the logs."


def _store(state: AppState, result: AnalysisResult) -> tuple[str, str | None]:
    """Save the result if possible; cache it either way. Returns ``(ref, save note)``."""
    if state.repo is not None:
        try:
            outcome = state.repo.save(result)
        except DatabaseError:
            logger.exception("Could not save analysis of %s", result.document.filename)
        else:
            ref = str(outcome.analysis_id)
            state.cache.put(ref, result)
            return ref, "new" if outcome.created else "existing"
    ref = new_unsaved_ref()
    state.cache.put(ref, result)
    return ref, None


def _load(state: AppState, ref: str) -> tuple[StoredAnalysis | None, AnalysisResult | None]:
    result = state.cache.get(ref)
    if ref.startswith(UNSAVED_PREFIX):
        return (view_from_result(result), result) if result is not None else (None, None)
    if not ref.isdigit() or state.repo is None:
        return None, None
    try:
        return hydrate(state.repo.get_analysis(int(ref))), result
    except DatabaseError:
        return None, None
