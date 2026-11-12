"""FastAPI application: routes for uploading, analysing and viewing threat reports.

Pages are server-rendered with Jinja2. HTMX swaps fragments for tab changes and filters;
every page also works as a plain full-page request.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path, PurePath

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

from config.settings import settings
from src.database.db_manager import AnalysisRepository, DatabaseError
from src.database.views import StoredAnalysis, hydrate, rescore_analysis, view_from_result
from src.intelligence.analyzer import AnalysisResult, Analyzer
from src.reporting import csv_report, json_report, pdf_report
from src.reporting.common import report_stem
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
EXPORTS = {
    "pdf": ("application/pdf", pdf_report.to_pdf),
    "json": ("application/json", json_report.to_json),
    "zip": ("application/zip", csv_report.to_csv_zip),
}


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

    def render_analysis(request: Request, ref: str, tab: str, flash: str | None = None,
                        fragment: bool = False, saved: str | None = None) -> HTMLResponse:
        view, result = _load(state, ref)
        if view is None:
            message = ("This unsaved analysis is no longer in memory (the server keeps only "
                       "the most recent ones). Analyse the document again."
                       if ref.startswith(UNSAVED_PREFIX) else "Analysis not found.")
            return page(request, "not_found.html", {"message": message}, status_code=404)
        available = tabs.available_tabs(result is not None)
        if tab not in {t.key for t in available}:
            tab = "risk"
        ctx = tabs.TabContext(view, result, request.query_params, state.repo, flash)
        context = {"ref": ref, "view": view, "tab": tab, "tabs": available,
                   "data": tabs.BUILDERS[tab](ctx), "query": request.url.query,
                   "summary": tabs.summary(view)}
        if fragment:
            return page(request, "_tab_area.html", context)
        note = SAVE_NOTES.get(saved or "")
        context.update(save_note=note.format(id=view.analysis_id) if note else None,
                       unsaved=ref.startswith(UNSAVED_PREFIX))
        return page(request, "analysis.html", context)

    @app.get("/analyses/{ref}", response_class=HTMLResponse)
    def analysis(request: Request, ref: str, tab: str = "risk",
                 saved: str | None = None) -> HTMLResponse:
        return render_analysis(request, ref, tab, fragment=_is_fragment(request), saved=saved)

    # --- analyst verdicts -----------------------------------------------------------

    def verdict_response(request: Request, analysis_id: int, tab: str,
                         message: str) -> Response:
        if request.headers.get("hx-request") == "true":
            response = render_analysis(request, str(analysis_id), tab, flash=message,
                                       fragment=True)
            response.headers["HX-Trigger"] = "cs:verdict"
            return response
        query = request.url.query
        return RedirectResponse(f"/analyses/{analysis_id}?{query or f'tab={tab}'}",
                                status_code=303)

    def stored_view(analysis_id: int) -> StoredAnalysis | None:
        if state.repo is None:
            return None
        try:
            return hydrate(state.repo.get_analysis(analysis_id))
        except DatabaseError:
            return None

    @app.post("/analyses/{analysis_id}/mappings/{mapping_id}/verdict")
    def mapping_verdict(request: Request, analysis_id: int, mapping_id: int,
                        verdict: str = Form(), note: str = Form("")) -> Response:
        view = stored_view(analysis_id)
        if view is None or mapping_id not in view.mapping_ids.values():
            return Response("Unknown mapping.", status_code=404, media_type="text/plain")
        try:
            state.repo.set_mapping_verdict(mapping_id, verdict, note.strip() or None)
        except DatabaseError as exc:
            return Response(str(exc), status_code=400, media_type="text/plain")
        # Confirmed suggestions now count toward the risk score; rejected ones don't.
        rescore_analysis(state.repo, analysis_id)
        return verdict_response(request, analysis_id, "attack",
                                f"Saved verdict '{verdict}'. The risk score was updated.")

    @app.post("/analyses/{analysis_id}/indicators/{indicator_id}/verdict")
    def indicator_verdict(request: Request, analysis_id: int, indicator_id: int,
                          verdict: str = Form(), note: str = Form("")) -> Response:
        view = stored_view(analysis_id)
        if view is None or indicator_id not in view.indicator_ids.values():
            return Response("Unknown indicator.", status_code=404, media_type="text/plain")
        try:
            state.repo.set_indicator_verdict(indicator_id, verdict, note.strip() or None)
        except DatabaseError as exc:
            return Response(str(exc), status_code=400, media_type="text/plain")
        return verdict_response(request, analysis_id, "iocs", f"Saved verdict '{verdict}'.")

    # --- reports ------------------------------------------------------------------------

    @app.get("/analyses/{ref}/export/{fmt}")
    def export(ref: str, fmt: str) -> Response:
        view, _ = _load(state, ref)
        if view is None or fmt not in EXPORTS:
            return Response("Not found.", status_code=404, media_type="text/plain")
        media_type, build = EXPORTS[fmt]
        # Built on request, so verdicts saved since the analysis are included.
        events = (state.repo.verification_events(view.analysis_id)
                  if state.repo is not None and view.analysis_id else [])
        filename = f"{report_stem(view)}.{fmt}"  # report_stem allows only [A-Za-z0-9_-]
        return Response(build(view, events), media_type=media_type, headers={
            "Content-Disposition": f'attachment; filename="{filename}"'})

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
