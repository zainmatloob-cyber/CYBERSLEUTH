"""HTTP hardening: security headers and a cross-site request check.

Document content is untrusted. Templates are rendered with Jinja2 autoescaping, so text
taken from a document is always shown as text. The Content-Security-Policy is a second
line of defence: only scripts served by this app may run (no inline scripts, no eval).

CSRF: the app has no login, so the risk is another website making the analyst's browser
send a POST to this server (e.g. to delete a document). Browsers label every request
with ``Sec-Fetch-Site`` and cross-origin POSTs with ``Origin``; state-changing requests
are refused unless both say the request came from this app's own pages. Clients that
send neither header (curl, the test client) are not browsers and cannot carry a
victim's ambient credentials, so they are allowed.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    # Plotly positions chart elements with inline style attributes.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ALLOWED_FETCH_SITES = frozenset({"same-origin", "none"})


def is_cross_site(request: Request) -> bool:
    """True if a browser reports this request as coming from another site."""
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site not in _ALLOWED_FETCH_SITES:
        return True
    origin = request.headers.get("origin")
    if origin is None:
        return False
    own = f"{request.url.scheme}://{request.headers.get('host', '')}"
    return origin != own


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method not in SAFE_METHODS and is_cross_site(request):
            response: Response = PlainTextResponse("Cross-site request refused.",
                                                   status_code=403)
        else:
            response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response
