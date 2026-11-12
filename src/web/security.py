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
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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


class _BodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    """Refuse request bodies over ``max_bytes`` while they stream in (HTTP 413).

    The multipart parser spools uploads to a temporary file before the endpoint sees them,
    so the endpoint's own size check alone would let one huge upload fill the disk. This
    checks the declared Content-Length up front and counts the bytes actually received, so
    a chunked upload with no Content-Length is stopped too.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_bytes):
            await self._refuse(scope, receive, send)
            return
        received = 0
        exceeded = False
        started = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if exceeded:  # the app turned the aborted read into its own error: replace it
                if message["type"] == "http.response.start" and not started:
                    started = True
                    await self._refuse(scope, receive, send)
                return
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except _BodyTooLarge:
            if not started:
                await self._refuse(scope, receive, send)

    async def _refuse(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit_mb = self.max_bytes // 1_048_576
        response = PlainTextResponse(f"Request too large (limit {limit_mb} MB).",
                                     status_code=413)
        await response(scope, receive, send)
