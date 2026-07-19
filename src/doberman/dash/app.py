"""Starlette app factory for the local dashboard (D1: serving skeleton only).

Binds to ``127.0.0.1`` only; the ``doberman dash`` CLI command hands in a
per-run bearer token generated with ``secrets.token_urlsafe(32)``. ``GET /``
(the inline HTML shell) carries no data and is served without auth; every
``/api/*`` route requires ``Authorization: Bearer <token>``, checked with
``hmac.compare_digest`` (constant-time, avoids a timing side-channel), else
401. No cookies are ever set - there is no CSRF surface.

This module (and the ``doberman.dash`` package) is only ever imported lazily
from the ``dash`` CLI command, never at module scope elsewhere, so ``import
doberman`` and the rest of the CLI keep working with the optional ``dash``
extra (``starlette``, ``uvicorn``) not installed - see
``tests/unit/test_dash_serve.py`` and the import-linter contract forbidding
the policy core from importing ``doberman.dash``.

Later slices add the live decision feed (SSE), summary stats, and
approve/deny actions; D1 is the skeleton only.
"""

from __future__ import annotations

import hmac

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

_BEARER_PREFIX = "Bearer "

# ponytail: one inline page, no build toolchain - real UI lands in a later slice.
_HTML_SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Doberman Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: dark light; }
  body {
    margin: 0; padding: 2rem; min-height: 100vh; box-sizing: border-box;
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #0b0d10; color: #e6e6e6;
  }
  @media (prefers-color-scheme: light) {
    body { background: #f7f7f8; color: #111; }
  }
  h1 { font-size: 1.1rem; font-weight: 600; margin: 0 0 1rem; }
  #status { display: inline-flex; align-items: center; gap: .5rem; font-size: .9rem; }
  .dot { width: .6rem; height: .6rem; border-radius: 50%; background: #888; flex: none; }
  .dot.ok { background: #3fb950; }
  .dot.err { background: #f85149; }
</style>
</head>
<body>
  <h1>Doberman Dashboard (preview)</h1>
  <div id="status"><span class="dot" id="dot"></span><span id="label">connecting...</span></div>
  <script>
    (function () {
      var params = new URLSearchParams(window.location.search);
      var token = params.get("token") || "";
      // Strip the token from the URL/history immediately so it never lingers
      // in browser history, a referrer header, or a screen share. It is kept
      // only in this closure's memory for the life of the page.
      params.delete("token");
      var clean = window.location.pathname
        + (params.toString() ? "?" + params.toString() : "");
      window.history.replaceState({}, document.title, clean);

      var dot = document.getElementById("dot");
      var label = document.getElementById("label");

      fetch("/api/health", { headers: { "Authorization": "Bearer " + token } })
        .then(function (res) {
          if (!res.ok) { throw new Error("status " + res.status); }
          return res.json();
        })
        .then(function () {
          dot.className = "dot ok";
          label.textContent = "connected";
        })
        .catch(function () {
          dot.className = "dot err";
          label.textContent = "not connected";
        });
    })();
  </script>
</body>
</html>
"""


def _unauthorized() -> JSONResponse:
    return JSONResponse({"error": "unauthorized"}, status_code=401)


def _token_matches(request: Request, token: str) -> bool:
    header = request.headers.get("authorization", "")
    if not header.startswith(_BEARER_PREFIX):
        return False
    supplied = header[len(_BEARER_PREFIX) :]
    return hmac.compare_digest(supplied, token)


async def _index(request: Request) -> Response:
    # No auth: the shell carries no data, only the JS that reads the token
    # back out of its own URL and calls the authenticated API routes.
    return HTMLResponse(_HTML_SHELL)


def _make_health_route(token: str) -> Route:
    async def health(request: Request) -> Response:
        if not _token_matches(request, token):
            return _unauthorized()
        return JSONResponse({"status": "ok"})

    return Route("/api/health", health)


def create_app(token: str) -> Starlette:
    """Build the dashboard's Starlette app, bound to one per-run ``token``.

    ``GET /`` is unauthenticated (no data). Every ``/api/*`` route requires
    the bearer token, checked in constant time.
    """
    routes = [
        Route("/", _index),
        _make_health_route(token),
    ]
    return Starlette(routes=routes)
