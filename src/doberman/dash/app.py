"""Starlette app factory for the local dashboard (D1 skeleton + D2 feed/stats).

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

D2 adds two READ-ONLY surfaces, both serving only already-redacted data (the
decision log is redacted at write time - see ``doberman.storage.log``):

* ``GET /api/stats`` - verdict counts, top reason codes, secret/taint event
  count, current mode + effective enforcement. Bearer token via header only.
* ``GET /api/feed`` - a Server-Sent Events stream: recent rows as backfill,
  then newly-written rows as they land. Browser ``EventSource`` cannot set
  request headers, so this route ALSO accepts the token as ``?token=``,
  compared in constant time exactly like the header - sound here because the
  server is loopback-only and the token is single-use per run (see
  ``_feed_token_matches``).

D3 adds the interactive AUTH approve/deny queue, mediated ENTIRELY through the
local SQLite ``pending_approvals`` table (:mod:`doberman.storage.approvals`) -
never HTTP into the decision path:

* ``GET /api/pending`` - unexpired rows still awaiting a decision. Same
  allow-listed, redaction-safe vocabulary as the D2 feed (action type, risk,
  reason codes, the human explanation, path *class*, tier) - never a raw
  target/argument/secret. Bearer token via header only (no query-param
  fallback - this route isn't consumed by ``EventSource``).
* ``POST /api/resolve/{id}`` - body ``{"decision": "approved"|"denied",
  "totp_code": <str, optional>}``. Resolves the row via the same race-safe,
  single-use ``UPDATE ... WHERE status='pending'`` :func:`doberman.storage.
  approvals.resolve` used everywhere else; an already-resolved or expired row
  -> 409. The dash server NEVER verifies the TOTP code itself - it only rides
  along on the row back to the ``DashboardPrompter`` polling it on the
  decision-path side, which feeds it through the EXISTING
  :func:`doberman.auth.totp.verify`.

D5 (polish) is a later slice - not built here.
"""

from __future__ import annotations

import asyncio
import hmac
import json
from collections.abc import AsyncIterator

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from doberman.dash.stats import build_stats, reason_codes
from doberman.storage import approvals
from doberman.storage.log import read_decisions, read_decisions_since

#: Tiers whose challenge requires a TOTP code (mirrors
#: ``LocalAuthProvider._run_tier``'s ``two_factor``/``role_elevation`` branch).
_TOTP_TIERS = frozenset({"two_factor", "role_elevation"})

_BEARER_PREFIX = "Bearer "
#: Rows sent immediately on `/api/feed` connect, oldest-first, before live polling starts.
_FEED_BACKFILL_LIMIT = 50
#: Default poll interval for new rows; overridable per `create_app` call (tests use a
#: much shorter one so the feed test doesn't wait on the wall clock).
_FEED_POLL_INTERVAL_S = 1.0

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
  #stats { margin: 1rem 0; font-size: .85rem; opacity: .85; }
  #feed {
    list-style: none; margin: .5rem 0 0; padding: 0; max-height: 60vh;
    overflow-y: auto; border: 1px solid #333; border-radius: 4px;
  }
  @media (prefers-color-scheme: light) { #feed { border-color: #ccc; } }
  #feed li {
    padding: .35rem .6rem; border-bottom: 1px solid #222; font-size: .8rem;
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
  }
  @media (prefers-color-scheme: light) { #feed li { border-color: #eee; } }
  #feed li:last-child { border-bottom: none; }
  h2 { font-size: .9rem; font-weight: 600; margin: 1.5rem 0 .5rem; }
  #pending-list { list-style: none; margin: 0; padding: 0; }
  #pending-list li {
    padding: .6rem; margin-bottom: .5rem; border: 1px solid #333; border-radius: 4px;
    font-size: .8rem;
  }
  @media (prefers-color-scheme: light) { #pending-list li { border-color: #ccc; } }
  #pending-list .row-explanation { margin: .3rem 0; }
  #pending-list input[type="text"] {
    font-family: inherit; font-size: .85rem; padding: .25rem .4rem; margin-right: .4rem;
    width: 8rem;
  }
  #pending-list button {
    font: inherit; font-size: .8rem; padding: .3rem .7rem; margin-right: .4rem;
    border: 1px solid #444; border-radius: 4px; background: transparent; color: inherit;
    cursor: pointer;
  }
  #pending-list button.approve { border-color: #3fb950; }
  #pending-list button.deny { border-color: #f85149; }
  #pending-empty { opacity: .6; font-size: .8rem; }
</style>
</head>
<body>
  <h1>Doberman Dashboard (preview)</h1>
  <div id="status"><span class="dot" id="dot"></span><span id="label">connecting...</span></div>
  <div id="stats">stats loading...</div>
  <h2>Pending approvals</h2>
  <ul id="pending-list"></ul>
  <div id="pending-empty">no pending approvals</div>
  <h2>Recent decisions</h2>
  <ul id="feed"></ul>
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
      var statsEl = document.getElementById("stats");
      var feedEl = document.getElementById("feed");
      var MAX_FEED_ROWS = 200;

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

      fetch("/api/stats", { headers: { "Authorization": "Bearer " + token } })
        .then(function (res) {
          if (!res.ok) { throw new Error("status " + res.status); }
          return res.json();
        })
        .then(function (s) {
          statsEl.textContent =
            "decisions: " + s.total_decisions +
            " | verdicts: " + JSON.stringify(s.verdict_counts) +
            " | secret/taint events: " + s.secret_taint_events +
            " | mode: " + s.mode + " | enforcement: " + s.enforcement;
        })
        .catch(function () {
          statsEl.textContent = "stats unavailable";
        });

      var pendingList = document.getElementById("pending-list");
      var pendingEmpty = document.getElementById("pending-empty");
      var PENDING_POLL_MS = 2000;

      function resolveApproval(id, decision, totpCode, card) {
        var body = { decision: decision };
        if (totpCode) { body.totp_code = totpCode; }
        fetch("/api/resolve/" + encodeURIComponent(id), {
          method: "POST",
          headers: {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(body)
        }).then(function (res) {
          if (res.ok) {
            card.remove();
          } else {
            // Already resolved/expired elsewhere, or a bad request — refresh
            // the list from the server rather than trust local state.
            refreshPending();
          }
        }).catch(function () { /* network hiccup — next poll retries */ });
      }

      function renderPending(rows) {
        pendingList.textContent = "";
        pendingEmpty.style.display = rows.length ? "none" : "block";
        rows.forEach(function (row) {
          var li = document.createElement("li");

          var header = document.createElement("div");
          // textContent only — every field is row-derived and must render
          // literally, never as markup (mirrors the feed's discipline).
          header.textContent = "[" + row.risk + "] " + row.action_type +
            " " + (row.target_path_class || "-") + " (tier: " + row.tier + ")";
          li.appendChild(header);

          var reasons = document.createElement("div");
          reasons.textContent = (row.reason_codes || []).join(", ") || "-";
          li.appendChild(reasons);

          var explanation = document.createElement("div");
          explanation.className = "row-explanation";
          explanation.textContent = row.explanation || "";
          li.appendChild(explanation);

          var totpInput = null;
          if (row.needs_totp) {
            totpInput = document.createElement("input");
            totpInput.type = "text";
            totpInput.placeholder = "TOTP code";
            totpInput.autocomplete = "off";
            li.appendChild(totpInput);
          }

          var approveBtn = document.createElement("button");
          approveBtn.type = "button";
          approveBtn.className = "approve";
          approveBtn.textContent = "Approve";
          approveBtn.addEventListener("click", function () {
            resolveApproval(row.id, "approved", totpInput ? totpInput.value : null, li);
          });
          li.appendChild(approveBtn);

          var denyBtn = document.createElement("button");
          denyBtn.type = "button";
          denyBtn.className = "deny";
          denyBtn.textContent = "Deny";
          denyBtn.addEventListener("click", function () {
            resolveApproval(row.id, "denied", totpInput ? totpInput.value : null, li);
          });
          li.appendChild(denyBtn);

          pendingList.appendChild(li);
        });
      }

      function refreshPending() {
        fetch("/api/pending", { headers: { "Authorization": "Bearer " + token } })
          .then(function (res) {
            if (!res.ok) { throw new Error("status " + res.status); }
            return res.json();
          })
          .then(renderPending)
          .catch(function () { /* leave the last known list showing */ });
      }

      refreshPending();
      setInterval(refreshPending, PENDING_POLL_MS);

      // EventSource cannot set request headers, so the token travels as a
      // query param here only (see doberman.dash.app._feed_token_matches).
      try {
        var source = new EventSource("/api/feed?token=" + encodeURIComponent(token));
        source.addEventListener("decision", function (evt) {
          var row;
          try {
            row = JSON.parse(evt.data);
          } catch (e) {
            return;
          }
          var li = document.createElement("li");
          // textContent only - a row-derived string must render literally,
          // never as markup (mirrors the TUI's markup=False discipline).
          li.textContent = "[" + row.verdict + "] " + row.action_type +
            " " + (row.target_path_class || "-") +
            " " + (row.reason_codes && row.reason_codes.length ? row.reason_codes.join(",") : "-") +
            " @ " + row.ts;
          feedEl.appendChild(li);
          while (feedEl.children.length > MAX_FEED_ROWS) {
            feedEl.removeChild(feedEl.firstChild);
          }
        });
      } catch (e) {
        // EventSource unsupported/blocked - the feed just stays empty.
      }
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


def _feed_token_matches(request: Request, token: str) -> bool:
    """Auth check for ``/api/feed`` only: header OR ``?token=`` query param.

    Browser ``EventSource`` cannot set custom request headers, so the header
    check alone would lock the dashboard's own feed UI out of its own feed.
    Accepting the token as a query param here is sound specifically because:
    the server is bound to 127.0.0.1 only (never reachable off-box), and the
    token is a fresh, single-run secret (not a long-lived credential) - so a
    query-string leak (proxy logs, shell history) has a narrow blast radius
    scoped to one local dashboard session. Still constant-time compared.
    """
    if _token_matches(request, token):
        return True
    supplied = request.query_params.get("token", "")
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


def _make_stats_route(token: str, repo_root: str) -> Route:
    async def stats(request: Request) -> Response:
        if not _token_matches(request, token):
            return _unauthorized()
        return JSONResponse(await build_stats(repo_root))

    return Route("/api/stats", stats)


def _feed_row(row: dict) -> dict:
    """The ONLY fields the feed ever serializes - exactly what the TUI shows.

    ``row`` comes from :func:`doberman.storage.log.read_decisions`/
    ``read_decisions_since``, already redacted at write time (path *class*,
    not a raw path; no raw arguments; no secrets). This picks a further
    subset - e.g. ``agent_role``/``source_context``/``auth_result`` are
    dropped even though they're on the row - per the D2 rule of only ever
    passing through what the decision-transparency TUI itself displays.
    """
    return {
        "id": row.get("id"),
        "ts": row.get("ts"),
        "verdict": row.get("final_verdict"),
        "action_type": row.get("action_type"),
        "target_path_class": row.get("target_path_class"),
        "reason_codes": reason_codes(row),
    }


def _sse_event(row: dict) -> str:
    return f"event: decision\ndata: {json.dumps(_feed_row(row))}\n\n"


def _make_feed_route(
    token: str,
    repo_root: str,
    *,
    poll_interval: float = _FEED_POLL_INTERVAL_S,
    max_polls: int | None = None,
    backfill_limit: int = _FEED_BACKFILL_LIMIT,
) -> Route:
    async def feed(request: Request) -> Response:
        if not _feed_token_matches(request, token):
            return _unauthorized()

        async def event_stream() -> AsyncIterator[str]:
            # Backfill: most recent `backfill_limit` rows, oldest first, so
            # the feed reads top-to-bottom in the order things happened.
            backfill = await read_decisions(repo_root, limit=backfill_limit)
            backfill.reverse()
            last_id = 0
            for row in backfill:
                last_id = max(last_id, row.get("id") or 0)
                yield _sse_event(row)

            # Live poll: cursor-based "what's new since the last id I sent".
            # `max_polls=None` (production) polls forever - a real ASGI
            # server streams each yield to the socket incrementally. Tests
            # pass a small bound instead: both starlette.testclient.TestClient
            # and httpx.ASGITransport fully await this generator to
            # completion before handing back any response bytes, so an
            # unbounded loop would hang a test forever rather than merely
            # "not stream incrementally" - bounding it is what makes the
            # route testable at all without a real socket.
            polls = 0
            while max_polls is None or polls < max_polls:
                await asyncio.sleep(poll_interval)
                new_rows = await read_decisions_since(repo_root, last_id)
                for row in new_rows:
                    last_id = max(last_id, row.get("id") or 0)
                    yield _sse_event(row)
                polls += 1

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return Route("/api/feed", feed)


def _pending_row(row: dict) -> dict:
    """The ONLY fields ``/api/pending`` ever serializes for one queued approval.

    ``row`` comes from :func:`doberman.storage.approvals.list_pending` /
    ``get_pending`` - already redaction-safe at write time (path *class*, the
    human explanation string, reason-code/tier/risk/action-type CLASSES). This
    is a further allow-list on top: ``decision``/``totp_code`` are the
    resolution's own write-side fields and are never echoed back out.
    """
    return {
        "id": row.get("id"),
        "created_at": row.get("created_at"),
        "expires_at": row.get("expires_at"),
        "tier": row.get("tier"),
        "action_type": row.get("action_type"),
        "risk": row.get("risk"),
        "reason_codes": row.get("reason_codes") or [],
        "explanation": row.get("explanation"),
        "target_path_class": row.get("target_path_class"),
        "needs_totp": row.get("tier") in _TOTP_TIERS,
    }


def _make_pending_route(token: str, repo_root: str) -> Route:
    async def pending(request: Request) -> Response:
        if not _token_matches(request, token):
            return _unauthorized()
        rows = await approvals.list_pending(repo_root=repo_root)
        return JSONResponse([_pending_row(row) for row in rows])

    return Route("/api/pending", pending)


def _make_resolve_route(token: str, repo_root: str) -> Route:
    async def resolve(request: Request) -> Response:
        if not _token_matches(request, token):
            return _unauthorized()
        approval_id = request.path_params["approval_id"]
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        decision = body.get("decision")
        if decision not in ("approved", "denied"):
            return JSONResponse({"error": "decision must be 'approved' or 'denied'"}, 400)
        totp_code = body.get("totp_code")
        won = await approvals.resolve(
            approval_id,
            decision=decision,
            totp_code=totp_code if isinstance(totp_code, str) else None,
            repo_root=repo_root,
        )
        if not won:
            return JSONResponse({"error": "already resolved or expired"}, status_code=409)
        return JSONResponse({"status": "resolved"})

    return Route("/api/resolve/{approval_id}", resolve, methods=["POST"])


def create_app(
    token: str,
    repo_root: str = ".",
    *,
    feed_poll_interval: float = _FEED_POLL_INTERVAL_S,
    feed_max_polls: int | None = None,
) -> Starlette:
    """Build the dashboard's Starlette app, bound to one per-run ``token``.

    ``GET /`` is unauthenticated (no data). Every ``/api/*`` route requires
    the bearer token, checked in constant time (``/api/feed`` also accepts it
    as ``?token=`` - see :func:`_feed_token_matches`). ``repo_root`` is the
    repo the dash was launched in - the same root every stats/feed read is
    scoped to. ``feed_poll_interval``/``feed_max_polls`` exist so tests can
    bound and speed up the feed's live-poll loop; production leaves both at
    their defaults (real interval, unbounded).
    """
    routes = [
        Route("/", _index),
        _make_health_route(token),
        _make_stats_route(token, repo_root),
        _make_feed_route(
            token, repo_root, poll_interval=feed_poll_interval, max_polls=feed_max_polls
        ),
        _make_pending_route(token, repo_root),
        _make_resolve_route(token, repo_root),
    ]
    return Starlette(routes=routes)
