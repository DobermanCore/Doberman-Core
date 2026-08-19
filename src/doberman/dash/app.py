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

D5 (polish) layers verdict/risk color badges, a mode + enforcement header bar,
and CSS-only empty states onto this same inline shell - the dark-by-default
palette is formalized as CSS custom properties. Still no build toolchain, no
new endpoints, no change to auth/redaction/decision-path behavior.
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
  :root {
    color-scheme: dark light;
    --ink-0: oklch(13% 0.008 55);
    --ink-1: oklch(16% 0.009 55);
    --ink-2: oklch(19.5% 0.010 55);
    --ink-3: oklch(25% 0.012 55);
    --rule: oklch(34% 0.012 55);
    --rule-2: oklch(28% 0.011 55);
    --fg: oklch(96% 0 0);
    --fg-2: oklch(82% 0.004 55);
    --fg-3: oklch(64% 0.006 55);
    --tan: oklch(74% 0.140 58);
    --tan-hi: oklch(84% 0.150 64);
    --mono: ui-monospace, "SF Mono", Consolas, monospace;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    --pass: oklch(76% 0.16 152);
    --pass-bg: oklch(76% 0.16 152 / 14%);
    --auth: oklch(82% 0.155 78);
    --auth-bg: oklch(82% 0.155 78 / 14%);
    --block: oklch(66% 0.205 26);
    --block-bg: oklch(66% 0.205 26 / 14%);
    --neutral: var(--fg-3);
    --neutral-bg: oklch(64% 0.006 55 / 14%);
    --r-sm: 8px;
    --r: 10px;
    --r-lg: 12px;
    --d: 140ms ease-out;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --ink-0: #f7f7f8; --ink-1: #ffffff; --ink-2: #eef0f2; --ink-3: #e2e5e9;
      --rule: #c7ccd2; --rule-2: #dde1e6;
      --fg: #15181d; --fg-2: #3a4048; --fg-3: #5b6572;
      --tan: #6b4a1f; --tan-hi: #52380f;
      --pass: #116329;  --pass-bg: rgba(17, 99, 41, .12);
      --auth: #7d5200;  --auth-bg: rgba(125, 82, 0, .12);
      --block: #a40e26; --block-bg: rgba(164, 14, 38, .12);
      --neutral: #424a53; --neutral-bg: rgba(66, 74, 83, .12);
    }
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
  }
  body {
    margin: 0 auto; padding: 1.5rem 1.5rem 4rem; min-height: 100vh; max-width: 1080px;
    font: 14px/1.5 var(--font);
    background: var(--ink-0); color: var(--fg);
    -webkit-font-smoothing: antialiased;
  }
  h2 {
    font-family: var(--mono); font-size: .72rem; font-weight: 600;
    letter-spacing: .08em; text-transform: uppercase; color: var(--fg-3);
    margin: 1.75rem 0 .6rem;
  }
  .topbar {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    gap: .6rem 1rem;
    padding-bottom: 1.1rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--rule-2);
  }
  .brand { display: inline-flex; align-items: center; gap: .6rem; }
  .brand svg { width: 28px; height: 28px; flex: none; }
  .brand .word {
    font-family: var(--mono); font-weight: 700; font-size: .95rem;
    letter-spacing: .06em; color: var(--tan);
  }
  .topbar-right { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
  .chip {
    display: inline-flex; align-items: center; gap: .4rem;
    font-family: var(--mono); font-size: .72rem; letter-spacing: .02em;
    padding: .32rem .6rem; border: 1px solid var(--rule); border-radius: 999px;
    background: var(--ink-2); color: var(--fg-3); white-space: nowrap;
  }
  .dot { width: .5rem; height: .5rem; border-radius: 50%; background: var(--neutral); flex: none; }
  .dot.ok { background: var(--pass); }
  .dot.err { background: var(--block); }
  .status-pill {
    display: inline-flex; align-items: center; gap: .45rem;
    font-family: var(--mono); font-size: .76rem; font-weight: 600; letter-spacing: .03em;
    padding: .4rem .75rem; border-radius: 999px; border: 1px solid var(--rule);
    color: var(--fg-3); white-space: nowrap;
  }
  .status-pill .pip { font-size: .7em; }
  .status-pill.ok .pip { color: var(--tan); }
  .status-pill.alert { color: var(--auth); border-color: var(--auth); background: var(--auth-bg); }
  .status-pill.alert .pip { animation: pulse 1.6s ease-in-out infinite; }
  @media (prefers-reduced-motion: reduce) { .status-pill.alert .pip { animation: none; } }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
  .badge {
    display: inline-flex; align-items: center; font-family: var(--mono);
    font-size: .72rem; font-weight: 700; letter-spacing: .02em;
    padding: .24rem .5rem; border-radius: 5px; line-height: 1.4;
  }
  .badge-pass { color: var(--pass); background: var(--pass-bg); }
  .badge-auth { color: var(--auth); background: var(--auth-bg); }
  .badge-block { color: var(--block); background: var(--block-bg); }
  .badge-neutral { color: var(--neutral); background: var(--neutral-bg); }
  .badge-risk-low { color: var(--pass); background: var(--pass-bg); }
  .badge-risk-medium { color: var(--auth); background: var(--auth-bg); }
  .badge-risk-high, .badge-risk-critical { color: var(--block); background: var(--block-bg); }
  #stats {
    margin: 0 0 1.75rem; font-family: var(--mono); font-size: .82rem; color: var(--fg-3);
    display: flex; flex-wrap: wrap; gap: .4rem .6rem; align-items: center;
    padding: .85rem 1.1rem; border: 1px solid var(--rule-2); border-radius: var(--r);
    background: var(--ink-1);
  }
  #stats .count { color: var(--fg); }
  .empty-state {
    padding: 2rem 1.5rem; border: 1px dashed var(--rule); border-radius: var(--r);
    color: var(--fg-3); font-size: .85rem; text-align: center;
  }
  #feed, #pending-list { list-style: none; margin: .5rem 0 0; }
  #feed:not(:empty) ~ #feed-empty { display: none; }
  #pending-list:not(:empty) ~ #pending-empty { display: none; }
  #pending-list .badge { font-size: .76rem; padding: .25rem .55rem; }
  #pending-list li {
    padding: 1.4rem 1.5rem 1.5rem; margin-bottom: .9rem;
    border: 1px solid var(--auth); border-radius: var(--r-lg); background: var(--ink-1);
    font-size: .85rem;
    box-shadow: 0 6px 20px -10px oklch(0% 0 0 / 55%);
    animation: pending-arrive .28s ease-out both;
  }
  @keyframes pending-arrive {
    from { opacity: 0; transform: translateY(-6px); }
    to { opacity: 1; transform: none; }
  }
  @media (prefers-reduced-motion: reduce) {
    #pending-list li { animation: none; }
  }
  #pending-list .row-header { display: flex; align-items: center; gap: .5rem; margin-bottom: .6rem; flex-wrap: wrap; }
  #pending-list .row-header .detail { color: var(--fg); font-family: var(--mono); font-size: .82rem; }
  #pending-list > li > .detail {
    color: var(--auth); font-family: var(--mono); font-size: .84rem; font-weight: 600;
  }
  #pending-list .row-explanation { margin: .5rem 0 1rem; color: var(--fg-2); line-height: 1.6; max-width: 62ch; }
  #pending-list input {
    font-family: var(--mono); font-size: .95rem; padding: .45rem .6rem; margin-right: .5rem;
    letter-spacing: .12em; width: 9rem;
    background: var(--ink-0); color: var(--fg); border: 1px solid var(--rule); border-radius: 4px;
  }
  #pending-list button {
    font-family: var(--font); font-size: .86rem; font-weight: 600; padding: .55rem 1.15rem; margin-right: .5rem;
    border-radius: var(--r-sm); cursor: pointer;
    transition: background-color var(--d), border-color var(--d), color var(--d);
  }
  #pending-list button.deny { background: transparent; border: 1px solid var(--rule); color: var(--block); }
  #pending-list button.deny:hover { border-color: var(--block); background: var(--block-bg); }
  #pending-list button.approve { background: var(--auth); border: 1px solid var(--auth); color: var(--ink-0); }
  #pending-list button.approve:hover { background: var(--tan-hi); border-color: var(--tan-hi); }
  .feed-wrap { border: 1px solid var(--rule-2); border-radius: var(--r); background: var(--ink-1); overflow: hidden; }
  #feed { max-height: 60vh; overflow-y: auto; }
  #feed li {
    display: flex; align-items: baseline; gap: .5rem;
    padding: .6rem 1.1rem; border-bottom: 1px solid var(--rule-2);
    font-size: .8rem; font-family: var(--mono);
    transition: background-color var(--d);
  }
  #feed li:last-child { border-bottom: none; }
  #feed li:hover { background: var(--ink-2); }
  #feed li .detail { color: var(--fg-3); overflow-wrap: anywhere; }
</style>
</head>
<body>
  <h1 class="sr-only">Doberman local dashboard</h1>
  <div class="topbar">
    <div class="brand">
      <svg viewBox="0 0 32 32" aria-hidden="true">
        <circle cx="16" cy="16" r="15" style="fill:var(--ink-2); stroke:var(--tan); stroke-width:1.5" />
        <text x="16" y="21.5" text-anchor="middle" font-family="ui-monospace, Consolas, monospace" font-weight="700" font-size="15" style="fill:var(--tan)">D</text>
      </svg>
      <span class="word">DOBERMAN</span>
    </div>
    <div class="topbar-right">
      <span class="chip" id="status"><span class="dot" id="dot"></span><span id="label">connecting...</span></span>
      <span class="badge badge-neutral" id="mode-badge">mode: -</span>
      <span class="badge badge-neutral" id="enforcement-badge">enforcement: -</span>
      <span class="status-pill ok" id="guard-status"><span class="pip" id="guard-pip" aria-hidden="true">●</span><span id="guard-label">ON GUARD</span></span>
    </div>
  </div>
  <div id="stats">stats loading...</div>
  <h2>Pending approvals</h2>
  <ul id="pending-list" aria-live="polite"></ul>
  <div id="pending-empty" class="empty-state">Nothing pending. Doberman's watching.</div>
  <h2>Recent decisions</h2>
  <div class="feed-wrap"><ul id="feed"></ul></div>
  <div id="feed-empty" class="empty-state">No decisions yet. Doberman's watching quietly.</div>
  <script>
    (function () {
      // Verdict/risk/enforcement -> badge class lookups. Explicit,
      // exact-substring-matchable object literals (not an if/else chain) so
      // the served shell can be asserted against directly by a test.
      var VERDICT_BADGE_CLASS = {
        PASS: "badge badge-pass",
        AUTH: "badge badge-auth",
        BLOCK: "badge badge-block"
      };
      var RISK_BADGE_CLASS = {
        low: "badge badge-risk-low",
        medium: "badge badge-risk-medium",
        high: "badge badge-risk-high",
        critical: "badge badge-risk-critical"
      };
      var ENFORCEMENT_BADGE_CLASS = {
        enforce: "badge badge-pass",
        monitor: "badge badge-auth",
        off: "badge badge-block"
      };

      var TOKEN_KEY = "doberman-dash-token";
      var params = new URLSearchParams(window.location.search);
      var token = params.get("token") || "";
      // The token is stripped from the address bar below, so a reload re-fetches
      // a URL that no longer carries it. Hand it to sessionStorage (per-tab,
      // dies with the tab) so refreshing this tab doesn't strand the page
      // permanently unauthenticated with no way back but restarting the CLI.
      // Wrapped because sessionStorage throws outright in some privacy modes -
      // there we simply degrade to the old memory-only behavior.
      try {
        if (token) {
          window.sessionStorage.setItem(TOKEN_KEY, token);
        } else {
          token = window.sessionStorage.getItem(TOKEN_KEY) || "";
        }
      } catch (e) { /* no storage: this page load still works, a reload won't */ }
      // Strip the token from the URL/history immediately so it never lingers
      // in browser history, a referrer header, or a screen share. A brand-new
      // tab has no sessionStorage of its own, so it still needs the printed link.
      params.delete("token");
      var clean = window.location.pathname
        + (params.toString() ? "?" + params.toString() : "");
      window.history.replaceState({}, document.title, clean);

      var dot = document.getElementById("dot");
      var label = document.getElementById("label");
      var statsEl = document.getElementById("stats");
      var modeBadge = document.getElementById("mode-badge");
      var enforcementBadge = document.getElementById("enforcement-badge");
      var feedEl = document.getElementById("feed");
      var MAX_FEED_ROWS = 200;

      var guardStatus = document.getElementById("guard-status");
      var guardPip = document.getElementById("guard-pip");
      var guardLabel = document.getElementById("guard-label");
      // The guard-dog status pill: calm ("ON GUARD") while nothing is
      // waiting on a human, flips to "ALERT" the moment the pending queue
      // is non-empty - the same signal driving document.title's "(N)" below.
      function updateGuardStatus(pendingCount) {
        var alertMode = pendingCount > 0;
        guardStatus.className = "status-pill" + (alertMode ? " alert" : " ok");
        guardPip.textContent = alertMode ? "⚠" : "●";
        guardLabel.textContent = alertMode ? "ALERT" : "ON GUARD";
      }

      fetch("/api/health", { headers: { "Authorization": "Bearer " + token } })
        .then(function (res) {
          if (!res.ok) {
            var httpError = new Error("status " + res.status);
            httpError.status = res.status;
            throw httpError;
          }
          return res.json();
        })
        .then(function () {
          dot.className = "dot ok";
          label.textContent = "connected";
        })
        .catch(function (err) {
          dot.className = "dot err";
          // A rejected token is the one failure a human can actually fix, and
          // only by reopening the link THIS run printed - so say that instead
          // of a dead-end "not connected", and drop the stale token so the next
          // load doesn't silently retry it.
          if (err && err.status === 401) {
            try { window.sessionStorage.removeItem(TOKEN_KEY); } catch (e) {}
            label.textContent = "not authorized - reopen the link printed by doberman dash";
          } else {
            label.textContent = "not connected";
          }
        });

      function renderStats(s) {
        // Every piece is built via textContent, never innerHTML — mirrors
        // the feed/pending-card discipline below.
        statsEl.textContent = "";

        var total = document.createElement("span");
        total.textContent = "decisions: ";
        var totalCount = document.createElement("span");
        totalCount.className = "count";
        totalCount.textContent = String(s.total_decisions);
        total.appendChild(totalCount);
        statsEl.appendChild(total);

        ["PASS", "AUTH", "BLOCK"].forEach(function (verdict) {
          var n = (s.verdict_counts && s.verdict_counts[verdict]) || 0;
          var b = document.createElement("span");
          b.className = VERDICT_BADGE_CLASS[verdict];
          b.textContent = verdict + ": " + n;
          statsEl.appendChild(b);
        });

        var taint = document.createElement("span");
        taint.textContent = "secret/taint events: ";
        var taintCount = document.createElement("span");
        taintCount.className = "count";
        taintCount.textContent = String(s.secret_taint_events);
        taint.appendChild(taintCount);
        statsEl.appendChild(taint);

        modeBadge.textContent = "mode: " + s.mode;
        enforcementBadge.textContent = "enforcement: " + s.enforcement;
        enforcementBadge.className = ENFORCEMENT_BADGE_CLASS[s.enforcement] || "badge badge-neutral";
      }

      // Stats refresh on an interval, not just at page load - otherwise the
      // counters freeze at their load-time values while the live feed fills.
      var STATS_REFRESH_MS = 5000;
      function refreshStats() {
        fetch("/api/stats", { headers: { "Authorization": "Bearer " + token } })
          .then(function (res) {
            if (!res.ok) { throw new Error("status " + res.status); }
            return res.json();
          })
          .then(renderStats)
          .catch(function () {
            statsEl.textContent = "stats unavailable";
          });
      }
      refreshStats();
      setInterval(refreshStats, STATS_REFRESH_MS);

      var pendingList = document.getElementById("pending-list");
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

      var lastPendingKey = null;

      function renderPending(rows) {
        // A queued approval is IMMUTABLE once written (id / tier / risk / reason
        // codes are fixed at write time and `/api/pending` re-serializes the same
        // allow-list), so only the SET can change - a row arrives or it leaves.
        // Rebuilding an unchanged set on every poll destroyed and recreated the
        // TOTP <input>, throwing away focus and any digits already typed. At a 2s
        // poll that makes a 6-digit code effectively impossible to enter, and the
        // approval TTL is only 120s. Skip the rebuild when the id set is identical.
        var key = rows.map(function (row) { return row.id; }).join(",");
        if (key === lastPendingKey) { return; }
        lastPendingKey = key;

        // The empty state is CSS-only (`#pending-list:not(:empty) ~
        // #pending-empty`) - clearing to no children is enough to reveal it.
        pendingList.textContent = "";
        rows.forEach(function (row) {
          var li = document.createElement("li");

          var header = document.createElement("div");
          header.className = "row-header";

          var riskBadge = document.createElement("span");
          riskBadge.className = RISK_BADGE_CLASS[row.risk] || "badge badge-neutral";
          riskBadge.textContent = "RISK: " + (row.risk || "-").toUpperCase();
          header.appendChild(riskBadge);

          var summary = document.createElement("span");
          summary.className = "detail";
          // textContent only — every field is row-derived and must render
          // literally, never as markup (mirrors the feed's discipline).
          summary.textContent = row.action_type +
            " " + (row.target_path_class || "-") + " (tier: " + row.tier + ")";
          header.appendChild(summary);

          var expiry = document.createElement("span");
          expiry.className = "detail";
          expiry.textContent = "expires " + (String(row.expires_at || "").slice(11, 19) || "-") + " UTC";
          header.appendChild(expiry);
          li.appendChild(header);

          var reasons = document.createElement("div");
          reasons.className = "detail";
          reasons.textContent = (row.reason_codes || []).join(", ") || "-";
          li.appendChild(reasons);

          var explanation = document.createElement("div");
          explanation.className = "row-explanation";
          explanation.textContent = row.explanation || "";
          li.appendChild(explanation);

          var totpInput = null;
          if (row.needs_totp) {
            totpInput = document.createElement("input");
            // A masked field: this is a live second factor, and the dashboard is
            // exactly the screen that gets screen-shared and recorded.
            totpInput.type = "password";
            totpInput.inputMode = "numeric";
            totpInput.placeholder = "TOTP code";
            totpInput.autocomplete = "off";
            totpInput.setAttribute("aria-label", "TOTP code");
            li.appendChild(totpInput);
          }

          var approveBtn = document.createElement("button");
          approveBtn.type = "button";
          approveBtn.className = "approve";
          approveBtn.textContent = "Approve";
          var armTimer = null;
          approveBtn.addEventListener("click", function () {
            if (approveBtn.dataset.armed === "1") {
              clearTimeout(armTimer);
              resolveApproval(row.id, "approved", totpInput ? totpInput.value : null, li);
              return;
            }
            approveBtn.dataset.armed = "1";
            approveBtn.textContent = "Confirm approve";
            armTimer = setTimeout(function () {
              approveBtn.dataset.armed = "";
              approveBtn.textContent = "Approve";
            }, 3000);
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
        document.title = (rows.length ? "(" + rows.length + ") " : "") + "Doberman Dashboard";
        updateGuardStatus(rows.length);
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

          var badge = document.createElement("span");
          badge.className = VERDICT_BADGE_CLASS[row.verdict] || "badge badge-neutral";
          badge.textContent = row.verdict;
          li.appendChild(badge);

          // A PASS on a non-path action (e.g. shell_exec) has no
          // target_path_class and usually no reason codes either - without
          // the risk badge that row would render as bare noise ("PASS
          // shell_exec — — @ ..."), so it always shows even at "low".
          var riskBadge = document.createElement("span");
          riskBadge.className = RISK_BADGE_CLASS[row.risk] || "badge badge-neutral";
          riskBadge.textContent = (row.risk || "-").toUpperCase();
          li.appendChild(riskBadge);

          var detail = document.createElement("span");
          detail.className = "detail";
          // textContent only - a row-derived string must render literally,
          // never as markup (mirrors the TUI's markup=False discipline).
          // Compact HH:MM:SS (UTC) - the full ISO timestamp is noise at a glance
          // and stays available in `doberman log` / the TUI.
          detail.textContent = row.action_type +
            " " + (row.target_path_class || "-") +
            " from:" + (row.source_context || "-") +
            " " + (row.reason_codes && row.reason_codes.length ? row.reason_codes.join(",") : "-") +
            " @ " + (String(row.ts || "").slice(11, 19) || "-");
          li.appendChild(detail);

          // Rows are appended oldest-first, so the newest decision is always
          // the last child - keep the scrollable list pinned to that end
          // (unless the user has scrolled up to read older rows) so a
          // freshly loaded dashboard shows the latest activity, not the
          // oldest backfilled row.
          var nearBottom = feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight < 4;

          // The empty state is CSS-only (`#feed:not(:empty) ~ #feed-empty`) -
          // appending the first row is enough to reveal the real list.
          feedEl.appendChild(li);
          while (feedEl.children.length > MAX_FEED_ROWS) {
            feedEl.removeChild(feedEl.firstChild);
          }
          if (nearBottom) {
            feedEl.scrollTop = feedEl.scrollHeight;
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
    """The ONLY fields the feed ever serializes.

    ``row`` comes from :func:`doberman.storage.log.read_decisions`/
    ``read_decisions_since``, already redacted at write time (path *class*,
    not a raw path; no raw arguments; no secrets). This picks a further
    subset - e.g. ``agent_role``/``auth_result`` are dropped even though
    they're on the row.

    ``risk`` and ``source_context`` are included (beyond what the TUI's
    5-column table shows) because a PASS row for a non-path action (e.g.
    ``shell_exec``, which carries no ``target_path_class``) otherwise renders
    with no signal at all beyond the verdict and action type - both fields
    are already redaction-safe classifications, never a raw target/argument.
    """
    return {
        "id": row.get("id"),
        "ts": row.get("ts"),
        "verdict": row.get("final_verdict"),
        "action_type": row.get("action_type"),
        "target_path_class": row.get("target_path_class"),
        "risk": row.get("risk"),
        "source_context": row.get("source_context"),
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
