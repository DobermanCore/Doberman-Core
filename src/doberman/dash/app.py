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

D6 lets the strictness mode itself be changed from the dashboard: ``GET
/api/mode`` reports the current mode + the four valid names; ``POST
/api/mode`` (body ``{"mode": <name>, "code"?: <str>}``) sets it. This goes
through the SAME chokepoint as ``doberman mode``/``doberman setup`` -
:func:`doberman.policy.drift.apply_mode_change` - so raising strictness stays
frictionless and lowering it is gated behind the same possession factor (TOTP
if enrolled, else the Doberman password), recorded in the same append-only
ledger. Exactly like ``/api/resolve``, the dash server NEVER verifies the code
itself - ``code`` rides through opaquely to the existing gate, which performs
the real verification.
"""

from __future__ import annotations

import asyncio
import hmac
import html
import json
from collections.abc import AsyncIterator
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from doberman.branding import DASH_MARK_PNG_B64
from doberman.config import load_mode
from doberman.dash.stats import build_stats, reason_codes
from doberman.policy.drift import apply_mode_change
from doberman.policy.modes import SecurityMode
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

# ponytail: one inline page, no build toolchain.
_HTML_SHELL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%%DASH_PAGE_TITLE%%</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" id="favicon" type="image/png" href="data:image/png;base64,%%DASH_MARK_PNG_B64%%">
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
    --shadow-card: 0 6px 20px -10px oklch(0% 0 0 / 55%);
    /* Four-step type scale (12/14/16/20px against the 16px root default) -
       every adjacent step is >=1.14x the one below it, so nothing reads as
       an arbitrary in-between size. */
    --fs-1: .75rem;
    --fs-2: .875rem;
    --fs-3: 1rem;
    --fs-4: 1.25rem;
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
      --shadow-card: 0 6px 20px -10px oklch(0% 0 0 / 18%);
    }
  }
  /* Manual theme toggle (#theme-toggle-btn below): an attribute selector on
     :root beats a bare :root inside @media regardless of source order, so
     an explicit choice always wins over the OS preference in both
     directions. No attribute at all (the default) leaves the OS in charge. */
  :root[data-theme="light"] {
    --ink-0: #f7f7f8; --ink-1: #ffffff; --ink-2: #eef0f2; --ink-3: #e2e5e9;
    --rule: #c7ccd2; --rule-2: #dde1e6;
    --fg: #15181d; --fg-2: #3a4048; --fg-3: #5b6572;
    --tan: #6b4a1f; --tan-hi: #52380f;
    --pass: #116329;  --pass-bg: rgba(17, 99, 41, .12);
    --auth: #7d5200;  --auth-bg: rgba(125, 82, 0, .12);
    --block: #a40e26; --block-bg: rgba(164, 14, 38, .12);
    --neutral: #424a53; --neutral-bg: rgba(66, 74, 83, .12);
    --shadow-card: 0 6px 20px -10px oklch(0% 0 0 / 18%);
  }
  :root[data-theme="dark"] {
    --ink-0: oklch(13% 0.008 55); --ink-1: oklch(16% 0.009 55);
    --ink-2: oklch(19.5% 0.010 55); --ink-3: oklch(25% 0.012 55);
    --rule: oklch(34% 0.012 55); --rule-2: oklch(28% 0.011 55);
    --fg: oklch(96% 0 0); --fg-2: oklch(82% 0.004 55); --fg-3: oklch(64% 0.006 55);
    --tan: oklch(74% 0.140 58); --tan-hi: oklch(84% 0.150 64);
    --pass: oklch(76% 0.16 152); --pass-bg: oklch(76% 0.16 152 / 14%);
    --auth: oklch(82% 0.155 78); --auth-bg: oklch(82% 0.155 78 / 14%);
    --block: oklch(66% 0.205 26); --block-bg: oklch(66% 0.205 26 / 14%);
    --neutral: var(--fg-3); --neutral-bg: oklch(64% 0.006 55 / 14%);
    --shadow-card: 0 6px 20px -10px oklch(0% 0 0 / 55%);
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
  ::selection { background: var(--auth); color: var(--ink-0); }
  :focus-visible {
    outline: 2px solid var(--tan-hi); outline-offset: 2px; border-radius: var(--r-sm);
  }
  h2 {
    font-family: var(--mono); font-size: var(--fs-1); font-weight: 600;
    letter-spacing: .08em; text-transform: uppercase; color: var(--fg-3);
    margin: 1.75rem 0 .6rem;
  }
  button, input, select {
    font: inherit;
  }
  button {
    cursor: pointer; min-height: 44px; min-width: 44px; padding: .5rem .9rem;
    display: inline-flex; align-items: center; justify-content: center; gap: .35rem;
    border-radius: var(--r-sm); border: 1px solid transparent; background: none; color: inherit;
    transition: background-color var(--d), border-color var(--d), color var(--d), filter var(--d);
  }
  button:disabled { opacity: .55; cursor: default; }
  input, select { min-height: 44px; }
  .topbar {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    gap: .6rem 1rem;
    padding-bottom: 1.1rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--rule-2);
  }
  .brand { display: inline-flex; align-items: center; gap: .6rem; }
  .brand img { height: 28px; width: auto; flex: none; display: block; }
  .brand .word {
    font-family: var(--mono); font-weight: 700; font-size: var(--fs-3);
    letter-spacing: .06em; color: var(--tan);
  }
  .brand .project {
    font-family: var(--mono); font-weight: 600; font-size: var(--fs-3);
    color: var(--fg-2); padding-left: .6rem; margin-left: .6rem;
    border-left: 1px solid var(--rule);
  }
  .topbar-right { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
  .chip {
    display: inline-flex; align-items: center; gap: .4rem;
    font-family: var(--mono); font-size: var(--fs-1); letter-spacing: .02em;
    padding: .32rem .6rem; border: 1px solid var(--rule); border-radius: 999px;
    background: var(--ink-2); color: var(--fg-3); white-space: nowrap;
  }
  .dot { width: .5rem; height: .5rem; border-radius: 50%; background: var(--neutral); flex: none; }
  .dot.ok { background: var(--pass); }
  .dot.err { background: var(--block); }
  .status-pill {
    display: inline-flex; align-items: center; gap: .45rem;
    font-family: var(--mono); font-size: var(--fs-1); font-weight: 600; letter-spacing: .03em;
    padding: .4rem .75rem; border-radius: 999px; border: 1px solid var(--rule);
    color: var(--fg-3); white-space: nowrap;
  }
  .status-pill .pip { font-size: var(--fs-1); }
  .status-pill.ok .pip { color: var(--tan); }
  .status-pill.alert { color: var(--auth); border-color: var(--auth); background: var(--auth-bg); }
  .status-pill.alert .pip { animation: pulse 1.6s ease-in-out infinite; }
  @media (prefers-reduced-motion: reduce) { .status-pill.alert .pip { animation: none; } }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
  #theme-toggle-btn, #shortcuts-btn, #shortcuts-close-btn {
    font-family: var(--font); font-size: var(--fs-1); font-weight: 600; padding: .35rem .8rem;
    border: 1px solid var(--rule); background: transparent; color: var(--fg-2);
  }
  #theme-toggle-btn:hover, #shortcuts-btn:hover, #shortcuts-close-btn:hover {
    border-color: var(--tan-hi); color: var(--tan-hi);
  }
  .badge {
    display: inline-flex; align-items: center; font-family: var(--mono);
    font-size: var(--fs-1); font-weight: 700; letter-spacing: .02em;
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
    margin: 0 0 1.75rem; font-family: var(--mono); font-size: var(--fs-2); color: var(--fg-3);
    display: flex; flex-wrap: wrap; gap: .4rem .6rem; align-items: center;
    padding: .85rem 1.1rem; border: 1px solid var(--rule-2); border-radius: var(--r);
    background: var(--ink-1);
  }
  #stats .count { color: var(--fg); }
  #stats .retry-link { min-height: auto; padding: 0; }
  .empty-state {
    padding: 2rem 1.5rem; border: 1px dashed var(--rule); border-radius: var(--r);
    color: var(--fg-3); font-size: var(--fs-2); text-align: center;
  }
  #feed, #pending-list { list-style: none; margin: .5rem 0 0; }
  #feed:not(:empty) ~ #feed-empty { display: none; }
  #pending-list:not(:empty) ~ #pending-empty { display: none; }
  #pending-list li {
    padding: 1.4rem 1.5rem 1.5rem; margin-bottom: .9rem;
    border: 1px solid var(--auth); border-radius: var(--r-lg); background: var(--ink-1);
    font-size: var(--fs-2);
    box-shadow: var(--shadow-card);
    animation: pending-arrive .28s ease-out both;
  }
  #pending-list li.stale { opacity: .7; border-style: dashed; }
  @keyframes pending-arrive {
    from { opacity: 0; transform: translateY(-6px); }
    to { opacity: 1; transform: none; }
  }
  @media (prefers-reduced-motion: reduce) {
    #pending-list li { animation: none; }
  }
  #pending-list .row-header {
    display: flex; align-items: center; gap: .5rem; margin-bottom: .6rem; flex-wrap: wrap;
  }
  #pending-list .row-header .detail { color: var(--fg); font-family: var(--mono); font-size: var(--fs-2); }
  #pending-list .countdown {
    font-family: var(--mono); font-size: var(--fs-3); font-weight: 700; color: var(--auth);
    margin-left: auto;
  }
  #pending-list .row-explanation { margin: .5rem 0 1rem; color: var(--fg-2); line-height: 1.6; max-width: 62ch; }
  #pending-list input {
    font-family: var(--mono); font-size: var(--fs-3); padding: .45rem .6rem; margin: 0 .5rem .5rem 0;
    letter-spacing: .12em; width: 9rem;
    background: var(--ink-0); color: var(--fg); border: 1px solid var(--rule); border-radius: 4px;
  }
  #pending-list button { margin: 0 .5rem .5rem 0; }
  #pending-list button.deny { background: var(--block); border: 1px solid var(--block); color: var(--ink-0); }
  #pending-list button.deny:hover { filter: brightness(1.15); }
  #pending-list button.approve { background: transparent; border: 1px solid var(--auth); color: var(--auth); }
  #pending-list button.approve:hover { background: var(--auth-bg); }
  #pending-list button.btn-copy { background: transparent; border: 1px solid var(--rule); color: var(--fg-2); }
  #pending-list button.btn-copy:hover { border-color: var(--auth); color: var(--fg); }
  #pending-list .row-error { color: var(--block); font-family: var(--mono); font-size: var(--fs-1); margin-top: .4rem; }
  #pending-list .row-error:empty { display: none; }
  #pending-list .stale-note { color: var(--fg-3); font-size: var(--fs-1); margin-top: .4rem; }
  #pending-list .stale-note .retry-link { min-height: auto; padding: 0; margin: 0; }
  .retry-link {
    background: none; border: none; color: var(--tan-hi); text-decoration: underline;
    padding: 0; min-height: auto; min-width: auto;
  }
  .section-head { display: flex; align-items: center; justify-content: space-between; gap: .5rem; margin-top: 1.4rem; }
  #refresh-btn {
    font-family: var(--font); font-size: var(--fs-2); font-weight: 600;
    background: transparent; border: 1px solid var(--rule); color: var(--fg);
  }
  #refresh-btn:hover { border-color: var(--tan-hi); color: var(--tan-hi); }
  .feed-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: .6rem; margin: .7rem 0 .8rem; }
  .filter-chip-group { display: flex; gap: .4rem; flex-wrap: wrap; }
  .filter-chip {
    font-family: var(--mono); font-size: var(--fs-1); padding: .4rem .9rem;
    border: 1px solid var(--rule); border-radius: 999px; background: var(--ink-2); color: var(--fg-3);
  }
  .filter-chip[aria-pressed="true"] {
    background: var(--auth-bg); border-color: var(--auth); color: var(--auth);
  }
  #feed-filter {
    font-family: var(--font); font-size: var(--fs-2); padding: .5rem .8rem;
    border: 1px solid var(--rule); border-radius: var(--r-sm); background: var(--ink-2); color: var(--fg);
    flex: 1 1 12rem;
  }
  #feed {
    max-height: 60vh; overflow-y: auto;
    border: 1px solid var(--rule-2); border-radius: var(--r); background: var(--ink-1);
  }
  #feed li {
    display: flex; align-items: baseline; gap: .5rem;
    padding: .6rem 1.1rem; border-bottom: 1px solid var(--rule-2);
    font-size: var(--fs-2); font-family: var(--mono);
    transition: background-color var(--d);
  }
  #feed li:last-child { border-bottom: none; }
  #feed li:hover { background: var(--ink-2); }
  #feed li .detail { color: var(--fg-3); overflow-wrap: anywhere; }
  .feed-note {
    padding: .6rem 1.1rem; color: var(--fg-3); font-family: var(--mono); font-size: var(--fs-1);
    border-top: 1px solid var(--rule-2);
  }
  #mode-edit-btn {
    font-size: var(--fs-1); font-weight: 600; padding: .35rem .7rem;
    border: 1px solid var(--rule); border-radius: 4px; background: transparent;
    color: var(--fg-3);
  }
  #mode-edit-btn:hover { background: var(--neutral-bg); color: var(--fg); }
  #mode-form:not([hidden]) {
    display: flex; flex-wrap: wrap; align-items: center; gap: .5rem;
    margin: -.2rem 0 1.2rem; font-size: var(--fs-2);
  }
  #mode-form .mode-form-note {
    flex-basis: 100%; margin: 0 0 .2rem; color: var(--fg-3); font-size: var(--fs-1);
  }
  #mode-form select, #mode-form input {
    font-size: var(--fs-2); padding: .35rem .55rem;
    background: var(--ink-2); color: var(--fg); border: 1px solid var(--rule); border-radius: 4px;
  }
  #mode-form input { width: 16rem; letter-spacing: .04em; }
  .mode-form-actions { display: flex; gap: .5rem; align-items: center; }
  #mode-form button {
    font-size: var(--fs-2); font-weight: 600; padding: .35rem .85rem;
    border: 1px solid var(--rule); border-radius: 4px; background: transparent;
    color: inherit; min-height: auto;
  }
  #mode-save-btn { border-color: var(--pass); color: var(--pass); }
  #mode-save-btn:hover { background: var(--pass-bg); }
  #mode-cancel-btn:hover { background: var(--neutral-bg); }
  #mode-success { color: var(--pass); font-family: var(--mono); font-size: var(--fs-1); }
  #mode-error { color: var(--block); font-family: var(--mono); font-size: var(--fs-1); }
  #shortcuts-panel {
    position: fixed; right: 1.25rem; bottom: 1.25rem; z-index: 20; max-width: 20rem;
    padding: 1rem 1.25rem; border: 1px solid var(--rule); border-radius: var(--r-lg);
    background: var(--ink-1); box-shadow: var(--shadow-card); font-size: var(--fs-2);
  }
  #shortcuts-panel h2 { margin-top: 0; }
  #shortcuts-panel dl { display: grid; grid-template-columns: auto 1fr; gap: .3rem .8rem; margin: .5rem 0 .8rem; }
  #shortcuts-panel dt { font-family: var(--mono); color: var(--tan-hi); }
  #shortcuts-panel dd { color: var(--fg-2); }
  @media (max-width: 640px) {
    .topbar { flex-direction: column; align-items: flex-start; }
    .topbar-right { width: 100%; }
    #mode-form:not([hidden]) { flex-direction: column; align-items: stretch; }
    #mode-form select, #mode-form input { width: 100%; }
    .mode-form-actions { width: 100%; }
    .mode-form-actions button { flex: 1 1 0; }
    #feed li { flex-wrap: wrap; }
    #feed li .detail { flex-basis: 100%; }
    #pending-list .countdown { margin-left: 0; flex-basis: 100%; }
    .feed-toolbar { flex-direction: column; align-items: stretch; }
    #feed-filter { width: 100%; }
  }
</style>
</head>
<body>
  <div id="announcer" class="sr-only" aria-live="polite"></div>
  <header class="topbar">
    <div class="brand">
      <img src="data:image/png;base64,%%DASH_MARK_PNG_B64%%" alt="" aria-hidden="true" />
      <span class="word">DOBERMAN</span>
      <span class="project">%%DASH_PROJECT_NAME%%</span>
    </div>
    <div class="topbar-right">
      <span class="chip" id="status"><span class="dot" id="dot"></span><span id="label">connecting...</span></span>
      <span class="badge badge-neutral" id="mode-badge">mode: -</span>
      <button type="button" id="mode-edit-btn">change</button>
      <span class="badge badge-neutral" id="enforcement-badge">enforcement: -</span>
      <span class="status-pill ok" id="guard-status"><span class="pip" id="guard-pip" aria-hidden="true">●</span><span id="guard-label">ON GUARD</span></span>
      <button type="button" id="theme-toggle-btn">Switch to light theme</button>
      <button type="button" id="shortcuts-btn" aria-haspopup="true" aria-expanded="false">Shortcuts (?)</button>
    </div>
  </header>
  <main>
    <div id="mode-form" hidden>
      <p class="mode-form-note">Raising is immediate; lowering needs your code.</p>
      <select id="mode-select" aria-label="Security mode"></select>
      <input id="mode-code" type="password" autocomplete="off"
        placeholder="2FA code or password (only needed to lower strictness)">
      <div class="mode-form-actions">
        <button type="button" id="mode-save-btn">Save</button>
        <button type="button" id="mode-cancel-btn">Cancel</button>
      </div>
      <span id="mode-success"></span>
      <span id="mode-error"></span>
    </div>
    <div id="stats">stats loading...</div>
    <section aria-labelledby="pending-heading">
      <h2 id="pending-heading">Pending approvals</h2>
      <ul id="pending-list" aria-live="polite"></ul>
      <div id="pending-empty" class="empty-state">Nothing pending. Doberman's watching.</div>
    </section>
    <section aria-labelledby="feed-heading">
      <div class="section-head">
        <h2 id="feed-heading">Recent decisions</h2>
        <button type="button" id="refresh-btn">Refresh</button>
      </div>
      <div class="feed-toolbar">
        <div class="filter-chip-group" role="group" aria-label="Filter by verdict">
          <button type="button" class="filter-chip" data-verdict="" aria-pressed="true">All</button>
          <button type="button" class="filter-chip" data-verdict="BLOCK" aria-pressed="false">BLOCK</button>
          <button type="button" class="filter-chip" data-verdict="AUTH" aria-pressed="false">AUTH</button>
          <button type="button" class="filter-chip" data-verdict="PASS" aria-pressed="false">PASS</button>
        </div>
        <label class="sr-only" for="feed-filter">Filter recent decisions by text</label>
        <input type="search" id="feed-filter" placeholder="Filter (press / to focus)">
      </div>
      <ul id="feed" role="log" tabindex="0" aria-label="Recent decisions"></ul>
      <div id="feed-empty" class="empty-state">No decisions yet. Doberman's watching quietly.</div>
      <div id="feed-truncated" class="feed-note" hidden>older rows not shown - see doberman log</div>
    </section>
  </main>
  <div id="shortcuts-panel" hidden role="region" aria-label="Keyboard shortcuts">
    <h2>Shortcuts</h2>
    <dl>
      <dt>/</dt><dd>Focus the decisions filter</dd>
      <dt>r</dt><dd>Refresh stats + pending</dd>
      <dt>a</dt><dd>Approve the first pending item (press twice to confirm)</dd>
      <dt>d</dt><dd>Deny the first pending item</dd>
      <dt>?</dt><dd>Toggle this panel</dd>
      <dt>Esc</dt><dd>Close this panel or the mode form</dd>
    </dl>
    <button type="button" id="shortcuts-close-btn">Close</button>
  </div>
  <script>
    (function () {
      // Rendered server-side per `create_app(repo_root=...)` call - this is
      // why the tab title differs across dashboards opened for different
      // projects instead of every tab reading the same "Doberman Dashboard".
      var DASH_BASE_TITLE = %%DASH_JS_TITLE_JSON%%;
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

      var announcer = document.getElementById("announcer");
      var lastAnnounced = "";
      // A single aria-live=polite region for every status change (health,
      // feed connection, the guard pill) - one shared debounce so the same
      // message landing again on the next poll doesn't re-announce.
      function announce(message) {
        if (message === lastAnnounced) { return; }
        lastAnnounced = message;
        announcer.textContent = message;
      }

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

      // Manual theme toggle: persisted separately from the token above (a
      // different key, in localStorage - a per-viewer display preference has
      // no reason to die with the tab the way an auth secret must). Defaults
      // to whatever the OS prefers until the user overrides it explicitly.
      var THEME_KEY = "doberman-dash-theme";
      var themeToggleBtn = document.getElementById("theme-toggle-btn");
      var mediaDark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

      function readStoredTheme() {
        try {
          return window.localStorage.getItem(THEME_KEY);
        } catch (e) {
          return null;
        }
      }
      function writeStoredTheme(value) {
        try { window.localStorage.setItem(THEME_KEY, value); } catch (e) { /* privacy mode: just won't persist */ }
      }
      function effectiveTheme(explicit) {
        if (explicit === "light" || explicit === "dark") { return explicit; }
        return (mediaDark && !mediaDark.matches) ? "light" : "dark";
      }
      function applyTheme(explicit) {
        if (explicit === "light" || explicit === "dark") {
          document.documentElement.setAttribute("data-theme", explicit);
        } else {
          document.documentElement.removeAttribute("data-theme");
        }
        var eff = effectiveTheme(explicit);
        themeToggleBtn.textContent = eff === "dark" ? "Switch to light theme" : "Switch to dark theme";
      }
      applyTheme(readStoredTheme());
      themeToggleBtn.addEventListener("click", function () {
        var next = effectiveTheme(readStoredTheme()) === "dark" ? "light" : "dark";
        writeStoredTheme(next);
        applyTheme(next);
      });

      var dot = document.getElementById("dot");
      var label = document.getElementById("label");
      var favicon = document.getElementById("favicon");
      var statsEl = document.getElementById("stats");
      var modeBadge = document.getElementById("mode-badge");
      var enforcementBadge = document.getElementById("enforcement-badge");
      var modeEditBtn = document.getElementById("mode-edit-btn");
      var modeForm = document.getElementById("mode-form");
      var modeSelect = document.getElementById("mode-select");
      var modeCodeInput = document.getElementById("mode-code");
      var modeSaveBtn = document.getElementById("mode-save-btn");
      var modeCancelBtn = document.getElementById("mode-cancel-btn");
      var modeSuccessEl = document.getElementById("mode-success");
      var modeErrorEl = document.getElementById("mode-error");
      var modeEditing = false;
      var feedEl = document.getElementById("feed");
      var feedTruncatedEl = document.getElementById("feed-truncated");
      var MAX_FEED_ROWS = 200;

      // Recolor the mark amber on canvas once (offline, no network request)
      // so the browser tab itself signals a waiting approval, same as the
      // "(N)" title prefix and the ALERT pill below.
      var faviconDefaultHref = favicon.href;
      var faviconAlertHref = null;
      var lastPendingCountForFavicon = 0;
      (function buildAlertFavicon() {
        try {
          var img = new Image();
          img.onload = function () {
            var canvas = document.createElement("canvas");
            canvas.width = img.naturalWidth || img.width;
            canvas.height = img.naturalHeight || img.height;
            var ctx = canvas.getContext("2d");
            if (!ctx) { return; }
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            ctx.globalCompositeOperation = "source-atop";
            ctx.fillStyle = "rgba(217, 143, 33, 0.6)";
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            faviconAlertHref = canvas.toDataURL("image/png");
            if (lastPendingCountForFavicon > 0) { favicon.href = faviconAlertHref; }
          };
          img.src = faviconDefaultHref;
        } catch (e) { /* canvas unavailable: favicon just stays the default mark */ }
      })();
      function updateFavicon(pendingCount) {
        lastPendingCountForFavicon = pendingCount;
        favicon.href = (pendingCount > 0 && faviconAlertHref) ? faviconAlertHref : faviconDefaultHref;
      }

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
        updateFavicon(pendingCount);
        announce(alertMode ? "ALERT: " + pendingCount + " pending approval(s)." : "ON GUARD. Nothing pending.");
      }

      function checkHealth() {
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
            conn.health = "ok";
            renderConnection();
          })
          .catch(function (err) {
            // A rejected token is the one failure a human can actually fix, and
            // only by reopening the link THIS run printed - so say that instead
            // of a dead-end "not connected", and drop the stale token so the next
            // load doesn't silently retry it.
            if (err && err.status === 401) {
              try { window.sessionStorage.removeItem(TOKEN_KEY); } catch (e) {}
              conn.health = "unauthorized";
            } else {
              conn.health = "down";
            }
            renderConnection();
          });
      }

      // The chip reflects BOTH signals: the health poll (server reachable, token
      // accepted) and the live feed (SSE open). A 10 s health tick must never
      // paint "connected" over a dropped feed, and a state that hasn't changed
      // must not re-announce - so one renderer owns the chip and the announcer.
      var conn = { health: "unknown", feed: "unknown" };
      function renderConnection() {
        var text, ok;
        if (conn.health === "unauthorized") {
          ok = false; text = "not authorized - reopen the link printed by doberman dash";
        } else if (conn.health === "down") {
          ok = false; text = "not connected";
        } else if (conn.feed === "dropped") {
          ok = false; text = "feed dropped - reconnecting";
        } else if (conn.health === "ok" && conn.feed === "open") {
          ok = true; text = "connected";
        } else {
          ok = false; text = "connecting";
        }
        dot.className = ok ? "dot ok" : "dot err";
        label.textContent = text;
        announce("Dashboard " + text + ".");
      }
      checkHealth();
      // Health is also polled on an interval (not just at load) so a server
      // that goes away mid-session is reflected in the status chip instead
      // of it freezing on a stale "connected".
      var HEALTH_POLL_MS = 10000;
      setInterval(checkHealth, HEALTH_POLL_MS);

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

        // Top reason codes + a recent-window verdict breakdown, rendered in
        // the same compact strip - build_stats already computes both, this
        // was the only piece that never reached the page.
        if (s.top_reason_codes && s.top_reason_codes.length) {
          var topReasons = document.createElement("span");
          topReasons.className = "detail";
          topReasons.textContent = "top reasons: " + s.top_reason_codes.map(function (pair) {
            return pair[0] + " (" + pair[1] + ")";
          }).join(", ");
          statsEl.appendChild(topReasons);
        }
        if (s.recent_verdict_counts) {
          var recent = document.createElement("span");
          recent.className = "detail";
          var recentParts = ["PASS", "AUTH", "BLOCK"].map(function (verdict) {
            return verdict + " " + (s.recent_verdict_counts[verdict] || 0);
          });
          recent.textContent = "recent " + s.recent_window + ": " + recentParts.join(" / ");
          statsEl.appendChild(recent);
        }

        modeBadge.textContent = "mode: " + s.mode;
        enforcementBadge.textContent = "enforcement: " + s.enforcement;
        enforcementBadge.className = ENFORCEMENT_BADGE_CLASS[s.enforcement] || "badge badge-neutral";
        // Keep the (closed) mode selector's value in sync with reality - but
        // never while the user has the form open with an in-progress choice,
        // or a poll landing mid-edit would silently discard what they picked.
        if (!modeEditing && modeSelect.options.length) {
          modeSelect.value = s.mode;
        }
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
            statsEl.textContent = "";
            var msg = document.createElement("span");
            msg.textContent = "stats unavailable - ";
            statsEl.appendChild(msg);
            var retryBtn = document.createElement("button");
            retryBtn.type = "button";
            retryBtn.className = "retry-link";
            retryBtn.textContent = "retry";
            retryBtn.addEventListener("click", refreshStats);
            statsEl.appendChild(retryBtn);
          });
      }
      refreshStats();
      setInterval(refreshStats, STATS_REFRESH_MS);
      // The counters follow the feed: a new row re-fetches the stats right away
      // (trailing-debounced, so a backfill burst on connect costs one request)
      // instead of lagging up to STATS_REFRESH_MS behind the list.
      var statsSyncTimer = null;
      function syncStatsSoon() {
        clearTimeout(statsSyncTimer);
        statsSyncTimer = setTimeout(refreshStats, 150);
      }

      // Mode control: fetch the valid mode names once to populate the
      // selector, then let the user pick a new one. Raising strictness is
      // frictionless server-side; lowering it needs a possession-factor code
      // (2FA or password) in the same request - the server decides which is
      // required and verifies it, this page just forwards whatever the user
      // typed and shows the resulting error if any.
      fetch("/api/mode", { headers: { "Authorization": "Bearer " + token } })
        .then(function (res) {
          if (!res.ok) { throw new Error("status " + res.status); }
          return res.json();
        })
        .then(function (m) {
          modeSelect.textContent = "";
          (m.modes || []).forEach(function (name) {
            var opt = document.createElement("option");
            opt.value = name;
            opt.textContent = name;
            modeSelect.appendChild(opt);
          });
          modeSelect.value = m.mode;
        })
        .catch(function () {
          // No modes loaded -> leave the selector empty and the edit button
          // inert rather than let the user submit a change we can't populate.
          modeEditBtn.disabled = true;
        });

      function openModeForm() {
        modeEditing = true;
        modeErrorEl.textContent = "";
        modeSuccessEl.textContent = "";
        modeCodeInput.value = "";
        modeForm.hidden = false;
      }

      function closeModeForm() {
        modeEditing = false;
        modeForm.hidden = true;
        modeCodeInput.value = "";
        modeErrorEl.textContent = "";
        modeSuccessEl.textContent = "";
      }

      modeEditBtn.addEventListener("click", function () {
        if (modeForm.hidden) { openModeForm(); } else { closeModeForm(); }
      });
      modeCancelBtn.addEventListener("click", closeModeForm);

      modeSaveBtn.addEventListener("click", function () {
        var chosen = modeSelect.value;
        if (!chosen) { return; }
        var body = { mode: chosen };
        if (modeCodeInput.value) { body.code = modeCodeInput.value; }
        modeErrorEl.textContent = "";
        modeSuccessEl.textContent = "";
        modeSaveBtn.disabled = true;
        fetch("/api/mode", {
          method: "POST",
          headers: {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(body)
        }).then(function (res) {
          return res.json().then(function (data) {
            return { ok: res.ok, data: data };
          });
        }).then(function (result) {
          modeSaveBtn.disabled = false;
          if (result.ok) {
            modeBadge.textContent = "mode: " + result.data.mode;
            refreshStats();
            // Confirm inline before closing, so a raise (frictionless, no
            // code) still gets the same visible acknowledgment as a gated
            // lower does - the save wasn't silently swallowed either way.
            modeSuccessEl.textContent = "Mode: " + result.data.mode + " - saved";
            setTimeout(closeModeForm, 900);
          } else {
            // textContent only - never render a server error string as markup.
            modeErrorEl.textContent = (result.data && result.data.error) || "mode change failed";
            modeCodeInput.value = "";
          }
        }).catch(function () {
          modeSaveBtn.disabled = false;
          modeErrorEl.textContent = "network error - try again";
        });
      });

      var pendingList = document.getElementById("pending-list");
      var PENDING_POLL_MS = 2000;
      // Live countdown to the DASHBOARD's own 90s authority horizon
      // (DashboardPrompter.DEFAULT_TIMEOUT_S) - NOT row.expires_at, which is
      // a separate, longer 120s DB TTL: the row itself still expires against
      // that TTL even after the dashboard has stopped waiting and fallen
      // through to the terminal/GUI channel instead.
      var DASHBOARD_AUTHORITY_S = 90;

      function pendingDeadlineMs(row) {
        var created = Date.parse(row.created_at);
        return isNaN(created) ? null : created + DASHBOARD_AUTHORITY_S * 1000;
      }

      function formatCountdown(msRemaining) {
        var totalSeconds = Math.max(0, Math.round(msRemaining / 1000));
        var m = Math.floor(totalSeconds / 60);
        var s = totalSeconds % 60;
        return "auto-denies in " + m + ":" + (s < 10 ? "0" : "") + s + " if unanswered";
      }

      function tickCountdowns() {
        var now = Date.now();
        pendingList.querySelectorAll(".countdown[data-deadline]").forEach(function (node) {
          var remaining = Number(node.dataset.deadline) - now;
          node.textContent = remaining > 0 ? formatCountdown(remaining) : "auto-denies any moment now";
        });
      }
      setInterval(tickCountdowns, 1000);

      function resolveApproval(id, decision, totpCode, card, buttons) {
        buttons.forEach(function (b) { b.disabled = true; });
        var errorEl = card.querySelector(".row-error");
        if (errorEl) { errorEl.textContent = ""; }
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
            return null;
          }
          return res.json().catch(function () { return {}; }).then(function (data) {
            throw new Error((data && data.error) || ("request failed (status " + res.status + ")"));
          });
        }).catch(function (err) {
          // Already resolved/expired elsewhere, a validation error, or a
          // network hiccup - all of these must leave the card usable again,
          // not just fail silently (the old empty catch here).
          buttons.forEach(function (b) { b.disabled = false; });
          if (errorEl) {
            errorEl.textContent = (err && err.message) || "couldn't resolve - try again";
          }
          refreshPending();
        });
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
            " " + (row.target_path_class || "no target") + " (tier: " + row.tier + ")";
          header.appendChild(summary);

          // Promoted out of the grey detail style below (see .countdown) -
          // this is the moment the card exists to communicate.
          var countdown = document.createElement("span");
          countdown.className = "countdown";
          var deadlineMs = pendingDeadlineMs(row);
          if (deadlineMs !== null) {
            countdown.dataset.deadline = String(deadlineMs);
          } else {
            countdown.textContent = "auto-denies if unanswered";
          }
          header.appendChild(countdown);
          li.appendChild(header);

          var reasons = document.createElement("div");
          reasons.className = "detail";
          reasons.textContent = (row.reason_codes || []).join(", ") || "no reason codes recorded";
          li.appendChild(reasons);

          var explanation = document.createElement("div");
          explanation.className = "row-explanation";
          explanation.textContent = row.explanation || "";
          li.appendChild(explanation);

          var totpInput = null;
          if (row.needs_totp) {
            var totpId = "totp-" + row.id;
            var totpLabel = document.createElement("label");
            totpLabel.className = "sr-only";
            totpLabel.setAttribute("for", totpId);
            totpLabel.textContent = "TOTP code";
            li.appendChild(totpLabel);

            totpInput = document.createElement("input");
            totpInput.id = totpId;
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
              clearInterval(armTimer);
              approveBtn.dataset.armed = "";
              approveBtn.textContent = "Approve";
              resolveApproval(row.id, "approved", totpInput ? totpInput.value : null, li,
                [approveBtn, denyBtn]);
              return;
            }
            approveBtn.dataset.armed = "1";
            var remaining = 3;
            approveBtn.textContent = "Confirm approve (" + remaining + ")";
            armTimer = setInterval(function () {
              remaining -= 1;
              if (remaining <= 0) {
                clearInterval(armTimer);
                approveBtn.dataset.armed = "";
                approveBtn.textContent = "Approve";
                return;
              }
              approveBtn.textContent = "Confirm approve (" + remaining + ")";
            }, 1000);
          });
          li.appendChild(approveBtn);

          var denyBtn = document.createElement("button");
          denyBtn.type = "button";
          denyBtn.className = "deny";
          denyBtn.textContent = "Deny";
          denyBtn.addEventListener("click", function () {
            resolveApproval(row.id, "denied", totpInput ? totpInput.value : null, li,
              [approveBtn, denyBtn]);
          });
          li.appendChild(denyBtn);

          var copyBtn = document.createElement("button");
          copyBtn.type = "button";
          copyBtn.className = "btn btn-copy";
          copyBtn.textContent = "Copy details";
          copyBtn.addEventListener("click", async function () {
            try {
              await navigator.clipboard.writeText(JSON.stringify({
                id: row.id,
                tier: row.tier,
                risk: row.risk,
                action_type: row.action_type,
                reason_codes: row.reason_codes,
                explanation: row.explanation
              }, null, 2));
            } catch (e) { /* clipboard unavailable: keep the approval card usable */ }
          });
          li.appendChild(copyBtn);

          var errorEl = document.createElement("div");
          errorEl.className = "row-error";
          errorEl.setAttribute("role", "alert");
          li.appendChild(errorEl);

          pendingList.appendChild(li);
        });
        document.title = (rows.length ? "(" + rows.length + ") " : "") + DASH_BASE_TITLE;
        updateGuardStatus(rows.length);
        tickCountdowns();
      }

      function markPendingStale() {
        Array.prototype.forEach.call(pendingList.children, function (li) {
          if (li.classList.contains("stale")) { return; }
          li.classList.add("stale");
          li.querySelectorAll("button.approve, button.deny, button.btn-copy").forEach(function (b) {
            b.disabled = true;
          });
          var note = document.createElement("div");
          note.className = "stale-note";
          note.textContent = "couldn't refresh - ";
          var retryBtn = document.createElement("button");
          retryBtn.type = "button";
          retryBtn.className = "retry-link";
          retryBtn.textContent = "retry";
          retryBtn.addEventListener("click", refreshPending);
          note.appendChild(retryBtn);
          li.appendChild(note);
        });
      }

      function clearPendingStale() {
        Array.prototype.forEach.call(pendingList.children, function (li) {
          li.classList.remove("stale");
          li.querySelectorAll("button.approve, button.deny, button.btn-copy").forEach(function (b) {
            b.disabled = false;
          });
          var note = li.querySelector(".stale-note");
          if (note) { note.remove(); }
        });
      }

      function refreshPending() {
        fetch("/api/pending", { headers: { "Authorization": "Bearer " + token } })
          .then(function (res) {
            if (!res.ok) { throw new Error("status " + res.status); }
            return res.json();
          })
          .then(function (rows) {
            clearPendingStale();
            renderPending(rows);
          })
          .catch(markPendingStale);
      }

      refreshPending();
      setInterval(refreshPending, PENDING_POLL_MS);

      // Manual refresh for the stats + pending views; both functions are safe
      // to call at any time and no new endpoint is involved.
      document.getElementById("refresh-btn").addEventListener("click", function () {
        refreshStats();
        refreshPending();
      });

      // Find a BLOCK: verdict chips + a text filter over what's already on
      // screen (no new endpoint - the feed is already fully client-side).
      var feedEntries = [];
      var activeVerdict = "";
      var activeQuery = "";

      function matchesFilter(entry) {
        if (activeVerdict && entry.verdict !== activeVerdict) { return false; }
        if (activeQuery && entry.searchText.indexOf(activeQuery) === -1) { return false; }
        return true;
      }
      function applyFeedFilter() {
        feedEntries.forEach(function (entry) { entry.li.hidden = !matchesFilter(entry); });
      }

      var filterChips = document.querySelectorAll(".filter-chip");
      filterChips.forEach(function (chip) {
        chip.addEventListener("click", function () {
          filterChips.forEach(function (c) {
            c.setAttribute("aria-pressed", c === chip ? "true" : "false");
          });
          activeVerdict = chip.dataset.verdict || "";
          applyFeedFilter();
        });
      });

      var feedFilterInput = document.getElementById("feed-filter");
      feedFilterInput.addEventListener("input", function () {
        activeQuery = feedFilterInput.value.trim().toLowerCase();
        applyFeedFilter();
      });

      // A small non-modal shortcuts panel (see the keydown handler below for
      // the bindings it documents) - discoverable via the topbar button too,
      // not just the "?" key.
      var shortcutsBtn = document.getElementById("shortcuts-btn");
      var shortcutsPanel = document.getElementById("shortcuts-panel");
      var shortcutsCloseBtn = document.getElementById("shortcuts-close-btn");

      function openShortcuts() {
        shortcutsPanel.hidden = false;
        shortcutsBtn.setAttribute("aria-expanded", "true");
      }
      function closeShortcuts() {
        shortcutsPanel.hidden = true;
        shortcutsBtn.setAttribute("aria-expanded", "false");
      }
      shortcutsBtn.addEventListener("click", function () {
        if (shortcutsPanel.hidden) { openShortcuts(); } else { closeShortcuts(); }
      });
      shortcutsCloseBtn.addEventListener("click", closeShortcuts);

      // Keyboard: / focuses the filter, r refreshes, ? toggles the shortcuts
      // panel, a/d act on the first pending card (arm step preserved for
      // approve), Escape closes whatever panel is open. Ignored while
      // already typing in a field, except Escape which always works.
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
          if (!modeForm.hidden) { closeModeForm(); }
          if (!shortcutsPanel.hidden) { closeShortcuts(); }
          return;
        }
        var tag = (document.activeElement && document.activeElement.tagName) || "";
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") { return; }
        if (e.key === "/") {
          e.preventDefault();
          feedFilterInput.focus();
        } else if (e.key === "r") {
          refreshStats();
          refreshPending();
        } else if (e.key === "?") {
          if (shortcutsPanel.hidden) { openShortcuts(); } else { closeShortcuts(); }
        } else if (e.key === "a" || e.key === "d") {
          var firstCard = pendingList.querySelector("li");
          if (!firstCard) { return; }
          var actionBtn = firstCard.querySelector(e.key === "a" ? "button.approve" : "button.deny");
          if (!actionBtn) { return; }
          // `a` only ARMS and focuses Approve: the confirming press must land on
          // the button itself (Enter/Space/click), so a repeated `a` can never
          // approve unseen - the two-step stays two distinct gestures.
          if (e.key === "a" && actionBtn.dataset.armed === "1") { actionBtn.focus(); return; }
          actionBtn.click();
          actionBtn.focus();
        }
      });

      // EventSource cannot set request headers, so the token travels as a
      // query param here only (see doberman.dash.app._feed_token_matches).
      try {
        var source = new EventSource("/api/feed?token=" + encodeURIComponent(token));
        source.addEventListener("open", function () {
          conn.feed = "open";
          renderConnection();
        });
        source.addEventListener("error", function () {
          conn.feed = "dropped";
          renderConnection();
        });
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

          // The detail line always names something concrete now (a target
          // class or "no target", reason codes or "no auth"), so a low-risk
          // PASS is no longer bare noise without its own badge - reserve the
          // risk badge for medium+ instead of doubling up on every row.
          if (row.risk && row.risk !== "low") {
            var riskBadge = document.createElement("span");
            riskBadge.className = RISK_BADGE_CLASS[row.risk] || "badge badge-neutral";
            riskBadge.textContent = (row.risk || "-").toUpperCase();
            li.appendChild(riskBadge);
          }

          var detail = document.createElement("span");
          detail.className = "detail";
          // textContent only - a row-derived string must render literally,
          // never as markup (mirrors the TUI's markup=False discipline).
          // Compact HH:MM:SS (UTC) - the full ISO timestamp is noise at a glance
          // and stays available in `doberman log` / the TUI.
          detail.textContent = row.action_type +
            " " + (row.target_path_class || "no target") +
            " from:" + (row.source_context || "-") +
            " " + (row.reason_codes && row.reason_codes.length ? row.reason_codes.join(",") : "no auth") +
            " @ " + (String(row.ts || "").slice(11, 19) || "-");
          li.appendChild(detail);

          // Rows are appended oldest-first, so the newest decision is always
          // the last child - keep the scrollable list pinned to that end
          // (unless the user has scrolled up to read older rows) so a
          // freshly loaded dashboard shows the latest activity, not the
          // oldest backfilled row.
          var nearBottom = feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight < 4;

          var entry = {
            li: li,
            verdict: row.verdict,
            searchText: (
              row.action_type + " " + (row.target_path_class || "") + " " +
              (row.source_context || "") + " " + (row.reason_codes || []).join(" ")
            ).toLowerCase()
          };
          feedEntries.push(entry);
          li.hidden = !matchesFilter(entry);

          // The empty state is CSS-only (`#feed:not(:empty) ~ #feed-empty`) -
          // appending the first row is enough to reveal the real list.
          feedEl.appendChild(li);
          while (feedEl.children.length > MAX_FEED_ROWS) {
            feedEl.removeChild(feedEl.firstChild);
            feedEntries.shift();
            feedTruncatedEl.hidden = false;
          }
          if (nearBottom) {
            feedEl.scrollTop = feedEl.scrollHeight;
          }
          syncStatsSoon();
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


def _project_display_name(repo_root: str) -> str:
    """The folder name of ``repo_root``, for telling dashboards apart.

    Each ``doberman dash`` run is scoped to one repo (``--path``, default
    cwd) - see :func:`create_app`. Resolving before taking ``.name`` handles
    both a relative ``"."`` and a path with a trailing slash; falls back to
    the resolved path itself for the rare case that has no name component
    (e.g. ``repo_root="/"``).
    """
    resolved = Path(repo_root).resolve()
    return resolved.name or str(resolved)


def _js_string_literal(value: str) -> str:
    """Encode ``value`` as a JS string literal, safe inside a ``<script>`` body.

    ``json.dumps`` alone escapes quotes/backslashes but leaves ``<``, ``>``,
    and ``&`` untouched - a value containing ``</script>`` would prematurely
    close the enclosing script element, since the HTML tokenizer looks for
    that literal byte sequence regardless of JS string context. Escaping
    those three characters as unicode escapes closes that off entirely
    (the same pattern used to embed untrusted JSON inside inline scripts
    elsewhere), which matters here because the project name is a filesystem
    folder name, not a value Doberman controls.
    """
    encoded = json.dumps(value)
    return encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _render_shell(repo_root: str) -> str:
    project = _project_display_name(repo_root)
    page_title = f"{project} — Doberman Dashboard"
    return (
        _HTML_SHELL.replace("%%DASH_PAGE_TITLE%%", html.escape(page_title))
        .replace("%%DASH_PROJECT_NAME%%", html.escape(project))
        .replace("%%DASH_MARK_PNG_B64%%", DASH_MARK_PNG_B64)
        .replace("%%DASH_JS_TITLE_JSON%%", _js_string_literal(page_title))
    )


def _make_index_route(repo_root: str) -> Route:
    shell = _render_shell(repo_root)

    async def index(request: Request) -> Response:
        # No auth: the shell carries no data, only the JS that reads the
        # token back out of its own URL and calls the authenticated API
        # routes.
        return HTMLResponse(shell)

    return Route("/", index)


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


class _ModeChangePrompter:
    """Non-interactive :class:`~doberman.auth.challenge.Prompter` for ``POST /api/mode``.

    The POST request itself is the human's confirmation (they explicitly chose
    a new mode in the UI), so ``confirm`` always succeeds; ``read_code`` returns
    the possession-factor code the request body carried, or raises if none was
    supplied - the ``Prompter`` protocol requires a raise on no-input so the gate
    treats a missing code as a denial (fail closed), never as an empty-but-valid
    answer. Mirrors ``/api/resolve``: this module never verifies the code, only
    carries it opaquely to :func:`doberman.policy.drift.apply_mode_change`.
    """

    def __init__(self, code: str | None) -> None:
        self._code = code

    def confirm(self, message: str) -> bool:
        return True

    def read_code(self, message: str) -> str:
        if not self._code:
            raise ValueError("no possession-factor code supplied")
        return self._code


def _make_mode_route(token: str, repo_root: str) -> Route:
    async def mode_route(request: Request) -> Response:
        if not _token_matches(request, token):
            return _unauthorized()

        if request.method == "GET":
            return JSONResponse(
                {"mode": load_mode(repo_root), "modes": [m.value for m in SecurityMode]}
            )

        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        name = body.get("mode")
        if not isinstance(name, str) or not name:
            return JSONResponse({"error": "mode is required"}, status_code=400)
        code = body.get("code")

        try:
            saved = await apply_mode_change(
                name,
                repo_root,
                "doberman dashboard",
                prompter=_ModeChangePrompter(code if isinstance(code, str) else None),
            )
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        if saved is None:
            return JSONResponse({"error": "mode change denied"}, status_code=403)
        return JSONResponse({"mode": saved})

    return Route("/api/mode", mode_route, methods=["GET", "POST"])


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
        _make_index_route(repo_root),
        _make_health_route(token),
        _make_stats_route(token, repo_root),
        _make_feed_route(
            token, repo_root, poll_interval=feed_poll_interval, max_polls=feed_max_polls
        ),
        _make_pending_route(token, repo_root),
        _make_resolve_route(token, repo_root),
        _make_mode_route(token, repo_root),
    ]
    return Starlette(routes=routes)
