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
from doberman.explain import REASON_DESCRIPTIONS, headline, template_explanation
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
    --ink-1: oklch(22% 0.011 55);
    --ink-2: oklch(27% 0.012 55);
    --ink-3: oklch(33% 0.013 55);
    --rule: oklch(56% 0.016 55);
    --rule-2: oklch(52% 0.016 55);
    --fg: oklch(96% 0 0);
    --fg-2: oklch(82% 0.004 55);
    /* 66%, not 64%: --fg-3 on the feed row's :hover background (--ink-2, the
       lightest dark-mode ink step) measured 4.48:1 at 64% - just under the
       4.5:1 body-text floor. 66% clears it with margin (~4.85:1) while
       staying visually "muted" against --fg/--fg-2. */
    --fg-3: oklch(66% 0.006 55);
    --tan: oklch(74% 0.140 58);
    --tan-hi: oklch(84% 0.150 64);
    --mono: ui-monospace, "SF Mono", Consolas, monospace;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    --pass: oklch(76% 0.16 152);
    --pass-bg: oklch(76% 0.16 152 / 10%);
    --auth: oklch(82% 0.155 78);
    --auth-bg: oklch(82% 0.155 78 / 10%);
    --block: oklch(66% 0.205 26);
    --block-bg: oklch(66% 0.205 26 / 10%);
    --neutral: var(--fg-3);
    --neutral-bg: oklch(64% 0.006 55 / 10%);
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
      --ink-0: #eaecee; --ink-1: #ffffff; --ink-2: #dfe2e5; --ink-3: #d2d6da;
      --rule: #707478; --rule-2: #7c8084;
      --fg: #15181d; --fg-2: #2f353c; --fg-3: #48515b;
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
    --ink-0: #eaecee; --ink-1: #ffffff; --ink-2: #dfe2e5; --ink-3: #d2d6da;
    --rule: #707478; --rule-2: #7c8084;
    --fg: #15181d; --fg-2: #2f353c; --fg-3: #48515b;
    --tan: #6b4a1f; --tan-hi: #52380f;
    --pass: #116329;  --pass-bg: rgba(17, 99, 41, .12);
    --auth: #7d5200;  --auth-bg: rgba(125, 82, 0, .12);
    --block: #a40e26; --block-bg: rgba(164, 14, 38, .12);
    --neutral: #424a53; --neutral-bg: rgba(66, 74, 83, .12);
    --shadow-card: 0 6px 20px -10px oklch(0% 0 0 / 18%);
  }
  :root[data-theme="dark"] {
    --ink-0: oklch(13% 0.008 55); --ink-1: oklch(22% 0.011 55);
    --ink-2: oklch(27% 0.012 55); --ink-3: oklch(33% 0.013 55);
    --rule: oklch(56% 0.016 55); --rule-2: oklch(52% 0.016 55);
    --fg: oklch(96% 0 0); --fg-2: oklch(82% 0.004 55); --fg-3: oklch(66% 0.006 55);
    --tan: oklch(74% 0.140 58); --tan-hi: oklch(84% 0.150 64);
    --pass: oklch(76% 0.16 152); --pass-bg: oklch(76% 0.16 152 / 10%);
    --auth: oklch(82% 0.155 78); --auth-bg: oklch(82% 0.155 78 / 10%);
    --block: oklch(66% 0.205 26); --block-bg: oklch(66% 0.205 26 / 10%);
    --neutral: var(--fg-3); --neutral-bg: oklch(64% 0.006 55 / 10%);
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
  /* Placeholder text defaults to a browser-chosen, often-translucent grey in
     several engines - measured under 4.5:1 on this palette's input
     backgrounds. `opacity: 1` stops that translucency from further diluting
     the token, which is itself engineered to clear 4.5:1 against the
     `--ink-2` input background in both themes (see the `--fg-3` comment
     above). */
  ::placeholder { color: var(--fg-3); opacity: 1; }
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
    /* Pinned so the connection/guard/posture controls (and the mode-change
       trigger) stay reachable while scrolling a long feed - the popover and
       scrim are `position: fixed` (viewport-relative, see positionModeForm),
       so anchoring them off a sticky trigger needs no change there. z-index
       stays BELOW the scrim (14) / mode-form (15) / shortcuts panel (20) so
       an open popover still stacks above the pinned bar, not under it. */
    position: sticky; top: 0; z-index: 10; background: var(--ink-0);
  }
  /* JS toggles this once `window.scrollY > 0` (see the scroll listener below)
     - a stronger separator than the always-on border above, so the pinned
     bar visibly lifts off the content scrolling underneath it. */
  .topbar.scrolled { box-shadow: 0 1px 0 var(--rule-2), 0 6px 12px -8px oklch(0% 0 0 / 35%); }
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
  /* Brand + connection/guard travel together as one unit (round 6) so a
     narrow viewport can keep them on the SAME first row - see the <=640px
     block below, where this is the row that must fit brand + dot + pill. */
  .topbar-row1 { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
  .topbar-right { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
  /* Three visually separated clusters - status / posture / utilities - so the
     topbar reads as grouped controls instead of one long undifferentiated row. */
  .topbar-group { display: inline-flex; align-items: center; gap: .6rem; }
  .topbar-group + .topbar-group {
    padding-left: .9rem; margin-left: .3rem; border-left: 1px solid var(--rule-2);
  }
  /* Round 6: a plain-text TAG chip (rounded rect), not a pill - the guard
     pill below (.status-pill, border-radius: 999px) is the only true pill,
     so the two green "connected" / "ON GUARD" states read as visually
     distinct shapes, not just a dot vs. a pip glyph. */
  .chip {
    display: inline-flex; align-items: center; gap: .4rem;
    font-family: var(--mono); font-size: var(--fs-1); letter-spacing: .02em;
    padding: .32rem .6rem; border: 1px solid var(--rule); border-radius: var(--r-sm);
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
  .status-pill.ok .pip { color: var(--pass); }
  .status-pill.alert { color: var(--auth); border-color: var(--auth); background: var(--auth-bg); }
  .status-pill.alert .pip { animation: pulse 1.6s ease-in-out infinite; }
  @media (prefers-reduced-motion: reduce) { .status-pill.alert .pip { animation: none; } }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
  /* Ghost buttons: the theme and shortcuts toggles are conveniences, so they
     carry no border - the one control that changes the security posture
     (#mode-edit-btn) is the bordered one in the topbar. */
  #theme-toggle-btn, #shortcuts-btn, #shortcuts-close-btn, #shortcuts-toggle-btn,
  #panel-theme-toggle-btn, #feed-announce-toggle-btn {
    font-family: var(--font); font-size: var(--fs-1); font-weight: 600; padding: .35rem .8rem;
    border: 1px solid transparent; background: transparent; color: var(--fg-3);
  }
  #theme-toggle-btn:hover, #shortcuts-btn:hover, #shortcuts-close-btn:hover,
  #shortcuts-toggle-btn:hover, #panel-theme-toggle-btn:hover, #feed-announce-toggle-btn:hover {
    border-color: var(--tan-hi); color: var(--tan-hi);
  }
  #shortcuts-toggle-btn[aria-pressed="false"] { color: var(--fg-3); font-style: italic; }
  #feed-announce-toggle-btn[aria-pressed="false"] { color: var(--fg-3); font-style: italic; }
  /* Round 6: `Shortcuts: off` dims the binding list itself, and the panel
     title grows an "(off)" suffix (see renderShortcutsToggle) - the toggle
     button alone saying "off" was easy to miss against a full dl of bindings
     that mostly still work (only the bare single-character ones are gated).
     Round 7: scoped to `.gated` only (the five bare single-key rows: / r ? a
     d) - the toggle never gates Up/Down/Enter/Space/Home/End (those are the
     feed's own roving-focus listener, wired independently of
     shortcutsEnabled()), so dimming the WHOLE list read as "none of this
     works" when most of it still did. */
  #shortcuts-dl.dimmed dt.gated, #shortcuts-dl.dimmed dd.gated { opacity: .55; }
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
  /* Base state: hidden on wide screens. `.badge`'s own `display: inline-flex`
     (an AUTHOR rule) otherwise overrides the `hidden` ATTRIBUTE's UA
     `display: none` outright regardless of specificity (author beats
     user-agent in the cascade) - caught live in Chrome, the same class of
     bug this file's other `[hidden]`-restatement comments describe. An ID
     selector here beats `.badge`'s class selector on specificity alone, and
     the <=640px media rule below (same ID, later in source order) then
     wins back at that breakpoint. */
  #posture-badge { display: none; }
  #stats {
    margin: 0 0 1.75rem; font-family: var(--mono); font-size: var(--fs-2); color: var(--fg-3);
    display: flex; flex-wrap: wrap; gap: .6rem 1.4rem; align-items: flex-start;
    padding: .85rem 1.1rem; border: 1px solid var(--rule-2); border-radius: var(--r);
    background: var(--ink-1);
  }
  /* Three labeled groups (decisions / verdicts / top reasons) instead of one
     run-on line of bare spans - each group wraps as its own unit. */
  .stat-group { display: flex; flex-wrap: wrap; align-items: center; gap: .4rem; }
  .stat-label {
    font-family: var(--mono); font-size: var(--fs-1); font-weight: 600;
    letter-spacing: .06em; text-transform: uppercase; color: var(--fg-3);
  }
  #stats .count { color: var(--fg); }
  #stats .retry-link { min-height: auto; padding: 0; }
  /* Mobile fold: only the verdict badges + the freshness timestamp survive -
     the decisions/top-reasons groups cost vertical room the first feed row
     needs at 390px (see docs/SETUP.md's mobile note). Round 7: what's left
     (three badges + the recent-window detail + the timestamp) still wrapped
     to two lines at 390px - drop the "recent N: ..." detail too and force
     one non-wrapping line (scrollable, not clipped, if it's ever still too
     tight) so "the stats show one line" holds at the narrowest width this
     dashboard supports. */
  @media (max-width: 640px) {
    #stats-decisions, #stats-reasons { display: none; }
    #stats { flex-wrap: nowrap; overflow-x: auto; }
    #stats-verdicts .detail { display: none; }
  }
  .empty-state {
    padding: 2rem 1.5rem; border: 1px dashed var(--rule); border-radius: var(--r);
    color: var(--fg-3); font-size: var(--fs-2); text-align: center;
  }
  #feed, #pending-list { list-style: none; margin: .5rem 0 0; }
  #feed:not(:empty) ~ #feed-empty { display: none; }
  #pending-list:not(:empty) ~ #pending-empty { display: none; }
  /* Direct-child combinator (round 5) - a pending card's own .gloss-list is
     a <ul> of <li> nested INSIDE this <li>, and a bare descendant selector
     matched those too (each gloss line rendered as its own bordered/
     shadowed/animated card). Caught live in Chrome. */
  #pending-list > li {
    padding: 1.4rem 1.5rem 1.5rem; margin-bottom: .9rem;
    border: 1px solid var(--auth); border-radius: var(--r-lg); background: var(--ink-1);
    font-size: var(--fs-2);
    box-shadow: var(--shadow-card);
    animation: pending-arrive .28s ease-out both;
  }
  #pending-list > li.stale { opacity: .7; border-style: dashed; }
  @keyframes pending-arrive {
    from { opacity: 0; transform: translateY(-6px); }
    to { opacity: 1; transform: none; }
  }
  @media (prefers-reduced-motion: reduce) {
    #pending-list > li { animation: none; }
  }
  #pending-list .row-header {
    display: flex; align-items: center; gap: .5rem; margin-bottom: .6rem; flex-wrap: wrap;
  }
  #pending-list .row-header .detail { color: var(--fg); font-family: var(--mono); font-size: var(--fs-2); }
  /* Downsized from --fs-3 (round 5) - the explanation sentence below is now
     the card's largest element, not the countdown. */
  #pending-list .countdown {
    font-family: var(--mono); font-size: var(--fs-2); font-weight: 700; color: var(--auth);
    margin-left: auto;
  }
  /* Sentence first (primary, full-contrast body text, now the card's LARGEST
     element - round 5), codes second (see .reason-line below) - same
     hierarchy as the feed's now-primary explanation. */
  #pending-list .row-explanation {
    margin: .5rem 0 .5rem; color: var(--fg); line-height: 1.6; max-width: 62ch;
    font-size: var(--fs-3); font-weight: 600;
  }
  #pending-list .reason-line {
    margin: 0 0 .5rem; color: var(--fg-3); font-family: var(--mono); font-size: var(--fs-1);
    overflow-wrap: anywhere;
  }
  #pending-list .privacy-note {
    margin: 0 0 1rem; color: var(--fg-3); font-family: var(--font); font-size: var(--fs-1);
  }
  #pending-list .totp-label {
    display: block; color: var(--fg-3); font-family: var(--font); font-size: var(--fs-1);
    margin: 0 0 .3rem;
  }
  #pending-list input {
    font-family: var(--mono); font-size: var(--fs-3); padding: .45rem .6rem; margin: 0 .5rem .5rem 0;
    letter-spacing: .12em; width: 9rem;
    background: var(--ink-0); color: var(--fg); border: 1px solid var(--rule); border-radius: 4px;
  }
  #pending-list button { margin: 0 .5rem .5rem 0; }
  /* Deny is the solid/primary action (Approve stays outlined) but in the
     neutral/tan fill, not red - a filled red Deny read as "the dangerous
     button" in review. --block stays reserved for verdict/risk badges and
     the mode form's downgrade Save (see #mode-save-btn.danger below), where
     red actually signals danger rather than a routine security decision. */
  #pending-list button.deny { background: var(--tan); border: 1px solid var(--tan); color: var(--ink-0); }
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
  /* The clear-filters link borrows .retry-link's compact look, but as the one
     actionable control in the no-match empty state it still needs a real
     44px hit target, not a link's inline auto sizing (it measured under the
     floor at 390px, but the same gap exists at any width). */
  #feed-clear-filters-btn { min-height: 44px; min-width: 44px; }
  .section-head { display: flex; align-items: center; justify-content: space-between; gap: .5rem; margin-top: 1.4rem; }
  #refresh-btn {
    font-family: var(--font); font-size: var(--fs-2); font-weight: 600;
    background: transparent; border: 1px solid var(--rule); color: var(--fg);
  }
  #refresh-btn:hover { border-color: var(--tan-hi); color: var(--tan-hi); }
  .feed-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: .6rem; margin: .7rem 0 .8rem; }
  /* Round 7: the verdict select, the count, and the mobile "Filters"
     disclosure toggle travel together as one unit so they can share a row in
     the <=640px column layout (see the mobile override below) - `display:
     contents` at every OTHER width unwraps it back into plain flex children
     of .feed-toolbar, so nothing changes visually at desktop widths. */
  .feed-toolbar-row1 { display: contents; }
  /* Verdict chips (desktop/wide) vs. a single <select> (<=640px, see
     #feed-verdict-select below) are two separate controls kept in sync by
     setVerdictFilter() - a native <select> reads and operates far better
     than a wrapped row of pill buttons once there's no room for five of
     them side by side. */
  .filter-chip-group { display: flex; gap: .4rem; flex-wrap: wrap; }
  .filter-chip {
    font-family: var(--mono); font-size: var(--fs-1); padding: .4rem .9rem;
    border: 1px solid var(--rule); border-radius: 999px; background: var(--ink-2); color: var(--fg-2);
  }
  /* An active chip colors by the verdict it filters to (BLOCK=red, AUTH=amber,
     PASS=green) - a filter for BLOCK rows should itself read as a BLOCK signal,
     not the generic amber every chip used before. "All" (no data-verdict) gets
     the neutral treatment. */
  .filter-chip[aria-pressed="true"] {
    background: var(--neutral-bg); border-color: var(--rule); color: var(--fg);
  }
  .filter-chip[data-verdict="BLOCK"][aria-pressed="true"] {
    background: var(--block-bg); border-color: var(--block); color: var(--block);
  }
  .filter-chip[data-verdict="AUTH"][aria-pressed="true"] {
    background: var(--auth-bg); border-color: var(--auth); color: var(--auth);
  }
  .filter-chip[data-verdict="PASS"][aria-pressed="true"] {
    background: var(--pass-bg); border-color: var(--pass); color: var(--pass);
  }
  #feed-filter {
    font-family: var(--font); font-size: var(--fs-2); padding: .5rem .8rem;
    border: 1px solid var(--rule); border-radius: var(--r-sm); background: var(--ink-2); color: var(--fg);
    flex: 1 1 12rem;
  }
  /* Hidden by default (desktop keeps the chip group, see .filter-chip-group
     above) - shown only <=640px, see the mobile block below. */
  #feed-verdict-select {
    display: none;
    font-family: var(--mono); font-size: var(--fs-1); padding: .4rem .7rem;
    border: 1px solid var(--rule); border-radius: var(--r-sm); background: var(--ink-2); color: var(--fg);
  }
  /* Same ghost-button look as the theme/shortcuts toggles - a convenience
     disclosure, not a control that changes what's on screen by itself.
     Hidden at desktop: the filter input + announce toggle it discloses are
     already inline there (see #feed-filters-panel below). */
  #feed-filters-toggle-btn {
    display: none;
    font-family: var(--font); font-size: var(--fs-1); font-weight: 600; padding: .35rem .8rem;
    border: 1px solid var(--rule); border-radius: var(--r-sm); background: transparent; color: var(--fg-3);
  }
  #feed-filters-toggle-btn:hover { border-color: var(--tan-hi); color: var(--tan-hi); }
  /* Desktop: no wrapping box at all - `display: contents` unwraps the text
     filter + announce toggle back into plain flex children of
     .feed-toolbar, same trick as .feed-toolbar-row1 above. An author
     `display` here outranks the UA's `[hidden]` rule (the mode form and the
     feed's own row-hiding above have the identical bug), so this stays
     visible regardless of the mobile disclosure's collapsed/expanded state -
     the <=640px override below is what actually makes `hidden` hide it. */
  #feed-filters-panel { display: contents; }
  #feed {
    max-height: 60vh; overflow-y: auto;
    border: 1px solid var(--rule-2); border-radius: var(--r); background: var(--ink-1);
  }
  /* Direct-child combinator (round 5) - a feed row's own .gloss-list is a
     <ul> of <li> nested INSIDE this <li>, and a bare descendant selector
     matched those too (each gloss line inherited the row's padding/font/
     hover/focus/active treatment). Caught live in Chrome alongside the
     identical #pending-list bug above. */
  #feed > li {
    padding: .6rem 1.1rem; border-bottom: 1px solid var(--rule-2);
    font-size: var(--fs-2); font-family: var(--mono);
    transition: background-color var(--d);
  }
  #feed li .row-main { display: flex; align-items: baseline; gap: .5rem; }
  /* The filter hides rows with the `hidden` attribute; an author `display`
     on the same element outranks the UA's [hidden] rule, so restate it here
     (the mode form had exactly this bug). */
  #feed > li[hidden] { display: none; }
  #feed > li:last-child { border-bottom: none; }
  #feed > li:hover { background: var(--ink-2); }
  /* A row with an explanation is click/tap-expandable (see the feed's click
     handler below); a bare PASS row with no explanation carries nothing to
     expand, so it gets no pointer cursor. */
  #feed > li.has-explanation { cursor: pointer; }
  /* Real roving focus (Up/Down/Home/End move DOM focus here, see
     setActiveFeedEntry). Round 6: `.active` and a plain `:focus` rule
     (outline suppressed to `none` on it) used to be two separate rules of
     EQUAL specificity (0,0,1,1 each) - source order made the suppression
     win over the active row's own outline on the very row that was both
     active AND focused (which is every roving-focus row, since
     setActiveFeedEntry() always calls .focus() right after adding the
     class), so the ring never actually rendered. One rule, no suppression,
     at the highest specificity either state needs. */
  #feed > li.active { background: var(--ink-2); }
  #feed > li:focus-visible, #feed > li.active:focus {
    outline: 2px solid var(--tan-hi); outline-offset: -2px;
  }
  #feed li .detail { color: var(--fg-3); overflow-wrap: anywhere; }
  /* Shared with the pending card's own reason line below - not scoped to the
     feed, since both use the same glossed-span markup (appendReasonCodeSpans). */
  .reason-code[title] { text-decoration: underline dotted; text-underline-offset: 2px; }
  /* No more per-code "?" buttons (round 5 - they were Tab-focusable inside a
     list that otherwise deliberately has no per-row buttons). A row with
     glossed codes is itself the toggle: a feed row with an explanation
     already expands by click/tap/Enter/Space (see .has-explanation below);
     expanding it reveals this same muted list. Pending cards are never
     collapsed, so they just render it always-visible. */
  .gloss-list {
    list-style: none; margin: .5rem 0 0; padding: 0;
    display: flex; flex-direction: column; gap: .2rem;
    color: var(--fg-3); font-family: var(--font); font-size: var(--fs-1);
  }
  /* An author `display` on the same element outranks the UA's [hidden] rule
     (the mode form and the feed filter both had exactly this bug) - a
     collapsed feed row's gloss list was rendering unconditionally without
     this. Pending cards never set `hidden` at all, so this never hides them. */
  .gloss-list[hidden] { display: none; }
  /* First line, body face, full contrast - the human "why" is the row's
     PRIMARY text; the verdict/action metadata below it is secondary. One
     line by default, click/tap or Enter/Space (roving focus) expands it
     (see the feed's click handler and keydown handler) since some
     explanations run well past a single line. */
  #feed li .row-explanation {
    color: var(--fg); font-family: var(--font); font-size: var(--fs-2);
    line-height: 1.5; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  /* Round 7: expanding a row no longer REPLACES the headline with the full
     sentence (a keyboard user landing back on a collapsed row used to lose
     the very fragment that told rows apart) - the full sentence is now its
     OWN element, appended under the (always-visible) headline, hidden until
     the row is expanded. */
  #feed li .row-explanation-full {
    color: var(--fg); font-family: var(--font); font-size: var(--fs-2);
    line-height: 1.5; margin-top: .3rem; max-width: 62ch;
  }
  #feed li .row-explanation-full[hidden] { display: none; }
  /* The metadata line (verdict/risk badges + action/target/reason codes) now
     reads as the SECONDARY line under the explanation - already muted mono
     via .detail above; this just adds the spacing that used to sit above
     .row-explanation instead. */
  #feed li .row-explanation ~ .row-main { margin-top: .3rem; }
  .feed-note {
    padding: .6rem 1.1rem; color: var(--fg-3); font-family: var(--mono); font-size: var(--fs-1);
    border-top: 1px solid var(--rule-2);
  }
  #mode-edit-btn {
    font-size: var(--fs-1); font-weight: 600; padding: .35rem .7rem;
    border: 1px solid var(--fg-3); border-radius: 4px; background: transparent;
    color: var(--fg-2);
  }
  #mode-edit-btn[aria-expanded="true"] { background: var(--neutral-bg); color: var(--fg); }
  #mode-edit-btn:hover { background: var(--neutral-bg); color: var(--fg); }
  #mode-form:not([hidden]) {
    display: flex; flex-wrap: wrap; align-items: center; gap: .5rem;
    margin: -.2rem 0 1.2rem; font-size: var(--fs-2);
  }
  /* >=641px: an anchored popover under the posture cluster (positioned in JS -
     see positionModeForm - right-aligned to #mode-edit-btn) instead of an
     inline band, with the surface/shadow of a card. <=640px keeps the
     full-width band below (see the max-width:640px block). */
  @media (min-width: 641px) {
    #mode-form:not([hidden]) {
      position: fixed; width: 28rem; max-width: calc(100vw - 2rem);
      padding: 1rem 1.25rem; margin: 0; border-radius: var(--r-lg);
      background: var(--ink-1); box-shadow: var(--shadow-card); z-index: 15;
    }
    /* A small tail pointing back at #mode-edit-btn (positionModeForm
       right-aligns the popover under it) - so the popover reads as
       anchored to its trigger, not a stray floating box. */
    #mode-form:not([hidden])::before {
      content: ""; position: absolute; top: -7px; right: 1.4rem;
      width: 14px; height: 14px; background: var(--ink-1);
      transform: rotate(45deg); border-radius: 2px 0 0 0;
      box-shadow: -1px -1px 2px -1px oklch(0% 0 0 / 30%);
    }
  }
  /* A blocked dismiss (Escape/outside click while a change is pending, see
     attemptCloseModeForm) shakes the popover once - a silent no-op read as
     broken. prefers-reduced-motion: reduce drops the transform entirely,
     the aria-live hint text change alone still carries the signal. */
  @keyframes mode-form-nudge {
    0%, 100% { transform: translateX(0); }
    25% { transform: translateX(-6px); }
    75% { transform: translateX(6px); }
  }
  #mode-form.nudge { animation: mode-form-nudge .3s ease-in-out; }
  @media (prefers-reduced-motion: reduce) { #mode-form.nudge { animation: none; } }
  /* Visible popover title (round 6 - was sr-only, so the popover had no
     on-screen heading at all) - same look as the shortcuts panel's title. */
  #mode-form-title {
    flex-basis: 100%; margin: 0 0 .3rem;
    font-family: var(--mono); font-size: var(--fs-1); font-weight: 600;
    letter-spacing: .08em; text-transform: uppercase; color: var(--fg-3);
  }
  /* A translucent scrim behind the popover while it's open - #main and
     #header are also `inert` at that point (see openModeForm), so the scrim
     is mostly a visual cue; it also doubles as an oversized outside-click
     target since the light-dismiss handler is on `document`. */
  #mode-scrim {
    position: fixed; inset: 0; z-index: 14; background: oklch(0% 0 0 / 45%);
  }
  #mode-hint { flex-basis: 100%; margin: -.15rem 0 .2rem; color: var(--fg); font-size: var(--fs-2); }
  /* A downgrade in progress restyles the hint to the BLOCK color - it's the
     one form of this hint that actually weakens the guard. */
  #mode-hint.lowering { color: var(--block); }
  #mode-hint:empty { display: none; }
  #mode-form select, #mode-form input {
    font-size: var(--fs-2); padding: .35rem .55rem;
    background: var(--ink-2); color: var(--fg); border: 1px solid var(--rule); border-radius: 4px;
  }
  #mode-form input { width: 16rem; letter-spacing: .04em; }
  .mode-form-actions { display: flex; gap: .5rem; align-items: center; }
  #mode-form button {
    font-size: var(--fs-2); font-weight: 600; padding: .35rem .85rem;
    border: 1px solid var(--rule); border-radius: 4px; background: transparent;
    color: inherit;
  }
  #mode-save-btn { border-color: var(--pass); color: var(--pass); }
  #mode-save-btn:hover { background: var(--pass-bg); }
  /* A selected mode LOWER than the current one restyles Save to the BLOCK
     color and requires the same arm-then-confirm gesture as Approve (see the
     modeSaveBtn click handler) - a strictness downgrade is gated at least as
     hard as an approval, never a single frictionless click. */
  #mode-save-btn.danger { border-color: var(--block); color: var(--block); }
  #mode-save-btn.danger:hover { background: var(--block-bg); }
  #mode-cancel-btn:hover { background: var(--neutral-bg); }
  #mode-success { color: var(--pass); font-family: var(--mono); font-size: var(--fs-1); }
  #mode-error { color: var(--block); font-family: var(--mono); font-size: var(--fs-1); }
  /* >=641px: anchored under the "?" trigger by JS (positionShortcutsPanel),
     same fixed-position technique as the mode-form popover (positionModeForm)
     - JS sets top/right inline on open, clamped to stay inside the viewport.
     This media query is only the pre-JS/no-JS fallback (round 5 - without
     it, a `position: fixed` box with no inset at all falls back to its
     static DOM position instead of anywhere near its trigger), so it still
     reads as "near the button", never the opposite corner. <=640px falls
     back to the fixed viewport corner below instead, since a topbar button
     can itself have wrapped to an unpredictable position at that width. */
  #shortcuts-panel {
    position: fixed; z-index: 20; max-width: 20rem;
    padding: 1rem 1.25rem; border-radius: var(--r-lg);
    background: var(--ink-1); box-shadow: var(--shadow-card); font-size: var(--fs-2);
  }
  @media (min-width: 641px) {
    #shortcuts-panel { top: 4.5rem; right: 1.25rem; }
    /* Wide enough that the theme toggle, the on/off toggle, and Close all
       fit .panel-actions' one flex row without wrapping - at the base
       20rem max-width (set for the <=640px fixed-corner case) three buttons
       of this length wrapped to two lines. */
    #shortcuts-panel { max-width: 27rem; }
    .panel-actions { flex-wrap: nowrap; }
  }
  @media (max-width: 640px) {
    #shortcuts-panel { right: 1.25rem; bottom: 1.25rem; }
  }
  #shortcuts-panel:focus { outline: none; }
  /* Round 7: body colour + --fs-2 (was --fg-3/--fs-1, easy to miss next to
     the muted announce toggle it used to sit beside) - "2 of 43 shown" is
     feedback about what's actually on screen, not a muted aside, and it now
     sits right next to the verdict control that produced it (see
     .feed-toolbar-row1 above) rather than paired with the announce toggle. */
  #feed-count { color: var(--fg); font-size: var(--fs-2); align-self: center; }
  /* Empty (no active filter) at initial load - a `<span>` with no `display:
     none` still costs a full row in the mobile column layout for zero
     content. Same pattern as #mode-hint:empty above. */
  #feed-count:empty { display: none; }
  .row-done { color: var(--pass); font-weight: 600; margin-top: .4rem; }
  /* A styled <p>, not a heading - this panel is a transient overlay, not a
     section of the page outline. */
  #shortcuts-panel .panel-title {
    font-family: var(--mono); font-size: var(--fs-1); font-weight: 600;
    letter-spacing: .08em; text-transform: uppercase; color: var(--fg-3);
    margin: 0 0 .6rem;
  }
  #shortcuts-panel dl { display: grid; grid-template-columns: auto 1fr; gap: .3rem .8rem; margin: .5rem 0 .8rem; }
  #shortcuts-panel dt { font-family: var(--mono); color: var(--tan-hi); }
  #shortcuts-panel dd { color: var(--fg-2); }
  .panel-actions { display: flex; gap: .5rem; flex-wrap: wrap; }
  @media (max-width: 640px) {
    .topbar { flex-direction: column; align-items: flex-start; }
    /* Row 1: brand + connection dot + guard pill, nothing else - the goal is
       the first feed row starting within 600px of the top (round 6). Every
       rule from here down to #pending-empty below trims vertical padding/
       margin toward that same budget - none of it changes at wider widths. */
    .topbar { padding-bottom: .6rem; margin-bottom: .75rem; }
    h2 { margin-top: .85rem; }
    #stats { padding: .5rem .75rem; margin-bottom: 1rem; }
    .topbar-row1 { width: 100%; justify-content: space-between; }
    .topbar-right { width: 100%; }
    /* mode + enforcement collapse into ONE joined badge ("posture: strict
       - enforcing"); the standalone theme toggle moves into the shortcuts
       panel (see #panel-theme-toggle-btn) - only the "?" trigger stays. */
    #mode-badge, #enforcement-badge, #theme-toggle-btn { display: none; }
    #posture-badge { display: inline-flex; }
    /* Wrapped groups would otherwise show a stray leading divider. */
    .topbar-group + .topbar-group { border-left: none; padding-left: 0; margin-left: 0; }
    /* A squeezed flex row lets a badge/pill shrink below its text's natural
       width, which - with no nowrap - wraps "mode: paranoid" onto two lines
       instead of shrinking the group's own layout. Keep each pill one line
       and let the GROUP wrap onto a second row instead. */
    .badge, .status-pill { white-space: nowrap; }
    .topbar-group { flex-wrap: wrap; row-gap: .4rem; }
    #mode-form:not([hidden]) { flex-direction: column; align-items: stretch; }
    #mode-form select, #mode-form input { width: 100%; }
    .mode-form-actions { width: 100%; }
    .mode-form-actions button { flex: 1 1 0; }
    #feed li .row-main { flex-wrap: wrap; }
    #feed li .detail { flex-basis: 100%; }
    #pending-list .countdown { margin-left: 0; flex-basis: 100%; }
    .feed-toolbar { flex-direction: column; align-items: stretch; margin: .35rem 0 .4rem; gap: .4rem; }
    /* Round 7: the four verdict chips become one native <select> - a row of
       five pill buttons (Needs attention/All/BLOCK/AUTH/PASS) has no room at
       this width, and a <select> reads and operates better than a wrapped
       button row anyway. */
    .filter-chip-group { display: none; }
    #feed-verdict-select { display: inline-block; }
    /* The select + the count + the "Filters" disclosure trigger share ONE
       row (see .feed-toolbar-row1's desktop `display: contents` above) -
       the goal is still the first feed row starting within 600px (round 6),
       so nothing here costs it more than one line. */
    .feed-toolbar-row1 {
      display: flex; align-items: center; flex-wrap: wrap; gap: .5rem .6rem; width: 100%;
    }
    #feed-filters-toggle-btn { display: inline-flex; }
    /* The text filter + "Announce new rows" toggle move BEHIND the "Filters"
       disclosure (collapsed by default - see renderFeedFiltersToggle) so
       they don't cost the first-feed-row budget above; expanding reveals
       them stacked, same reasoning as #feed-filter's `flex: none` below. An
       author `display` on the same element outranks the UA's `[hidden]`
       rule (the mode form and the feed's own row-hiding above have the
       identical bug), so both states need restating here. */
    #feed-filters-panel[hidden] { display: none; }
    #feed-filters-panel:not([hidden]) {
      display: flex; flex-direction: column; align-items: stretch; gap: .5rem; width: 100%;
    }
    #feed-filter {
      width: 100%;
      /* In a column flex-toolbar the main axis is now vertical, so the
         general `flex: 1 1 12rem` rule (written for a row layout) makes this
         input GROW to fill the remaining vertical space instead of sizing to
         its own content - it measured 192px tall. `flex: none` opts back out. */
      flex: none;
    }
    /* A single-line note, not the big dashed empty-state box - this is the
       FIRST thing on the page at this width, and the feed below it needs
       the vertical room more than an empty queue does (round 5 - the first
       feed row should start within the first 600px). */
    #pending-empty {
      padding: .4rem 0; border: none; text-align: left; font-size: var(--fs-1);
    }
  }
</style>
</head>
<body>
  <div id="announcer" class="sr-only" aria-live="polite"></div>
  <header class="topbar">
    <div class="topbar-row1">
      <div class="brand">
        <img src="data:image/png;base64,%%DASH_MARK_PNG_B64%%" alt="" aria-hidden="true" />
        <span class="word">DOBERMAN</span>
        <span class="project">%%DASH_PROJECT_NAME%%</span>
      </div>
      <div class="topbar-group">
        <span class="chip" id="status"><span class="dot" id="dot"></span><span id="label">connecting...</span></span>
        <span class="status-pill ok" id="guard-status"><span class="pip" id="guard-pip" aria-hidden="true">●</span><span id="guard-label">ON GUARD</span></span>
      </div>
    </div>
    <div class="topbar-right">
      <div class="topbar-group">
        <span class="badge badge-neutral" id="mode-badge">mode: -</span>
        <span class="badge badge-neutral" id="posture-badge" hidden>posture: -</span>
        <button type="button" id="mode-edit-btn" aria-expanded="false" aria-controls="mode-form">change</button>
        <span class="badge badge-neutral" id="enforcement-badge">enforcement: -</span>
      </div>
      <div class="topbar-group" id="topbar-utility-group">
        <button type="button" id="theme-toggle-btn">Switch to light theme</button>
        <button type="button" id="shortcuts-btn" aria-haspopup="true" aria-expanded="false">Shortcuts (?)</button>
      </div>
    </div>
  </header>
  <main>
    <h1 class="sr-only">Doberman local dashboard</h1>
    <div id="stats">stats loading...</div>
    <section aria-labelledby="pending-heading">
      <h2 id="pending-heading">Pending approvals</h2>
      <ul id="pending-list"></ul>
      <div id="pending-empty" class="empty-state">Nothing pending. Doberman's watching.</div>
    </section>
    <section aria-labelledby="feed-heading">
      <div class="section-head">
        <h2 id="feed-heading">Recent decisions</h2>
        <button type="button" id="refresh-btn">Refresh</button>
      </div>
      <div class="feed-toolbar">
        <div class="filter-chip-group" role="group" aria-label="Filter by verdict">
          <button type="button" class="filter-chip" data-verdict="needs_attention" aria-pressed="true">Needs attention</button>
          <button type="button" class="filter-chip" data-verdict="" aria-pressed="false">All</button>
          <button type="button" class="filter-chip" data-verdict="BLOCK" aria-pressed="false">BLOCK</button>
          <button type="button" class="filter-chip" data-verdict="AUTH" aria-pressed="false">AUTH</button>
          <button type="button" class="filter-chip" data-verdict="PASS" aria-pressed="false">PASS</button>
        </div>
        <div class="feed-toolbar-row1">
          <select id="feed-verdict-select" aria-label="Filter by verdict">
            <option value="needs_attention">Needs attention</option>
            <option value="">All</option>
            <option value="BLOCK">BLOCK</option>
            <option value="AUTH">AUTH</option>
            <option value="PASS">PASS</option>
          </select>
          <span id="feed-count" aria-live="polite"></span>
          <button type="button" id="feed-filters-toggle-btn" aria-expanded="false" aria-controls="feed-filters-panel">Filters</button>
        </div>
        <div id="feed-filters-panel" hidden>
          <label class="sr-only" for="feed-filter">Filter recent decisions by text</label>
          <input type="search" id="feed-filter" placeholder="Filter (press / to focus)">
          <button type="button" id="feed-announce-toggle-btn" aria-pressed="true">Announce new rows: on</button>
        </div>
      </div>
      <ul id="feed" role="log" aria-live="off" tabindex="0" aria-label="Recent decisions"></ul>
      <div id="feed-empty" class="empty-state">No decisions yet. Doberman's watching quietly.</div>
      <div id="feed-nomatch" class="empty-state" hidden>
        <span id="feed-nomatch-text">No decisions match this filter.</span>
        <button type="button" id="feed-clear-filters-btn" class="retry-link">Clear filters</button>
      </div>
      <div id="feed-truncated" class="feed-note" hidden>older rows not shown - see doberman log</div>
    </section>
  </main>
  <div id="mode-scrim" hidden></div>
  <div id="mode-form" hidden role="dialog" aria-modal="true" aria-labelledby="mode-form-title">
    <p id="mode-form-title">Security mode</p>
    <select id="mode-select" aria-label="Security mode"></select>
    <p id="mode-hint" aria-live="polite"></p>
    <label class="sr-only" for="mode-code">2FA code or password, only needed to lower strictness</label>
    <input id="mode-code" type="password" autocomplete="off"
      placeholder="code (to lower strictness)">
    <div class="mode-form-actions">
      <button type="button" id="mode-save-btn">Save</button>
      <button type="button" id="mode-cancel-btn">Cancel</button>
    </div>
    <span id="mode-success"></span>
    <span id="mode-error" role="alert"></span>
  </div>
  <div id="shortcuts-panel" hidden role="region" aria-label="Keyboard shortcuts" tabindex="-1">
    <p class="panel-title" id="shortcuts-panel-title">Shortcuts</p>
    <dl id="shortcuts-dl">
      <dt class="gated">/</dt><dd class="gated">Focus the decisions filter</dd>
      <dt>&uarr; / &darr;</dt><dd>Move the active row in the decisions feed</dd>
      <dt>Enter / Space</dt><dd>Expand or collapse the active row's explanation</dd>
      <dt>Home / End</dt><dd>Jump to the first/last row in the feed</dd>
      <dt class="gated">r</dt><dd class="gated">Refresh stats + pending</dd>
      <dt class="gated">a</dt><dd class="gated">Arm Approve on the first pending item, then Enter to confirm</dd>
      <dt class="gated">d</dt><dd class="gated">Arm Deny on the first pending item, then Enter to confirm</dd>
      <dt class="gated">?</dt><dd class="gated">Toggle this panel</dd>
      <dt>Esc</dt><dd>Clear the decisions filter, or close this panel or the mode form</dd>
    </dl>
    <div class="panel-actions">
      <button type="button" id="panel-theme-toggle-btn">Switch to light theme</button>
      <button type="button" id="shortcuts-toggle-btn" aria-pressed="true">Shortcuts: on</button>
      <button type="button" id="shortcuts-close-btn">Close</button>
    </div>
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
      // Round 6: a single word ("enforcing"/"monitoring"), not the raw dial
      // name repeated verbatim after its own label ("enforcement: enforce"
      // read as a stutter) - the exact pair still reaches the user via
      // `title`, see renderStats below.
      var ENFORCEMENT_WORD = {
        enforce: "enforcing",
        monitor: "monitoring",
        off: "off"
      };
      var ENFORCEMENT_TITLE = {
        enforce: "enforce: Doberman blocks and authenticates for real",
        monitor: "monitor: decisions are logged only, nothing is blocked",
        off: "off: Doberman is not evaluating actions"
      };
      // Plain-words gloss for a reason code (title="..." tooltip on the feed's
      // reason-code spans) - the exact same dict doberman.explain.template_explanation
      // uses server-side, interpolated once at render time so there is only one
      // source of truth for these descriptions. A code missing here (a future
      // ReasonCode) just renders with no title.
      var REASON_DESCRIPTIONS = %%DASH_REASON_DESCRIPTIONS_JSON%%;
      // Modes are always returned by /api/mode in strictness order (light ->
      // paranoid); this labels each option and lets the raise/lower hint below
      // be computed purely from array position, no hardcoded ordering logic.
      var MODE_LABELS = {
        light: "light - least strict",
        balanced: "balanced - default",
        strict: "strict - more strict",
        paranoid: "paranoid - most strict"
      };
      // One factual sentence of consequence per doberman/policy/modes.py's
      // MODES thresholds (paranoid is never a "lower" target - it's already
      // the strictest - so it needs no entry). Update both together if those
      // numbers change; the floor hard blocks (FLOOR_HARD_BLOCKS) never move
      // with the mode regardless, which is why every sentence gets that same
      // closing reassurance appended below rather than repeating it here.
      var MODE_DOWNGRADE_CONSEQUENCE = {
        light: "Light turns off the out-of-scope, unknown-destination, and " +
          "unusual-behavior step-ups, and only flags bulk deletes at 100+ items",
        balanced: "Balanced stops treating a merely-unknown destination as " +
          "AUTH-worthy on its own, raises the bulk-delete threshold to 25 items, " +
          "and raises the abnormality threshold to 0.7",
        strict: "Strict raises the bulk-delete threshold to 10 items and the " +
          "abnormality threshold to 0.5, and drops Paranoid's egress hard-block"
      };

      function pad2(n) { return n < 10 ? "0" + n : String(n); }

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
      // Round 6: at <=640px the standalone topbar button hides (see the
      // mobile CSS block) and this one inside the shortcuts panel takes
      // over - both stay in sync via applyTheme() below either way.
      var panelThemeToggleBtn = document.getElementById("panel-theme-toggle-btn");
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
        var nextLabel = eff === "dark" ? "Switch to light theme" : "Switch to dark theme";
        themeToggleBtn.textContent = nextLabel;
        panelThemeToggleBtn.textContent = nextLabel;
      }
      applyTheme(readStoredTheme());
      function toggleTheme() {
        var next = effectiveTheme(readStoredTheme()) === "dark" ? "light" : "dark";
        writeStoredTheme(next);
        applyTheme(next);
      }
      themeToggleBtn.addEventListener("click", toggleTheme);
      panelThemeToggleBtn.addEventListener("click", toggleTheme);

      // Sticky topbar (round 7): a bottom hairline/shadow that only shows
      // once the page has actually scrolled - at scrollY 0 the plain
      // border-bottom is enough, so this doesn't double up on it.
      var topbarEl = document.querySelector(".topbar");
      function syncTopbarScrolled() {
        topbarEl.classList.toggle("scrolled", window.scrollY > 0);
      }
      window.addEventListener("scroll", syncTopbarScrolled, { passive: true });
      syncTopbarScrolled();

      var dot = document.getElementById("dot");
      var label = document.getElementById("label");
      var favicon = document.getElementById("favicon");
      var statsEl = document.getElementById("stats");
      var modeBadge = document.getElementById("mode-badge");
      var enforcementBadge = document.getElementById("enforcement-badge");
      // Combined "posture: strict - enforcing" badge for the <=640px topbar
      // fold (see the mobile CSS block) - mode + enforcement joined into one
      // line instead of two separate badges neither of which fits.
      var postureBadge = document.getElementById("posture-badge");
      var modeEditBtn = document.getElementById("mode-edit-btn");
      var modeForm = document.getElementById("mode-form");
      var modeSelect = document.getElementById("mode-select");
      var modeCodeInput = document.getElementById("mode-code");
      var modeSaveBtn = document.getElementById("mode-save-btn");
      var modeCancelBtn = document.getElementById("mode-cancel-btn");
      var modeSuccessEl = document.getElementById("mode-success");
      var modeErrorEl = document.getElementById("mode-error");
      var modeHintEl = document.getElementById("mode-hint");
      var modeEditing = false;
      var modesOrder = [];
      var currentModeName = null;
      // True from a blocked Escape/outside-click dismiss (see
      // attemptCloseModeForm) until Save, Cancel, or a new select change -
      // guards MODE_FORM_BLOCKED_DISMISS_HINT below from being silently
      // overwritten by the next background stats poll's refreshModeHint().
      var modeDismissBlocked = false;
      var feedEl = document.getElementById("feed");
      var feedTruncatedEl = document.getElementById("feed-truncated");
      var feedRowsEverTruncated = false;
      var feedRowsDroppedCount = 0;
      var feedRowCounter = 0;
      var activeFeedEntry = null;
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
          ok = false;
          text = "not authorized - reopen the link printed by doberman dash " +
            "(the token lives only in the tab that opened it)";
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

      function makeStatGroup(id, labelText) {
        var group = document.createElement("div");
        group.className = "stat-group";
        group.id = id;
        var label = document.createElement("span");
        label.className = "stat-label";
        label.textContent = labelText;
        group.appendChild(label);
        return group;
      }

      function renderStats(s) {
        // Every piece is built via textContent, never innerHTML - mirrors
        // the feed/pending-card discipline below. Three labeled groups
        // (round 5) instead of one run-on line of spans: decisions (total +
        // taint events), verdicts (the three badges + a recent window when
        // it says something new), top reasons. `asOf` is appended directly
        // to statsEl, outside any group, so the mobile fold below can hide
        // the decisions/top-reasons groups while still keeping it visible.
        statsEl.textContent = "";

        var decisionsGroup = makeStatGroup("stats-decisions", "decisions");
        var totalCount = document.createElement("span");
        totalCount.className = "count";
        totalCount.textContent = String(s.total_decisions);
        decisionsGroup.appendChild(totalCount);
        var taint = document.createElement("span");
        taint.className = "detail";
        taint.textContent = (s.secret_taint_events || 0) + " secret/taint events";
        decisionsGroup.appendChild(taint);
        statsEl.appendChild(decisionsGroup);

        var verdictsGroup = makeStatGroup("stats-verdicts", "verdicts");
        ["PASS", "AUTH", "BLOCK"].forEach(function (verdict) {
          var n = (s.verdict_counts && s.verdict_counts[verdict]) || 0;
          var b = document.createElement("span");
          b.className = VERDICT_BADGE_CLASS[verdict];
          b.textContent = verdict + ": " + n;
          verdictsGroup.appendChild(b);
        });
        var totalDecisions = s.total_decisions != null ? s.total_decisions : s.total;
        // The recent line only earns its place when it says something the
        // all-time badges above it don't (a window smaller than the log).
        if (s.recent_verdict_counts && (totalDecisions == null || totalDecisions > s.recent_window)) {
          var recent = document.createElement("span");
          recent.className = "detail";
          var recentParts = ["PASS", "AUTH", "BLOCK"].map(function (verdict) {
            return verdict + " " + (s.recent_verdict_counts[verdict] || 0);
          });
          recent.textContent = "recent " + s.recent_window + ": " + recentParts.join(" / ");
          verdictsGroup.appendChild(recent);
        }
        statsEl.appendChild(verdictsGroup);

        // Top reason codes - build_stats already computes this, this was the
        // only piece that never reached the page.
        if (s.top_reason_codes && s.top_reason_codes.length) {
          var reasonsGroup = makeStatGroup("stats-reasons", "top reasons");
          var reasonsList = document.createElement("span");
          reasonsList.className = "detail";
          reasonsList.textContent = s.top_reason_codes.map(function (pair) {
            return pair[0] + " (" + pair[1] + ")";
          }).join(", ");
          reasonsGroup.appendChild(reasonsList);
          statsEl.appendChild(reasonsGroup);
        }

        modeBadge.textContent = "mode: " + s.mode;
        var enforcementWord = ENFORCEMENT_WORD[s.enforcement] || s.enforcement;
        enforcementBadge.textContent = "enforcement: " + enforcementWord;
        enforcementBadge.title = ENFORCEMENT_TITLE[s.enforcement] || "";
        enforcementBadge.className = ENFORCEMENT_BADGE_CLASS[s.enforcement] || "badge badge-neutral";
        postureBadge.textContent = "posture: " + s.mode + " · " + enforcementWord;
        currentModeName = s.mode;
        // Keep the (closed) mode selector's value in sync with reality - but
        // never while the user has the form open with an in-progress choice,
        // or a poll landing mid-edit would silently discard what they picked.
        if (!modeEditing && modeSelect.options.length) {
          modeSelect.value = s.mode;
        }
        // Text-only refresh - a background stats poll landing mid-edit must
        // never reset an in-progress downgrade arm (updateModeHint's job),
        // only keep the hint's own wording current.
        if (modeEditing) { refreshModeHint(); }

        // A visible freshness signal: when THIS browser last successfully
        // refreshed, not a server timestamp - stats.py computes no such field.
        var asOf = document.createElement("span");
        asOf.className = "detail";
        var now = new Date();
        // "(local)" - this is the viewer's own wall clock, not the server's
        // and not UTC; never let it read as an unlabeled clock of unknown zone.
        asOf.textContent = "updated " +
          pad2(now.getHours()) + ":" + pad2(now.getMinutes()) + ":" + pad2(now.getSeconds()) + " (local)";
        statsEl.appendChild(asOf);
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
          modesOrder = m.modes || [];
          modesOrder.forEach(function (name) {
            var opt = document.createElement("option");
            opt.value = name;
            opt.textContent = MODE_LABELS[name] || name;
            modeSelect.appendChild(opt);
          });
          modeSelect.value = m.mode;
          currentModeName = m.mode;
        })
        .catch(function () {
          // No modes loaded -> leave the selector empty and the edit button
          // inert rather than let the user submit a change we can't populate.
          modeEditBtn.disabled = true;
        });

      // Raise (a stricter mode = a later position in modesOrder) is always
      // frictionless; lower needs a possession-factor code - purely a
      // function of array position, so a future mode added to SecurityMode
      // needs no change here.
      function computeModeDirection() {
        var chosenIdx = modesOrder.indexOf(modeSelect.value);
        var curIdx = modesOrder.indexOf(currentModeName);
        if (chosenIdx === -1 || curIdx === -1 || chosenIdx === curIdx) { return "none"; }
        return chosenIdx > curIdx ? "raise" : "lower";
      }

      // A downgrade is gated at least as hard as an Approve: Save restyles to
      // the BLOCK color and needs the same arm-then-confirm gesture (5s
      // window, visible countdown) before it actually submits. Raising stays
      // a single click. Server-side semantics are unchanged either way - this
      // is purely a client-side speed bump on top of the same POST.
      var modeArmed = false;
      var modeArmTimer = null;

      function cancelModeArm() {
        clearInterval(modeArmTimer);
        modeArmTimer = null;
        modeArmed = false;
      }

      function syncModeSaveButton() {
        cancelModeArm();
        var direction = computeModeDirection();
        modeSaveBtn.classList.toggle("danger", direction === "lower");
        modeSaveBtn.textContent = direction === "lower" ? ("Lower to " + modeSelect.value) : "Save";
      }

      // True whenever the popover has something a Cancel would actually
      // discard: a different mode picked (either direction), or a downgrade
      // mid-arm. Escape and an outside click both consult this - see
      // attemptCloseModeForm below.
      function pendingModeChange() {
        return modeArmed || computeModeDirection() !== "none";
      }

      function modeHintText() {
        var direction = computeModeDirection();
        var text = "";
        if (direction === "raise") {
          text = "Raise: applies immediately.";
        } else if (direction === "lower") {
          var consequence = MODE_DOWNGRADE_CONSEQUENCE[modeSelect.value];
          text = "Lower: needs your 2FA code or password. " +
            (consequence || "This weakens the guard's step-up thresholds.") +
            " - hard blocks (secrets, destructive commands, protected paths) " +
            "stay in force regardless of mode.";
        }
        if (pendingModeChange()) {
          text += (text ? " " : "") + "Unsaved change - Save or Cancel.";
        }
        return text;
      }

      // Only refreshes the hint's TEXT/color - never touches the arm timer,
      // so a blocked Escape/outside-click dismiss (see attemptCloseModeForm)
      // can surface the "Unsaved change" line without silently disarming an
      // in-progress downgrade confirmation. Round 7: while that blocked
      // dismiss's OWN wording is showing (modeDismissBlocked), this is a
      // no-op - a background stats poll landing mid-block (renderStats calls
      // this every 5s while modeEditing) must not silently overwrite
      // MODE_FORM_BLOCKED_DISMISS_HINT with the routine raise/lower text.
      function refreshModeHint() {
        if (modeDismissBlocked) { return; }
        modeHintEl.textContent = modeHintText();
        modeHintEl.classList.toggle("lowering", computeModeDirection() === "lower");
      }

      function updateModeHint() {
        // A different selection both invalidates any in-progress downgrade
        // arm AND clears a blocked-dismiss hint - the user just acted on the
        // form, so the stale warning no longer applies.
        modeDismissBlocked = false;
        syncModeSaveButton();
        refreshModeHint();
      }
      modeSelect.addEventListener("change", updateModeHint);

      // >=640px: anchor the popover under #mode-edit-btn, right-aligned to it.
      // <=640px: the CSS media query below switches it back to a full-width
      // band, so no inline position is needed there.
      function positionModeForm() {
        if (window.matchMedia && window.matchMedia("(max-width: 640px)").matches) {
          modeForm.style.top = "";
          modeForm.style.right = "";
          return;
        }
        // The trigger may have been scrolled out of view (a long feed): bring
        // it back first, then anchor - and never place the popover above the
        // viewport's top edge whatever the rect says.
        if (modeEditBtn.scrollIntoView) { modeEditBtn.scrollIntoView({ block: "nearest" }); }
        var rect = modeEditBtn.getBoundingClientRect();
        modeForm.style.top = Math.max(8, rect.bottom + 8) + "px";
        modeForm.style.right = Math.max(8, window.innerWidth - rect.right) + "px";
      }
      // Keep the popover anchored while it is open (resize, scroll).
      window.addEventListener("resize", function () { if (!modeForm.hidden) { positionModeForm(); } });
      window.addEventListener("scroll", function () { if (!modeForm.hidden) { positionModeForm(); } }, { passive: true });

      var mainEl = document.querySelector("main");
      // NOT the whole <header> - #mode-edit-btn (the popover's own trigger,
      // needed to close it by clicking it again) lives inside the header's
      // "posture" group alongside the mode/enforcement badges, so only the
      // OTHER two header groups (brand+status+guard, theme+shortcuts) go
      // inert; that group stays fully interactive throughout.
      var topbarRow1El = document.querySelector(".topbar-row1");
      var topbarUtilityGroupEl = document.getElementById("topbar-utility-group");
      var modeScrim = document.getElementById("mode-scrim");
      // Distinct from modeHintText()'s passive "Unsaved change - Save or
      // Cancel." (still shown while merely editing) - a BLOCKED dismiss
      // attempt needs its OWN wording, or setting the identical string again
      // is a silent no-op to aria-live (screen readers only announce a
      // CHANGE in textContent, and Escape-while-pending would otherwise just
      // re-assert text that was already there).
      var MODE_FORM_BLOCKED_DISMISS_HINT =
        "Unsaved change - use Cancel to discard or Save to apply";
      var modeNudgeTimer = null;
      function nudgeModeForm() {
        modeForm.classList.remove("nudge");
        void modeForm.offsetWidth; // restart the animation on a repeated blocked dismiss
        modeForm.classList.add("nudge");
        clearTimeout(modeNudgeTimer);
        modeNudgeTimer = setTimeout(function () { modeForm.classList.remove("nudge"); }, 300);
      }

      function openModeForm() {
        modeEditing = true;
        modeErrorEl.textContent = "";
        modeSuccessEl.textContent = "";
        modeCodeInput.value = "";
        modeForm.hidden = false;
        modeScrim.hidden = false;
        // While the popover is open the rest of the page is genuinely
        // unreachable (not just visually dimmed) - Tab, a stray click, and a
        // screen reader's virtual cursor all stay contained to the popover.
        mainEl.inert = true;
        topbarRow1El.inert = true;
        topbarUtilityGroupEl.inert = true;
        modeEditBtn.setAttribute("aria-expanded", "true");
        positionModeForm();
        updateModeHint();
        // Focus follows the disclosure: the next Tab must not land on the
        // theme/shortcuts buttons that sit between the trigger and the form.
        setTimeout(function () { modeSelect.focus(); }, 0);
      }

      function closeModeForm() {
        var wasOpen = !modeForm.hidden;
        modeEditing = false;
        modeForm.hidden = true;
        modeScrim.hidden = true;
        mainEl.inert = false;
        topbarRow1El.inert = false;
        topbarUtilityGroupEl.inert = false;
        modeCodeInput.value = "";
        modeErrorEl.textContent = "";
        modeSuccessEl.textContent = "";
        modeHintEl.textContent = "";
        modeHintEl.classList.remove("lowering");
        modeDismissBlocked = false;
        cancelModeArm();
        // Cancel (or any other path here) genuinely DISCARDS an unsaved pick -
        // reopening the popover before the next stats poll must not still
        // show the abandoned selection.
        if (currentModeName && modeSelect.options.length) {
          modeSelect.value = currentModeName;
        }
        modeEditBtn.setAttribute("aria-expanded", "false");
        if (wasOpen) { modeEditBtn.focus(); }
      }

      // One dismiss semantics for the popover: Escape (see the shared keydown
      // handler below) and an outside click both call this, and both get the
      // same answer - if nothing is unsaved, close for real; otherwise stay
      // open and surface the "Unsaved change" hint instead of silently
      // discarding a pending mode change - now with a visible nudge (a
      // blocked dismiss otherwise looked like nothing happened at all).
      function attemptCloseModeForm() {
        if (pendingModeChange()) {
          modeDismissBlocked = true;
          modeHintEl.textContent = MODE_FORM_BLOCKED_DISMISS_HINT;
          modeHintEl.classList.toggle("lowering", computeModeDirection() === "lower");
          nudgeModeForm();
          return false;
        }
        closeModeForm();
        return true;
      }

      modeEditBtn.addEventListener("click", function () {
        if (modeForm.hidden) { openModeForm(); } else { closeModeForm(); }
      });
      modeCancelBtn.addEventListener("click", closeModeForm);

      // Light dismiss: a click outside the open popover attempts to close it,
      // same as Escape (attemptCloseModeForm handles the "pending change"
      // case identically either way). A BLOCKED attempt refocuses the
      // popover's first control instead of leaving focus wherever the click
      // landed (main/header are `inert` while open, so a click there would
      // otherwise drop focus to <body> with nothing announced).
      document.addEventListener("click", function (e) {
        if (modeForm.hidden) { return; }
        if (modeForm.contains(e.target) || e.target === modeEditBtn) { return; }
        var closed = attemptCloseModeForm();
        if (!closed) { modeSelect.focus(); }
      });

      // Focus containment: Tab/Shift+Tab cycles within the popover's own
      // controls while it is open, rather than escaping to the rest of the
      // page (a light-dismiss popover is still a dialog while focus is in it).
      modeForm.addEventListener("keydown", function (e) {
        if (e.key !== "Tab") { return; }
        var focusable = Array.prototype.slice
          .call(modeForm.querySelectorAll("select, input, button"))
          .filter(function (el) { return !el.disabled; });
        if (!focusable.length) { return; }
        var first = focusable[0];
        var last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      });

      function submitModeChange() {
        var chosen = modeSelect.value;
        if (!chosen) { return; }
        // The user just acted (Save) - a stale blocked-dismiss hint from an
        // earlier Escape/outside-click no longer applies either way, success
        // or failure both render their own message below.
        modeDismissBlocked = false;
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
            setTimeout(closeModeForm, 2500);
          } else {
            // textContent only - never render a server error string as markup.
            modeErrorEl.textContent = (result.data && result.data.error) || "mode change failed";
            modeCodeInput.value = "";
          }
        }).catch(function () {
          modeSaveBtn.disabled = false;
          modeErrorEl.textContent = "network error - try again";
        });
      }

      modeSaveBtn.addEventListener("click", function () {
        if (computeModeDirection() === "lower" && !modeArmed) {
          // First press only arms: a countdown identical in shape to
          // Approve's, so lowering strictness never happens on one click.
          modeArmed = true;
          var remaining = 5;
          modeSaveBtn.textContent = "Confirm lower (" + remaining + ")";
          modeArmTimer = setInterval(function () {
            remaining -= 1;
            if (remaining <= 0) {
              syncModeSaveButton();
              return;
            }
            modeSaveBtn.textContent = "Confirm lower (" + remaining + ")";
          }, 1000);
          return;
        }
        cancelModeArm();
        submitModeChange();
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

      // Truthful about what happens at 0: the challenge MOVES to the
      // terminal/GUI channel (DashboardPrompter raises PrompterUnavailableError
      // at the timeout, it does not deny) - never say "auto-denies" here.
      function formatCountdown(msRemaining) {
        var totalSeconds = Math.max(0, Math.round(msRemaining / 1000));
        var m = Math.floor(totalSeconds / 60);
        var s = totalSeconds % 60;
        return "answerable here for " + m + ":" + (s < 10 ? "0" : "") + s +
          ", then it moves to your terminal";
      }

      function tickCountdowns() {
        var now = Date.now();
        pendingList.querySelectorAll(".countdown[data-deadline]").forEach(function (node) {
          var remaining = Number(node.dataset.deadline) - now;
          if (remaining > 0) {
            node.textContent = formatCountdown(remaining);
            return;
          }
          // Past the dashboard's authority horizon the challenge has fallen
          // through to the terminal/GUI channel: say so and stop offering
          // buttons that would only 409. The next poll removes the card.
          node.textContent = "moved to your terminal - answer it there";
          // Announce the crossing exactly once per card (this tick re-runs
          // every second for as long as the card is still on screen) - a
          // per-node flag, not the shared announce() dedupe alone, since two
          // different cards crossing moments apart would otherwise share
          // the identical message and the second would be silently dropped.
          if (!node.dataset.horizonAnnounced) {
            node.dataset.horizonAnnounced = "1";
            announce("Approval moved to your terminal.");
          }
          var expiredCard = node.closest("li");
          if (expiredCard) {
            expiredCard.querySelectorAll("button.approve, button.deny").forEach(function (b) {
              b.disabled = true;
            });
          }
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
            // Say what happened before the card goes: a screen-reader user
            // otherwise only hears the next poll's "Nothing pending".
            var done = document.createElement("div");
            done.className = "row-done";
            done.textContent = decision === "approved"
              ? "Approved - released to the agent."
              : "Denied - the action was blocked.";
            card.appendChild(done);
            announce(done.textContent);
            setTimeout(function () { card.remove(); lastPendingKey = null; }, 1500);
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

      // Shared by the feed's detail line and the pending card's reason line:
      // each code is its own span (not one joined string) so it can carry a
      // title="..." gloss from REASON_DESCRIPTIONS - the same dict
      // doberman.explain.template_explanation uses server-side. A code
      // missing from the dict just skips the title. No per-code toggle
      // button any more (round 5 - see buildGlossList below for how
      // keyboard/touch users reach the same text, since title="..." only
      // ever shows on :hover).
      function appendReasonCodeSpans(container, codes, separator) {
        codes.forEach(function (code, i) {
          if (i > 0) { container.appendChild(document.createTextNode(separator)); }
          var codeSpan = document.createElement("span");
          codeSpan.className = "reason-code";
          codeSpan.textContent = code;
          var gloss = REASON_DESCRIPTIONS[code];
          if (gloss) { codeSpan.title = gloss; }
          container.appendChild(codeSpan);
        });
      }

      // The keyboard/touch path to the same text a title="..." only ever
      // shows on hover: one muted <ul>, "code - gloss" per line. A feed row
      // with an explanation already expands by click/tap/Enter/Space (see
      // toggleActiveFeedExplanation) - expanding it reveals this list, so
      // that's the row's "one gloss toggle at most", not a separate button.
      // Pending cards are never collapsed, so they just render it always.
      // Returns null when no code in `codes` has a gloss (nothing to show).
      function buildGlossList(codes) {
        var withGloss = (codes || []).filter(function (code) {
          return Boolean(REASON_DESCRIPTIONS[code]);
        });
        if (!withGloss.length) { return null; }
        var list = document.createElement("ul");
        list.className = "gloss-list";
        withGloss.forEach(function (code) {
          var item = document.createElement("li");
          item.textContent = code + " - " + REASON_DESCRIPTIONS[code];
          list.appendChild(item);
        });
        return list;
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
          // textContent only - every field is row-derived and must render
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
            countdown.textContent = "moves to your terminal if unanswered here";
          }
          header.appendChild(countdown);
          li.appendChild(header);

          // Sentence first (primary), codes second (secondary, muted mono,
          // glossed) - same hierarchy as the feed's now-primary explanation.
          var explanation = document.createElement("div");
          explanation.className = "row-explanation";
          explanation.textContent = row.explanation || "";
          li.appendChild(explanation);

          var reasons = document.createElement("div");
          reasons.className = "reason-line";
          if (row.reason_codes && row.reason_codes.length) {
            appendReasonCodeSpans(reasons, row.reason_codes, ", ");
          } else {
            reasons.appendChild(document.createTextNode("no reason codes recorded"));
          }
          li.appendChild(reasons);

          // Pending cards are never collapsed, so the gloss list (see
          // buildGlossList) just renders always-visible here - there's
          // nothing to expand into.
          var pendingGlossList = buildGlossList(row.reason_codes);
          if (pendingGlossList) { li.appendChild(pendingGlossList); }

          // The card says what it deliberately does NOT show: only a
          // redacted class/summary ever reaches this screen, never the raw
          // command.
          var privacyNote = document.createElement("div");
          privacyNote.className = "privacy-note";
          privacyNote.textContent =
            "Doberman never shows the raw command here - see doberman log for the redacted record.";
          li.appendChild(privacyNote);

          var totpInput = null;
          if (row.needs_totp) {
            var totpId = "totp-" + row.id;
            // A real VISIBLE label, not sr-only - a live second factor is
            // worth a moment's care, and title-casing "6-digit code" as
            // ordinary text costs nothing a screen reader user loses either.
            var totpLabel = document.createElement("label");
            totpLabel.className = "totp-label";
            totpLabel.setAttribute("for", totpId);
            totpLabel.textContent = "6-digit code";
            li.appendChild(totpLabel);

            totpInput = document.createElement("input");
            totpInput.id = totpId;
            // A masked field: this is a live second factor, and the dashboard is
            // exactly the screen that gets screen-shared and recorded.
            totpInput.type = "password";
            totpInput.inputMode = "numeric";
            totpInput.placeholder = "000000";
            totpInput.autocomplete = "off";
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
            var remaining = 5;
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
          // Deny now gets the exact same arm-then-confirm gesture as Approve
          // (round 5) - a single click no longer denies outright.
          var denyArmTimer = null;
          denyBtn.addEventListener("click", function () {
            if (denyBtn.dataset.armed === "1") {
              clearInterval(denyArmTimer);
              denyBtn.dataset.armed = "";
              denyBtn.textContent = "Deny";
              resolveApproval(row.id, "denied", totpInput ? totpInput.value : null, li,
                [approveBtn, denyBtn]);
              return;
            }
            denyBtn.dataset.armed = "1";
            var remaining = 5;
            denyBtn.textContent = "Confirm deny (" + remaining + ")";
            denyArmTimer = setInterval(function () {
              remaining -= 1;
              if (remaining <= 0) {
                clearInterval(denyArmTimer);
                denyBtn.dataset.armed = "";
                denyBtn.textContent = "Deny";
                return;
              }
              denyBtn.textContent = "Confirm deny (" + remaining + ")";
            }, 1000);
          });
          li.appendChild(denyBtn);

          var errorEl = document.createElement("div");
          errorEl.className = "row-error";
          errorEl.setAttribute("role", "alert");

          var copyBtn = document.createElement("button");
          copyBtn.type = "button";
          copyBtn.className = "btn btn-copy";
          var copyBtnDefaultText = "Copy details";
          copyBtn.textContent = copyBtnDefaultText;
          var copyResetTimer = null;
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
              clearTimeout(copyResetTimer);
              copyBtn.textContent = "Copied";
              announce("Copied approval details to the clipboard.");
              copyResetTimer = setTimeout(function () {
                copyBtn.textContent = copyBtnDefaultText;
              }, 1200);
            } catch (e) {
              // Clipboard unavailable (permissions, insecure context, an
              // iframe, ...) - the card stays usable, but say so instead of
              // failing silently.
              errorEl.textContent = "Couldn't copy - select the text instead";
            }
          });
          li.appendChild(copyBtn);
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
      // Two tabs open on the same dashboard: a background tab's poll timer
      // still runs, but a human switching back to it shouldn't wait up to
      // PENDING_POLL_MS to see what the OTHER tab already resolved - catch
      // up immediately the moment this tab becomes visible again.
      document.addEventListener("visibilitychange", function () {
        if (document.visibilityState === "visible") { refreshPending(); }
      });

      // Manual refresh for the stats + pending views; both functions are safe
      // to call at any time and no new endpoint is involved.
      var refreshBtn = document.getElementById("refresh-btn");
      function manualRefresh() {
        refreshBtn.disabled = true;
        refreshBtn.textContent = "Refreshing...";
        refreshStats();
        refreshPending();
        setTimeout(function () {
          refreshBtn.disabled = false;
          refreshBtn.textContent = "Refresh";
        }, 600);
      }
      refreshBtn.addEventListener("click", manualRefresh);

      // Find a BLOCK: verdict chips (desktop) / a <select> (<=640px, see
      // #feed-verdict-select) + a text filter over what's already on screen
      // (no new endpoint - the feed is already fully client-side). Default
      // view is "Needs attention" (BLOCK + AUTH, round 7) - a fresh
      // dashboard leads with what needs a human, not a wall of PASS noise;
      // "All" and "PASS" stay one explicit choice away. Persisted per
      // browser so a reload doesn't silently reset back to noise either.
      var DEFAULT_VERDICT_FILTER = "needs_attention";
      var VERDICT_FILTER_KEY = "doberman-dash-feed-verdict-filter";
      var VALID_VERDICT_FILTERS = ["", "needs_attention", "BLOCK", "AUTH", "PASS"];
      function readStoredVerdictFilter() {
        try {
          var stored = window.localStorage.getItem(VERDICT_FILTER_KEY);
          return VALID_VERDICT_FILTERS.indexOf(stored) !== -1 ? stored : null;
        } catch (e) {
          return null;
        }
      }
      function writeStoredVerdictFilter(value) {
        try { window.localStorage.setItem(VERDICT_FILTER_KEY, value); } catch (e) { /* privacy mode: won't persist */ }
      }

      var feedEntries = [];
      var activeVerdict = readStoredVerdictFilter();
      if (activeVerdict === null) { activeVerdict = DEFAULT_VERDICT_FILTER; }
      var activeQuery = "";

      function matchesFilter(entry) {
        if (activeVerdict === "needs_attention") {
          if (entry.verdict !== "BLOCK" && entry.verdict !== "AUTH") { return false; }
        } else if (activeVerdict && entry.verdict !== activeVerdict) {
          return false;
        }
        if (activeQuery && entry.searchText.indexOf(activeQuery) === -1) { return false; }
        return true;
      }

      var feedCountEl = document.getElementById("feed-count");
      var feedEmptyEl = document.getElementById("feed-empty");
      var feedNoMatchEl = document.getElementById("feed-nomatch");
      var feedNoMatchTextEl = document.getElementById("feed-nomatch-text");
      var feedClearFiltersBtn = document.getElementById("feed-clear-filters-btn");
      var filterChips = document.querySelectorAll(".filter-chip");
      var feedVerdictSelect = document.getElementById("feed-verdict-select");
      var feedFilterInput = document.getElementById("feed-filter");

      // The one string used whenever the DEFAULT filter is what's hiding
      // everything - whether the feed is genuinely empty so far, or it has
      // rows that are all PASS (filtered out by "Needs attention" itself).
      var ATTENTION_EMPTY_TEXT =
        "No blocks or approvals yet - Doberman's watching quietly (show All to see passes)";

      function isDefaultFilterActive() {
        return activeVerdict === DEFAULT_VERDICT_FILTER && !activeQuery;
      }

      function applyFeedFilter() {
        var shown = 0;
        feedEntries.forEach(function (entry) {
          var match = matchesFilter(entry);
          entry.li.hidden = !match;
          if (match) { shown += 1; }
        });
        var filtering = Boolean(activeVerdict || activeQuery);
        feedCountEl.textContent = filtering && feedEntries.length
          ? shown + " of " + feedEntries.length + " shown"
          : "";
        var defaultActive = isDefaultFilterActive();
        // #feed-empty is CSS-shown only when the feed has never received a
        // single row (see `#feed:not(:empty) ~ #feed-empty`) - on the
        // default filter that state gets the attention-aware copy too, so a
        // brand-new dashboard never reads as a burned-out one.
        feedEmptyEl.textContent = defaultActive
          ? ATTENTION_EMPTY_TEXT
          : "No decisions yet. Doberman's watching quietly.";
        var noMatch = filtering && feedEntries.length > 0 && shown === 0;
        feedNoMatchEl.hidden = !noMatch;
        if (noMatch) {
          feedNoMatchTextEl.textContent = defaultActive ? ATTENTION_EMPTY_TEXT : "No decisions match this filter.";
          feedClearFiltersBtn.textContent = defaultActive ? "Show all" : "Clear filters";
        }
        // The roving-focus row must never point at a row the filter just hid.
        if (activeFeedEntry && activeFeedEntry.li.hidden) { setActiveFeedEntry(null); }
      }

      // Single source of truth for BOTH verdict controls (the desktop chip
      // group and the <=640px <select>, see #feed-verdict-select) - whichever
      // one the viewport is showing, the other stays in sync so a resize
      // never leaves a stale pressed/selected state on the hidden one.
      function setVerdictFilter(verdict) {
        activeVerdict = verdict;
        filterChips.forEach(function (c) {
          c.setAttribute("aria-pressed", (c.dataset.verdict || "") === verdict ? "true" : "false");
        });
        feedVerdictSelect.value = verdict;
        writeStoredVerdictFilter(verdict);
        applyFeedFilter();
      }

      // Lands back on the app's DEFAULT view (Needs attention), not raw
      // "All" - clearing filters should return to something sane, not noise.
      function resetFeedFilters() {
        activeQuery = "";
        feedFilterInput.value = "";
        setVerdictFilter(DEFAULT_VERDICT_FILTER);
      }

      filterChips.forEach(function (chip) {
        chip.addEventListener("click", function () {
          setVerdictFilter(chip.dataset.verdict || "");
        });
      });
      feedVerdictSelect.addEventListener("change", function () {
        setVerdictFilter(feedVerdictSelect.value);
      });

      feedFilterInput.addEventListener("input", function () {
        activeQuery = feedFilterInput.value.trim().toLowerCase();
        applyFeedFilter();
      });

      feedClearFiltersBtn.addEventListener("click", function () {
        // The default filter itself is what's showing nothing - "Show all"
        // (verdict-only, matching the copy's own promise) rather than the
        // generic reset, which would just reselect the same empty filter.
        if (isDefaultFilterActive()) {
          setVerdictFilter("");
        } else {
          resetFeedFilters();
        }
        // Clearing the filter is meaningless if focus stays on a button
        // that's about to disappear (the no-match empty state hides right
        // here) - hand it back to the feed itself. Deferred a tick (same
        // pattern as openModeForm's modeSelect.focus()): this button's own
        // container just went `hidden`, and a real click's native blur-to-
        // body for a newly-unfocusable element can otherwise land AFTER this
        // handler returns, overriding a same-tick .focus() call here.
        setTimeout(function () { feedEl.focus(); }, 0);
      });

      // Reflect whichever filter (persisted, or the default) was chosen
      // before either control's own listener ever fires - also paints the
      // initial #feed-empty copy correctly before the first row ever
      // arrives.
      setVerdictFilter(activeVerdict);

      // Mobile-only "Filters" disclosure (round 7) - the text filter + the
      // announce toggle collapse behind it at <=640px (see #feed-filters-panel
      // above); at every other width the CSS unwraps the panel back into
      // plain flex children regardless of this, so `hidden` here only ever
      // has a visible effect on the width it's meant to.
      var feedFiltersToggleBtn = document.getElementById("feed-filters-toggle-btn");
      var feedFiltersPanel = document.getElementById("feed-filters-panel");
      function setFeedFiltersOpen(open) {
        feedFiltersPanel.hidden = !open;
        feedFiltersToggleBtn.setAttribute("aria-expanded", open ? "true" : "false");
      }
      feedFiltersToggleBtn.addEventListener("click", function () {
        setFeedFiltersOpen(feedFiltersPanel.hidden);
      });

      // #feed is `role="log" aria-live="off"` (round 6 - `role="log"` alone
      // implies a live region, so every arriving row was ALREADY being
      // announced individually, one at a time, with no way to turn it off).
      // This toggle (WCAG 2.1.4-style persistence, same pattern as the
      // shortcuts on/off toggle) gates a single DEBOUNCED summary instead:
      // arrivals within a rolling 2s window collapse into one announcement
      // ("3 new decisions: 2 BLOCK, 1 PASS").
      var ANNOUNCE_FEED_KEY = "doberman-dash-announce-feed";
      function announceFeedEnabled() {
        try {
          return window.localStorage.getItem(ANNOUNCE_FEED_KEY) !== "off";
        } catch (e) {
          return true;
        }
      }
      function writeAnnounceFeedEnabled(on) {
        try { window.localStorage.setItem(ANNOUNCE_FEED_KEY, on ? "on" : "off"); } catch (e) {}
      }
      var feedAnnounceToggleBtn = document.getElementById("feed-announce-toggle-btn");
      function renderFeedAnnounceToggle() {
        var on = announceFeedEnabled();
        feedAnnounceToggleBtn.textContent = "Announce new rows: " + (on ? "on" : "off");
        feedAnnounceToggleBtn.setAttribute("aria-pressed", on ? "true" : "false");
      }
      renderFeedAnnounceToggle();
      feedAnnounceToggleBtn.addEventListener("click", function () {
        writeAnnounceFeedEnabled(!announceFeedEnabled());
        renderFeedAnnounceToggle();
      });

      var FEED_ANNOUNCE_DEBOUNCE_MS = 2000;
      var VERDICT_ANNOUNCE_ORDER = ["BLOCK", "AUTH", "PASS"];
      var feedArrivalCounts = {};
      var feedArrivalTotal = 0;
      var feedAnnounceTimer = null;
      function queueFeedArrivalAnnouncement(verdict) {
        if (!announceFeedEnabled()) { return; }
        feedArrivalTotal += 1;
        feedArrivalCounts[verdict] = (feedArrivalCounts[verdict] || 0) + 1;
        if (feedAnnounceTimer) { return; }
        feedAnnounceTimer = setTimeout(function () {
          var counts = feedArrivalCounts;
          var total = feedArrivalTotal;
          feedArrivalCounts = {};
          feedArrivalTotal = 0;
          feedAnnounceTimer = null;
          var known = VERDICT_ANNOUNCE_ORDER.filter(function (v) { return counts[v]; });
          var rest = Object.keys(counts).filter(function (v) {
            return VERDICT_ANNOUNCE_ORDER.indexOf(v) === -1;
          });
          var parts = known.concat(rest).map(function (v) { return counts[v] + " " + v; });
          announce(
            total + " new decision" + (total === 1 ? "" : "s") + ": " + parts.join(", ")
          );
        }, FEED_ANNOUNCE_DEBOUNCE_MS);
      }

      // --- Feed roving focus (Up/Down/Home/End move REAL DOM focus, not just
      // a CSS class + aria-activedescendant - a screen reader hears each row
      // as focus actually lands on it). Enter/Space expands the active row's
      // explanation - see the shortcuts panel for the full key list. ---

      function visibleFeedEntries() {
        return feedEntries.filter(function (entry) { return !entry.li.hidden; });
      }

      function setActiveFeedEntry(entry) {
        if (activeFeedEntry) { activeFeedEntry.li.classList.remove("active"); }
        activeFeedEntry = entry || null;
        if (!activeFeedEntry) { return; }
        activeFeedEntry.li.classList.add("active");
        activeFeedEntry.li.scrollIntoView({ block: "nearest" });
        activeFeedEntry.li.focus();
      }

      function moveActiveFeedEntry(delta) {
        var visible = visibleFeedEntries();
        if (!visible.length) { return; }
        var curPos = activeFeedEntry ? visible.indexOf(activeFeedEntry) : -1;
        var nextPos = curPos === -1
          ? (delta > 0 ? 0 : visible.length - 1)
          : Math.min(visible.length - 1, Math.max(0, curPos + delta));
        setActiveFeedEntry(visible[nextPos]);
      }

      function jumpActiveFeedEntry(toEnd) {
        var visible = visibleFeedEntries();
        if (!visible.length) { return; }
        setActiveFeedEntry(toEnd ? visible[visible.length - 1] : visible[0]);
      }

      function toggleActiveFeedExplanation() {
        if (!activeFeedEntry) { return; }
        var li = activeFeedEntry.li;
        var fullEl = li.querySelector(".row-explanation-full");
        var glossListEl = li.querySelector(".gloss-list");
        if (!fullEl && !glossListEl) { return; }
        // The row's own aria-expanded is the single source of truth here
        // (round 7: the headline element itself no longer changes state -
        // see the "decision" SSE handler below, which builds it as a plain,
        // always-visible node) - reveals whichever of the full sentence /
        // gloss list this row actually has.
        var expanded = li.getAttribute("aria-expanded") !== "true";
        if (fullEl) { fullEl.hidden = !expanded; }
        li.setAttribute("aria-expanded", expanded ? "true" : "false");
        if (glossListEl) { glossListEl.hidden = !expanded; }
      }

      feedEl.addEventListener("keydown", function (e) {
        if (e.key === "ArrowDown") { e.preventDefault(); moveActiveFeedEntry(1); }
        else if (e.key === "ArrowUp") { e.preventDefault(); moveActiveFeedEntry(-1); }
        else if (e.key === "Home") { e.preventDefault(); jumpActiveFeedEntry(false); }
        else if (e.key === "End") { e.preventDefault(); jumpActiveFeedEntry(true); }
        else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleActiveFeedExplanation(); }
      });
      // The scroller itself is tabindex="0" (in the tab order); a row is
      // tabindex="-1" (only reachable via roving focus, never via Tab). So
      // when the SCROLLER is what receives focus (a fresh Tab into it, not a
      // row already claiming it), hand focus straight on to the active row
      // (or the first one). `focus` doesn't bubble, so this only fires when
      // feedEl itself is the direct target - never on every row focus.
      feedEl.addEventListener("focus", function (e) {
        if (e.target !== feedEl) { return; }
        var visible = visibleFeedEntries();
        if (!visible.length) { return; }
        var target = activeFeedEntry && visible.indexOf(activeFeedEntry) !== -1
          ? activeFeedEntry
          : visible[0];
        setActiveFeedEntry(target);
      });

      // A small non-modal shortcuts panel (see the keydown handler below for
      // the bindings it documents) - discoverable via the topbar button too,
      // not just the "?" key.
      var shortcutsBtn = document.getElementById("shortcuts-btn");
      var shortcutsPanel = document.getElementById("shortcuts-panel");
      var shortcutsCloseBtn = document.getElementById("shortcuts-close-btn");

      // >=641px: anchor under #shortcuts-btn, same technique as the mode
      // form's positionModeForm. <=640px: the CSS media query pins it back to
      // the fixed viewport corner (the trigger may itself have wrapped).
      function positionShortcutsPanel() {
        if (window.matchMedia && window.matchMedia("(max-width: 640px)").matches) {
          shortcutsPanel.style.top = "";
          shortcutsPanel.style.right = "";
          return;
        }
        if (shortcutsBtn.scrollIntoView) { shortcutsBtn.scrollIntoView({ block: "nearest" }); }
        var rect = shortcutsBtn.getBoundingClientRect();
        shortcutsPanel.style.top = Math.max(8, rect.bottom + 8) + "px";
        shortcutsPanel.style.right = Math.max(8, window.innerWidth - rect.right) + "px";
      }
      window.addEventListener("resize", function () { if (!shortcutsPanel.hidden) { positionShortcutsPanel(); } });
      window.addEventListener("scroll", function () { if (!shortcutsPanel.hidden) { positionShortcutsPanel(); } }, { passive: true });

      function openShortcuts() {
        shortcutsPanel.hidden = false;
        shortcutsBtn.setAttribute("aria-expanded", "true");
        positionShortcutsPanel();
        shortcutsPanel.focus();
      }
      function closeShortcuts() {
        var wasOpen = !shortcutsPanel.hidden;
        shortcutsPanel.hidden = true;
        shortcutsBtn.setAttribute("aria-expanded", "false");
        if (wasOpen) { shortcutsBtn.focus(); }
      }
      shortcutsBtn.addEventListener("click", function () {
        if (shortcutsPanel.hidden) { openShortcuts(); } else { closeShortcuts(); }
      });
      shortcutsCloseBtn.addEventListener("click", closeShortcuts);

      // WCAG 2.1.4 (Character Key Shortcuts): every single-character,
      // no-modifier binding below (/, r, ?, a, d) must be turnable off. This
      // toggle is a real button (always reachable by click/Tab, gate-exempt
      // itself) and persists per browser like the theme toggle. Escape is
      // NOT gated - it's not a bare character key, and it's the only way to
      // close this very panel if shortcuts were just turned off from it.
      var SHORTCUTS_ENABLED_KEY = "doberman-dash-shortcuts-enabled";
      function shortcutsEnabled() {
        try {
          return window.localStorage.getItem(SHORTCUTS_ENABLED_KEY) !== "off";
        } catch (e) {
          return true;
        }
      }
      function writeShortcutsEnabled(on) {
        try { window.localStorage.setItem(SHORTCUTS_ENABLED_KEY, on ? "on" : "off"); } catch (e) {}
      }
      var shortcutsToggleBtn = document.getElementById("shortcuts-toggle-btn");
      var shortcutsPanelTitleEl = document.getElementById("shortcuts-panel-title");
      var shortcutsDlEl = document.getElementById("shortcuts-dl");
      function renderShortcutsToggle() {
        var on = shortcutsEnabled();
        shortcutsToggleBtn.textContent = "Shortcuts: " + (on ? "on" : "off");
        shortcutsToggleBtn.setAttribute("aria-pressed", on ? "true" : "false");
        // "off" alone on the toggle button was easy to miss against a full
        // dl of bindings that mostly still work (only the bare single-
        // character ones are actually gated) - dim the list and say so on
        // the panel's own title too.
        shortcutsPanelTitleEl.textContent = "Shortcuts" + (on ? "" : " (off)");
        shortcutsDlEl.classList.toggle("dimmed", !on);
      }
      renderShortcutsToggle();
      shortcutsToggleBtn.addEventListener("click", function () {
        writeShortcutsEnabled(!shortcutsEnabled());
        renderShortcutsToggle();
      });

      // Keyboard: / focuses the filter, r refreshes, ? toggles the shortcuts
      // panel, a/d act on the first pending card (both arm-then-confirm),
      // Escape closes ONE thing per press - whichever is topmost (the mode
      // popover, then the shortcuts panel, then the filter) - never all of
      // them at once, and always works regardless of the toggle above.
      // Ignored while already typing in a field, except Escape which always
      // works.
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
          if (!modeForm.hidden) { attemptCloseModeForm(); return; }
          if (!shortcutsPanel.hidden) { closeShortcuts(); return; }
          // The filter is not a trap: clear it and hand focus back to the
          // feed's NEWEST row (the one being watched), rather than leaving
          // the user stuck in the input or dropped on the oldest backfilled
          // row.
          if (document.activeElement === feedFilterInput) {
            feedFilterInput.value = "";
            activeQuery = "";
            applyFeedFilter();
            jumpActiveFeedEntry(true);
          }
          return;
        }
        if (!shortcutsEnabled()) { return; }
        var tag = (document.activeElement && document.activeElement.tagName) || "";
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") { return; }
        if (e.key === "/") {
          e.preventDefault();
          feedFilterInput.focus();
        } else if (e.key === "r") {
          manualRefresh();
        } else if (e.key === "?") {
          if (shortcutsPanel.hidden) { openShortcuts(); } else { closeShortcuts(); }
        } else if (e.key === "a" || e.key === "d") {
          var firstCard = pendingList.querySelector("li");
          if (!firstCard) { return; }
          var actionBtn = firstCard.querySelector(e.key === "a" ? "button.approve" : "button.deny");
          if (!actionBtn) { return; }
          // Both only ARM and focus the button: the confirming press must
          // land on the button itself (Enter/Space/click), so a repeated
          // a/d can never approve or deny unseen - the two-step stays two
          // distinct gestures either way.
          if (actionBtn.dataset.armed === "1") { actionBtn.focus(); return; }
          actionBtn.click();
          actionBtn.focus();
        }
      });

      // Relative age for a feed row's timestamp (round 7) - client-computed
      // from the row's own UTC `ts` (an aware ISO 8601 string, always
      // offset-bearing - see doberman/storage/log.py's
      // `datetime.now(timezone.utc).isoformat()`), a time a human can
      // actually place ("3m ago", "2h ago", "yesterday 11:00") rather than a
      // bare HH:MM:SS with no zone. Refreshed on a timer (see
      // refreshFeedTimes) so an open tab doesn't silently go stale
      // ("3m ago" forever).
      function localDateKey(d) {
        return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate());
      }

      function formatRelativeAge(tsIso) {
        var thenMs = Date.parse(tsIso);
        if (isNaN(thenMs)) { return "-"; }
        var nowMs = Date.now();
        var diffS = Math.max(0, Math.round((nowMs - thenMs) / 1000));
        if (diffS < 60) { return "just now"; }
        var diffM = Math.round(diffS / 60);
        if (diffM < 60) { return diffM + "m ago"; }
        var diffH = Math.round(diffM / 60);
        if (diffH < 24) { return diffH + "h ago"; }
        var then = new Date(thenMs);
        var now = new Date(nowMs);
        var hm = pad2(then.getHours()) + ":" + pad2(then.getMinutes());
        var yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
        if (localDateKey(then) === localDateKey(yesterday)) { return "yesterday " + hm; }
        return then.getFullYear() + "-" + pad2(then.getMonth() + 1) + "-" + pad2(then.getDate()) + " " + hm;
      }

      // The absolute time a human can actually place: LOCAL wall-clock time
      // first (what the reader's own clock says this instant was), the raw
      // UTC value second and explicitly labeled - never an unlabeled UTC
      // clock passed off as local, or vice versa.
      function absoluteTimeTitle(tsIso) {
        var ms = Date.parse(tsIso);
        if (isNaN(ms)) { return ""; }
        var d = new Date(ms);
        var local = d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) + " " +
          pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds()) + " local";
        var utc = String(tsIso)
          .replace("T", " ")
          .replace(/([+-]\\d\\d:\\d\\d|Z)$/, "")
          .replace(/\\.\\d+$/, "");
        return local + " (" + utc + " UTC)";
      }

      var FEED_TIME_REFRESH_MS = 30000;
      function refreshFeedTimes() {
        Array.prototype.forEach.call(feedEl.querySelectorAll(".row-time[data-ts]"), function (node) {
          node.textContent = formatRelativeAge(node.dataset.ts);
        });
      }
      setInterval(refreshFeedTimes, FEED_TIME_REFRESH_MS);

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
          li.id = "feed-row-" + (++feedRowCounter);
          // Roving-focus target (see setActiveFeedEntry) - reachable by
          // Up/Down/Home/End, never by Tab.
          li.tabIndex = -1;

          var rowMain = document.createElement("div");
          rowMain.className = "row-main";

          var badge = document.createElement("span");
          badge.className = VERDICT_BADGE_CLASS[row.verdict] || "badge badge-neutral";
          badge.textContent = row.verdict;
          rowMain.appendChild(badge);

          // The detail line always names something concrete now (a target
          // class or "no target", reason codes or "no auth"), so a low-risk
          // PASS is no longer bare noise without its own badge - reserve the
          // risk badge for medium+ instead of doubling up on every row.
          if (row.risk && row.risk !== "low") {
            var riskBadge = document.createElement("span");
            riskBadge.className = RISK_BADGE_CLASS[row.risk] || "badge badge-neutral";
            riskBadge.textContent = (row.risk || "-").toUpperCase();
            rowMain.appendChild(riskBadge);
          }

          var detail = document.createElement("span");
          detail.className = "detail";
          // textContent-equivalent for everything but the reason codes below -
          // a row-derived string must render literally, never as markup
          // (mirrors the TUI's markup=False discipline). Compact HH:MM:SS
          // (UTC) - the full ISO timestamp is noise at a glance and stays
          // available in `doberman log` / the TUI.
          detail.appendChild(document.createTextNode(
            row.action_type + " " + (row.target_path_class || "no target") + " "
          ));
          // "unknown" is a real SourceContext value, not an absent one - a row
          // showing "from:unknown" on every single PASS was noise with no
          // signal, so the origin is only rendered when it's actually known.
          if (row.source_context && row.source_context !== "unknown") {
            detail.appendChild(document.createTextNode("from:" + row.source_context + " "));
          }
          if (row.reason_codes && row.reason_codes.length) {
            appendReasonCodeSpans(detail, row.reason_codes, ", ");
          } else {
            detail.appendChild(document.createTextNode("no auth"));
          }
          detail.appendChild(document.createTextNode(" @ "));
          var timeEl = document.createElement("span");
          timeEl.className = "row-time";
          if (row.ts) {
            timeEl.dataset.ts = row.ts;
            timeEl.textContent = formatRelativeAge(row.ts);
            timeEl.title = absoluteTimeTitle(row.ts);
          } else {
            timeEl.textContent = "-";
          }
          detail.appendChild(timeEl);
          rowMain.appendChild(detail);

          // BLOCK/AUTH only (CLAUDE.md #9 - every such row carries a human
          // explanation AND a short reason-first `headline`, see
          // doberman.explain.headline; _feed_row leaves both empty for
          // PASS). Round 6: the COLLAPSED state shows the HEADLINE
          // ("Recursive delete blocked - shell_exec"), not the full
          // sentence - eight consecutive BLOCKs used to all start with the
          // identical "<role> attempted <action>." until each was expanded.
          // This is the row's PRIMARY text (body face, full contrast) and
          // comes FIRST in the DOM - rowMain (verdict/risk badges + the now-
          // secondary, muted-mono action/target/reason-code line) follows.
          // Round 7: expanding no longer REPLACES this text with the full
          // sentence - the headline stays put, and the full sentence is a
          // SEPARATE element appended right under it, hidden until the row
          // is expanded (see toggleActiveFeedExplanation) - a keyboard user
          // landing back on a collapsed row must still see the fragment
          // that told it apart from its neighbors.
          if (row.headline || row.explanation) {
            var explanationEl = document.createElement("div");
            explanationEl.className = "row-explanation";
            explanationEl.textContent = row.headline || row.explanation;
            li.appendChild(explanationEl);

            if (row.explanation && row.explanation !== row.headline) {
              var fullEl = document.createElement("div");
              fullEl.className = "row-explanation-full";
              fullEl.textContent = row.explanation;
              fullEl.hidden = true;
              li.appendChild(fullEl);
            }
          }
          li.appendChild(rowMain);

          // The muted gloss list (see buildGlossList) is the row's expanded
          // state for its reason codes - hidden until the row itself is
          // expanded (a row with an explanation reuses that same toggle; a
          // row with only glossed codes and no explanation gets this as its
          // one gloss "toggle" - the row itself, not a separate button).
          var glossListEl = buildGlossList(row.reason_codes);
          if (glossListEl) {
            glossListEl.hidden = true;
            li.appendChild(glossListEl);
          }

          var expandable = Boolean(row.headline) || Boolean(row.explanation) || Boolean(glossListEl);
          if (expandable) {
            li.classList.add("has-explanation");
            li.setAttribute("aria-expanded", "false");
          }

          // An accessible name independent of the visual layout above -
          // a screen reader hears this the moment roving focus lands here,
          // rather than having to walk the row's child nodes itself. The
          // headline LEADS (round 6) - the same reason-first fragment the
          // collapsed row shows visually, ahead of the verdict/action recap.
          var accessibleReasons = row.reason_codes && row.reason_codes.length
            ? row.reason_codes.join(", ")
            : "no reason codes";
          li.setAttribute(
            "aria-label",
            (row.headline ? row.headline + ". " : "") +
            row.verdict + " " + row.action_type + " " +
            (row.target_path_class || "no target") + " - " +
            (row.explanation || accessibleReasons)
          );

          // Rows are appended oldest-first, so the newest decision is always
          // the last child - keep the scrollable list pinned to that end
          // (unless the user has scrolled up to read older rows) so a
          // freshly loaded dashboard shows the latest activity, not the
          // oldest backfilled row.
          var nearBottom = feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight < 4;

          // Search must find the text a human can actually read on the row -
          // the explanation sentence and the glossed reason-code words, not
          // just the raw codes/action type (round 5).
          var reasonGlosses = (row.reason_codes || []).map(function (code) {
            return REASON_DESCRIPTIONS[code] || "";
          }).join(" ");
          var entry = {
            li: li,
            verdict: row.verdict,
            searchText: (
              row.action_type + " " + (row.target_path_class || "") + " " +
              (row.source_context || "") + " " + (row.reason_codes || []).join(" ") + " " +
              reasonGlosses + " " + (row.explanation || "")
            ).toLowerCase()
          };
          feedEntries.push(entry);
          // Round 7: was a bare `li.hidden = !matchesFilter(entry);` - with
          // the default filter now ALWAYS active ("Needs attention" isn't
          // "no filter"), the "N of M shown" count/no-match text needs to
          // stay current as rows stream in, not just when the user touches
          // a filter control. applyFeedFilter() re-derives every row's
          // `hidden` too, so this remains the single source of truth.
          applyFeedFilter();

          // Rows expand by mouse and touch, not only by Enter: clicking/
          // tapping an expandable row makes it the roving-focus active row
          // (so subsequent arrow keys continue from here) and toggles the
          // same .expanded state Enter/Space does.
          if (expandable) {
            li.addEventListener("click", function () {
              setActiveFeedEntry(entry);
              toggleActiveFeedExplanation();
            });
          }

          // The empty state is CSS-only (`#feed:not(:empty) ~ #feed-empty`) -
          // appending the first row is enough to reveal the real list.
          feedEl.appendChild(li);
          while (feedEl.children.length > MAX_FEED_ROWS) {
            var removedEntry = feedEntries.shift();
            feedEl.removeChild(feedEl.firstChild);
            if (activeFeedEntry === removedEntry) { setActiveFeedEntry(null); }
            feedRowsEverTruncated = true;
            feedRowsDroppedCount += 1;
          }
          // Idempotent, not a one-way latch: re-hides if the row count ever
          // drops back under the cap (it never rises back above it once
          // trimmed, so this only ever shows once truncation has actually
          // happened - never merely upon first reaching the cap).
          feedTruncatedEl.hidden = !feedRowsEverTruncated || feedEntries.length < MAX_FEED_ROWS;
          if (feedRowsEverTruncated) {
            feedTruncatedEl.textContent =
              "older rows not shown (" + feedRowsDroppedCount + ") - see doberman log";
          }
          if (nearBottom) {
            feedEl.scrollTop = feedEl.scrollHeight;
          }
          syncStatsSoon();
          queueFeedArrivalAnnouncement(row.verdict);
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


def _js_json_literal(value: object) -> str:
    """Encode any JSON-able ``value`` as a raw (unquoted) JS object/array literal.

    Same ``</script>``-breakout escaping as :func:`_js_string_literal`, but for a
    value embedded directly as JS source (e.g. ``var X = <this>;``) rather than
    wrapped in a JS string literal.
    """
    encoded = json.dumps(value, sort_keys=True)
    return encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _render_shell(repo_root: str) -> str:
    project = _project_display_name(repo_root)
    page_title = f"{project} - Doberman Dashboard"
    return (
        _HTML_SHELL.replace("%%DASH_PAGE_TITLE%%", html.escape(page_title))
        .replace("%%DASH_PROJECT_NAME%%", html.escape(project))
        .replace("%%DASH_MARK_PNG_B64%%", DASH_MARK_PNG_B64)
        .replace("%%DASH_JS_TITLE_JSON%%", _js_string_literal(page_title))
        .replace("%%DASH_REASON_DESCRIPTIONS_JSON%%", _js_json_literal(REASON_DESCRIPTIONS))
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

    ``explanation`` (CLAUDE.md #9 - every BLOCK/AUTH carries a human
    explanation) is populated via :func:`doberman.explain.template_explanation`
    for BLOCK/AUTH rows only, and left empty for PASS - a PASS row needs no
    "why", and skipping it keeps the SSE payload small on the (usually
    dominant) common case. ``with_reasons=False`` because the feed's own
    glossed ``gloss-list`` (built client-side from ``reason_codes`` below)
    already carries the reason codes - the "Reasons: ..." clause would just
    say it twice.

    ``headline`` (round 6) is a short, reason-first fragment
    (:func:`doberman.explain.headline`, e.g. "Recursive delete blocked -
    shell_exec") the feed shows as the row's COLLAPSED primary line, so eight
    consecutive BLOCKs no longer all read as the identical opening sentence
    until expanded - the full ``explanation`` only shows once a row is
    expanded. Same BLOCK/AUTH-only gating as ``explanation``.
    """
    verdict = row.get("final_verdict")
    show_why = verdict in ("BLOCK", "AUTH")
    return {
        "id": row.get("id"),
        "ts": row.get("ts"),
        "verdict": verdict,
        "action_type": row.get("action_type"),
        "target_path_class": row.get("target_path_class"),
        "risk": row.get("risk"),
        "source_context": row.get("source_context"),
        "reason_codes": reason_codes(row),
        "headline": headline(row) if show_why else "",
        "explanation": template_explanation(row, with_reasons=False) if show_why else "",
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
