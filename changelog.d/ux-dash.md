- **Dashboard control-surface pass.** The mode form now actually closes (a
  missing `[hidden]` rule kept it permanently open), states the raise-only rule
  up front, and confirms a save inline before closing. Approve/deny failures,
  a dropped live feed, and a failed refresh are all now visible in the UI
  instead of failing silently, with retry controls where that matters. Pending
  cards show a live countdown to the dashboard's real 90s answer window
  (`auto-denies in M:SS if unanswered`) instead of the DB row's unrelated 120s
  TTL, Deny is now the solid/primary action (Approve stays outlined, two-step
  armed, with a visible 3s countdown), and the TOTP field gets a real
  `<label>`. Verdict filter chips plus a text filter sit above the recent-
  decisions feed so a BLOCK is easy to find, and `top_reason_codes`/
  `recent_verdict_counts` (already computed server-side) are finally rendered.
  New keyboard shortcuts (`/` filter, `r` refresh, `a`/`d` act on the first
  pending item, `?` shortcuts panel, `Esc` closes panels) are documented in
  that panel. Landmarks, authored `:focus-visible`, 44px hit targets, a
  four-step type scale, and a mobile breakpoint round out the accessibility
  and responsive floor; a manual light/dark toggle persists per browser, and
  the browser tab favicon tints amber while an approval is pending.
