- **An unanswered approval now expires within 10 minutes, not 20.** The whole-challenge deadline
  (`DEFAULT_CHALLENGE_TIMEOUT_S`) drops from 1200 s to 600 s, and the MCP-elicitation channel's wait
  drops from 300 s to 60 s so two full passes of the channel chain (dashboard 90 s → elicitation 60 s →
  GUI dialog 120 s) still finish before the ceiling. A `two_factor` challenge nobody answered previously
  stayed approvable for about 13.5 minutes; it now resolves to the fail-closed `timeout` denial by
  10 minutes at the latest. Tightening only: no approval path changes, a late answer is still discarded.
