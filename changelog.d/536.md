- **The auth dialog names the target, the risk, and the deadline clearly, and never hides the
  question.** The target/command now sits in its own bold, high-contrast panel, capped at 6 lines
  with a middle-ellipsis preview and a "Show full target" toggle for a very long or many-line
  target — the question, risk line, and countdown are drawn outside that panel so they can never be
  pushed out of view. The countdown now ticks live ("auto-denies in 1:59") instead of a static note,
  and shows "Denied - no answer in 2:00" before closing on silence. Deny is the solid/primary button
  and Approve is outlined/secondary (the fail-closed default reads as the dominant one); both are
  real, accessible `ttk.Button`s (44px+ tall, a native focus ring in a distinct color from Approve's
  amber) instead of hand-drawn canvas shapes, with Tab/Shift-Tab/Left/Right cycling between them and
  Return/Ctrl+Enter invoking only whichever one is actually focused. The one-time-code dialog rejects
  non-digit input as you type, accepts a pasted code, and shows an inline message on a blank/invalid
  submit instead of silently denying. A new short line under the question — "Denying stops only this
  action; your agent keeps running." — states what a Deny actually does. Best-effort per-monitor DPI
  awareness and centering on the monitor under the mouse round out the polish.
- **The human-tone auth challenge states risk, not just the target and reason.** `doberman.auth.provider`
  gains a `challenge_parts()` seam that builds the structured facts behind a challenge (target, why,
  risk, tier, role, tool, ...) once and renders both tones from it, so the plain "human" tone now
  includes a line like "Risk: high - this needs your code" alongside the exact target. A `Prompter`
  can optionally implement `confirm_challenge(parts)` / `read_code_challenge(parts)` to receive these
  tagged facts directly (the GUI does); every existing `confirm(message)`/`read_code(message)`
  prompter — TTY, dashboard, a plugin — keeps working unchanged via the flattened string.
