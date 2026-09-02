- **`doberman tui` is now a real decision browser.** Columns are reordered (verdict, time, risk,
  auth, action, target, why) with an ASCII verdict glyph (`X BLOCK` / `? AUTH` / `. PASS`) that stays
  legible under the cursor; the "why" panel is scrollable and focusable (`tab` to move focus), `enter`/`w`
  opens a full-screen why view with every reason code and the action id, and the panel now says whether
  it's showing the offline template or an LLM narration (and when the LLM fell back). New bindings: `?`
  help, `/` filter, `b`/`B` next/previous BLOCK, `a` next AUTH, `y` copy the action id, `home`/`end`,
  all listed in the footer. `--last` (default 500, mirrors `doberman log --last`) bounds the load and
  shows "showing N of M"; a missing decision log, an empty one, and a nonexistent `--path` (now exit
  code 2) each get their own honest message instead of one generic placeholder (#tbd)
