- **A new verification-integrity rule pack catches an agent quietly disabling its own safety net.**
  `git commit --no-verify`/`-n`/`--no-gpg-sign` now requires authentication (`verification_bypass_flag`),
  as does the same bypass expressed at the config level (`git -c core.hooksPath=...`, `git -c
  commit.gpgsign=false`, `git --config-env=core.hooksPath=...`) rather than as a commit flag. Deleting or
  renaming a tool-mediated file that matches a test-file name/path pattern (including `.tsx`/`.jsx`/`.mjs`
  test/spec shapes) also requires authentication (`test_file_removal`, scoped to delete/rename only — an
  ordinary test edit is unaffected); a shell-level `rm`/`git rm` of the same file is a command line, not a
  path-target action, and is invisible to this check (documented limitation, not covered here).
  `CODEOWNERS` and lint/type-check config (`ruff.toml`, `mypy.ini`, `.eslintrc*`, `eslint.config.*`,
  including nested copies) join the existing CI-pipeline glob table (`sensitive_path_access`), the same
  raise-only treatment `.github/workflows` already had.
