- **A new verification-integrity rule pack catches an agent quietly disabling its own safety net.**
  `git commit --no-verify`/`-n`/`--no-gpg-sign` now requires authentication (`verification_bypass_flag`),
  as does deleting or renaming a file that matches a test-file name/path pattern (`test_file_removal`,
  scoped to delete/rename only — an ordinary test edit is unaffected). `CODEOWNERS` and lint/type-check
  config (`ruff.toml`, `mypy.ini`, `.eslintrc*`) join the existing CI-pipeline glob table
  (`sensitive_path_access`), the same raise-only treatment `.github/workflows` already had.
