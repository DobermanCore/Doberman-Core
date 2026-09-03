- **Dependency admission gate (name-only, offline).** A new built-in objective rule parses
  package-manager install commands (`pip`/`npm`/`cargo`/`gem`/`go`/...) and blocks a package name on a
  bundled known-malicious list, or requires authentication for a name one character away from a
  bundled popular-package name (a possible typosquat) — a zero-filesystem, zero-network, purely
  offline check. New reason codes: `dependency_known_malicious`, `dependency_name_typosquat`.
