"""Health checks backing ``doberman doctor`` (issue #94).

A **read-only** self-check: every check *diagnoses*, it never mutates state. The
logic lives here (a pure function over a repo root) so it is trivially testable
without Typer and so the CLI command in :mod:`doberman.cli.main` is a thin
renderer.

Two safety rules, straight from the Prime Directives:

* **Fail closed in the reporting.** A check that cannot be determined resolves to
  a :class:`CheckStatus.WARN`, never a false ``OK`` — an unknown is never "all good".
* **Script-friendly exit code.** The three checks that decide whether Doberman is
  actually wired up and healthy — host hooks, config, decision DB — are marked
  *critical*. The CLI exits non-zero if any critical check is not ``OK`` (a fail
  *or* an indeterminate warning), so a half-configured install is caught in CI.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class CheckStatus(str, Enum):
    """Traffic-light state of a single health check."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class CheckResult:
    """One line of the ``doctor`` checklist."""

    name: str
    status: CheckStatus
    detail: str
    #: Critical checks drive the process exit code (see :func:`is_healthy`).
    critical: bool = False


def _safe_check(name: str, critical: bool, fn):
    """Run one check, converting any unexpected error into a fail-closed WARN.

    A check must never crash ``doctor`` and must never report ``OK`` when it
    could not actually determine health.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — a diagnostic must never crash; fail closed to WARN
        return CheckResult(
            name, CheckStatus.WARN, f"could not be determined ({type(exc).__name__})", critical
        )


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_hooks(path: str) -> CheckResult:
    from doberman.hosthooks.install import hook_install_states

    installed = [scope for scope, _p, ok in hook_install_states(path) if ok]
    if installed:
        return CheckResult("Host hooks", CheckStatus.OK, f"installed ({', '.join(installed)})")
    return CheckResult(
        "Host hooks",
        CheckStatus.FAIL,
        "not installed in any scope — run `doberman install-hooks`",
        critical=True,
    )


def _check_config(path: str) -> CheckResult:
    from doberman.config import CONFIG_DIR, POLICY_FILE, load_policy

    policy_file = Path(path) / CONFIG_DIR / POLICY_FILE
    doc = load_policy(path)
    if doc is not None:
        enabled = sum(1 for it in doc.items if it.enabled)
        return CheckResult(
            "Config", CheckStatus.OK, f"policy loaded ({enabled}/{len(doc.items)} items enabled)"
        )
    if policy_file.exists():
        # File is there but load_policy returned None → corrupt/unreadable. Fail closed.
        return CheckResult(
            "Config",
            CheckStatus.FAIL,
            f"{policy_file} present but failed to load (corrupt?)",
            critical=True,
        )
    return CheckResult(
        "Config",
        CheckStatus.FAIL,
        "no policy saved — run `doberman setup` or `doberman review --yes`",
        critical=True,
    )


def _check_db(path: str) -> CheckResult:
    from doberman.storage.db import db_path

    p = db_path(path)
    if not p.exists():
        return CheckResult(
            "Decision DB",
            CheckStatus.FAIL,
            "not found — created on first decision; run `doberman setup`",
            critical=True,
        )
    # Read-only probe: open in SQLite `mode=ro` so we never create or migrate.
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return CheckResult(
            "Decision DB", CheckStatus.FAIL, f"present but unreadable ({exc})", critical=True
        )
    return CheckResult("Decision DB", CheckStatus.OK, f"reachable ({p})")


def _check_enforcement(path: str) -> CheckResult:
    from doberman.config import load_mode, resolve_enforcement_sync

    mode = load_mode(path)
    enforcement = resolve_enforcement_sync(path)  # fails closed to "enforce"
    detail = f"enforcement={enforcement}, mode={mode}"
    if enforcement == "enforce":
        return CheckResult("Enforcement", CheckStatus.OK, detail)
    # monitor / off: Doberman is not blocking. Surface it loudly (still not a
    # critical *health* failure — it is an intentional, human-gated dial).
    return CheckResult("Enforcement", CheckStatus.WARN, f"{detail} — NOT blocking (advisory only)")


def _check_2fa() -> CheckResult:
    from doberman.auth import totp

    if totp.is_enrolled():
        return CheckResult("2FA", CheckStatus.OK, "enrolled")
    return CheckResult(
        "2FA", CheckStatus.WARN, "not enrolled (optional) — run `doberman 2fa setup`"
    )


def _check_fingerprint_key() -> CheckResult:
    from doberman.storage.fingerprint import _key_path

    p = _key_path()
    if not p.exists():
        return CheckResult(
            "Fingerprint key", CheckStatus.WARN, "not yet created (generated on first use)"
        )
    if os.name == "nt":
        # POSIX mode bits are meaningless on Windows ACLs — can't verify, so warn
        # rather than claim a false OK.
        return CheckResult(
            "Fingerprint key", CheckStatus.WARN, "present (permissions not verifiable on Windows)"
        )
    mode = stat.S_IMODE(p.stat().st_mode)
    if mode & 0o077:
        return CheckResult(
            "Fingerprint key",
            CheckStatus.WARN,
            f"present but group/other-accessible ({oct(mode)}; expected 0o600)",
        )
    return CheckResult("Fingerprint key", CheckStatus.OK, f"present with {oct(mode)} permissions")


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


def run_checks(path: str = ".") -> list[CheckResult]:
    """Run every health check against *path* and return the results in display order."""
    return [
        _safe_check("Host hooks", True, lambda: _check_hooks(path)),
        _safe_check("Config", True, lambda: _check_config(path)),
        _safe_check("Decision DB", True, lambda: _check_db(path)),
        _safe_check("Enforcement", False, lambda: _check_enforcement(path)),
        _safe_check("2FA", False, _check_2fa),
        _safe_check("Fingerprint key", False, _check_fingerprint_key),
    ]


def critical_failures(results: list[CheckResult]) -> list[CheckResult]:
    """Critical checks that are not ``OK`` (a fail *or* an indeterminate warning)."""
    return [r for r in results if r.critical and r.status is not CheckStatus.OK]


def is_healthy(results: list[CheckResult]) -> bool:
    """True iff every *critical* check passed — the process-exit health signal."""
    return not critical_failures(results)
