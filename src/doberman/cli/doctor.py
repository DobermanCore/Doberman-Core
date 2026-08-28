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
import shutil
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
    from doberman.hosthooks.install_codex import codex_hook_install_states

    installed = [scope for scope, _p, ok in hook_install_states(path) if ok]
    installed += [f"codex:{scope}" for scope, _p, ok in codex_hook_install_states(path) if ok]
    if installed:
        return CheckResult("Host hooks", CheckStatus.OK, f"installed ({', '.join(installed)})")
    return CheckResult(
        "Host hooks",
        CheckStatus.FAIL,
        "not installed in any scope — run `doberman install-hooks` (add `--host codex` for Codex)",
        critical=True,
    )


def _check_hook_command(path: str) -> CheckResult:
    """Every hook entry runs the bare ``doberman`` command, so the host can only
    execute them if ``doberman`` is on PATH. A dangling entry (package removed, or
    its bin dir not on PATH) makes the host fail the hook and carry on
    **unmediated** - critical whenever hooks are installed (ADR 0086 follow-up).

    Diagnosis only: the fix is putting the binary back on PATH or stripping the
    entries with ``uninstall-hooks``; ``doctor`` never edits settings. Resolution
    happens on *this* process's PATH, which can differ from the host's, so the
    detail says so.
    """
    from doberman.hosthooks.install import hook_install_states
    from doberman.hosthooks.install_codex import codex_hook_install_states

    resolved = shutil.which("doberman")
    if resolved:
        return CheckResult("Hook command", CheckStatus.OK, f"`doberman` resolves to {resolved}")
    installed = any(ok for _scope, _p, ok in hook_install_states(path)) or any(
        ok for scope, _p, ok in codex_hook_install_states(path) if scope != "plugin"
    )
    if not installed:
        return CheckResult(
            "Hook command",
            CheckStatus.WARN,
            "`doberman` is not on PATH (checked from this shell) - hooks installed later would not run",
        )
    return CheckResult(
        "Hook command",
        CheckStatus.FAIL,
        "hooks call `doberman`, which is not on PATH (checked from this shell): the host cannot run "
        "them, so tool calls go unmediated. Put the install's bin dir on PATH (or `pipx install "
        "doberman-core`), or strip the dangling entries with `doberman uninstall-hooks` "
        "(`--global` for the user-wide ones)",
        critical=True,
    )


def _check_codex_version() -> CheckResult:
    """Report the installed Codex CLI version against the adapter's supported
    range. Always **non-critical** (WARN, never FAIL): a newer or absent Codex is
    not "Doberman may not be protecting you" — Codex support is opt-in.

    Windows regression (live-tested): a bare ``["codex", "--version"]`` argv
    cannot resolve npm's ``codex.cmd`` shim — Windows ``CreateProcess`` does not
    apply ``PATHEXT`` to a bare command name the way a shell does — so this
    reported a false "not found" on a box where ``codex`` ran fine from a
    terminal. Resolving via :func:`shutil.which` first (it *does* apply
    ``PATHEXT``) fixes this on every platform, POSIX included.
    """
    import shutil
    import subprocess

    from doberman.hosthooks.codex import SUPPORTED_CODEX_RANGE

    resolved = shutil.which("codex")
    if resolved is None:
        return CheckResult(
            "Codex CLI", CheckStatus.WARN, "not found (only needed for `--host codex`)"
        )

    try:
        # noqa on the argv line: fixed argv (from shutil.which, not user input), no
        # shell. Timeout raised from 2s -> 5s: the npm shim is a colder start.
        proc = subprocess.run(  # noqa: S603
            [resolved, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except OSError:  # resolved path became unreachable between the which() and run()
        return CheckResult(
            "Codex CLI", CheckStatus.WARN, "not found (only needed for `--host codex`)"
        )
    except subprocess.SubprocessError:
        return CheckResult("Codex CLI", CheckStatus.WARN, "version could not be determined")

    import re

    match = re.search(r"(\d+\.\d+\.\d+)", proc.stdout or proc.stderr or "")
    if not match:
        return CheckResult("Codex CLI", CheckStatus.WARN, "version string not recognized")
    version = match.group(1)
    low, high = SUPPORTED_CODEX_RANGE
    if _version_tuple(low) <= _version_tuple(version) < _version_tuple(high):
        return CheckResult("Codex CLI", CheckStatus.OK, f"{version} (supported)")
    return CheckResult(
        "Codex CLI",
        CheckStatus.WARN,
        f"{version} outside tested range [{low}, {high}) — adapter may need an update",
    )


def _version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in v.split("."))
    except ValueError:
        return (0,)


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
        # Absent is the normal state of a fresh install (the DB appears on the
        # first gated decision), so it must not fail the run — a red "may not be
        # protecting you" on a healthy first-run `doctor` teaches users to
        # ignore the tool. Present-but-unreadable below stays a critical FAIL.
        return CheckResult(
            "Decision DB",
            CheckStatus.WARN,
            "not created yet — appears on the first gated decision",
        )
    # Read-only probe: open in SQLite `mode=ro` so we never create or migrate.
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        try:
            # Must touch the schema: a bare `SELECT 1` never reads the file, so
            # a corrupt/non-SQLite file would probe as healthy.
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
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


def _check_password() -> CheckResult:
    from doberman.auth import password

    if password.is_enrolled():
        return CheckResult("Password", CheckStatus.OK, "set")
    return CheckResult(
        "Password", CheckStatus.WARN, "not set (optional) — run `doberman password set`"
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
        _safe_check("Hook command", True, lambda: _check_hook_command(path)),
        _safe_check("Config", True, lambda: _check_config(path)),
        _safe_check("Decision DB", True, lambda: _check_db(path)),
        _safe_check("Enforcement", False, lambda: _check_enforcement(path)),
        _safe_check("2FA", False, _check_2fa),
        _safe_check("Password", False, _check_password),
        _safe_check("Fingerprint key", False, _check_fingerprint_key),
        _safe_check("Codex CLI", False, _check_codex_version),
    ]


def critical_failures(results: list[CheckResult]) -> list[CheckResult]:
    """Critical checks that are not ``OK`` (a fail *or* an indeterminate warning)."""
    return [r for r in results if r.critical and r.status is not CheckStatus.OK]


def is_healthy(results: list[CheckResult]) -> bool:
    """True iff every *critical* check passed — the process-exit health signal."""
    return not critical_failures(results)
