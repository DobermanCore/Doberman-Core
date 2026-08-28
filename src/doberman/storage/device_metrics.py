"""Device-global session-metrics rollup, for ``doberman dashboard``.

A tiny, best-effort SQLite counter at ``~/.doberman/metrics.db`` — distinct
from the per-repo decision log in :mod:`doberman.storage.db`. Every recorded
decision increments this rollup, so it spans **all** repos/sessions for the OS
user (scoped by virtue of living in their home directory), giving a lifetime
"how many times has Doberman stepped in" summary.

Redaction discipline matches the decision log: this store holds **only** a
verdict class (PASS/AUTH/BLOCK) and a count — never a path, reason code, role,
or any other per-action detail.

Location override: pass ``home=`` directly, or set the ``DOBERMAN_HOME`` env
var (tests point this at a temp dir so the real user rollup is never touched —
see ``tests/conftest.py``).

SECURITY / resilience: both functions are **best-effort** and **never raise**.
Incrementing the rollup happens on the decision hot path
(:func:`doberman.storage.log.record_decision`); a missing dir, a locked db, or
a permissions error must never slow down or break a decision.
"""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

#: Env var overriding the device-metrics home dir (tests inject a tmp_path).
HOME_ENV = "DOBERMAN_HOME"

_DB_NAME = "metrics.db"

_EMPTY_METRICS = {"total": 0, "pass": 0, "auth": 0, "block": 0, "first_seen": None}


def _db_path(home: Path | None = None) -> Path:
    base = home if home is not None else Path(os.environ.get(HOME_ENV) or Path.home())
    return base / ".doberman" / _DB_NAME


def resolve_path() -> Path:
    """Resolve the device-wide state directory, including ``DOBERMAN_HOME``."""
    return _db_path().parent


def _restrict_permissions(path: Path) -> None:
    """Best-effort tighten the metrics dir/file to owner-only (no-op on Windows ACLs)."""
    try:
        os.chmod(path.parent, 0o700)
        if path.exists():
            os.chmod(path, 0o600)
    except OSError:
        pass


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS metrics (verdict TEXT PRIMARY KEY, count INTEGER NOT NULL)"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")


def record_decision_metric(verdict: str, *, home: Path | None = None) -> None:
    """Best-effort increment of the device-global counter for *verdict*.

    Creates ``~/.doberman/`` (``0700``) and the table on first use. Wrapped
    end-to-end so a missing dir, a locked db, or a permissions error is
    swallowed — this must NEVER raise into the decision path.
    """
    try:
        path = _db_path(home)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        conn = sqlite3.connect(str(path), timeout=1)
        try:
            _ensure_schema(conn)
            conn.execute(
                "INSERT INTO metrics (verdict, count) VALUES (?, 1) "
                "ON CONFLICT(verdict) DO UPDATE SET count = count + 1",
                (verdict,),
            )
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('first_seen', ?) "
                "ON CONFLICT(key) DO NOTHING",
                (datetime.now(timezone.utc).date().isoformat(),),
            )
            conn.commit()
        finally:
            conn.close()
        _restrict_permissions(path)
    except Exception:  # noqa: BLE001, S110 — device metrics must never break the decision path
        pass


def read_metrics(*, home: Path | None = None) -> dict:
    """Read the device-global rollup for ``doberman dashboard``.

    Returns ``{total, pass, auth, block, first_seen}`` — all zero/None if the
    store doesn't exist yet. Never raises (a dashboard read must never crash
    the CLI or a SessionStart hook).
    """
    try:
        path = _db_path(home)
        if not path.exists():
            return dict(_EMPTY_METRICS)
        conn = sqlite3.connect(str(path), timeout=1)
        try:
            counts = dict(conn.execute("SELECT verdict, count FROM metrics").fetchall())
            row = conn.execute("SELECT value FROM meta WHERE key = 'first_seen'").fetchone()
        finally:
            conn.close()
        return {
            "total": sum(counts.values()),
            "pass": counts.get("PASS", 0),
            "auth": counts.get("AUTH", 0),
            "block": counts.get("BLOCK", 0),
            "first_seen": row[0] if row else None,
        }
    except Exception:  # noqa: BLE001 — a dashboard read must never crash the CLI
        return dict(_EMPTY_METRICS)


def render_dashboard(metrics: dict) -> str:
    """Render the compact ASCII panel for ``doberman dashboard``.

    Pure ASCII by design (no box-drawing runes, no emoji) — CLI output must
    render cleanly on a legacy cp1252 Windows console (same rule
    :mod:`doberman.branding` documents for onboarding output), which matters
    doubly here since this prints on every Claude Code SessionStart.
    """
    total = metrics["total"]
    lines = ["Doberman - session guard summary"]
    if total == 0:
        lines.append("No activity recorded yet on this device.")
    else:
        lines.append(f"Tracking since {metrics.get('first_seen') or '?'} - this device")
        lines.append("")
        lines.append(f"Interceptions   {total:,}")
        for label, key in (("Auto-passed", "pass"), ("Authed", "auth"), ("Blocked", "block")):
            count = metrics[key]
            pct = (count / total * 100) if total else 0.0
            lines.append(f"{label:<12} {count:>6,}  ({pct:5.1f}%)")

    width = max(len(line) for line in lines) + 2
    border = "+" + "-" * width + "+"
    body = "\n".join(f"| {line:<{width - 2}} |" for line in lines)
    return f"{border}\n{body}\n{border}"
