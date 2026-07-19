"""Dashboard liveness heartbeat (D3: interactive AUTH approve/deny).

The dash server process touches this marker every ~2s while running so
:class:`~doberman.auth.dashboard_prompter.DashboardPrompter` can tell, with
zero added latency, whether a dashboard is actually alive before queuing an
approval into it. Content-based (an ISO timestamp written into the file), not
mtime-based, so it is trivial to fake with an injected ``now`` in tests and
behaves the same across filesystems.

Fails closed: any read/parse/missing-file error is treated as "no dashboard"
-- a broken heartbeat can only ever cause an immediate fallback to the next
auth channel, never a hang or a false "dashboard is here".
"""

from datetime import datetime, timezone
from pathlib import Path

from doberman.storage.db import CONFIG_DIR

HEARTBEAT_FILE = "dash_heartbeat"

#: A dash server is considered "gone" once its heartbeat is older than this.
DEFAULT_HEARTBEAT_MAX_AGE_S = 5.0


def heartbeat_path(repo_root: str = ".") -> Path:
    """Path to the per-repo heartbeat marker (never committed - lives in
    the same gitignored ``.doberman/`` dir as the DB)."""
    return Path(repo_root) / CONFIG_DIR / HEARTBEAT_FILE


def touch_heartbeat(repo_root: str = ".", *, now: datetime | None = None) -> None:
    """Write the current time into the heartbeat file. Best-effort."""
    when = now or datetime.now(timezone.utc)
    path = heartbeat_path(repo_root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(when.isoformat(), encoding="utf-8")
    except OSError:
        pass  # a heartbeat write failure must only ever cost the dash channel


def heartbeat_is_fresh(
    repo_root: str = ".",
    *,
    max_age_s: float = DEFAULT_HEARTBEAT_MAX_AGE_S,
    now: datetime | None = None,
) -> bool:
    """Whether a dash server appears to be alive right now.

    Fails closed to ``False`` on any missing file, read error, or unparsable
    content - never let a broken heartbeat be mistaken for a live dashboard.
    """
    when = now or datetime.now(timezone.utc)
    path = heartbeat_path(repo_root)
    try:
        text = path.read_text(encoding="utf-8").strip()
        stamp = datetime.fromisoformat(text)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
    except (OSError, ValueError):
        return False
    return (when - stamp).total_seconds() < max_age_s
