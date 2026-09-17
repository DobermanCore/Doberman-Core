"""Process liveness heartbeats (D3 dashboard; FM.2 ambient monitor).

A long-running process touches its marker file every so often while alive so
another process can tell, with zero added latency, whether it is actually
running — no socket, no PID file, no port probe. Content-based (an ISO
timestamp written into the file), not mtime-based, so it is trivial to fake
with an injected ``now`` in tests and behaves the same across filesystems.

Fails closed: any read/parse/missing-file error is treated as "not running" —
a broken heartbeat can only ever cause an immediate fallback (dash: the next
auth channel; monitor: a refused second daemon becomes a refused *first*
daemon instead), never a hang or a false positive.

Two independent heartbeat files share this module (each caller passes its own
``filename``, so the two can never be mistaken for one another):

* ``HEARTBEAT_FILE`` ("dash_heartbeat") — the dash server (D3), read by
  :class:`~doberman.auth.dashboard_prompter.DashboardPrompter`.
* ``MONITOR_HEARTBEAT_FILE`` ("monitor_heartbeat") — the ambient monitor
  daemon (FM.2, ``doberman.monitor.daemon``), read by its own single-instance
  guard and by ``doberman monitor status``.
"""

from datetime import datetime, timezone
from pathlib import Path

from doberman.storage.db import CONFIG_DIR

HEARTBEAT_FILE = "dash_heartbeat"
MONITOR_HEARTBEAT_FILE = "monitor_heartbeat"

#: A dash server is considered "gone" once its heartbeat is older than this.
DEFAULT_HEARTBEAT_MAX_AGE_S = 5.0


def heartbeat_path(repo_root: str = ".", *, filename: str = HEARTBEAT_FILE) -> Path:
    """Path to a per-repo heartbeat marker (never committed - lives in
    the same gitignored ``.doberman/`` dir as the DB)."""
    return Path(repo_root) / CONFIG_DIR / filename


def touch_heartbeat(
    repo_root: str = ".",
    *,
    now: datetime | None = None,
    filename: str = HEARTBEAT_FILE,
) -> None:
    """Write the current time into the heartbeat file. Best-effort."""
    when = now or datetime.now(timezone.utc)
    path = heartbeat_path(repo_root, filename=filename)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(when.isoformat(), encoding="utf-8")
    except OSError:
        pass  # a heartbeat write failure must only ever cost its own channel


def heartbeat_is_fresh(
    repo_root: str = ".",
    *,
    max_age_s: float = DEFAULT_HEARTBEAT_MAX_AGE_S,
    now: datetime | None = None,
    filename: str = HEARTBEAT_FILE,
) -> bool:
    """Whether the process behind ``filename`` appears to be alive right now.

    Fails closed to ``False`` on any missing file, read error, or unparsable
    content - never let a broken heartbeat be mistaken for a live process.
    """
    when = now or datetime.now(timezone.utc)
    path = heartbeat_path(repo_root, filename=filename)
    try:
        text = path.read_text(encoding="utf-8").strip()
        stamp = datetime.fromisoformat(text)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
    except (OSError, ValueError):
        return False
    return (when - stamp).total_seconds() < max_age_s
