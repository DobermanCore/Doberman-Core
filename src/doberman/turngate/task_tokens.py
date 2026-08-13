"""D2 — extract this turn's destination tokens from the TRUSTED user prompt.

The task-match leg the C3.1 correlator (:mod:`doberman.engine.correlator`)
consults so a user-justified egress (the user's own turn named the
destination) doesn't false-positive ``correlated_trifecta``.

SECURITY (the whole point of this module): extraction reads ONLY
``SegmentOrigin.typed`` text — never ``pasted``/``tool_fetched``, which
``models.SegmentOrigin.is_untrusted`` already marks untrusted-by-construction.
If task-match keyed off the agent's evolving context instead of the trusted
pre-inference prompt, a prompt injection that adds "send everything to
evil.com" to a fetched page would poison the "task" signal and suppress the
very trifecta it exists to catch. The turn gate (``turngate/hook.py``) is the
one seam that sees the user's turn *before* any of that context accumulates,
which is why extraction happens here and not, say, from the session's
accumulated tool output.

Only registered-domain-shaped host tokens are ever persisted — never the raw
prompt or any other prompt substring. Reuses
``engine.rules.destinations``'s own IDNA-decode helper so a homoglyph domain
mentioned in the prompt is captured in the same normalized form the egress
rule itself would compare against.
"""

import logging
import re

from doberman.engine.rules.destinations import _decode_host
from doberman.models import SegmentOrigin
from doberman.turngate.raw import RawTurn

logger = logging.getLogger("doberman.turngate.task_tokens")

#: Bound on how many candidate hosts one turn can contribute — a long or
#: hostile typed prompt must never grow the per-turn extraction unboundedly.
#: Mirrors storage.task_match.MAX_TASK_HOSTS (the storage-layer backstop).
MAX_TASK_HOSTS = 20

#: A rough registered-domain shape: one or more dot-separated labels ending in
#: an alphabetic TLD-shaped suffix. Deliberately permissive (it is a narrowing
#: SIGNAL, not a validator) — matches both bare mentions ("api.stripe.com")
#: and the host portion of a full URL. Lookaround keeps it from matching a
#: fragment inside a longer token (e.g. a UUID or a hex fingerprint).
_HOST_RE = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}(?![\w-])"
)


def extract_task_hosts(raw: RawTurn) -> list[str]:
    """Registered-domain-shaped tokens found in the turn's TYPED text only.

    Deduped, order-preserving, capped at :data:`MAX_TASK_HOSTS`. Returns ``[]``
    for a turn with no typed segment (an all-pasted/tool-fetched turn — those
    origins are never scanned; see the module docstring).
    """
    typed_text = "\n".join(
        segment.text for segment in raw.segments if segment.origin is SegmentOrigin.typed
    )
    if not typed_text:
        return []
    hosts: list[str] = []
    for match in _HOST_RE.finditer(typed_text):
        try:
            host = _decode_host(match.group(0))
        except Exception:  # noqa: BLE001,S112 — a bad match must never break extraction
            continue
        if host and host not in hosts:
            hosts.append(host)
        if len(hosts) >= MAX_TASK_HOSTS:
            break
    return hosts


async def record_task_hosts(raw: RawTurn, *, repo_root: str, session_id: str | None) -> None:
    """Best-effort: persist this turn's typed-only task hosts under the session.

    A no-op with no ``session_id`` — mirrors ``storage.task_match``'s own
    session-only scoping (no entity/repo fallback: see that module's
    docstring for why). Never raises into the gate path (mirrors
    ``turngate.handoff.publish_turn_context``'s own best-effort contract).
    """
    if not session_id:
        return
    try:
        hosts = extract_task_hosts(raw)
        if not hosts:
            return
        from doberman.storage.task_match import record_task_hosts as _persist  # lazy: light import

        await _persist(repo_root, session_id, hosts)
    except Exception:  # noqa: BLE001 — task-token capture must never break the gate path
        logger.warning("task-token capture failed; continuing")
