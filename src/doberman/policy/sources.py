"""Ordered policy sources with authority layering (Feature 4, slice 4.4).

The agent role (F4.3) is the top of the *local* authority hierarchy. But an
enterprise/org deployment needs a way to layer a **higher** authority above the
role — e.g. an org hard-policy that blocks a path the role would allow — without
the public core ever importing the enterprise package.

This module provides that seam:

* :class:`PolicySource` — the interface a source implements (a name, an integer
  ``authority``, and a :meth:`snapshot` returning blocked/sensitive globs).
* :func:`resolve_policy` — merges an ordered set of sources into one
  :class:`ResolvedPolicy`. The merge is **raise-only across sources**: it only
  ever *unions* constraints, so a lower-authority source can never loosen a
  higher one, and ``blocked`` always wins over ``sensitive`` on a tie.
* Extra sources are discovered via the F3 entry-point registry (group
  ``doberman.policy_sources``); with none installed, only the local sources
  passed in are used and behavior is unchanged.

This module is policy core. It imports the registry **lazily** (inside
:func:`resolve_policy`) so there is no import cycle with the engine, and it
never imports ``doberman.proxy``.
"""

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from doberman.roles.roles import RoleDefinition

#: Authority levels for the built-in local sources. Higher outranks lower; the
#: enterprise registers sources above ``ROLE_AUTHORITY`` to outrank the role.
DEFAULTS_AUTHORITY = 0
LEARNED_AUTHORITY = 5
ROLE_AUTHORITY = 10

_WHOLE_TREE = {"*", "**", "**/*", "/**"}


def _normalize_globs(globs: Iterable[str]) -> tuple[str, ...]:
    """Lower-case, strip, and drop empty/whole-tree globs (canonical paths are lower-cased)."""
    cleaned: list[str] = []
    for raw in globs:
        pattern = (raw or "").strip().lower()
        if not pattern or pattern in _WHOLE_TREE:
            continue
        cleaned.append(pattern)
    return tuple(dict.fromkeys(cleaned))


class PolicySnapshot(BaseModel):
    """One source's contribution to the effective policy (immutable)."""

    model_config = ConfigDict(frozen=True)

    blocked_globs: tuple[str, ...] = ()
    sensitive_globs: tuple[str, ...] = ()

    def model_post_init(self, _context: object) -> None:
        object.__setattr__(self, "blocked_globs", _normalize_globs(self.blocked_globs))
        object.__setattr__(self, "sensitive_globs", _normalize_globs(self.sensitive_globs))


@runtime_checkable
class PolicySource(Protocol):
    """A source of policy constraints, ordered by ``authority`` (higher wins).

    Implementations live in core (local sources) or in separately-installed
    packages registered via the ``doberman.policy_sources`` entry-point group.
    A source may only ever *add* constraints (blocked/sensitive globs) — the
    resolver guarantees it cannot loosen a higher-authority source.
    """

    name: str
    authority: int

    def snapshot(self) -> PolicySnapshot: ...


class RoleSource:
    """A :class:`PolicySource` derived from the active agent role."""

    authority = ROLE_AUTHORITY

    def __init__(self, role: RoleDefinition) -> None:
        self._role = role
        self.name = f"role:{role.name}"

    def snapshot(self) -> PolicySnapshot:
        # A role's blocked paths are hard blocks; its out-of-scope (suspicious)
        # paths map to sensitive (AUTH).
        return PolicySnapshot(
            blocked_globs=self._role.blocked,
            sensitive_globs=self._role.suspicious,
        )


class StaticSource:
    """A simple :class:`PolicySource` with a fixed snapshot (local/test use)."""

    def __init__(self, name: str, authority: int, snapshot: PolicySnapshot) -> None:
        self.name = name
        self.authority = authority
        self._snapshot = snapshot

    def snapshot(self) -> PolicySnapshot:
        return self._snapshot


class ResolvedPolicy(BaseModel):
    """The merged effective policy across all sources (immutable, raise-only).

    ``blocked_globs`` and ``sensitive_globs`` are the unions across sources,
    with ``blocked`` taking precedence (a glob blocked by any source is removed
    from ``sensitive``). ``contributors`` records ``(name, authority)`` per
    source in ascending-authority order for audit/explainability.
    """

    model_config = ConfigDict(frozen=True)

    blocked_globs: tuple[str, ...] = ()
    sensitive_globs: tuple[str, ...] = ()
    contributors: tuple[tuple[str, int], ...] = Field(default_factory=tuple)

    @property
    def is_empty(self) -> bool:
        return not self.blocked_globs and not self.sensitive_globs


def _looks_like_policy_source(obj: object) -> bool:
    """Structural check (the Protocol's isinstance is attribute-only)."""
    return (
        hasattr(obj, "authority")
        and callable(getattr(obj, "snapshot", None))
        and isinstance(getattr(obj, "name", None), str)
    )


def resolve_policy(
    local_sources: Sequence[PolicySource] = (),
    *,
    discover: bool = True,
) -> ResolvedPolicy:
    """Merge ``local_sources`` plus any registered sources into one policy.

    The merge is raise-only: blocked/sensitive globs are unioned across all
    sources and ``blocked`` wins over ``sensitive`` on overlap, so a
    lower-authority source can never weaken a higher one. With no sources at
    all, returns an empty :class:`ResolvedPolicy` (callers then behave exactly
    as if no policy layering existed).
    """
    sources: list[PolicySource] = [s for s in local_sources if _looks_like_policy_source(s)]
    if discover:
        # Lazy import: avoids an engine<->policy import cycle at module load.
        from doberman.engine.registry import discover_policy_sources

        sources.extend(discover_policy_sources())

    # Ascending authority for stable, auditable contributor ordering. (The
    # union merge below is order-independent, but the audit trail is not.)
    sources.sort(key=lambda s: getattr(s, "authority", 0))

    blocked: set[str] = set()
    sensitive: set[str] = set()
    contributors: list[tuple[str, int]] = []
    for source in sources:
        snap = source.snapshot()
        blocked.update(snap.blocked_globs)
        sensitive.update(snap.sensitive_globs)
        contributors.append(
            (str(getattr(source, "name", "?")), int(getattr(source, "authority", 0)))
        )

    # Blocked wins over sensitive on a tie (stricter constraint dominates).
    sensitive -= blocked

    return ResolvedPolicy(
        blocked_globs=tuple(sorted(blocked)),
        sensitive_globs=tuple(sorted(sensitive)),
        contributors=tuple(contributors),
    )
