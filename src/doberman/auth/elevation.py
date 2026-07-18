"""Narrow, temporary role elevation (Feature 7, slice 7.4).

A satisfied ``role_elevation`` challenge grants a *tight* permission: it covers
one specific path glob (not ``**``), for a short time (a TTL), and — for
destructive scopes — for a single use. An elevation only ever satisfies a
**role** out-of-scope ``AUTH``; it never relaxes a hard block, and the other
objective rules (secrets, protected paths, destructive commands) still apply.

This module is a deliberate **leaf**: it imports only the stdlib and the shared
:func:`doberman.canonical.canonicalize` helper, never ``doberman.models`` or
``doberman.proxy``. That lets the role-boundary rule consult elevations without
an import cycle, and lets the storage layer persist :class:`ElevationGrant`
rows. Persistence and the active-grant query live in ``doberman.storage.db``;
the *matching* logic lives here so the engine can stay decoupled from the DB.

SECURITY: matching is a pure glob test against the **canonical** target. The
caller (the role rule) hands an already-active grant set — expiry, revocation,
and single-use consumption are enforced at the storage layer (which excludes
spent/expired grants) and at the proxy (which marks single-use grants used after
a forward), never softened here.
"""

from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatch
from glob import escape as glob_escape

from doberman.canonical import canonicalize

#: Default elevation lifetime: long enough to finish one approved edit, short
#: enough that a stale grant cannot be reused hours later.
DEFAULT_TTL_SECONDS = 15 * 60

#: Globs that would widen an elevation to (nearly) everything. A grant whose
#: canonical scope is empty or whole-tree is refused — elevation must be narrow.
_WHOLE_TREE = {"", "*", "**", "**/*", "/**"}


@dataclass(frozen=True)
class ElevationGrant:
    """One granted role elevation (immutable).

    Attributes:
        id: opaque unique id (also the audit/revocation handle).
        scope_glob: the canonical, lower-cased, root-relative path glob this
            grant covers. Narrow by construction (a single file in the MVP).
        task_id: the task/action this elevation was granted for (audit only).
        granted_at / expires_at: timezone-aware UTC bounds.
        revoked: explicitly revoked by the user (``doberman revoke``).
        single_use: destructive scopes are consumed after one forward.
        used: whether a single-use grant has already been spent.
    """

    id: str
    scope_glob: str
    task_id: str | None
    granted_at: datetime
    expires_at: datetime
    revoked: bool = False
    single_use: bool = False
    used: bool = False

    def is_active(self, now: datetime) -> bool:
        """True if this grant is currently usable (not expired/revoked/spent)."""
        if self.revoked:
            return False
        if self.single_use and self.used:
            return False
        return now < self.expires_at

    def covers(self, target_relposix: str) -> bool:
        """True if ``target_relposix`` (a canonical path) falls in this grant's scope."""
        if not target_relposix or self.scope_glob in _WHOLE_TREE:
            return False
        return fnmatch(target_relposix, self.scope_glob)


def scope_for_target(target: str | None, *, root: str = ".") -> str | None:
    """Build a narrow scope glob from an action target, or ``None`` if unsafe.

    The scope is the canonical, root-relative form of the exact target path, so
    the grant covers *that one file* and nothing else. Returns ``None`` for a
    non-path target, a path that escapes the repo root, or a whole-tree result —
    none of which may ever be elevated (fail toward refusing the grant).

    SECURITY (H3): ``covers`` matches the stored scope as an ``fnmatch`` glob
    pattern, so any ``*``/``?``/``[``/``]`` in the target's canonical path must
    be escaped before it becomes the scope — otherwise a target like
    ``secret*`` would grant a wildcard instead of the one literal path
    requested (scope widening).
    """
    if not target:
        return None
    canonical = canonicalize(target, root=root)
    if canonical.escapes_root or canonical.relposix in _WHOLE_TREE:
        return None
    return glob_escape(canonical.relposix)


def find_cover(
    target: str | None,
    grants: tuple[ElevationGrant, ...] | list[ElevationGrant],
    *,
    root: str = ".",
) -> ElevationGrant | None:
    """Return the first grant in ``grants`` whose scope covers ``target``.

    ``grants`` are assumed already-active (the storage layer filters expired /
    revoked / spent grants). Matching canonicalizes ``target`` through the one
    shared helper so traversal/symlink/case bypasses cannot dodge or forge
    coverage. Returns ``None`` when nothing covers it (the role AUTH stands).
    """
    if not target:
        return None
    canonical = canonicalize(target, root=root)
    if canonical.escapes_root:
        return None
    rel = canonical.relposix
    for grant in grants:
        if grant.covers(rel):
            return grant
    return None
