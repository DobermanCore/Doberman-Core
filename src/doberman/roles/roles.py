"""Agent role definitions, loading, and the role-boundary matcher (Feature 4).

A *role* is the top of Doberman's **local** authority hierarchy: it declares
which path globs an agent is in-scope for (`allowed`), which are out-of-scope
but recoverable (`suspicious` → AUTH), and which are forbidden for that role
(`blocked` → BLOCK). The thesis point is that the role outranks casual user
intent — a frontend agent touching ``backend/auth/**`` escalates even if the
prompt asks nicely (the escalation lives in the objective layer; see
``engine/rules/role_boundary.py``).

This module is part of the policy core and deliberately imports **only**
``doberman.canonical`` (plus stdlib/pydantic/yaml) — never ``doberman.models``
— so ``models`` can embed a :class:`RoleDefinition` in ``EvalContext`` without
an import cycle, and never ``doberman.proxy`` (import-linter).

SECURITY:

* ``blocked`` wins on overlap, and a target matched by no ``allowed`` glob is
  treated as ``suspicious`` (empty ``allowed`` ⇒ nothing implicitly in scope).
* Matching always goes through the one shared :func:`doberman.canonical.canonicalize`
  helper, so ``..`` traversal, symlink, and case bypasses cannot dodge a role
  boundary; a target that escapes the repo root is treated as ``blocked``.
"""

from collections.abc import Iterable, Sequence
from enum import StrEnum
from fnmatch import fnmatch
from functools import lru_cache
from importlib.resources import files

import yaml
from pydantic import BaseModel, ConfigDict, Field

from doberman.canonical import canonicalize

#: Repo root used when a caller does not supply one (matches the path rule).
_DEFAULT_ROOT = "."

#: Over-broad globs that would match everything are dropped from a boundary set
#: (a blocked ``**`` would block every action; a suspicious ``**`` would AUTH
#: everything). Mirrors the protected-path rule's sanitizer.
_WHOLE_TREE = {"*", "**", "**/*", "/**"}


class RoleBoundary(StrEnum):
    """How a target relates to a role's scope."""

    allowed = "allowed"
    suspicious = "suspicious"
    blocked = "blocked"
    unknown = "unknown"  # non-path action — the role rule abstains


def _normalize_globs(globs: Iterable[str]) -> tuple[str, ...]:
    """Lower-case, strip, and drop empty/whole-tree globs.

    Canonical paths are lower-cased, so globs must be too; whole-tree patterns
    are dropped so a misconfiguration cannot make everything match.
    """
    cleaned: list[str] = []
    for raw in globs:
        pattern = (raw or "").strip().lower()
        if not pattern or pattern in _WHOLE_TREE:
            continue
        cleaned.append(pattern)
    return tuple(cleaned)


class RoleDefinition(BaseModel):
    """An agent role's path-boundary policy (immutable).

    ``allowed``/``suspicious``/``blocked`` are path globs matched against the
    canonical, root-relative, lower-cased target. They are normalized on
    construction (lower-cased, whole-tree patterns dropped).

    ``protected_branches`` (#199) is unrelated to path scope: extra branch
    names ``engine/rules/commands.py::DestructiveCommandRule`` unions into its
    own protected set for force-push detection. Exact names only, no glob
    normalization -- ``_git_force_push_to_protected`` already matches
    case-insensitively.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    description: str = ""
    allowed: tuple[str, ...] = ()
    suspicious: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ()
    protected_branches: tuple[str, ...] = ()

    def model_post_init(self, _context: object) -> None:
        # Normalize globs once at construction. object.__setattr__ is required
        # because the model is frozen.
        object.__setattr__(self, "allowed", _normalize_globs(self.allowed))
        object.__setattr__(self, "suspicious", _normalize_globs(self.suspicious))
        object.__setattr__(self, "blocked", _normalize_globs(self.blocked))


#: The most-restrictive fallback role: nothing is in scope, so every path
#: action is at least ``suspicious`` (→ AUTH). Used when a configured role name
#: cannot be resolved — fail toward restriction, never toward open scope.
MOST_RESTRICTIVE_ROLE = RoleDefinition(
    name="restricted",
    description="Fallback role: nothing is implicitly in scope; everything escalates.",
)


def _matches_any(relposix: str, globs: Sequence[str]) -> bool:
    if not relposix:
        return False
    return any(fnmatch(relposix, pattern) for pattern in globs)


@lru_cache(maxsize=1)
def load_builtin_roles() -> dict[str, RoleDefinition]:
    """Load and validate the packaged built-in roles.

    Returns a mapping of role name → :class:`RoleDefinition`. Raises
    ``ValueError`` if the packaged data is malformed (a corrupt install should
    fail loudly, not silently ship an empty role set).

    Cached for the life of the process (``lru_cache(maxsize=1)``, same
    mechanism as :func:`doberman.storage.fingerprint._load_or_create_key`):
    this reads a file packaged with the install, which cannot change without
    a reinstall (a new process), so re-parsing it on every
    :func:`doberman.config.load_active_role` call (every decided action, #552)
    is pure overhead. A raised exception is never cached.
    """
    raw = files("doberman.roles").joinpath("builtin_roles.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    roles_section = data.get("roles") if isinstance(data, dict) else None
    if not isinstance(roles_section, dict) or not roles_section:
        raise ValueError("builtin_roles.yaml must contain a non-empty 'roles' mapping")

    roles: dict[str, RoleDefinition] = {}
    for name, spec in roles_section.items():
        spec = spec or {}
        if not isinstance(spec, dict):
            raise ValueError(f"role {name!r} must be a mapping")
        roles[name] = RoleDefinition(
            name=name,
            description=str(spec.get("description", "")),
            allowed=tuple(spec.get("allowed") or ()),
            suspicious=tuple(spec.get("suspicious") or ()),
            blocked=tuple(spec.get("blocked") or ()),
        )
    return roles


def classify(
    role: RoleDefinition,
    target: str | None,
    *,
    root: str = _DEFAULT_ROOT,
) -> RoleBoundary:
    """Classify ``target`` against ``role``'s boundaries.

    Returns:
        ``unknown`` for a non-path action (no target); ``blocked`` if the
        canonical path escapes the repo root or matches a ``blocked`` glob;
        ``suspicious`` if it matches a ``suspicious`` glob *or* no ``allowed``
        glob; ``allowed`` only when it matches an ``allowed`` glob and nothing
        stricter. Precedence is blocked → suspicious → allowed.
    """
    if not target:
        return RoleBoundary.unknown

    canonical = canonicalize(target, root=root)
    if canonical.escapes_root:
        # Out of the repository entirely — never in scope for any role.
        return RoleBoundary.blocked

    rel = canonical.relposix
    if _matches_any(rel, role.blocked):
        return RoleBoundary.blocked
    if _matches_any(rel, role.suspicious):
        return RoleBoundary.suspicious
    if _matches_any(rel, role.allowed):
        return RoleBoundary.allowed
    # Matched by nothing in `allowed` — out of scope, escalate (safe default).
    return RoleBoundary.suspicious
