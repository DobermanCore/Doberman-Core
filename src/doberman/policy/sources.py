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

import hashlib
import json
import logging
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from doberman.roles.roles import RoleDefinition

logger = logging.getLogger("doberman.policy.sources")

#: Authority levels for the built-in local sources. Higher outranks lower; a
#: team-committed policy FILE (#147) outranks the role; the enterprise
#: registers sources above ``ROLE_AUTHORITY`` to outrank the role too.
DEFAULTS_AUTHORITY = 0
LEARNED_AUTHORITY = 5
ROLE_AUTHORITY = 10
FILE_AUTHORITY = 20

#: The repo-committed policy file's name (repo ROOT only -- never under
#: ``.doberman/``, which is gitignored local state; see ``load_file_policy``).
POLICY_FILE_NAME = "doberman.policy.yaml"

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


class FilePolicySource:
    """A :class:`PolicySource` for the repo-committed ``doberman.policy.yaml`` (#147).

    A team-committed policy file, reviewed the same way as any other code
    change, resolved into every action decision exactly like a registered
    enterprise source. ``FILE_AUTHORITY`` (20) outranks the local role (10) in
    the audit-trail ``contributors`` ordering only -- the merge in
    :func:`resolve_policy` is a raise-only UNION, so a source's authority
    never changes which constraints apply, only how they are ordered for
    explainability. Built via :func:`load_file_policy`; never constructed
    directly by a caller (its snapshot is the already-pin-merged effective
    one, not a raw parse of the file).
    """

    name = "repo-file"
    authority = FILE_AUTHORITY

    def __init__(self, snapshot: PolicySnapshot) -> None:
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


# --- #147: the repo-committed doberman.policy.yaml, layered raise-only -----
#
# A file that DROPS a constraint the last-approved pin already held must never
# silently loosen what is enforced (Prime Directive #2). ``load_file_policy``
# is the single loader: it validates the file (never raises), diffs it
# against the local pin (``.doberman/policy_file_pin.json``) using the same
# raise-only rank table as every other drift chokepoint (``classify_change``),
# and only ever WIDENS what is pinned when the file drops something -- the
# human path back to a smaller pin is ``doberman policy-file --accept``
# (``cli/main.py``), gated behind a possession factor like every other
# weakening in this codebase.

_PIN_FILE_NAME = "policy_file_pin.json"
_MISSING_DIGEST = "<missing>"
_KNOWN_FILE_KEYS = frozenset({"version", "blocked", "sensitive"})

#: Per-(repo_root, file-content-digest) dedup so a malformed/dropping file
#: warns once, not once per action (the loader runs on every decision).
_warned_states: set[tuple[str, str]] = set()
#: Per-(repo_root, policy-file digest, pin digest) memoization so entry-point
#: discovery does not re-run on every action; a cache entry is only ever
#: reused while BOTH files are byte-identical to when it was computed.
_effective_policy_cache: dict[tuple[str, str, str], ResolvedPolicy] = {}


def _policy_file_path(repo_root: str) -> Path:
    return Path(repo_root) / POLICY_FILE_NAME


def _pin_path(repo_root: str) -> Path:
    from doberman.config import CONFIG_DIR

    return Path(repo_root) / CONFIG_DIR / _PIN_FILE_NAME


def _digest(path: Path) -> str:
    """A stable content digest, or :data:`_MISSING_DIGEST` if unreadable."""
    try:
        data = path.read_bytes()
    except OSError:
        return _MISSING_DIGEST
    return hashlib.sha256(data).hexdigest()


def _warn_once(repo_root: str, digest: str, message: str) -> None:
    key = (repo_root, digest)
    if key in _warned_states:
        return
    _warned_states.add(key)
    logger.warning(message)


def _read_pin(repo_root: str) -> dict[str, list[str]] | None:
    """The last-approved ``{blocked, sensitive}`` snapshot, or ``None``.

    ``None`` covers both "never adopted" and "unreadable" -- an unreadable
    LOCAL pin is treated the same as a fresh adoption rather than guessed at:
    the file itself (git-reviewed) is the source of truth, and the next valid
    load re-establishes the pin from it.
    """
    path = _pin_path(repo_root)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    blocked, sensitive = raw.get("blocked"), raw.get("sensitive")
    if not isinstance(blocked, list) or not isinstance(sensitive, list):
        return None
    return {"blocked": [str(g) for g in blocked], "sensitive": [str(g) for g in sensitive]}


def _write_pin(repo_root: str, snapshot: PolicySnapshot) -> None:
    """Atomically persist *snapshot* as the new last-approved pin."""
    path = _pin_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "blocked": sorted(snapshot.blocked_globs),
        "sensitive": sorted(snapshot.sensitive_globs),
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _load_raw_file(repo_root: str) -> tuple[PolicySnapshot, str]:
    """Parse+validate ``doberman.policy.yaml``; never raises.

    Returns ``(snapshot, digest)``. Missing, unreadable, non-mapping, a bad
    ``version``, or a non-list ``blocked``/``sensitive`` all yield an EMPTY
    snapshot (the file contributes nothing new this load) and log one warning
    (deduped by *digest* -- the caller may warn again under the same digest
    for the raise-only drop check, which the dedup then silently absorbs, so
    a bad file state is still exactly one warning end to end). An unknown
    top-level key warns too but does not reject the recognized keys.
    """
    import yaml

    path = _policy_file_path(repo_root)
    digest = _digest(path)
    if digest == _MISSING_DIGEST:
        return PolicySnapshot(), digest

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        _warn_once(repo_root, digest, f"{POLICY_FILE_NAME} could not be read ({exc}); ignoring it")
        return PolicySnapshot(), digest

    data = raw if raw is not None else {}
    if not isinstance(data, dict):
        _warn_once(repo_root, digest, f"{POLICY_FILE_NAME} is not a mapping; ignoring it")
        return PolicySnapshot(), digest

    version = data.get("version")
    if version is not None and version != 1:
        _warn_once(
            repo_root,
            digest,
            f"{POLICY_FILE_NAME} has unsupported version {version!r} (expected 1); ignoring it",
        )
        return PolicySnapshot(), digest

    blocked_raw = data.get("blocked", [])
    sensitive_raw = data.get("sensitive", [])
    for key_name, value in (("blocked", blocked_raw), ("sensitive", sensitive_raw)):
        if not isinstance(value, list) or not all(isinstance(g, str) for g in value):
            _warn_once(
                repo_root,
                digest,
                f"{POLICY_FILE_NAME}'s {key_name!r} must be a list of strings; ignoring it",
            )
            return PolicySnapshot(), digest

    unknown = sorted(set(data) - _KNOWN_FILE_KEYS)
    if unknown:
        _warn_once(
            repo_root,
            digest,
            f"{POLICY_FILE_NAME} has unknown key(s) {unknown}; the recognized keys still apply",
        )

    return PolicySnapshot(blocked_globs=blocked_raw, sensitive_globs=sensitive_raw), digest


def _glob_rank_map(snapshot: PolicySnapshot) -> dict[str, str]:
    """``{key: state}`` shaped for ``classify_change``'s raise-only rank table.

    A glob changing CATEGORY (sensitive -> blocked or back) changes its key,
    so classify_change sees a removal + an addition rather than a same-key
    rank change -- a mixed change, which its "ambiguous/mixed -> weaken"
    fail-safe rule already covers correctly (deliberate; matches every other
    drift chokepoint in this codebase).
    """
    m = {f"blocked:{g}": "enforce" for g in snapshot.blocked_globs}
    m.update({f"sensitive:{g}": "monitor" for g in snapshot.sensitive_globs})
    return m


def load_file_policy(repo_root: str) -> FilePolicySource | None:
    """Load ``doberman.policy.yaml`` layered raise-only over the local pin.

    * No pin and nothing in the file today -> ``None`` (nothing to adopt;
      matches today's behavior byte-for-byte with no file at all).
    * No pin, file has something -> adopt it: apply + write the initial pin.
    * Pin exists, file only adds/keeps (or is identical) -> apply the file,
      rewrite the pin (auto-tighten is always allowed, no gate).
    * Pin exists, file drops anything (including "file is now gone/invalid")
      -> the effective snapshot is ``pin UNION file`` so nothing already
      enforced is lost; the pin is left untouched; warn once. The human path
      back down is ``doberman policy-file --accept`` (gated).
    """
    from doberman.policy.drift import Classification, classify_change

    file_snapshot, digest = _load_raw_file(repo_root)
    pin = _read_pin(repo_root)

    if pin is None:
        if not file_snapshot.blocked_globs and not file_snapshot.sensitive_globs:
            return None
        _write_pin(repo_root, file_snapshot)
        return FilePolicySource(file_snapshot)

    pin_snapshot = PolicySnapshot(blocked_globs=pin["blocked"], sensitive_globs=pin["sensitive"])
    classification = classify_change(_glob_rank_map(pin_snapshot), _glob_rank_map(file_snapshot))

    if classification is Classification.weaken:
        effective = PolicySnapshot(
            blocked_globs=pin_snapshot.blocked_globs + file_snapshot.blocked_globs,
            sensitive_globs=pin_snapshot.sensitive_globs + file_snapshot.sensitive_globs,
        )
        dropped = (set(pin_snapshot.blocked_globs) | set(pin_snapshot.sensitive_globs)) - (
            set(file_snapshot.blocked_globs) | set(file_snapshot.sensitive_globs)
        )
        _warn_once(
            repo_root,
            digest,
            f"{POLICY_FILE_NAME} drops {len(dropped)} constraint(s) held since the last "
            "approval; the stricter set stays in force until `doberman policy-file --accept`",
        )
        return FilePolicySource(effective)

    if classification is Classification.strengthen:
        _write_pin(repo_root, file_snapshot)
    return FilePolicySource(file_snapshot)


def effective_policy(repo_root: str) -> ResolvedPolicy:
    """The merged, effective policy for *repo_root* (F4.4 layering + #147's file).

    Memoized per (resolved repo root, policy-file digest, pin digest) so
    entry-point discovery does not re-run on every action; the key changes
    the instant either file's bytes change on disk (including a
    ``policy-file --accept`` rewriting the pin), so a stale cache entry can
    never mask a real update. With no file and nothing registered, sets
    nothing new: :attr:`ResolvedPolicy.is_empty` is then ``True``, exactly as
    it was before this source existed.
    """
    root = str(Path(repo_root).resolve())
    file_path, pin_path = _policy_file_path(root), _pin_path(root)
    lookup_key = (root, _digest(file_path), _digest(pin_path))
    cached = _effective_policy_cache.get(lookup_key)
    if cached is not None:
        return cached

    # load_file_policy() can itself WRITE the pin (first adoption / auto-
    # tighten) -- re-digest afterwards so the stored key reflects that, not
    # the pre-write state captured in lookup_key above.
    file_source = load_file_policy(root)
    result = resolve_policy([file_source] if file_source else [], discover=True)
    store_key = (root, _digest(file_path), _digest(pin_path))
    _effective_policy_cache[store_key] = result
    if store_key != lookup_key:
        _effective_policy_cache[lookup_key] = result
    return result
