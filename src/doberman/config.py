"""Local configuration loading (Feature 4+).

Reads the per-repo Doberman configuration from ``.doberman/`` — currently the
active agent role (``.doberman/role.yaml``). Configuration is **optional**: a
repo with no ``.doberman/role.yaml`` simply has no active role, and role-based
escalation stays dormant until the user sets one (F6 onboarding will write it).

Resolution rules for the active role (fail toward restriction):

* no ``.doberman/role.yaml``, and the D1 default-role opt-in is not set →
  ``None`` (role enforcement is opt-in; the role rule abstains so nothing
  benign is gratuitously blocked). This is the historical, byte-identical
  behavior for anyone who hasn't opted in.
* no ``.doberman/role.yaml``, and the opt-in *is* set (``doberman role
  enable-default``) → the built-in ``"default"`` role (a generic least-
  privilege role for a coding assistant; see ``builtin_roles.yaml``).
* ``role: <name>`` naming a built-in → that built-in. An explicit
  ``role.yaml`` always wins over the opt-in default, even when both are
  present.
* an *inline* custom role definition (``allowed``/``suspicious``/``blocked``) →
  that custom :class:`RoleDefinition` (a permissive custom role is allowed but
  logged — the user owns that choice).
* a named role that does not resolve, or a malformed file →
  :data:`MOST_RESTRICTIVE_ROLE` (a configured-but-unresolvable role must never
  silently widen scope).

This module is policy core: it must never import ``doberman.proxy``.
"""

import asyncio
import logging
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import yaml

from doberman.policy.checklist import PolicyDoc, recommend_policy
from doberman.policy.modes import DEFAULT_MODE, resolve_mode
from doberman.policy.preferences import PreferenceVector, vector_for
from doberman.roles.roles import (
    MOST_RESTRICTIVE_ROLE,
    RoleDefinition,
    load_builtin_roles,
)

logger = logging.getLogger("doberman.config")

#: Per-repo config directory (never committed; see .gitignore).
CONFIG_DIR = ".doberman"
ROLE_FILE = "role.yaml"
POLICY_FILE = "policies.yaml"

#: The built-in role name the D1 opt-in activates (see builtin_roles.yaml).
DEFAULT_ROLE_NAME = "default"


def _role_file_path(repo_root: str) -> Path:
    return Path(repo_root) / CONFIG_DIR / ROLE_FILE


def _policy_file_path(repo_root: str) -> Path:
    return Path(repo_root) / CONFIG_DIR / POLICY_FILE


@lru_cache(maxsize=8)
def _parse_role_yaml_data(raw: bytes) -> dict:
    """Parse+validate ``role.yaml``, cached on its raw content (#552).

    Same mechanism as #547's key cache (``functools.lru_cache``), keyed on
    the file's ``bytes`` rather than ``(path, mtime_ns)``: a same-mtime-tick
    rewrite (coarse filesystem clock resolution, or two fast writes) could
    hash to the same mtime key and serve stale data -- a raise-only
    violation. Content is the only key that can never be stale. The read
    itself stays outside this helper (see ``load_active_role``) so this
    function is pure parse+validate; ``maxsize=8`` bounds memory across a
    handful of repo roots/edits without unbounded growth. Raises straight
    through on parse failure -- never cached (``lru_cache`` only memoizes
    success).
    """
    return yaml.safe_load(raw.decode("utf-8")) or {}


def load_active_role(repo_root: str = ".") -> RoleDefinition | None:
    """Resolve the repo's active role, or ``None`` if none is configured.

    Never raises: a malformed config fails closed to the most-restrictive role
    rather than crashing the decision path.
    """
    path = _role_file_path(repo_root)
    if not path.exists():
        # No explicit role file: fall to the D1 opt-in default (still None
        # unless a human explicitly turned it on) — byte-identical to today
        # for anyone who hasn't opted in.
        if not default_role_enabled(repo_root):
            return None
        return load_builtin_roles().get(DEFAULT_ROLE_NAME, MOST_RESTRICTIVE_ROLE)

    try:
        # ponytail: one small read per decision; the parse+validate work below
        # is cached on the bytes themselves, so no staleness ceiling remains.
        raw = path.read_bytes()
        data = _parse_role_yaml_data(raw)
    except (OSError, yaml.YAMLError):
        logger.warning("could not read %s; falling back to the most-restrictive role", path)
        return MOST_RESTRICTIVE_ROLE

    if not isinstance(data, dict):
        logger.warning("%s is not a mapping; using the most-restrictive role", path)
        return MOST_RESTRICTIVE_ROLE

    # #199: optional 'protected_branches' key -- extra branch names for
    # DestructiveCommandRule to union into its force-push protection. Parsed
    # once here (independent of the role branch below) since it is a sibling
    # of 'role'/the inline keys, not part of either. Invalid → fail closed to
    # the most-restrictive role, same as every other malformed value here.
    extra_protected = _extra_protected_branches(data, path)
    if extra_protected is None:
        return MOST_RESTRICTIVE_ROLE

    # Inline custom role definition takes precedence over a named built-in.
    if any(key in data for key in ("allowed", "suspicious", "blocked")):
        try:
            role = RoleDefinition(
                name=str(data.get("role") or data.get("name") or "custom"),
                description=str(data.get("description", "")),
                allowed=tuple(data.get("allowed") or ()),
                suspicious=tuple(data.get("suspicious") or ()),
                blocked=tuple(data.get("blocked") or ()),
                protected_branches=extra_protected,
            )
        except (TypeError, ValueError):
            logger.warning("invalid inline role in %s; using the most-restrictive role", path)
            return MOST_RESTRICTIVE_ROLE
        if not role.blocked and not role.suspicious:
            logger.warning(
                "custom role %r declares no blocked/suspicious globs (permissive)", role.name
            )
        return role

    name = data.get("role")
    if not isinstance(name, str) or not name:
        logger.warning("%s has no usable 'role'; using the most-restrictive role", path)
        return MOST_RESTRICTIVE_ROLE

    builtins = load_builtin_roles()
    role = builtins.get(name)
    if role is None:
        logger.warning("unknown role %r; using the most-restrictive role", name)
        return MOST_RESTRICTIVE_ROLE
    if extra_protected:
        role = role.model_copy(
            update={"protected_branches": role.protected_branches + extra_protected}
        )
    return role


def _extra_protected_branches(data: dict, path: Path) -> tuple[str, ...] | None:
    """Parse+validate the optional 'protected_branches' role.yaml key (#199).

    A list of branch name strings, unioned into DestructiveCommandRule's
    protected set (see RoleDefinition.protected_branches) -- raise-only by
    construction, since a union can only ever add names, never drop the
    built-in DEFAULT_PROTECTED_BRANCHES. Absent/``None`` is valid (``()`` --
    byte-identical to before this key existed). A non-list value, or any
    non-string entry, is a schema error: ``None`` is the fail-closed sentinel
    the caller uses to fall back to MOST_RESTRICTIVE_ROLE, same as every other
    malformed role.yaml value in this module.

    ponytail: exact string match only, no glob patterns -- YAGNI until a real
    need for wildcard branch names shows up (would also need
    ``_git_force_push_to_protected``'s matching to grow glob support).
    """
    raw = data.get("protected_branches")
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(b, str) for b in raw):
        logger.warning(
            "%s has an invalid 'protected_branches' (must be a list of branch name "
            "strings); using the most-restrictive role",
            path,
        )
        return None
    return tuple(raw)


def load_policy(repo_root: str = ".") -> PolicyDoc | None:
    """Load the saved policy checklist, or ``None`` if none is saved.

    Never raises: a corrupt/unreadable file logs and returns ``None`` (callers
    fall back to the recommended defaults), never crashes the decision path.
    """
    path = _policy_file_path(repo_root)
    if not path.exists():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("could not read %s; ignoring saved policy", path)
        return None
    if not isinstance(data, dict):
        logger.warning("%s is not a mapping; ignoring saved policy", path)
        return None
    try:
        return PolicyDoc.from_mapping(data)
    except (TypeError, ValueError, KeyError):
        logger.warning("invalid policy in %s; ignoring saved policy", path)
        return None


def save_policy(doc: PolicyDoc, repo_root: str = ".", *, ledger_ts: str | None = None) -> None:
    """Persist ``doc`` to ``.doberman/policies.yaml`` (creating the dir).

    Writes via a temp file + replace so a failed write never corrupts a prior
    valid policy file. Afterwards the saved policy is recorded in the policy
    catalogue (``.doberman/policies.db``) as the version now in force, linked to
    ``ledger_ts`` — the ``policy_changes`` row that authorised it — when the
    caller has one.
    """
    path = _policy_file_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(doc.to_mapping(), sort_keys=False)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    _record_policy_version(doc, repo_root, ledger_ts)


def _record_policy_version(doc: PolicyDoc, repo_root: str, ledger_ts: str | None) -> None:
    """Best-effort catalogue append for a policy that was just saved (never raises).

    The gate has just run, so the on-disk enforcement is ledger-legitimate by
    construction; only the soften timer is applied (pure), which is why this does
    not call :func:`resolve_enforcement_sync` — that fails closed to ``enforce``
    inside a running event loop (the dashboard reaches here inside one) and would
    record a false version. Imported lazily to avoid a config<->storage cycle.
    """
    try:
        from doberman import __version__
        from doberman.storage.policy_catalogue import (
            ORIGIN_CHANGE,
            build_snapshot,
            effective_enforcement_at_save,
            record_version,
        )

        now = datetime.now(timezone.utc)
        snapshot = build_snapshot(
            doc,
            load_active_role(repo_root),
            effective_enforcement_at_save(doc, now),
            __version__,
        )
        record_version(repo_root, snapshot, origin=ORIGIN_CHANGE, ledger_ts=ledger_ts, now=now)
    except Exception as exc:  # noqa: BLE001 — the catalogue is observational; a save must never fail for it
        logger.warning(
            "policy catalogue update failed after saving the policy; continuing: %s", exc
        )


def load_mode(repo_root: str = ".") -> str:
    """Return the active security mode name (default Balanced).

    Reads the mode from the saved policy; an unknown/garbage stored mode falls
    back to the default rather than failing.
    """
    doc = load_policy(repo_root)
    if doc is None:
        return DEFAULT_MODE.value
    try:
        return resolve_mode(doc.mode).value
    except ValueError:
        logger.warning("saved mode %r is unknown; using %s", doc.mode, DEFAULT_MODE.value)
        return DEFAULT_MODE.value


def load_enforcement(repo_root: str = ".") -> tuple[str, float | None, str]:
    """The on-disk enforcement fields: ``(state, expires_at, revert_target)``.

    Defaults to full ``enforce`` when no policy is saved. This is the RAW on-disk
    claim — a caller on the decision path MUST pass it through
    :func:`doberman.policy.drift.effective_enforcement` (ledger-verified,
    tamper-clamped) before acting on it, never trust the field directly.
    """
    doc = load_policy(repo_root)
    if doc is None:
        return "enforce", None, "enforce"
    return doc.enforcement, doc.enforcement_expires_at, doc.enforcement_revert


def resolve_enforcement_sync(repo_root: str = ".") -> str:
    """Synchronous resolution of the effective enforcement state for sync callers.

    The host-hook decision path (``evaluate_pre``) runs synchronously in a
    one-shot hook process (no running event loop), but the ledger cross-check in
    :func:`doberman.policy.drift.effective_enforcement` is async. The common
    ``enforce`` case short-circuits with zero I/O (matching that clamp), so the
    hot path is untouched; only a softened deployment pays one ``asyncio.run``.
    Any failure — including being called while an event loop is already running —
    fails closed to ``enforce``.
    """
    from doberman.policy.drift import effective_enforcement

    enforcement, expires_at, revert = load_enforcement(repo_root)
    if str(enforcement).strip().lower() == "enforce":
        return "enforce"
    try:
        return asyncio.run(
            effective_enforcement(
                repo_root,
                enforcement=enforcement,
                expires_at=expires_at,
                revert=revert,
            )
        )
    except Exception:  # noqa: BLE001 — the sync bridge fails closed to enforce
        logger.warning("sync enforcement resolution failed; defaulting to enforce")
        return "enforce"


def load_preferences(repo_root: str = ".") -> PreferenceVector:
    """The active preference vector (SL5): declared, else the mode's preset.

    Never raises — with no saved policy (or no declared vector) the active
    mode's preset applies, and an unknown stored mode resolves to the strictest
    preset inside :func:`vector_for`.
    """
    doc = load_policy(repo_root)
    if doc is not None and doc.preferences is not None:
        return doc.preferences
    return vector_for(load_mode(repo_root))


def save_preferences(
    vector: PreferenceVector, repo_root: str = ".", *, ledger_ts: str | None = None
) -> None:
    """Persist the declared preference vector into the policy document."""
    doc = load_policy(repo_root) or recommend_policy()
    save_policy(doc.with_preferences(vector), repo_root, ledger_ts=ledger_ts)


def default_role_enabled(repo_root: str = ".") -> bool:
    """Whether the D1 opt-in default role is turned on for this repo.

    Fails closed to ``False`` (dormant) on any missing/malformed
    ``.doberman/policies.yaml`` — :func:`load_policy` already returns ``None``
    for a corrupt file, and :meth:`PolicyDoc.from_mapping` only ever honors a
    literal boolean ``True`` for the field, so a garbage value never widens
    scope.
    """
    doc = load_policy(repo_root)
    return doc.default_role_enabled if doc is not None else False


def save_default_role_enabled(
    enabled: bool, repo_root: str = ".", *, ledger_ts: str | None = None
) -> bool:
    """Persist the D1 opt-in flag; returns the value written.

    Mirrors :func:`save_mode` — reuses the saved policy if one exists, else
    starts from the recommended defaults.
    """
    doc = load_policy(repo_root) or recommend_policy()
    save_policy(doc.with_default_role_enabled(enabled), repo_root, ledger_ts=ledger_ts)
    return bool(enabled)


def save_mode(name: str, repo_root: str = ".", *, ledger_ts: str | None = None) -> str:
    """Validate and persist the security mode; returns the canonical name.

    Raises ``ValueError`` on an unknown mode (the caller surfaces the error).
    """
    mode = resolve_mode(name)
    doc = load_policy(repo_root) or recommend_policy()
    save_policy(doc.with_mode(mode.value), repo_root, ledger_ts=ledger_ts)
    return mode.value


#: The only valid values for the S1 message-tone display preference.
MESSAGE_TONES: tuple[str, ...] = ("human", "technical")


def load_message_tone(repo_root: str = ".") -> str:
    """The active AUTH challenge message tone ("human" unless set to "technical").

    Never raises: a missing/corrupt saved policy resolves to "human", same as
    the field's own fail-closed default (see PolicyDoc.from_mapping).
    """
    doc = load_policy(repo_root)
    return doc.message_tone if doc is not None else "human"


def save_message_tone(tone: str, repo_root: str = ".") -> str:
    """Validate and persist the message tone; returns the canonical value.

    Raises ``ValueError`` on an unknown tone. Unlike ``save_default_role_enabled``
    and ``save_mode``'s enforcement-softening siblings, this is a purely cosmetic
    display preference with no strengthen/weaken ordering — it is written
    directly, with NO drift/possession-factor gate (see doberman.policy.drift).
    """
    if tone not in MESSAGE_TONES:
        raise ValueError(f"unknown message tone {tone!r}; choose one of {MESSAGE_TONES}")
    doc = load_policy(repo_root) or recommend_policy()
    save_policy(doc.with_message_tone(tone), repo_root)
    return tone


def load_approval_memory_seconds(repo_root: str = ".") -> int:
    """Return the bounded exact-approval TTL (default five minutes)."""
    doc = load_policy(repo_root)
    if doc is not None:
        return doc.approval_memory_seconds
    # A missing policy uses the product default; an existing but unreadable or
    # malformed policy disables memory so corruption cannot silently loosen auth.
    return 0 if _policy_file_path(repo_root).exists() else 300
