"""Local configuration loading (Feature 4+).

Reads the per-repo Doberman configuration from ``.doberman/`` — currently the
active agent role (``.doberman/role.yaml``). Configuration is **optional**: a
repo with no ``.doberman/role.yaml`` simply has no active role, and role-based
escalation stays dormant until the user sets one (F6 onboarding will write it).

Resolution rules for the active role (fail toward restriction):

* no ``.doberman/role.yaml`` → ``None`` (role enforcement is opt-in; the role
  rule abstains so nothing benign is gratuitously blocked).
* ``role: <name>`` naming a built-in → that built-in.
* an *inline* custom role definition (``allowed``/``suspicious``/``blocked``) →
  that custom :class:`RoleDefinition` (a permissive custom role is allowed but
  logged — the user owns that choice).
* a named role that does not resolve, or a malformed file →
  :data:`MOST_RESTRICTIVE_ROLE` (a configured-but-unresolvable role must never
  silently widen scope).

This module is policy core: it must never import ``doberman.proxy``.
"""

import logging
from pathlib import Path

import yaml

from doberman.policy.checklist import PolicyDoc, recommend_policy
from doberman.policy.modes import DEFAULT_MODE, resolve_mode
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


def _role_file_path(repo_root: str) -> Path:
    return Path(repo_root) / CONFIG_DIR / ROLE_FILE


def _policy_file_path(repo_root: str) -> Path:
    return Path(repo_root) / CONFIG_DIR / POLICY_FILE


def load_active_role(repo_root: str = ".") -> RoleDefinition | None:
    """Resolve the repo's active role, or ``None`` if none is configured.

    Never raises: a malformed config fails closed to the most-restrictive role
    rather than crashing the decision path.
    """
    path = _role_file_path(repo_root)
    if not path.exists():
        return None

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("could not read %s; falling back to the most-restrictive role", path)
        return MOST_RESTRICTIVE_ROLE

    if not isinstance(data, dict):
        logger.warning("%s is not a mapping; using the most-restrictive role", path)
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
    return role


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


def save_policy(doc: PolicyDoc, repo_root: str = ".") -> None:
    """Persist ``doc`` to ``.doberman/policies.yaml`` (creating the dir).

    Writes via a temp file + replace so a failed write never corrupts a prior
    valid policy file.
    """
    path = _policy_file_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(doc.to_mapping(), sort_keys=False)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


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


def save_mode(name: str, repo_root: str = ".") -> str:
    """Validate and persist the security mode; returns the canonical name.

    Raises ``ValueError`` on an unknown mode (the caller surfaces the error).
    """
    mode = resolve_mode(name)
    doc = load_policy(repo_root) or recommend_policy()
    save_policy(doc.with_mode(mode.value), repo_root)
    return mode.value
