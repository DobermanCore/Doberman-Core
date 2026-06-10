"""Generic inference layer (SL2): populate the action algebra for ANY action.

Infers the universal algebra dimensions from universally observable signals —
the tool's declared name, the argument shapes, and the destination — with **no
application-specific knowledge required**. This is what carries an unrecognized
application type: coverage never depends on an adapter existing (adapters, SL3,
only *sharpen* the result afterwards).

SECURITY: **tool metadata is untrusted** (tool-poisoning; Huang et al. 2026,
arXiv:2603.22489). A tool's name or description may push sensitivity UP, never
down — a tool claiming to be "safe" or "read-only" changes nothing. Ambiguity
always resolves to the HIGHER class with LOWER confidence, never to benign.
Reuses the objective layer's (F3) secret/destination classifiers as
*classifiers* rather than re-implementing them.

This module is policy core: it must never import ``doberman.proxy``.
"""

import re
from typing import Any

from doberman.engine.rules import secrets as _secret_classifiers
from doberman.models import (
    ActionType,
    Algebra,
    Capability,
    SecurityObject,
    TargetClass,
)

#: Severity ordering for capabilities — used to resolve ambiguity (the more
#: severe verb wins, with reduced confidence). ``other`` is lowest so any
#: concrete signal beats it.
CAPABILITY_SEVERITY: dict[Capability, int] = {
    Capability.other: 0,
    Capability.read: 1,
    Capability.mutate: 2,
    Capability.configure: 3,
    Capability.send: 4,
    Capability.execute: 5,
    Capability.grant: 6,
    Capability.delete: 7,
}

if set(CAPABILITY_SEVERITY) != set(Capability):  # pragma: no cover — import-time guard
    raise RuntimeError("CAPABILITY_SEVERITY must cover every Capability member")

# Verb-keyword classifiers over tool names / argument key names, checked in
# DESCENDING severity so a name carrying several verbs resolves to the most
# severe one (ambiguity raises, never lowers).
_CAPABILITY_KEYWORDS: tuple[tuple[Capability, re.Pattern[str]], ...] = (
    (
        Capability.delete,
        re.compile(r"(?i)delete|remove|drop|destroy|purge|erase|wipe|(?:^|[_\-])rm(?:[_\-]|$)"),
    ),
    (
        Capability.grant,
        re.compile(r"(?i)grant|chmod|chown|permission|authoriz|privilege|sudo"),
    ),
    (
        Capability.execute,
        re.compile(r"(?i)exec|shell|spawn|invoke|launch|(?:^|[_\-])(?:run|bash|sh)(?:[_\-]|$)"),
    ),
    (
        Capability.send,
        re.compile(r"(?i)send|mail|post|publish|upload|share|submit|broadcast|message|tweet"),
    ),
    (
        Capability.configure,
        re.compile(r"(?i)config|setting|option|toggle|enable|disable"),
    ),
    (
        Capability.mutate,
        re.compile(r"(?i)write|update|patch|edit|create|insert|append|rename|move|copy"),
    ),
    (
        Capability.read,
        re.compile(
            r"(?i)read|(?:^|[_\-])(?:get|list|cat|stat|head)(?:[_\-]|$)|fetch|view|search|query"
        ),
    ),
)

#: ActionType → Capability when normalize already classified the tool family.
_ACTION_TYPE_CAPABILITY: dict[ActionType, Capability] = {
    ActionType.file_read: Capability.read,
    ActionType.file_write: Capability.mutate,
    ActionType.file_delete: Capability.delete,
    ActionType.shell_exec: Capability.execute,
    ActionType.network_request: Capability.send,
    ActionType.git_op: Capability.send,  # conservative: git can push (egress)
    ActionType.package_install: Capability.execute,  # installs run code
    ActionType.memory_write: Capability.mutate,
    ActionType.final_output: Capability.send,
}

# Confidence levels per agreement strength of the observed signals.
_CONF_STRONG = 0.9  # two independent signals agree
_CONF_SINGLE = 0.6  # one signal only
_CONF_AMBIGUOUS = 0.5  # signals conflict — class raised, confidence lowered
_CONF_WEAK = 0.2  # nothing observable

# Description keywords that may RAISE the target class (a description claiming
# access to credential material). Benign claims ("safe", "read-only") are
# deliberately ignored — untrusted metadata can never lower a classification.
_DESCRIPTION_SENSITIVE = re.compile(
    r"(?i)secret|credential|password|token|private[ _-]?key|api[ _-]?key"
)

# Shapes a target string can take (used for the `internal` tier: a concrete
# workspace resource that is neither secret- nor sensitive-shaped).
_PATH_LIKE = re.compile(r"""(?x) ^(?:\.{0,2}[/\\~]) | [/\\] | ^[\w.\-]+\.\w{1,8}$ """)
_ADDRESS_LIKE = re.compile(
    r"""(?x) ^\w+:// | ^[\w.\-]+@[\w.\-]+$ | ^[\w\-]+(?:\.[\w\-]+)+(?::\d+)?(?:/|$) """
)


def _keyword_capability(text: str) -> Capability | None:
    """Most-severe capability whose verb keywords appear in ``text``."""
    for capability, pattern in _CAPABILITY_KEYWORDS:
        if pattern.search(text):
            return capability
    return None


def infer_capability(
    action: SecurityObject, raw_arguments: dict[str, Any] | None
) -> tuple[Capability, float]:
    """Infer the abstract verb from the tool's interface (name + arg keys).

    Two independent signals: the action-type family normalize derived from the
    tool name, and a severity-ordered verb-keyword scan over the tool name plus
    argument key names. Agreement → high confidence; conflict → the MORE severe
    capability at lower confidence (ambiguity raises, never lowers); neither →
    ``other`` at minimal confidence.
    """
    arg_keys = " ".join(str(k) for k in (raw_arguments or action.raw_args_redacted or {}))
    keyword = _keyword_capability(f"{action.tool_name} {arg_keys}")
    typed = _ACTION_TYPE_CAPABILITY.get(action.action_type)

    if keyword is not None and typed is not None:
        if keyword is typed:
            return keyword, _CONF_STRONG
        more_severe = (
            keyword if CAPABILITY_SEVERITY[keyword] >= CAPABILITY_SEVERITY[typed] else typed
        )
        return more_severe, _CONF_AMBIGUOUS
    if keyword is not None:
        return keyword, _CONF_SINGLE
    if typed is not None:
        return typed, _CONF_SINGLE
    return Capability.other, _CONF_WEAK


def _argument_strings(action: SecurityObject, raw_arguments: dict[str, Any] | None) -> list[str]:
    """Every string reachable in the call (raw args when available, else the
    redacted view + target) — the corpus the shape classifiers scan."""
    strings: list[str] = []
    source = raw_arguments if isinstance(raw_arguments, dict) else action.raw_args_redacted
    strings.extend(_secret_classifiers._iter_strings(source))
    if action.target:
        strings.append(str(action.target))
    return strings


def infer_target_class(
    action: SecurityObject,
    raw_arguments: dict[str, Any] | None,
    tool_description: str | None = None,
) -> tuple[TargetClass, float]:
    """Infer the sensitivity tier of what the action touches.

    Signals, strongest first: secret-store paths and strong credential shapes
    (F3 classifiers) → ``secret``; high-entropy material or a flagged sensitive
    asset → ``sensitive``; a concrete path/address target → ``internal``;
    nothing observable → ``unknown`` at minimal confidence. A tool DESCRIPTION
    may only ever raise the tier (to ``sensitive``) — never lower it.
    """
    strings = _argument_strings(action, raw_arguments)

    if _secret_classifiers._path_is_secret_store(
        action.target
    ) or _secret_classifiers._strong_secret_present(strings):
        return TargetClass.secret, _CONF_STRONG

    inferred: tuple[TargetClass, float]
    if action.sensitive_asset or _secret_classifiers._weak_secret_present(strings):
        inferred = (TargetClass.sensitive, _CONF_SINGLE)
    elif action.target and (
        _PATH_LIKE.search(str(action.target)) or _ADDRESS_LIKE.search(str(action.target))
    ):
        inferred = (TargetClass.internal, _CONF_SINGLE)
    else:
        inferred = (TargetClass.unknown, _CONF_WEAK)

    # Untrusted metadata may RAISE only: a description admitting credential
    # access lifts internal/unknown to sensitive; nothing in a description can
    # lower a tier already inferred from the call itself.
    if tool_description and _DESCRIPTION_SENSITIVE.search(tool_description):
        from doberman.models import TARGET_CLASS_ORDER

        if TARGET_CLASS_ORDER[inferred[0]] < TARGET_CLASS_ORDER[TargetClass.sensitive]:
            return TargetClass.sensitive, min(inferred[1], _CONF_SINGLE)
    return inferred


def infer_algebra(
    action: SecurityObject,
    raw_arguments: dict[str, Any] | None = None,
    tool_description: str | None = None,
) -> Algebra:
    """Build the full algebra for ``action`` from observable signals. Never raises.

    Any internal failure returns the conservative default :class:`Algebra`
    (all-unknown, zero confidence) — an inference bug fails toward caution,
    never toward benign.
    """
    try:
        capability, cap_conf = infer_capability(action, raw_arguments)
        target_class, target_conf = infer_target_class(action, raw_arguments, tool_description)
        confidence = max(0.0, min(1.0, (cap_conf + target_conf) / 2))
        return Algebra(
            capability=capability,
            target_class=target_class,
            classification_confidence=confidence,
        )
    except Exception:  # noqa: BLE001 — inference must never break the decision path
        return Algebra()
