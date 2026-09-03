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

import ipaddress
import re
from typing import Any

from doberman.engine.rules import destinations as _dest_classifiers
from doberman.engine.rules import secrets as _secret_classifiers
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    Provenance,
    Reversibility,
    SecurityObject,
    SourceContext,
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
    r"(?i)secret|credential|password|private[ _-]?key|api[ _-]?key"
    r"|(?:api|access|auth|bearer|oauth|session|refresh)[ _-]?token"
)

# Shapes a target string can take (used for the `internal` tier: a concrete
# workspace resource that is neither secret- nor sensitive-shaped).
_PATH_LIKE = re.compile(r"""(?x) ^(?:\.{0,2}[/\\~]) | [/\\] | ^[\w.\-]+\.\w{1,8}$ """)
_ADDRESS_LIKE = re.compile(
    r"""(?x) ^\w+:// | ^[\w.\-]+@[\w.\-]+$ | ^[\w\-]+(?:\.[\w\-]+)+(?::\d+)?(?:/|$) """
)


# --- conservative default for unrecognized application types (SL3.2) -----------

#: Below this classification confidence an action counts as UNCLASSIFIED and is
#: handled conservatively: its sensitivity is floored at "elevated" and it
#: contributes a bounded novelty signal to the surprise term.
CONFIDENCE_FLOOR = 0.4

#: The bounded novelty contribution an unclassified action adds to surprise.
#: One constant per ACTION (never per dimension, never compounding) so a
#: brand-new-but-benign application type leans cautious without storming.
NOVELTY_BONUS = 0.2

#: Sensitivity tier per target class, in [0, 1]. ``unknown`` deliberately sits
#: in elevated territory — unclassified never resolves to benign.
SENSITIVITY_BY_TARGET: dict[TargetClass, float] = {
    TargetClass.public: 0.1,
    TargetClass.internal: 0.4,
    TargetClass.unknown: 0.6,
    TargetClass.sensitive: 0.7,
    TargetClass.secret: 1.0,
}

#: The sensitivity floor applied to any unclassified action.
UNCLASSIFIED_SENSITIVITY_FLOOR = 0.6

if set(SENSITIVITY_BY_TARGET) != set(TargetClass):  # pragma: no cover — import-time guard
    raise RuntimeError("SENSITIVITY_BY_TARGET must cover every TargetClass member")


def is_unclassified(algebra: Algebra) -> bool:
    """True when neither the generic layer nor an adapter classified confidently."""
    return algebra.classification_confidence < CONFIDENCE_FLOOR


def novelty_bonus(algebra: Algebra) -> float:
    """Bounded novelty contribution for the surprise term (0 when classified).

    An unrecognized action is itself mildly anomalous; the bonus is a single
    bounded constant so it biases toward step-up without dominating the score.
    """
    return NOVELTY_BONUS if is_unclassified(algebra) else 0.0


def sensitivity(algebra: Algebra) -> float:
    """The algebra's sensitivity term in [0, 1] (the SL7 engine's second axis).

    Maps the target class to its tier; an UNCLASSIFIED action is floored at
    elevated sensitivity — low confidence biases toward step-up, never toward
    allow, and no input ever resolves to zero.
    """
    base = SENSITIVITY_BY_TARGET[algebra.target_class]
    if is_unclassified(algebra):
        return max(base, UNCLASSIFIED_SENSITIVITY_FLOOR)
    return base


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


# --- destination / provenance / blast radius / reversibility (SL2.2) ----------

#: Action families whose business is data egress: with no parseable destination
#: at all they classify ``unknown_external`` (conservative), never ``none``.
_EGRESS_ACTIONS = frozenset(
    {ActionType.network_request, ActionType.git_op, ActionType.final_output}
)

#: SourceContext → (Provenance, confidence). The origin being UNCLEAR defaults
#: to ``untrusted_data`` at low confidence (fail toward caution, never toward
#: trusted); ``tool_output`` is ``mixed`` (instruction passed through content
#: the agent ingested from tools).
_SOURCE_PROVENANCE: dict[SourceContext, tuple[Provenance, float]] = {
    SourceContext.user: (Provenance.trusted_instruction, 0.8),
    SourceContext.tool_output: (Provenance.mixed, 0.7),
    SourceContext.github_issue: (Provenance.untrusted_data, 0.7),
    SourceContext.readme: (Provenance.untrusted_data, 0.7),
    SourceContext.webpage: (Provenance.untrusted_data, 0.7),
    SourceContext.email: (Provenance.untrusted_data, 0.7),
    SourceContext.unknown: (Provenance.untrusted_data, 0.3),
}

if set(_SOURCE_PROVENANCE) != set(SourceContext):  # pragma: no cover — import-time guard
    raise RuntimeError("_SOURCE_PROVENANCE must cover every SourceContext member")

# Volume signals: argument keys that carry recipient/target collections, glob
# metacharacters, and recursive shell flags.
_RECIPIENT_KEYS = ("to", "cc", "bcc", "recipients", "emails", "targets", "ids", "user_ids")
_GLOB_CHARS = re.compile(r"[*\[]")
_RECURSIVE_SHELL = re.compile(r"(?i)(?:^|\s)-[rf]+\b|--recursive\b|\*\*?")

# Shell text whose effects are effectively irreversible (destroyed data /
# rewritten remote history). Matching is on the command string only.
_IRREVERSIBLE_SHELL = re.compile(
    r"(?i)\brm\b|\bshred\b|\bmkfs\b|\bdd\b\s+if=|drop\s+(?:table|database)"
    r"|\btruncate\b|push\b[^;&|\n]{0,40}--force|--hard\b(?!-)"
    # ponytail: 40-char budget between `push` and `--force` is a tunable heuristic
)

# Blast-radius tier boundaries on an observed target/recipient count.
_FEW_AT_MOST = 5
_MANY_AT_MOST = 50


def _is_internal_host(host: str) -> bool:
    """Loopback / private-range / link-local style hosts count as internal."""
    bare = host.strip("[]")
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        return bare == "localhost" or bare.endswith((".local", ".internal", ".lan"))
    return ip.is_loopback or ip.is_private or ip.is_link_local


def infer_destination_class(action: SecurityObject) -> tuple[DestinationClass, float]:
    """Classify where data goes, reusing the F3 destination parsing.

    Punycode/homoglyphs, embedded credentials, and IP literals are handled by
    the same hardened parser the objective rule uses. Unknowns are conservative:
    an egress-family action with no parseable destination is
    ``unknown_external``, never ``none``.
    """
    destination = action.external_destination
    if not destination and action.action_type in _EGRESS_ACTIONS and action.target:
        destination = str(action.target)
    # A URL-shaped target is a destination signal regardless of the action-type
    # family (a "send_email"-style tool maps to `other` but still egresses).
    if not destination and action.target and "://" in str(action.target):
        destination = str(action.target)

    if not destination:
        if action.action_type in _EGRESS_ACTIONS:
            return DestinationClass.unknown_external, _CONF_WEAK
        return DestinationClass.none, 0.8

    host, had_credentials, _is_mailbox = _dest_classifiers._parse_host(destination)
    if host is None:
        return DestinationClass.unknown_external, _CONF_AMBIGUOUS
    if _is_internal_host(host):
        return DestinationClass.internal, 0.8
    if had_credentials or _dest_classifiers._is_ip_literal(host):
        return DestinationClass.unknown_external, 0.7
    if _dest_classifiers._registered_match(host, _dest_classifiers.TRUSTED_HOSTS):
        return DestinationClass.known_external, _CONF_STRONG
    return DestinationClass.unknown_external, 0.7


def infer_provenance(action: SecurityObject) -> tuple[Provenance, float]:
    """Map the action's source context to a provenance class (cautious default)."""
    return _SOURCE_PROVENANCE[action.source_context]


def _recipient_count(raw_arguments: dict[str, Any] | None) -> int:
    """Total size of recipient/target collections in the arguments (0 if none)."""
    if not isinstance(raw_arguments, dict):
        return 0
    total = 0
    for key in _RECIPIENT_KEYS:
        value = raw_arguments.get(key)
        if isinstance(value, (list, tuple)):
            total += len(value)
    return total


def _count_to_blast(count: int) -> BlastRadius:
    if count <= 1:
        return BlastRadius.single
    if count <= _FEW_AT_MOST:
        return BlastRadius.few
    if count <= _MANY_AT_MOST:
        return BlastRadius.many
    return BlastRadius.mass


def infer_blast_radius(
    action: SecurityObject, raw_arguments: dict[str, Any] | None
) -> tuple[BlastRadius, float]:
    """Infer how many entities the action touches from volume signals.

    Explicit counts (target arrays, recipient lists) map to tiers; glob
    metacharacters or recursive shell flags imply an UNKNOWN-but-large reach
    (``many``, low confidence); a single concrete target is ``single``.
    """
    counted = 0
    meta_count = action.metadata.get("target_count") if isinstance(action.metadata, dict) else None
    if isinstance(meta_count, int) and meta_count > 0:
        counted = meta_count
    counted += _recipient_count(raw_arguments)
    if counted:
        return _count_to_blast(counted), 0.8

    target = str(action.target) if action.target else ""
    if target:
        if action.action_type is ActionType.shell_exec and _RECURSIVE_SHELL.search(target):
            return BlastRadius.many, _CONF_AMBIGUOUS
        if _GLOB_CHARS.search(target):
            return BlastRadius.many, _CONF_AMBIGUOUS
        return BlastRadius.single, 0.7
    return BlastRadius.unknown, _CONF_WEAK


def infer_reversibility(
    action: SecurityObject, raw_arguments: dict[str, Any] | None = None
) -> Reversibility:
    """Reversibility from operation semantics (`low` = hardest to undo).

    Deletions and destructive shell patterns (rm/shred/drop/force-push/--hard)
    are ``low``; pure reads are ``high`` (nothing to undo); anything else keeps
    the action's existing assessment (default ``medium``).
    """
    capability, _ = infer_capability(action, raw_arguments)
    if capability is Capability.delete:
        return Reversibility.low
    if action.action_type is ActionType.shell_exec and action.target:
        if _IRREVERSIBLE_SHELL.search(str(action.target)):
            return Reversibility.low
    if capability is Capability.read:
        return Reversibility.high
    return action.reversibility


def infer_algebra(
    action: SecurityObject,
    raw_arguments: dict[str, Any] | None = None,
    tool_description: str | None = None,
) -> Algebra:
    """Build the full algebra for ``action`` from observable signals. Never raises.

    Any internal failure returns the conservative default :class:`Algebra`
    (all-unknown, zero confidence) — an inference bug fails toward caution,
    never toward benign. ``classification_confidence`` is the mean of the
    per-dimension signal strengths.
    """
    try:
        capability, cap_conf = infer_capability(action, raw_arguments)
        target_class, target_conf = infer_target_class(action, raw_arguments, tool_description)
        destination_class, dest_conf = infer_destination_class(action)
        provenance, prov_conf = infer_provenance(action)
        blast_radius, blast_conf = infer_blast_radius(action, raw_arguments)
        confidence = (cap_conf + target_conf + dest_conf + prov_conf + blast_conf) / 5
        return Algebra(
            capability=capability,
            target_class=target_class,
            destination_class=destination_class,
            blast_radius=blast_radius,
            provenance=provenance,
            classification_confidence=max(0.0, min(1.0, confidence)),
        )
    except Exception:  # noqa: BLE001 — inference must never break the decision path
        return Algebra()
