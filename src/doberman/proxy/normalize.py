"""Normalize raw MCP tool calls into immutable :class:`SecurityObject`\\ s.

The chokepoint hands every intercepted call to :func:`normalize` before the
decision point. Normalization must NEVER raise on weird input: on any
failure it produces a conservative object (``action_type=other``,
``risk=high``) so the engine fails toward caution, and it never copies raw
argument values into the object — values are redacted first.

The redaction here is a deliberate stopgap (length- and shape-based); real
secret detection arrives with Feature 3's rules.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from doberman.models import ActionType, ReasonCode, Risk, SecurityObject, SourceContext
from doberman.subjective.adapters import apply_adapters
from doberman.subjective.infer import infer_algebra, infer_reversibility

REDACTED = "<redacted>"

# Values longer than this are replaced wholesale — avoids logging huge blobs.
MAX_VALUE_LENGTH = 256

# Obvious secret shapes (stopgap until Feature 3's secret rules):
# long unbroken token-ish strings, common key prefixes, key=value secrets.
_SECRET_SHAPES = re.compile(
    r"""
    (?:AKIA[0-9A-Z]{16})                              # AWS access key id
    | (?:sk-[A-Za-z0-9_\-]{16,})                      # api secret key prefix
    | (?:gh[pousr]_[A-Za-z0-9]{20,})                  # github tokens
    | (?:-----BEGIN[ A-Z]*PRIVATE\ KEY-----)          # PEM private key
    | (?:\b[A-Za-z0-9+/_\-]{40,}\b)                   # long unbroken token
    """,
    re.VERBOSE,
)

# Argument keys whose values are secret-ish regardless of shape.
_SENSITIVE_KEYS = re.compile(
    r"(?:pass(?:word)?|secret|token|api[_-]?key|credential|auth|bearer|private[_-]?key)",
    re.I,
)

# Don't bother shape-matching values shorter than the shortest secret shape.
_MIN_SECRET_LENGTH = 16

# Redaction recursion cap: anything nested deeper is redacted wholesale.
_MAX_REDACTION_DEPTH = 16

_TOOL_PREFIX_MAP: list[tuple[tuple[str, ...], ActionType]] = [
    (("fs_read", "file_read", "read_file"), ActionType.file_read),
    (("fs_write", "file_write", "write_file"), ActionType.file_write),
    (("fs_delete", "file_delete", "delete_file", "fs_rm"), ActionType.file_delete),
    (("shell_exec", "shell", "bash", "exec"), ActionType.shell_exec),
    (("net_", "http_", "fetch", "request"), ActionType.network_request),
    (("git_",), ActionType.git_op),
]

# Keys commonly carrying the action's target, in priority order.
_TARGET_KEYS = ("path", "file", "filename", "url", "command", "target")

# Arg keys whose value is an outbound recipient/address/channel, in priority
# order. Generic (matched by key shape, never tool name) so domain tools that
# normalize to ActionType.other still carry a destination for the trifecta /
# secret-exfil floors. Mirrors the benchmark adapter's _DEST_KEYS.
_EGRESS_DEST_KEYS: tuple[str, ...] = (
    "url",
    "recipient",
    "recipients",
    "to",
    "email",
    "address",
    "phone",
    "channel",
    "repo",
    "remote",
)


def _map_action_type(tool_name: str) -> ActionType:
    name = tool_name.lower()
    if "install" in name:
        return ActionType.package_install
    for prefixes, action_type in _TOOL_PREFIX_MAP:
        if name.startswith(prefixes):
            return action_type
    return ActionType.other


def _redact_value(key: str, value: Any, depth: int = 0) -> Any:
    """Redact a single argument value (never raises)."""
    if depth > _MAX_REDACTION_DEPTH:
        return REDACTED  # too deep to inspect — redact wholesale
    if isinstance(value, str):
        if _SENSITIVE_KEYS.search(key):
            return REDACTED
        if len(value) > MAX_VALUE_LENGTH:
            return REDACTED
        if len(value) >= _MIN_SECRET_LENGTH and _SECRET_SHAPES.search(value):
            return REDACTED
        return value
    if isinstance(value, list | tuple):
        return [_redact_value(key, item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {str(k): _redact_value(str(k), v, depth + 1) for k, v in value.items()}
    if isinstance(value, bool | int | float) or value is None:
        return value
    return REDACTED  # unknown types never pass through raw


def _redact_args(arguments: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _redact_value(str(key), value) for key, value in arguments.items()}


def _extract_egress_destination(redacted_args: dict[str, Any]) -> str | None:
    """Pick an outbound destination from well-known egress arg-keys (reads the
    REDACTED args, so a secret-shaped value is already redacted)."""
    for key in _EGRESS_DEST_KEYS:
        value = redacted_args.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, list | tuple) and value:
            parts = [str(v) for v in value if isinstance(v, str) and v]
            if parts:
                return ",".join(parts)
    return None


def _extract_target(action_type: ActionType, arguments: dict[str, Any]) -> tuple[str | None, dict]:
    """Pick a representative target; extra info (e.g. path counts) → metadata."""
    metadata: dict[str, Any] = {}
    for key in _TARGET_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return value, metadata
        if isinstance(value, list | tuple) and value:
            # Path arrays: representative first element + count in metadata.
            first = value[0]
            if isinstance(first, str):
                metadata["target_count"] = len(value)
                return first, metadata
    return None, metadata


def normalize(
    tool_name: str,
    arguments: dict[str, Any] | None,
    context: dict[str, Any] | None = None,
) -> SecurityObject:
    """Turn one intercepted tool call into a SecurityObject. Never raises."""
    context = context or {}
    safe_tool_name = tool_name if isinstance(tool_name, str) else "<unknown>"
    try:
        args = dict(arguments or {})
        action_type = _map_action_type(tool_name)
        # Extract the target from the REDACTED args so target /
        # external_destination get exactly the same secret protections as
        # raw_args_redacted (a redacted value yields target="<redacted>").
        redacted_args = _redact_args(args)
        target, metadata = _extract_target(action_type, redacted_args)
        if action_type is ActionType.network_request:
            external_destination = target
        else:
            external_destination = _extract_egress_destination(redacted_args)
        base = SecurityObject(
            id=uuid.uuid4().hex,
            ts=datetime.now(timezone.utc),
            agent_role=str(context.get("agent_role", "unknown")),
            action_type=action_type,
            tool_name=safe_tool_name,
            target=target,
            external_destination=external_destination,
            source_context=SourceContext.unknown,
            raw_args_redacted=redacted_args,
            metadata=metadata,
        )
        # SL9: every normalized object carries a populated algebra — generic
        # inference first (reads the RAW args, which never enter the object),
        # then any registered refine-only adapters (clamped raise-only). An
        # inference failure leaves the conservative default algebra in place.
        algebra = apply_adapters(
            infer_algebra(base, args),
            {"tool_name": safe_tool_name, "arguments": args},
        )
        return base.model_copy(
            update={"algebra": algebra, "reversibility": infer_reversibility(base, args)}
        )
    except Exception:  # noqa: BLE001 — normalization must never break the path
        # Conservative fallback: unknown action at high risk, no argument
        # values copied at all (we cannot trust that redaction succeeded).
        return SecurityObject(
            id=uuid.uuid4().hex,
            ts=datetime.now(timezone.utc),
            agent_role="unknown",
            action_type=ActionType.other,
            tool_name=safe_tool_name,
            risk=Risk.high,
            source_context=SourceContext.unknown,
            metadata={"reason_codes": [ReasonCode.normalization_failed]},
        )
