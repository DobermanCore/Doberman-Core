"""Destructive-command rule (Feature 3, slice 3.4).

Blocks catastrophic shell/git commands and steps up authentication on
risky-but-recoverable ones. Command parsing is treated as **adversarial**: a
single command string may chain many commands with ``;``, ``&``, ``&&``, ``||``,
or pipes, hide work in ``$(...)``/backtick substitutions, or carry an opaque
payload (``bash -c "<base64>"``). We therefore:

* split the command line into segments on the shell operators, and recurse into
  command-substitution bodies, so a destructive segment anywhere in the line is
  seen;
* match each segment's argv (parsed with :mod:`shlex`, env-assignment and
  ``sudo``/``nice`` prefixes stripped) against deny / step-up tables;
* treat anything we **cannot** confidently parse — opaque ``-c`` payloads,
  unbalanced quoting — as ``AUTH``, never PASS. We never *execute* anything to
  analyze it.

Verdicts:

* ``rm -rf /`` (or ``~`` / ``/*``), disk wipes (``mkfs``, ``dd of=/dev/...``),
  ``git push --force`` to a protected branch, fork bombs → ``BLOCK
  (destructive_command)``.
* recoverable-but-risky (``sudo``, ``curl | sh``, bulk deletes at/over the
  threshold, ``git reset --hard``) → ``AUTH``.
* opaque / unparseable commands → ``AUTH (opaque_command)``.
* small/benign commands → abstain (``PASS``).

SECURITY: the explanation names the *category* of danger, never echoes the
command string or its arguments.
"""

import fnmatch
import posixpath
import re
import shlex
from collections.abc import Iterable

from doberman.engine.rules.paths import names_control_plane
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.modes import thresholds_for

# Doberman's own CLI subcommands that install/remove the host hooks or otherwise
# mutate the control plane (posture, enforcement, auth factors, or an active
# elevation): an agent invoking these through a shell is tampering with the cop,
# not doing project work (HK.5.0b). The human runs these directly (not via a
# gated tool), so the hook only ever sees the *agent* invoking them. Read/utility
# verbs (`status`, `doctor`, `encode-safe`, `log`, `scan`, `review`) are
# deliberately excluded — they don't mutate anything. `memory` joined this set
# with Subj1's `memory reset`/`memory prune` (they mutate the learned behavioral
# baseline/preference memory, the same class of action as `taint`); the bare
# read-only `doberman memory` summary is blocked as collateral — the CLI verb
# has no subcommand granularity here, and an unrecognized/ambiguous case fails
# closed like everywhere else in this module.
_DOBERMAN_CONTROL_SUBCOMMANDS = {
    "install-hooks",
    "uninstall-hooks",
    "uninstall",
    "setup",
    "mode",
    "prefs",
    "enforcement",
    "2fa",
    "taint",
    "password",
    "revoke",
    "memory",
    "decision-log-prune",
    "tools",
    "approvals",
    # `tune --accept` grants a standing elevation (a weakening) through the
    # same gated chokepoint as any other loosening (#243) — shelling it out
    # is the same tampering shape as `revoke`/`2fa`/`taint`.
    "tune",
}

#: Default bulk-operation threshold: deleting/touching this many paths in one
#: command steps up to AUTH. Overridable (F6 wires this from policy/mode).
DEFAULT_BULK_THRESHOLD = 25

#: Action types the proxy itself labels as command-bearing (normalize.py's
#: ``_COMMAND_EGRESS_ACTIONS``) — these get the ``action.target`` fallback too.
_COMMAND_ACTION_TYPES = frozenset(
    {ActionType.shell_exec, ActionType.git_op, ActionType.package_install}
)

#: Branch names whose history is protected — a force-push here is catastrophic.
DEFAULT_PROTECTED_BRANCHES: tuple[str, ...] = ("main", "master", "release", "develop")

# Command-substitution bodies: $(...) and `...`. We recurse into these so a
# destructive command hidden inside a substitution is still evaluated.
_SUBSTITUTION = re.compile(r"\$\((?P<paren>[^()]*)\)|`(?P<backtick>[^`]*)`")

# Env-assignment prefixes (FOO=bar) and benign wrappers we look through.
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_TRANSPARENT_WRAPPERS = {"sudo", "nice", "ionice", "nohup", "time", "env", "command", "exec"}

# `env`'s own no-op flags (no operand) and its unset flags (take one operand),
# recognised so `env -i -0 -u FOO` with no trailing command still resolves to
# "no command to run" -> a dump, same as bare `env`.
_ENV_NOOP_FLAGS = {"-i", "-0", "--null", "--ignore-environment"}
_ENV_UNSET_FLAGS = {"-u", "--unset"}
# `Get-ChildItem`/`gci`/`dir`/`ls` are all valid PowerShell aliases for the
# same provider cmdlet; `Env:` (optionally trailing `\`) is the environment
# drive - listing it prints every variable and value, same as POSIX `env`.
_POWERSHELL_LISTING_VERBS = {"get-childitem", "gci", "dir", "ls"}
_POWERSHELL_ENV_DRIVE = re.compile(r"(?i)^env:\\?$")

# Shells that take an opaque "-c <payload>" we cannot statically vet.
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}

# PowerShell / cmd.exe: same "opaque inline payload" problem as _SHELLS, but a
# different flag vocabulary (-Command/-EncodedCommand, /c) — see _opaque_shell_payload.
_WINDOWS_SHELLS = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_CMD_SHELLS = {"cmd", "cmd.exe"}

# Non-shell interpreters whose inline payloads can directly mutate files.
_INTERPRETERS = {"python", "python3", "py", "node", "nodejs", "deno", "bun", "perl", "ruby"}
_INLINE_CODE_FLAGS = {"-c", "-e", "--eval", "-p", "--print"}
# Attached forms (no space before the payload): shlex glues the quoted body to
# the flag, e.g. `python -c"..."` -> token `-cimport ...` (never equals "-c").
_SHORT_INLINE_CODE_FLAGS = ("-c", "-e")
_LONG_INLINE_CODE_FLAG_PREFIXES = ("--eval=", "--print=")
_DESTRUCTIVE_INTERPRETER_OP = re.compile(
    r"\b(?:shutil\.)?rmtree\b|\bos\.(?:remove|unlink)\b|\brmSync\b|"
    r"\bunlinkSync\b|\bfs\.rm\b|\bRemove-Item\b|\brm\s+-rf\b|\bunlink\b",
    re.IGNORECASE,
)

# HK.5.6 — raw-socket / bare-TCP egress shapes the destructive-command walk
# does not otherwise see: a shell redirection into /dev/tcp or /dev/udp
# (bash's built-in TCP/UDP pseudo-device), netcat/ncat used in exec-on-connect
# (reverse/bind-shell) form, socat's EXEC:/SYSTEM: address type (socat's
# equivalent of `nc -e`), and openssl's TLS client mode. AUTH-only, never
# BLOCK: a routine port probe (`nc -zv host port`) and DNS-label exfil
# (`dig`/`nslookup`) must stay indistinguishable from ordinary DevOps without
# an entropy/calibration signal this module doesn't have (out of scope for
# this slice — see docs/REASON_CODES.md and the README known-limitations
# entry for `raw_socket_channel`).
_DEV_TCP_UDP_RE = re.compile(r"/dev/(?:tcp|udp)/")
_NC_LIKE_COMMANDS = {"nc", "ncat", "netcat"}
# The exec-on-connect flags that turn a network tool into a reverse/bind
# shell: `-e`/`--exec` (classic netcat/ncat), ncat's `-c`/`--sh-exec` (runs
# the command via /bin/sh -c). A bare port probe (`-zv`) never sets these.
_NC_EXEC_FLAGS = {"-e", "--exec", "-c", "--sh-exec"}
# socat's EXEC:/SYSTEM: address types spawn a subprocess wired to the socket
# (socat's equivalent of `nc -e`) — not socat's routine port-forwarding use.
_SOCAT_EXEC_ADDRESS_RE = re.compile(r"(?i)\b(?:exec|system):")
# Best-effort shape match over an inline interpreter payload's source text
# (paired with _INTERPRETERS/_INLINE_CODE_FLAGS above): a socket/network-
# client call assembled directly in a `python -c`/`node -e` one-liner. Layered
# on top of the existing opaque-payload AUTH, not static analysis — misses an
# obfuscated variant (string concatenation, getattr, a base64-decoded module
# name); see the README known-limitations entry for `raw_socket_channel`.
_INLINE_SOCKET_OP = re.compile(
    r"\bsocket\.|\bconnect\(|\bhttp\.client\b|\brequests\.|\burllib\b|"
    r"\bnet\.Socket\b|\bfetch\(",
    re.IGNORECASE,
)

# Shared work bound for every static command walk. Exhaustion is ambiguity,
# never silent success.
_MAX_COMMAND_SEGMENTS = 256

# Any shell expansion can construct a destination at runtime. The shared walk
# reports the fact; consumers decide whether it matters for their rule.
_DYNAMIC_SHELL = re.compile(r"\$\(|`|\$(?:\{|[A-Za-z_])")

# Whole-word trigger for _normalize_windows_backslashes: any command naming one
# of these Windows verbs/shells (or `rm`, whose own unrecoverable-data check also
# needs a backslash-separated operand intact) gets `\` -> `/` before tokenization.
_WINDOWS_PATH_TRIGGER_RE = re.compile(
    r"(?i)\b(?:"
    r"rm|remove-item|ri|rmdir|del|erase|rd|clear-content|clc|"
    r"powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|"
    r"format-volume|clear-disk|format"
    r")\b"
)


def _strip_substitutions(segment: str) -> tuple[str, list[str]]:
    """Remove ``$()``/backtick bodies from a segment, returning them separately."""
    bodies: list[str] = []

    def _collect(match: re.Match[str]) -> str:
        body = match.group("paren")
        if body is None:
            body = match.group("backtick") or ""
        if body.strip():
            bodies.append(body)
        return " "

    stripped = _SUBSTITUTION.sub(_collect, segment)
    return stripped, bodies


def _split_segments(command: str) -> list[str]:
    """Split a command line into top-level segments on shell operators."""
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            current.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            index += 1
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            index += 1
            continue

        operator_width = 2 if command[index : index + 2] in {"&&", "||"} else 0
        # A single ``&`` separates commands too: cmd.exe runs both sides
        # unconditionally and POSIX shells background the left and run the right.
        if operator_width or char in {"|", ";", "&", "\n"}:
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            index += operator_width or 1
            continue
        current.append(char)
        index += 1

    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    return segments


def walk_command(command: str) -> tuple[list[list[str]], bool, bool]:
    """Tokenize every shell segment/substitution without stripping prefixes.

    Returns ``(segments, ambiguous, dynamic)``. Each segment is the raw
    :func:`shlex.split` token list *before* env assignments or transparent
    wrappers are removed, so security consumers can still see proxy/route
    overrides. Unbalanced input and the shared work-cap surface through
    ``ambiguous``. No command is executed.
    """
    pending = _split_segments(command)
    segments: list[list[str]] = []
    ambiguous = False
    processed = 0

    while pending and processed < _MAX_COMMAND_SEGMENTS:
        processed += 1
        segment = pending.pop()
        stripped, bodies = _strip_substitutions(segment)
        for body in bodies:
            pending.extend(_split_segments(body))
        try:
            tokens = shlex.split(stripped, comments=True, posix=True)
        except ValueError:
            ambiguous = True
            continue
        if tokens:
            segments.append(tokens)

    if pending:
        ambiguous = True
    return segments, ambiguous, bool(_DYNAMIC_SHELL.search(command))


def _normalize_windows_backslashes(command: str) -> str:
    """``\\`` is a Windows path separator, but shlex (POSIX mode, used below) treats
    it as an escape character — it silently eats ``foo\\.env`` -> ``foo.env`` or
    raises ``ValueError`` on a trailing ``C:\\``. A line naming a Windows verb/shell
    (see ``_WINDOWS_PATH_TRIGGER_RE``) gets every backslash flipped to ``/`` before
    tokenization so a Windows path survives intact.

    ponytail: a whole-line, word-triggered flip rather than per-segment/per-operand
    surgery — simplest fix that passes the live-tested Windows commands, and a no-op
    (verified against the existing POSIX test suite) unless both a trigger word and a
    literal backslash are present. Known ceiling: a POSIX ``rm`` operand that
    legitimately backslash-escapes a space or glob character (rare) would have that
    escape flattened too; upgrade to a per-segment flip if that ever bites.
    """
    if _WINDOWS_PATH_TRIGGER_RE.search(command):
        return command.replace("\\", "/")
    return command


def _argv_from_tokens(tokens: list[str]) -> list[str]:
    """Strip prefixes from an already parsed segment for command classification."""
    tokens = list(tokens)
    while tokens and (_ENV_ASSIGNMENT.match(tokens[0]) or tokens[0] in _TRANSPARENT_WRAPPERS):
        tokens.pop(0)
    return tokens


def _argv(segment: str) -> list[str] | None:
    """Parse one segment into argv with shlex; ``None`` if it cannot be parsed.

    Unparseable (e.g. unbalanced quotes) returns ``None`` so the caller fails
    upward to AUTH rather than guessing.
    """
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return None
    return _argv_from_tokens(tokens)


#: A Windows drive root in any form a delete operand can arrive in: ``C:\``,
#: ``C:/``, ``C:\*``, or the backslash-eaten ``C:*`` (see
#: ``_normalize_windows_backslashes`` — normally already flipped to ``C:/``).
_WINDOWS_ROOT_RE = re.compile(r"^[A-Za-z]:[/\\]?(\*)?$")


def _is_root_or_home_target(arg: str) -> bool:
    """True if an argument denotes ``/``, ``~``, a whole-tree wildcard, or a
    Windows drive root / home-profile variable (``C:\\``, ``~``, ``$env:USERPROFILE``)."""
    raw = arg.strip().strip("'\"")
    if raw.lower() in {"~", "$home", "$env:userprofile"}:
        return True
    if _WINDOWS_ROOT_RE.match(raw):
        return True
    normalized = posixpath.normpath(raw.replace("\\", "/"))
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized in {"/", "~", "~/", "/*", "/.", "~/*", "*"} or normalized.startswith("/*")


def _rm_is_catastrophic(tokens: list[str]) -> bool:
    """``rm`` with a recursive+force flag aimed at root/home/whole-tree."""
    flags = "".join(t[1:] for t in tokens[1:] if t.startswith("-") and not t.startswith("--"))
    long_flags = {t for t in tokens[1:] if t.startswith("--")}
    recursive = "r" in flags or "R" in flags or "--recursive" in long_flags
    force = "f" in flags or "--force" in long_flags
    if not (recursive and force):
        return False
    operands = [t for t in tokens[1:] if not t.startswith("-")]
    return any(_is_root_or_home_target(op) for op in operands)


def _count_delete_operands(tokens: list[str]) -> int:
    """Number of path operands to an ``rm`` (for the bulk-operation threshold)."""
    return len([t for t in tokens[1:] if not t.startswith("-")])


# Gitignored, unrecoverable-by-git data whose deletion git cannot undo: local
# databases and secret/key material. Matched lexically on the operand basename.
_UNRECOVERABLE_DELETE_GLOBS = ("*.db", "*.sqlite", "*.sqlite3", "*.key", ".env", ".env.*")


def _unrecoverable_basename(operand: str) -> str:
    """Basename of a delete operand, tolerant of Windows backslashes and a
    leading ``.\\`` (normalized to ``/`` before ``posixpath.basename``)."""
    return posixpath.basename(operand.strip().strip("'\"").replace("\\", "/"))


def _any_operand_unrecoverable(operands: Iterable[str]) -> bool:
    """True if any operand's basename matches an unrecoverable, gitignored data
    file (local DB / secret / key). Shared by the ``rm`` and Windows delete paths."""
    return any(
        fnmatch.fnmatch(_unrecoverable_basename(op), pattern)
        for op in operands
        for pattern in _UNRECOVERABLE_DELETE_GLOBS
    )


def _rm_targets_unrecoverable_data(tokens: list[str]) -> bool:
    """``rm`` whose operand basename matches an unrecoverable, gitignored data
    file (local DB / secret / key)."""
    # ponytail: lexical glob on operands only — no filesystem or git access in the
    # decision path. Catches file targets; a directory operand (rm -rf data/) cannot
    # be classified lexically and is deliberately out of scope (deferred — see ADR).
    operands = [t for t in tokens[1:] if not t.startswith("-")]
    return _any_operand_unrecoverable(operands)


# --- Windows/PowerShell delete-verb coverage --------------------------------
#
# Codex/agents on Windows run tool commands through PowerShell or cmd.exe, whose
# destructive-delete vocabulary (Remove-Item, del, rd, ...) is invisible to the
# POSIX-only `rm` handling above. `_windows_delete_verdict` maps these verbs onto
# the SAME severity ladder as `rm`'s own branches — not a second policy — and is
# kept separate from the `rm` branches so this addition can never regress `rm`.

#: Verbs that delete or wipe file content the Windows way.
_WINDOWS_DELETE_VERBS = frozenset(
    {"remove-item", "ri", "rmdir", "del", "erase", "rd", "clear-content", "clc"}
)


def _windows_delete_flag(token: str) -> tuple[bool, bool, bool]:
    """Classify one Windows delete-verb argument: ``(is_flag, recursive, force)``.

    PowerShell flags (``-Recurse``, ``-Force``, ...) abbreviate by prefix — ``-r``/
    ``-f`` alone are valid PowerShell abbreviations too, so we match "is this body a
    prefix of the canonical word" rather than the reverse. cmd.exe flags are the
    fixed 1-2 char ``/s`` (recursive) / ``/q``, ``/f`` (force). Any other ``-``/``/``
    -prefixed token (e.g. ``-Path``, whose value arrives as the next token) still
    counts as a flag so it isn't miscounted as an operand — it just isn't Recurse/Force.
    """
    if token.startswith("-") and len(token) > 1:
        body = token[1:].lower()
        # ponytail: prefix-match against "recurse"/"force" only (not the full
        # PowerShell parameter-disambiguation table) — over-classifying Force is
        # raise-only (safe); a non-recurse/force switch (-Path, -Confirm, ...) is
        # still correctly excluded from the operand count.
        return True, "recurse".startswith(body), "force".startswith(body)
    if token.startswith("/") and 1 <= len(token) - 1 <= 2:
        body = token[1:].lower()
        return True, body == "s", body in {"q", "f"}
    return False, False, False


def _windows_delete_flags_and_operands(tokens: list[str]) -> tuple[bool, bool, list[str]]:
    """``(recursive, force, operands)`` for a Windows delete-verb argv."""
    recursive = force = False
    operands: list[str] = []
    for token in tokens[1:]:
        is_flag, r, f = _windows_delete_flag(token)
        if is_flag:
            recursive = recursive or r
            force = force or f
        else:
            operands.append(token)
    return recursive, force, operands


def _windows_delete_verdict(tokens: list[str], bulk_threshold: int) -> GuardrailResult | None:
    """Windows/PowerShell delete-verb classifier (Remove-Item/del/rd/...): recursive
    + force at a root/home target -> BLOCK; bulk or unrecoverable-data operand ->
    AUTH; otherwise ``None`` (not a recognized Windows delete verb, or benign)."""
    if not tokens or tokens[0].lower() not in _WINDOWS_DELETE_VERBS:
        return None
    recursive, force, operands = _windows_delete_flags_and_operands(tokens)
    if recursive and force and any(_is_root_or_home_target(op) for op in operands):
        return _block("Recursive force-delete of a root/home/whole-tree target.")
    if len(operands) >= bulk_threshold:
        return _auth(
            ReasonCode.bulk_operation,
            "Bulk delete at or above the configured threshold; authentication required.",
        )
    if _any_operand_unrecoverable(operands):
        return _auth(
            ReasonCode.destructive_command,
            "Deleting an unrecoverable, gitignored data file (local database, "
            "secret, or key); authentication required.",
        )
    return None


def _git_force_push_to_protected(tokens: list[str], protected: Iterable[str]) -> bool:
    """``git push`` with a force flag targeting a protected branch."""
    if len(tokens) < 2 or tokens[0] != "git" or "push" not in tokens:
        return False
    has_force = any(
        t in ("-f", "--force") or t.startswith("--force-with-lease") or t == "+HEAD" for t in tokens
    )
    if not has_force:
        # A refspec like ``+main`` is also a force push of that ref.
        if not any(t.startswith("+") for t in tokens[1:]):
            return False
        has_force = True
    protected_set = {b.lower() for b in protected}
    push_args = tokens[tokens.index("push") + 1 :]
    positional = [t for t in push_args if not t.startswith("-")]
    explicit_refs = positional[1:]  # the first positional is the remote
    # Any token that names (or pushes to) a protected branch.
    for token in explicit_refs:
        ref = token.lstrip("+").split(":")[-1].lower()
        ref = re.sub(r"^(?:refs/(?:heads|tags)/|heads/)", "", ref)
        if ref in protected_set:
            return True
    # A bare ``git push --force`` (no explicit ref) defaults to the current
    # branch — unknown here, so treat it as protected (fail safe).
    return not explicit_refs


# Catastrophic non-rm commands (whole-disk wipes, fork bombs). IGNORECASE covers
# the Windows disk-wipe names (Format-Volume, Clear-Disk, format).
_DISK_WIPE = re.compile(
    r"^(?:mkfs(?:\.\w+)?|shred|wipefs|format-volume|clear-disk|format)$", re.IGNORECASE
)


def _is_doberman_control_cli(tokens: list[str]) -> bool:
    """``doberman <verb>`` for a posture/auth-mutating verb (install/uninstall-hooks,
    uninstall, setup, mode, prefs, enforcement, 2fa, taint, password, revoke) —
    control-plane tamper. Read/utility verbs are not in the set and stay allowed."""
    return (
        bool(tokens)
        and tokens[0] == "doberman"
        and any(t in _DOBERMAN_CONTROL_SUBCOMMANDS for t in tokens[1:])
    )


def _package_manager_removes_doberman(tokens: list[str]) -> bool:
    """True for package-manager commands that uninstall Doberman itself."""
    if (
        len(tokens) >= 3
        and tokens[0] in {"python", "python3", "py"}
        and tokens[1] == "-m"
        and tokens[2] == "pip"
    ):
        manager_args = tokens[2:]
    elif tokens[:2] == ["uv", "pip"]:
        manager_args = tokens[1:]
    else:
        manager_args = tokens
    if (
        len(manager_args) < 3
        or manager_args[0] not in {"pip", "pip3", "pipx", "uv"}
        or manager_args[1] not in {"uninstall", "remove"}
    ):
        return False
    packages = {
        token.lower().replace("-", "_") for token in manager_args[2:] if not token.startswith("-")
    }
    return bool(packages & {"doberman", "doberman_core", "doberman_enterprise"})


def _token_path_candidates(token: str) -> list[str]:
    """Path-like candidates from one argv token: the token itself and the value
    after ``=`` (for ``--flag=path`` forms). Redirection targets already arrive as
    their own tokens (``shlex`` keeps ``>``/``>>`` separate)."""
    if "=" in token:
        return [token, token.split("=", 1)[1]]
    return [token]


def _segment_targets_control_plane(tokens: list[str], root: str) -> bool:
    """True if any argv token (operand or redirect target) names Doberman's
    control plane. Skips a token's leading ``-`` switch but still checks a
    ``--flag=path`` value."""
    for token in tokens:
        for candidate in _token_path_candidates(token):
            if candidate and not candidate.startswith("-") and names_control_plane(candidate, root):
                return True
    return False


def _control_plane_in_windows_form(command: str, root: str) -> bool:
    """True if the command names the control plane using ``\\`` separators.

    :func:`shlex.split` in POSIX mode treats ``\\`` as an **escape character**, so
    ``rm .doberman\\policies.yaml`` tokenizes to ``.dobermanpolicies.yaml`` — the
    separators are consumed before any path check runs, and the token matches no
    glob. Every control-plane guarantee in this module was therefore reachable on
    Windows just by spelling the path the way Windows spells it.

    Re-scan a separator-normalized copy of the raw command so the Windows form is
    caught too. This is **scan-only**: these tokens never reach verb
    classification, operand counting, or the bulk-delete threshold, so the pass
    can only ever add a control-plane BLOCK — it can never change what a command
    is understood to *do*, and never lowers a verdict.

    Normalizing is safe for a genuine POSIX escape (``rm my\\ file.txt`` becomes
    the harmless tokens ``my/`` and ``file.txt``) because only control-plane glob
    matching consumes the result.
    """
    if "\\" not in command:
        return False
    normalized = command.replace("\\", "/")
    try:
        tokens = shlex.split(normalized, comments=True, posix=True)
    except ValueError:
        # Unbalanced quoting: fall back to a crude split rather than give up —
        # the caller still treats an unparseable command as ambiguous.
        tokens = [t for t in re.split(r"[\s'\"`(){}\[\],;]+", normalized) if t]
    return _segment_targets_control_plane(tokens, root)


def _interpreter_payload_verdict(tokens: list[str], root: str) -> GuardrailResult | None:
    """BLOCK obvious control-plane or destructive interpreter one-liners."""
    if not tokens or tokens[0] not in _INTERPRETERS:
        return None
    payloads: list[str] = []
    for index in range(1, len(tokens)):
        token = tokens[index]
        if token in _INLINE_CODE_FLAGS:
            if index + 1 < len(tokens):
                payloads.append(tokens[index + 1])
        elif token.startswith(_SHORT_INLINE_CODE_FLAGS) and len(token) > 2:
            payloads.append(token[2:])
        elif token.startswith(_LONG_INLINE_CODE_FLAG_PREFIXES):
            payloads.append(token.split("=", 1)[1])
    if not payloads:
        return None

    for payload in payloads:
        candidates = [
            candidate for candidate in re.split(r"[\s'\"`(){}\[\],;]+", payload) if candidate
        ]
        if _segment_targets_control_plane(candidates, root):
            return _block_control_plane(
                "Interpreter inline payload references Doberman's own control plane."
            )
    if any(_DESTRUCTIVE_INTERPRETER_OP.search(payload) for payload in payloads):
        return _block("Interpreter inline payload contains a destructive filesystem operation.")
    if any(_INLINE_SOCKET_OP.search(payload) for payload in payloads):
        return _auth(
            ReasonCode.opaque_command,
            "Interpreter inline payload opens a network socket directly; authentication required.",
        )
    return None


def _is_environment_dump_segment(raw_tokens: list[str]) -> bool:
    """True for a segment whose sole effect is to print the process
    environment: bare ``env``, ``printenv`` (any form), ``export``/``export
    -p``, ``declare -x``/``typeset -x`` with no named variable, or a
    PowerShell ``Env:`` drive listing.

    Runs on the RAW parsed segment, *before* :func:`_argv_from_tokens` strips
    leading wrappers/assignments — that stripping is what makes bare ``env``
    invisible to :func:`_segment_verdict` (stripping ``env`` off ``["env"]``
    leaves an empty list, which the caller's ``if not tokens`` guard silently
    skips). We look through non-``env`` wrappers (``sudo env`` etc.) and
    env-assignment prefixes ourselves so this still fires under them, but stop
    at ``env``/``printenv`` themselves so we can inspect what follows.

    Known ceiling: ``dir``/``ls``/``gci`` are not in
    ``_WINDOWS_PATH_TRIGGER_RE``, so a literal trailing backslash (``dir
    env:\\``) fails POSIX shlex parsing before this function ever sees the
    segment and falls back to the generic ``opaque_command`` AUTH instead —
    still fails upward, just under a different reason code. The no-backslash
    form (``dir env:``) is unaffected.
    """
    idx = 0
    look_through = _TRANSPARENT_WRAPPERS - {"env"}
    while idx < len(raw_tokens) and (
        _ENV_ASSIGNMENT.match(raw_tokens[idx]) or raw_tokens[idx] in look_through
    ):
        idx += 1
    rest = raw_tokens[idx:]
    if not rest:
        return False
    cmd, tail = rest[0], rest[1:]

    if cmd == "printenv":
        return True  # every form reads the process environment

    if cmd == "env":
        i = 0
        while i < len(tail):
            token = tail[i]
            if _ENV_ASSIGNMENT.match(token) or token in _ENV_NOOP_FLAGS:
                i += 1
                continue
            if token in _ENV_UNSET_FLAGS:
                i += 2  # flag + its variable-name operand
                continue
            if token.startswith("--unset="):
                i += 1
                continue
            return False  # a real command to hand off to - not a dump
        return True

    if cmd in ("export", "declare", "typeset"):
        flags = [t for t in tail if t.startswith("-")]
        names = [t for t in tail if not t.startswith("-")]
        if names:
            return False  # names a specific variable, not a full listing
        return cmd == "export" or "-x" in flags

    if cmd.lower() in _POWERSHELL_LISTING_VERBS:
        return any(_POWERSHELL_ENV_DRIVE.match(t) for t in tail)

    return False


def _environment_dump_auth() -> GuardrailResult:
    return _auth(
        ReasonCode.environment_dump_command,
        "Command reads/prints the process environment, a common carrier for "
        "secrets (API keys, tokens); authentication required.",
    )


def _segment_verdict(
    tokens: list[str], protected_branches: Iterable[str], bulk_threshold: int, root: str
) -> GuardrailResult | None:
    """Classify one parsed segment; ``None`` means this segment is benign."""
    if not tokens:
        return None
    cmd = tokens[0]

    # --- Control-plane tamper → BLOCK (HK.5.0b) ---
    # A shell command that names .doberman/ or the .claude/ hook config, or runs
    # the Doberman hook-install CLI, is disabling the cop — block it. (A path-
    # *target* rule misses a path hidden inside a command string.)
    if _segment_targets_control_plane(tokens, root):
        return _block_control_plane(
            "Shell command targets Doberman's own control plane "
            "(.doberman/ state or the .claude/ host-hook config)."
        )
    if _is_doberman_control_cli(tokens):
        return _block_control_plane(
            "Shell command would tamper with Doberman's control plane (install/remove/"
            "uninstall hooks, or change mode, enforcement, prefs, 2FA, taint, or password)."
        )
    if _package_manager_removes_doberman(tokens):
        return _block_control_plane(
            "Package-manager command would uninstall Doberman's guard (control-plane tamper)."
        )
    interpreter_payload = _interpreter_payload_verdict(tokens, root)
    if interpreter_payload is not None:
        return interpreter_payload

    # --- Catastrophic → BLOCK ---
    if cmd == "rm" and _rm_is_catastrophic(tokens):
        return _block("Recursive force-delete of a root/home/whole-tree target.")
    if _DISK_WIPE.match(cmd):
        return _block("Disk-wipe / filesystem-format command.")
    if cmd == "dd" and any("of=/dev/" in t for t in tokens[1:]):
        return _block("Raw write to a block device (data-destroying dd).")
    if cmd == "git" and _git_force_push_to_protected(tokens, protected_branches):
        return _block("Force-push to a protected branch (rewrites shared history).")
    if ":(){" in "".join(tokens) or _looks_like_fork_bomb(tokens):
        return _block("Fork-bomb-style command.")

    windows_delete = _windows_delete_verdict(tokens, bulk_threshold)
    if windows_delete is not None:
        return windows_delete

    # --- Risky but recoverable → AUTH ---
    if cmd == "rm" and _count_delete_operands(tokens) >= bulk_threshold:
        return _auth(
            ReasonCode.bulk_operation,
            "Bulk delete at or above the configured threshold; authentication required.",
        )
    if cmd == "rm" and _rm_targets_unrecoverable_data(tokens):
        return _auth(
            ReasonCode.destructive_command,
            "Deleting an unrecoverable, gitignored data file (local database, "
            "secret, or key); authentication required.",
        )
    if cmd == "git" and _git_is_history_rewrite(tokens):
        return _auth(
            ReasonCode.destructive_command,
            "Git history rewrite / hard reset; authentication required.",
        )
    if _is_pipe_to_shell(tokens):
        return _auth(
            ReasonCode.destructive_command,
            "Piping a downloaded payload into a shell; authentication required.",
        )
    channel = _raw_socket_channel_explanation(tokens)
    if channel is not None:
        return _auth(
            ReasonCode.raw_socket_channel,
            f"Command opens a raw network channel outside the normal tool path ({channel}); "
            "authentication required.",
        )
    return None


def _looks_like_fork_bomb(tokens: list[str]) -> bool:
    joined = " ".join(tokens)
    return bool(re.search(r":\s*\(\s*\)\s*\{.*\|\s*:", joined))


def _git_is_history_rewrite(tokens: list[str]) -> bool:
    if tokens[0] != "git" or len(tokens) < 2:
        return False
    if "reset" in tokens and "--hard" in tokens:
        return True
    if "filter-branch" in tokens:
        return True
    # ``git clean -f`` permanently removes untracked files.
    return "clean" in tokens and any(t.startswith("-") and "f" in t for t in tokens)


def _is_pipe_to_shell(tokens: list[str]) -> bool:
    """A fetch tool (curl/wget) whose output is piped into a shell.

    Pipe splitting already separated segments, but ``curl ... | sh`` arrives as
    two segments; we flag the *fetch* side conservatively when it targets a
    shell via a following segment is handled at the line level. Here we catch a
    fetch that itself names a shell interpreter as an argument.
    """
    if tokens[0] not in {"curl", "wget"}:
        return False
    return any(part in _SHELLS for part in tokens[1:])


def _raw_socket_channel_explanation(tokens: list[str]) -> str | None:
    """Explanation fragment for a raw-socket/bare-TCP egress shape, or ``None``.

    Shapes: a ``/dev/tcp``/``/dev/udp`` redirection target (checked across
    every token, not just ``tokens[0]``, since bash writes it as a redirect
    operand anywhere in the segment); ``nc``/``ncat``/``socat`` used in
    exec-on-connect (reverse/bind-shell) form; or
    ``openssl s_client -connect``. Deliberately narrow (HK.5.6) so a routine
    port probe (``nc -zv host port``) or an unrelated ``openssl`` subcommand
    stays ``PASS``. Returns a small fixed string, never the matched token, so
    the caller's explanation never echoes a host/port/payload.
    """
    if any(_DEV_TCP_UDP_RE.search(token) for token in tokens):
        return "bare-TCP/UDP device redirection"
    cmd = tokens[0]
    if cmd in _NC_LIKE_COMMANDS and any(token in _NC_EXEC_FLAGS for token in tokens[1:]):
        return "an exec-on-connect listener"
    if cmd == "socat" and any(_SOCAT_EXEC_ADDRESS_RE.search(t) for t in tokens[1:]):
        return "an exec-on-connect listener"
    if cmd == "openssl" and len(tokens) > 1 and tokens[1] == "s_client" and "-connect" in tokens:
        return "a direct TLS client connection"
    return None


def _is_powershell_command_flag(token: str) -> bool:
    """``-Command``/``-c`` — PowerShell abbreviates parameter names by prefix,
    case-insensitive."""
    if not token.startswith("-") or len(token) < 2:
        return False
    return "command".startswith(token[1:].lower())


def _is_powershell_encoded_flag(token: str) -> bool:
    """``-EncodedCommand``/``-e`` — a base64 payload; never scanned (cannot
    decode/vet it), so the caller keeps this an opaque AUTH with no body scan."""
    if not token.startswith("-") or len(token) < 2:
        return False
    return "encodedcommand".startswith(token[1:].lower())


def _opaque_shell_payload(tokens: list[str]) -> bool:
    """True for ``bash -c <payload>``, PowerShell ``-Command``/``-EncodedCommand``,
    or ``cmd /c <payload>`` — a payload we cannot (or must not) statically vet."""
    if not tokens:
        return False
    head = tokens[0].lower()
    if head in _SHELLS:
        return "-c" in tokens or "--command" in tokens
    if head in _WINDOWS_SHELLS:
        return any(
            _is_powershell_command_flag(t) or _is_powershell_encoded_flag(t) for t in tokens[1:]
        )
    if head in _CMD_SHELLS:
        return any(t.lower() == "/c" for t in tokens[1:])
    return False


def _block(explanation: str) -> GuardrailResult:
    return GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.destructive_command],
        explanation=explanation,
    )


# Surfaced on every control-plane block so a legitimate user isn't dead-ended:
# the agent is intentionally blocked from touching its own guard (anti-tamper),
# so the recovery path is out-of-band — a regular terminal where the hooks don't
# intercept. No user path is echoed here, so redaction holds.
_CONTROL_PLANE_RECOVERY_HINT = (
    " To change Doberman's own hooks/config, do it in a regular terminal outside the"
    " agent session (e.g. `doberman uninstall-hooks`) — the agent is intentionally"
    " blocked from tampering with its own guard."
)


def _block_control_plane(explanation: str) -> GuardrailResult:
    # Reuse the path rule's reason code — semantically this *is* a protected-path
    # hit, just surfaced from inside a command string (HK.5.0b).
    return GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.protected_path_blocked],
        explanation=explanation + _CONTROL_PLANE_RECOVERY_HINT,
    )


def _auth(reason: ReasonCode, explanation: str) -> GuardrailResult:
    return GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[reason],
        explanation=explanation,
    )


def command_line_from_arguments(arguments: dict) -> str | None:
    """Reconstruct the command line a tool will run from its raw arguments.

    A string ``command``/``cmd``/``script`` is the line. A list-valued ``args``
    is an argv: joined with ``shlex.join`` so every token keeps its boundary
    (never plain-space-joined then re-split — that loses the token boundary of
    e.g. ``bash -c "rm -rf /"`` and mis-splits values with a bare apostrophe),
    and appended to a string ``command``/``cmd`` when both are present (the
    common ``{"command": "rm", "args": ["-rf", "/"]}`` shape). Never raises.
    """
    head: str | None = None
    for key in ("command", "cmd", "script"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            head = value
            break
        if isinstance(value, (list, tuple)) and value:
            head = shlex.join(str(v) for v in value)
            break

    args_value = arguments.get("args")
    args_line: str | None = None
    if isinstance(args_value, (list, tuple)) and args_value:
        args_line = shlex.join(str(v) for v in args_value)

    if head is not None and args_line is not None:
        return f"{head} {args_line}"
    return head if head is not None else args_line


def _raw_command_payload(ctx: EvalContext) -> str | None:
    """Extract a command-shaped string from the un-redacted raw arguments, if any."""
    raw_arguments = ctx.metadata.get("raw_arguments") if isinstance(ctx.metadata, dict) else None
    if isinstance(raw_arguments, dict):
        return command_line_from_arguments(raw_arguments)
    return None


def _command_text(action: SecurityObject, ctx: EvalContext) -> str | None:
    """Extract the raw command string (from un-redacted context, else target)."""
    payload = _raw_command_payload(ctx)
    if payload is not None:
        return payload
    if action.target:
        return action.target
    return None


class DestructiveCommandRule:
    """Detect catastrophic and risky shell/git commands; opaque → AUTH."""

    def __init__(
        self,
        protected_branches: Iterable[str] = DEFAULT_PROTECTED_BRANCHES,
        bulk_threshold: int | None = None,
    ) -> None:
        self._protected = tuple(protected_branches)
        # None → derive the bulk threshold from the active security mode (F6);
        # an explicit value overrides the mode (used by tests).
        self._bulk_threshold_override = bulk_threshold

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        # Classify by payload shape, not by the tool's declared action type: a
        # command-bearing action type (shell_exec/git_op/package_install) also
        # gets the action.target fallback, but ANY action type carrying a
        # command-shaped raw_arguments payload (command/cmd/script/args) must
        # still be scanned — a tool label is not a safety boundary.
        if action.action_type in _COMMAND_ACTION_TYPES:
            command = _command_text(action, ctx)
        else:
            command = _raw_command_payload(ctx)
        if not command or not command.strip():
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        root = "."
        if isinstance(ctx.metadata, dict):
            root = str(ctx.metadata.get("repo_root") or ".")

        threshold = self._bulk_threshold_override
        if threshold is None:
            threshold = thresholds_for(getattr(ctx, "mode", "balanced")).bulk_delete_threshold
        return self._classify_line(command, threshold, root)

    def _classify_line(self, command: str, bulk_threshold: int, root: str) -> GuardrailResult:
        worst: GuardrailResult = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        # Checked against the RAW command, before shlex: POSIX tokenization eats
        # the `\` separators, so a Windows-spelled control-plane path never
        # survives to the per-segment scan below. _normalize_windows_backslashes
        # only fires on Windows-verb trigger words, so a POSIX verb with a
        # backslash-spelled path (`rm .doberman\policies.yaml`) needs this check.
        if _control_plane_in_windows_form(command, root):
            return _block_control_plane(
                "Shell command targets Doberman's own control plane "
                "(.doberman/ state or the .claude/ host-hook config)."
            )

        pending, saw_unparseable, _ = walk_command(_normalize_windows_backslashes(command))
        processed = 0
        while pending and processed < _MAX_COMMAND_SEGMENTS:
            processed += 1
            raw_segment = pending.pop()
            if _is_environment_dump_segment(raw_segment):
                worst = _max_result(worst, _environment_dump_auth())
                continue
            tokens = _argv_from_tokens(raw_segment)
            if not tokens:
                continue
            if _opaque_shell_payload(tokens):
                # We cannot statically vet a -c payload → escalate, never guess.
                worst = _max_result(
                    worst,
                    _auth(
                        ReasonCode.opaque_command,
                        "Opaque shell payload (-c) that cannot be statically vetted; "
                        "authentication required.",
                    ),
                )
                # Still scan the payload body for obvious catastrophes — an
                # opaque AUTH can be raised to BLOCK if the body is e.g. rm -rf /.
                payload = _payload_command(tokens)
                if payload is not None:
                    payload_segments, payload_ambiguous, _ = walk_command(
                        _normalize_windows_backslashes(payload)
                    )
                    pending.extend(payload_segments)
                    saw_unparseable = saw_unparseable or payload_ambiguous
                continue

            verdict = _segment_verdict(tokens, self._protected, bulk_threshold, root)
            if verdict is not None:
                worst = _max_result(worst, verdict)
                if worst.verdict is Verdict.BLOCK:
                    return worst

        if pending:
            saw_unparseable = True

        # ``curl ... | sh`` arrives as two segments; if the line both fetches
        # and pipes into a shell, escalate (defense-in-depth at the line level).
        if worst.verdict is Verdict.PASS and _line_fetches_and_pipes_to_shell(command):
            worst = _auth(
                ReasonCode.destructive_command,
                "Piping a downloaded payload into a shell; authentication required.",
            )

        if saw_unparseable and worst.verdict is Verdict.PASS:
            return _auth(
                ReasonCode.opaque_command,
                "Command could not be parsed safely; authentication required.",
            )
        return worst


def _payload_command(tokens: list[str]) -> str | None:
    """Pull the argument after ``-c``/``-Command``/``cmd /c`` for a bounded
    shared-command walk. ``None`` for ``-EncodedCommand`` (base64 — cannot
    decode/vet) so the caller skips body scanning and keeps the opaque AUTH."""
    for flag in ("-c", "--command"):
        if flag in tokens:
            idx = tokens.index(flag)
            if idx + 1 < len(tokens):
                return tokens[idx + 1]
    for idx, token in enumerate(tokens):
        if _is_powershell_encoded_flag(token):
            return None
        if _is_powershell_command_flag(token) or token.lower() == "/c":
            if idx + 1 < len(tokens):
                return tokens[idx + 1]
    return None


def _line_fetches_and_pipes_to_shell(command: str) -> bool:
    has_fetch = re.search(r"\b(?:curl|wget)\b", command) is not None
    piped_shell = re.search(r"\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh)\b", command) is not None
    return has_fetch and piped_shell


def _max_result(a: GuardrailResult, b: GuardrailResult) -> GuardrailResult:
    from doberman.models import VERDICT_ORDER

    return a if VERDICT_ORDER[a.verdict] >= VERDICT_ORDER[b.verdict] else b
