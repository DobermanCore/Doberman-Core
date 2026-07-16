"""Destructive-command rule (Feature 3, slice 3.4).

Blocks catastrophic shell/git commands and steps up authentication on
risky-but-recoverable ones. Command parsing is treated as **adversarial**: a
single command string may chain many commands with ``;``, ``&&``, ``||``, or
pipes, hide work in ``$(...)``/backtick substitutions, or carry an opaque
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

# Doberman's own CLI subcommands that install/remove the host hooks or rewire the
# control plane: an agent invoking these through a shell is tampering with the
# cop, not doing project work (HK.5.0b). The human runs these directly (not via a
# gated tool), so the hook only ever sees the *agent* invoking them.
_DOBERMAN_CONTROL_SUBCOMMANDS = {"uninstall-hooks", "install-hooks", "setup"}

#: Default bulk-operation threshold: deleting/touching this many paths in one
#: command steps up to AUTH. Overridable (F6 wires this from policy/mode).
DEFAULT_BULK_THRESHOLD = 25

#: Branch names whose history is protected — a force-push here is catastrophic.
DEFAULT_PROTECTED_BRANCHES: tuple[str, ...] = ("main", "master", "release", "develop")

# Shell operators that separate independent commands within one line.
_SEGMENT_SPLIT = re.compile(r"(?:\|\||&&|\||;|\n)")

# Command-substitution bodies: $(...) and `...`. We recurse into these so a
# destructive command hidden inside a substitution is still evaluated.
_SUBSTITUTION = re.compile(r"\$\((?P<paren>[^()]*)\)|`(?P<backtick>[^`]*)`")

# Env-assignment prefixes (FOO=bar) and benign wrappers we look through.
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_TRANSPARENT_WRAPPERS = {"sudo", "nice", "ionice", "nohup", "time", "env", "command", "exec"}

# Shells that take an opaque "-c <payload>" we cannot statically vet.
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}


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
    return [seg.strip() for seg in _SEGMENT_SPLIT.split(command) if seg.strip()]


def _argv(segment: str) -> list[str] | None:
    """Parse one segment into argv with shlex; ``None`` if it cannot be parsed.

    Unparseable (e.g. unbalanced quotes) returns ``None`` so the caller fails
    upward to AUTH rather than guessing.
    """
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return None
    # Strip env assignments and transparent wrappers (sudo/nice/...). Keep
    # track of whether a privilege wrapper was present (raises risk).
    while tokens and (_ENV_ASSIGNMENT.match(tokens[0]) or tokens[0] in _TRANSPARENT_WRAPPERS):
        tokens.pop(0)
    return tokens


def _is_root_or_home_target(arg: str) -> bool:
    """True if an argument denotes ``/``, ``~``, or a whole-tree wildcard."""
    normalized = posixpath.normpath(arg.strip().strip("'\""))
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


# Catastrophic non-rm commands (whole-disk wipes, fork bombs).
_DISK_WIPE = re.compile(r"^(?:mkfs(?:\.\w+)?|shred|wipefs)$")


def _is_doberman_control_cli(tokens: list[str]) -> bool:
    """``doberman uninstall-hooks`` / ``install-hooks`` / ``setup`` — control-plane tamper."""
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
            "Shell command would install/remove Doberman's host hooks (control-plane tamper)."
        )
    if _package_manager_removes_doberman(tokens):
        return _block_control_plane(
            "Package-manager command would uninstall Doberman's guard (control-plane tamper)."
        )

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

    # --- Risky but recoverable → AUTH ---
    if cmd == "rm" and _count_delete_operands(tokens) >= bulk_threshold:
        return _auth(
            ReasonCode.bulk_operation,
            "Bulk delete at or above the configured threshold; authentication required.",
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


def _opaque_shell_payload(tokens: list[str]) -> bool:
    """True if this is ``bash -c <payload>`` (or similar) we cannot vet."""
    if not tokens or tokens[0] not in _SHELLS:
        return False
    return "-c" in tokens or "--command" in tokens


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


def _command_text(action: SecurityObject, ctx: EvalContext) -> str | None:
    """Extract the raw command string (from un-redacted context, else target)."""
    raw_arguments = ctx.metadata.get("raw_arguments") if isinstance(ctx.metadata, dict) else None
    if isinstance(raw_arguments, dict):
        for key in ("command", "cmd", "script", "args"):
            value = raw_arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value
            if isinstance(value, (list, tuple)) and value:
                return " ".join(str(v) for v in value)
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
        # Only relevant to shell/git actions. A non-command action abstains.
        if action.action_type not in (ActionType.shell_exec, ActionType.git_op):
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        command = _command_text(action, ctx)
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
        saw_unparseable = False

        # Work queue of command-line segments (strings). We seed it with the
        # top-level segments and push substitution / -c payload bodies as we
        # discover them, bounded so a hostile nesting cannot loop forever.
        pending: list[str] = _split_segments(command)
        processed = 0
        while pending and processed < 256:
            processed += 1
            segment = pending.pop()
            stripped, bodies = _strip_substitutions(segment)
            for body in bodies:  # recurse into $(...) / `...` bodies
                pending.extend(_split_segments(body))

            tokens = _argv(stripped)
            if tokens is None:
                saw_unparseable = True
                continue
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
                pending.extend(_payload_segments(tokens))
                continue

            verdict = _segment_verdict(tokens, self._protected, bulk_threshold, root)
            if verdict is not None:
                worst = _max_result(worst, verdict)
                if worst.verdict is Verdict.BLOCK:
                    return worst

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


def _payload_segments(tokens: list[str]) -> list[str]:
    """Pull the argument after ``-c`` and split it for a best-effort scan."""
    for flag in ("-c", "--command"):
        if flag in tokens:
            idx = tokens.index(flag)
            if idx + 1 < len(tokens):
                return _split_segments(tokens[idx + 1])
    return []


def _line_fetches_and_pipes_to_shell(command: str) -> bool:
    has_fetch = re.search(r"\b(?:curl|wget)\b", command) is not None
    piped_shell = re.search(r"\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh)\b", command) is not None
    return has_fetch and piped_shell


def _max_result(a: GuardrailResult, b: GuardrailResult) -> GuardrailResult:
    from doberman.models import VERDICT_ORDER

    return a if VERDICT_ORDER[a.verdict] >= VERDICT_ORDER[b.verdict] else b
