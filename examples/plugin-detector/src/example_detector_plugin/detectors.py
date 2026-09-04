"""Minimal custom Detector: step up shell execs with an unusually long pipeline.

This is the worked example for issue #200's ``doberman.detectors`` seam. It
intentionally mirrors the style of
``examples/plugin-guardrail/src/example_plugin/rules.py`` (the ``doberman.rules``
worked example) — the two groups are structurally identical, both contributing
``Guardrail``-shaped objects (per ``discover_detectors()``'s own docstring):

* deterministic and stateless: a pure function of the action + context, no
  I/O, no shared mutable state between calls;
* prefer the raw (un-redacted) command from ``ctx.metadata["raw_arguments"]``
  when present, so a redacted ``action.target`` cannot hide a chained command;
* return only ``PASS`` / ``AUTH`` shaped results (raise-only: never ``BLOCK``
  from a tutorial detector);
* never put the raw command, arguments, or any payload into ``explanation``.

Behavioral flavor: a shell command chaining more than ``_STAGE_THRESHOLD``
pipeline stages (segments separated by ``|``, ``&&``, ``||``, or ``;``) is a
common obfuscation / command-injection shape — deliberately simple so the demo
is easy to read and unit test from a bare ``SecurityObject`` + ``EvalContext``.

Raise-only: this detector only ever abstains (PASS) or steps up (AUTH). The
subjective guardrail combines every detector's result with ``combine()``, so a
plugin cannot lower another detector's (or the scoring signal's) verdict.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping

from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

#: Keys that may carry a raw shell command in un-redacted call arguments —
#: same idea as the guardrail example's ``_RAW_PATH_KEYS`` (kept local so this
#: package does not import ``doberman.proxy`` or the built-in command rule).
_RAW_COMMAND_KEYS: tuple[str, ...] = ("command", "cmd", "script")

#: More than this many pipeline stages (segments separated by a shell chaining
#: operator) steps up to AUTH. Kept low and fixed for the demo — a real
#: detector would likely make this configurable.
_STAGE_THRESHOLD = 3

#: Shell operators that start a new pipeline stage.
_STAGE_OPERATORS = frozenset({"|", "&&", "||", ";"})


def _abstain() -> GuardrailResult:
    """Fresh PASS/low — no shared mutable result object for callers to alias."""
    return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def _raw_command(raw_arguments: Mapping[str, object]) -> str | None:
    """Extract a command string from raw call arguments (match only, never log)."""
    for key in _RAW_COMMAND_KEYS:
        value = raw_arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _command_for(action: SecurityObject, ctx: EvalContext) -> str | None:
    """Prefer raw_arguments' command, then the (possibly redacted) action target."""
    raw_arguments = None
    if isinstance(ctx.metadata, dict):
        raw_arguments = ctx.metadata.get("raw_arguments")
    if isinstance(raw_arguments, dict):
        command = _raw_command(raw_arguments)
        if command:
            return command
    return action.target or None


def _stage_count(command: str) -> int:
    """Count pipeline stages in ``command`` (quote-aware, never raises).

    Uses :mod:`shlex` with the shell-chaining characters as punctuation so a
    quoted ``"a | b"`` argument is not mistaken for a real pipe operator (the
    same quote-awareness principle the built-in command rule uses, kept local
    and much simpler here since this is only a demo). A command that cannot be
    tokenized (unbalanced quotes) is treated as a single, opaque stage — this
    tutorial detector never guesses at a structure it cannot parse.
    """
    lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;")
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return 1
    separators = sum(1 for token in tokens if token in _STAGE_OPERATORS)
    return separators + 1


class ExampleDetector:
    """Step up shell execs that chain more than ``_STAGE_THRESHOLD`` pipeline stages.

    Implements the :class:`~doberman.engine.decision_engine.Guardrail` protocol
    (one method: ``evaluate``) — the subjective guardrail's home for behavioral
    (UEBA-style) detectors. Registered via::

        [project.entry-points."doberman.detectors"]
        example_detector = "example_detector_plugin.detectors:ExampleDetector"
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        # Scope: only shell execs. Keep the demo obvious and minimal.
        if action.action_type is not ActionType.shell_exec:
            return _abstain()

        command = _command_for(action, ctx)
        if not command:
            return _abstain()

        if _stage_count(command) > _STAGE_THRESHOLD:
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.unusual_for_workflow],
                # Names the *signal*, never the command text or its arguments.
                explanation=(
                    "Shell command chains an unusually long pipeline; "
                    "authentication required before proceeding."
                ),
            )
        return _abstain()
