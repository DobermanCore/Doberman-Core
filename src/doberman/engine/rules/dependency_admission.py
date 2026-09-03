"""Dependency admission rule (C3, v1 — offline, name-only).

Parses package-manager install commands (pip/pip3/pipx/uv/poetry, npm/pnpm/
yarn/bun, cargo, gem, go — including a `python -m pip ...` wrapper, chained
commands, and command-substitution bodies, all via
:func:`~doberman.engine.rules.commands.walk_command`) and raises on the
package NAME alone:

* ``BLOCK`` when the name is on a bundled known-malicious list.
* ``AUTH``  when the name is edit-distance 1 from a bundled popular-package
  name AND is not itself on that popular list (the false-positive guard —
  npm's real `request` package must never flag a neighbor of `requests`).

v1 is deliberately name-only and 100% offline: **zero filesystem I/O, zero
network I/O inside evaluate()**. The two bundled lists
(`data/known_malicious_packages.json`, `data/popular_packages.json`) are
read ONCE at module import time via :mod:`importlib.resources` and cached
as in-memory, length-bucketed frozensets; nothing in this module reads a
lockfile, `package.json`, or any other file on disk, and nothing calls a
registry. That is a deliberate scope cut: reading a project's OWN lockfile
would be the first filesystem read any objective rule has ever made
(verified: zero hits for open/read_text/os.environ/.exists across
`engine/rules/` before this slice) and needs its own design decision
(mutable external state, TOCTOU, repo-root confinement) before it ships —
see `rules/__init__.py`'s module docstring and the README known-limitations
entry this slice adds.

Never scans postinstall/preinstall scripts, never resolves a registry,
never checks package age/maintainer history — all deferred. The
edit-distance heuristic is the ONLY statistical signal in this rule and is
capped at AUTH by construction: it must never be promoted to BLOCK
(Doberman's raise-only invariant — a membership predicate may BLOCK, a
distance score may not).

SECURITY: explanations name the ecosystem classification only, never the
raw package name or any other argv text — mirrors the module contract in
`rules/__init__.py`.
"""

from __future__ import annotations

import json
from importlib.resources import files

from doberman.engine.rules.commands import (
    _COMMAND_ACTION_TYPES,
    _argv_from_tokens,
    _command_text,
    _raw_command_payload,
    walk_command,
)
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

#: verb -> (ecosystem, install-subcommands that take a package NAME
#: operand). Deliberately excludes publish/upload/push (C3 is an admission
#: gate, not a publish gate — that table belongs to C6) and go's "install"
#: (builds from an already-resolved module-cache entry, not a fresh-name
#: admission point); "go get" is the fetch-a-new-dependency verb.
_ECOSYSTEM_VERBS: dict[str, tuple[str, frozenset[str]]] = {
    "pip": ("pypi", frozenset({"install"})),
    "pip3": ("pypi", frozenset({"install"})),
    "pipx": ("pypi", frozenset({"install"})),
    "uv": ("pypi", frozenset({"add"})),
    "poetry": ("pypi", frozenset({"add"})),
    "npm": ("npm", frozenset({"install", "i", "add"})),
    "pnpm": ("npm", frozenset({"install", "i", "add"})),
    "yarn": ("npm", frozenset({"add"})),
    "bun": ("npm", frozenset({"install", "i", "add"})),
    "cargo": ("cargo", frozenset({"add"})),
    "gem": ("rubygems", frozenset({"install"})),
    "go": ("go", frozenset({"get"})),
}

#: `python -m pip install X` / `python3 -m pip install X`:
#: `_argv_from_tokens` strips env assignments and shell wrappers
#: (sudo/env/...) but not this interpreter-module-runner shape, so it is
#: peeled here.
_MODULE_RUNNERS = frozenset({"python", "python3", "py"})

#: Flags whose value is a separate token (never a package name) — both are
#: skipped. `-r`/`-c` point at a local requirements/constraints FILE:
#: reading it would be the lockfile-read this slice explicitly defers.
_VALUE_FLAGS = frozenset(
    {"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url"}
)

#: Never edit-distance-check a name this short — a 1-2 char name is close
#: to almost everything and the false-positive rate swamps any signal.
_MIN_TYPOSQUAT_NAME_LEN = 4


def _peel_module_runner(tokens: list[str]) -> list[str]:
    if len(tokens) >= 3 and tokens[0].lower() in _MODULE_RUNNERS and tokens[1] == "-m":
        return tokens[2:]
    return tokens


def _strip_version(token: str) -> str:
    """Strip a trailing version/extras suffix so only the bare name remains.

    A leading ``@`` (npm scoped package, e.g. ``@myorg/utils``) is never
    itself treated as a version separator.
    """
    scoped = token.startswith("@")
    body = token[1:] if scoped else token
    for sep in ("==", ">=", "<=", "~=", "!=", "===", "<", ">", "@"):
        body = body.split(sep, 1)[0]
    body = body.split("[", 1)[0]  # extras: package[extra1,extra2]
    name = ("@" + body) if scoped else body
    return name.strip()


def _is_installable_name(name: str) -> bool:
    """False for flags, local paths, URLs, and VCS refs — never a registry name."""
    if not name:
        return False
    if name.startswith(("-", ".", "/")):
        return False
    if "://" in name or "git+" in name.lower():
        return False
    if "\\" in name:
        return False  # Windows-style local path
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return False  # Windows drive prefix, e.g. "C:..."
    return True


def _extract_names(tokens: list[str]) -> list[str]:
    """Package-name operands in a subcommand's argument tail, minus flags."""
    names: list[str] = []
    skip_value = False
    for tok in tokens:
        if skip_value:
            skip_value = False
            continue
        if tok.startswith("-"):
            if tok in _VALUE_FLAGS:
                skip_value = True
            continue
        candidate = _strip_version(tok).lower()
        if _is_installable_name(candidate):
            names.append(candidate)
    return names


def _ecosystem_and_names(raw_tokens: list[str]) -> tuple[str, list[str]] | None:
    """One segment's ``(ecosystem, [package names])``, or ``None`` if it is
    not a recognized package-manager install/add invocation."""
    tokens = _peel_module_runner(_argv_from_tokens(raw_tokens))
    if not tokens:
        return None
    entry = _ECOSYSTEM_VERBS.get(tokens[0].lower())
    if entry is None:
        return None
    ecosystem, subcommands = entry
    rest = tokens[1:]
    if not rest or rest[0].lower() not in subcommands:
        return None
    names = _extract_names(rest[1:])
    return (ecosystem, names) if names else None


def _within_edit_distance_one(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` differ by at most one insertion, deletion, or
    substitution. O(len) single pass — safe on an arbitrarily large input
    (the bounded-time property test in Task 4 covers this)."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(1 for x, y in zip(a, b, strict=True) if x != y) == 1
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    used = False
    while i < len(shorter) and j < len(longer):
        if shorter[i] == longer[j]:
            i += 1
            j += 1
            continue
        if used:
            return False
        used = True
        j += 1
    return True


_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

# _COMMAND_ACTION_TYPES (the command-bearing action types
# DestructiveCommandRule recognizes — a tool-name label is not a trust
# boundary) is imported from commands.py above rather than redefined here;
# any OTHER action type still gets scanned via the raw-arguments fallback
# below, just without the `action.target` fallback (a file path or URL on
# an unrelated action must never be misread as a shell command) — see
# `commands.py:895-906` for the pattern being mirrored.


def _bucket_by_length(names: frozenset[str]) -> dict[int, frozenset[str]]:
    buckets: dict[int, set[str]] = {}
    for name in names:
        buckets.setdefault(len(name), set()).add(name)
    return {length: frozenset(members) for length, members in buckets.items()}


def _load_json_lists(filename: str) -> dict[str, frozenset[str]]:
    """Load a bundled ``{ecosystem: [names]}`` JSON file once, at import time."""
    raw = files("doberman.engine.rules.data").joinpath(filename).read_text(encoding="utf-8")
    data = json.loads(raw)
    return {
        ecosystem: frozenset(name.lower() for name in names)
        for ecosystem, names in data.items()
        if ecosystem != "generated_at"
    }


_DEFAULT_KNOWN_MALICIOUS: dict[str, frozenset[str]] = _load_json_lists(
    "known_malicious_packages.json"
)
_DEFAULT_POPULAR_BY_LEN: dict[str, dict[int, frozenset[str]]] = {
    ecosystem: _bucket_by_length(names)
    for ecosystem, names in _load_json_lists("popular_packages.json").items()
}


class DependencyAdmissionRule:
    """BLOCK on a bundled known-malicious package name; AUTH on a name one
    edit away from a bundled popular name that is not itself popular.

    Pure: all data is loaded once at import time (the module-level
    constants above); ``evaluate()`` touches no filesystem, environment
    variable, or socket. Raise-only within this rule (PASS -> AUTH -> BLOCK,
    never handed back downgraded), and the edit-distance heuristic never
    reaches BLOCK on its own — only exact known-malicious membership does.
    """

    def __init__(
        self,
        known_malicious: dict[str, frozenset[str]] | None = None,
        popular_by_len: dict[str, dict[int, frozenset[str]]] | None = None,
    ) -> None:
        self._known_malicious = (
            known_malicious if known_malicious is not None else _DEFAULT_KNOWN_MALICIOUS
        )
        self._popular_by_len = (
            popular_by_len if popular_by_len is not None else _DEFAULT_POPULAR_BY_LEN
        )

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        if action.action_type in _COMMAND_ACTION_TYPES:
            command = _command_text(action, ctx)
        else:
            command = _raw_command_payload(ctx)
        if not command or not command.strip():
            return _PASS

        segments, _ambiguous, _dynamic = walk_command(command)
        auth_hit: GuardrailResult | None = None
        for tokens in segments:
            parsed = _ecosystem_and_names(tokens)
            if parsed is None:
                continue
            ecosystem, names = parsed
            for name in names:
                if self._is_known_malicious(ecosystem, name):
                    return self._block_result(ecosystem)
                if auth_hit is None and self._is_typosquat(ecosystem, name):
                    auth_hit = self._auth_result(ecosystem)
        return auth_hit if auth_hit is not None else _PASS

    def _is_known_malicious(self, ecosystem: str, name: str) -> bool:
        return name in self._known_malicious.get(ecosystem, frozenset())

    def _is_typosquat(self, ecosystem: str, name: str) -> bool:
        if len(name) < _MIN_TYPOSQUAT_NAME_LEN or name.startswith("@"):
            return False
        by_len = self._popular_by_len.get(ecosystem, {})
        if name in by_len.get(len(name), frozenset()):
            return False  # itself a recognized popular package
        for delta in (-1, 0, 1):
            for candidate in by_len.get(len(name) + delta, frozenset()):
                if _within_edit_distance_one(name, candidate):
                    return True
        return False

    @staticmethod
    def _block_result(ecosystem: str) -> GuardrailResult:
        return GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.dependency_known_malicious],
            explanation=(
                f"A {ecosystem} package name in this command is on Doberman's "
                "bundled known-malicious list; installation is blocked."
            ),
        )

    @staticmethod
    def _auth_result(ecosystem: str) -> GuardrailResult:
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.medium,
            reason_codes=[ReasonCode.dependency_name_typosquat],
            explanation=(
                f"A {ecosystem} package name in this command is one character "
                "away from a popular package name and is not itself a "
                "recognized popular package (possible typosquat); "
                "authentication required."
            ),
        )
