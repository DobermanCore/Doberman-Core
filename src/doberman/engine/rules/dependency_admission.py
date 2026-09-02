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

from doberman.engine.rules.commands import _argv_from_tokens

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
