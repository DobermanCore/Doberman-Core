"""Bounded, read-only filesystem effect enumeration for delete-class commands.

ADR 0094 ("Bounded, read-only filesystem effect enumeration in the decision
path") permits exactly this module — and only this module — to touch the
filesystem beyond the usual DB/config reads: read-only ``os.walk``/``Path``
calls against the ALREADY-ADVERSARIALLY-PARSED operands of a delete-class
command (see ``engine/rules/commands.py::delete_class_operands``). No
subprocess, no network, ever. Display and audit only — the returned
``EffectSet`` never feeds risk or a verdict; see ``models.Decision.effects``,
structurally isolated from ``final_verdict``/``final_risk`` the same way
``Decision.shadow`` is.

Fail-toward-caution (ADR 0094 clause 3): any OS error, wall-clock timeout, or
the entry cap ends the walk in a NON-authoritative state — never a partial
count presented as complete. See ``EffectSet``'s own docstring for the two
non-authoritative shades and why they share one digest sentinel.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from doberman.canonical import canonicalize
from doberman.models import EffectSet

#: Sentinel digest for BOTH non-authoritative shades. A fixed, non-path token
#: distinct from any real content digest, so a transition into OR out of a
#: non-authoritative state always compares unequal — see the TOCTOU check in
#: ``proxy/executor.py::_handle_auth``.
_UNKNOWN_DIGEST = hashlib.sha256(b"doberman:effects:unknown\x00").hexdigest()

#: Shell glob metacharacters. An operand containing one that does not exist as
#: a literal path is NOT resolved (no glob engine here) — see the loop below.
_GLOB_CHARS = frozenset("*?[")


def _digest(relpaths: set[str]) -> str:
    return hashlib.sha256("\n".join(sorted(relpaths)).encode("utf-8", "surrogatepass")).hexdigest()


def _touches_git(relposix: str) -> bool:
    """True if ``.git`` is a path segment anywhere in ``relposix`` — not just
    at the operand root (a delete under ``target/.git/`` still hits git)."""
    return ".git" in relposix.split("/")


def _unknown(hits_git: bool, hits_outside_repo: bool) -> EffectSet:
    """Hard failure: OS error, timeout, or an unresolved glob — no lower bound."""
    return EffectSet(
        file_count=None,
        dir_count=None,
        capped=True,
        hits_git=hits_git,
        hits_outside_repo=hits_outside_repo,
        digest=_UNKNOWN_DIGEST,
    )


def _cap_hit(cap: int, hits_git: bool, hits_outside_repo: bool) -> EffectSet:
    """Hit the entry cap: at least ``cap`` entries exist, exact count unknown."""
    return EffectSet(
        file_count=cap,
        dir_count=None,
        capped=True,
        hits_git=hits_git,
        hits_outside_repo=hits_outside_repo,
        digest=_UNKNOWN_DIGEST,
    )


def _raise_walk_error(error: OSError) -> None:
    raise error


def compute_delete_effects(
    operands: list[str],
    repo_root: str,
    *,
    cap: int = 1000,
    budget_s: float = 0.25,
) -> EffectSet:
    """Bounded, read-only count of files/dirs ``operands`` would remove.

    ``os.walk(followlinks=False)`` per operand, a hard cap on total matched
    entries, and a monotonic wall-clock budget checked once per directory
    visited. Never raises: any OS error (an unreadable directory included —
    ``onerror`` is wired to re-raise rather than the default silent skip, so
    a permission error degrades to ``unknown`` instead of an undercount), a
    symlink loop (impossible to enter — ``followlinks=False``), the cap, or
    the budget all degrade to a non-authoritative result. See ADR 0094.

    A glob-shaped operand (contains ``*``/``?``/``[``) that does not exist as
    a literal path is not resolved — no glob engine here (ponytail) — and is
    conservatively treated as unknown rather than silently contributing zero:
    a real `rm -rf build/*` must never render as a false-safe empty preview.
    Full glob resolution is a follow-up if real commands need it.
    """
    if not operands:
        return EffectSet(
            file_count=0,
            dir_count=0,
            capped=False,
            hits_git=False,
            hits_outside_repo=False,
            digest=_digest(set()),
        )

    deadline = time.monotonic() + budget_s
    root = os.path.abspath(str(repo_root))
    files: set[str] = set()
    dirs: set[str] = set()
    hits_git = False
    hits_outside_repo = False

    def _relposix(abs_path: str) -> str:
        return os.path.relpath(abs_path, root).replace(os.sep, "/")

    for operand in operands:
        canon = canonicalize(operand, root=repo_root)
        if canon.escapes_root:
            hits_outside_repo = True
            continue  # never walk outside the confined root
        if _touches_git(canon.relposix):
            hits_git = True
        try:
            target = Path(canon.resolved)
            if target.is_symlink():
                continue  # never follow/count a symlink operand itself
            if not target.exists():
                if any(c in operand for c in _GLOB_CHARS):
                    return _unknown(hits_git, hits_outside_repo)
                continue  # nothing on disk yet for this operand
            if target.is_file():
                files.add(canon.relposix)
                continue
            dirs.add(canon.relposix)
            for dirpath, dirnames, filenames in os.walk(
                target, onerror=_raise_walk_error, followlinks=False
            ):
                if time.monotonic() > deadline:
                    return _unknown(hits_git, hits_outside_repo)
                for d in dirnames:
                    rel = _relposix(os.path.join(dirpath, d))
                    if _touches_git(rel):
                        hits_git = True
                    dirs.add(rel)
                    if len(files) + len(dirs) >= cap:
                        return _cap_hit(cap, hits_git, hits_outside_repo)
                for f in filenames:
                    full = os.path.join(dirpath, f)
                    if os.path.islink(full):
                        continue
                    rel = _relposix(full)
                    if _touches_git(rel):
                        hits_git = True
                    files.add(rel)
                    if len(files) + len(dirs) >= cap:
                        return _cap_hit(cap, hits_git, hits_outside_repo)
        except OSError:
            return _unknown(hits_git, hits_outside_repo)

    return EffectSet(
        file_count=len(files),
        dir_count=len(dirs),
        capped=False,
        hits_git=hits_git,
        hits_outside_repo=hits_outside_repo,
        digest=_digest(files | dirs),
    )
