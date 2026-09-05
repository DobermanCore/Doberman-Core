"""Bounded, read-only filesystem effect enumeration for delete-class commands.

ADR 0094 ("Bounded, read-only filesystem effect enumeration in the decision
path") permits exactly this module — and only this module — to touch the
filesystem beyond the usual DB/config reads: read-only ``os.walk``/``Path``
calls against the ALREADY-ADVERSARIALLY-PARSED operands of a delete-class
command (see ``engine/rules/commands.py::delete_class_operands_and_dynamic``). No
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
    at the operand root (a delete under ``target/.git/`` still hits git).

    Case-insensitive on Windows only (C2 cleanup, #558): NTFS is case-
    insensitive-but-preserving, so a git dir the filesystem happens to report
    as ``.GIT`` names the SAME directory as ``.git`` there and must still be
    flagged. Left case-sensitive on POSIX, where ``.git``/``.GIT`` are
    genuinely distinct directories — folding case there would over-flag an
    unrelated delete as touching git.
    """
    segments = relposix.split("/")
    if os.name == "nt":
        return ".git" in (segment.lower() for segment in segments)
    return ".git" in segments


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


def _cap_hit(files_seen: int, dirs_seen: int, hits_git: bool, hits_outside_repo: bool) -> EffectSet:
    """Hit the entry cap: ``files_seen``/``dirs_seen`` are the exact counts
    scanned before the cap fired (their sum is the cap) — a lower bound on
    each true total, never a confirmed complete count.

    C2 cleanup (#558): this used to dump the whole cap value into
    ``file_count`` with ``dir_count=None`` regardless of what was actually
    found, so a delete that was mostly directories rendered as "N+ files".
    The caller already tracks both counts (``len(files)``/``len(dirs)``) —
    passing them through instead of discarding them is the whole fix.
    """
    return EffectSet(
        file_count=files_seen,
        dir_count=dirs_seen,
        capped=True,
        hits_git=hits_git,
        hits_outside_repo=hits_outside_repo,
        digest=_UNKNOWN_DIGEST,
    )


def _raise_walk_error(error: OSError) -> None:
    raise error


def unknown_effects() -> EffectSet:
    """The ``unknown`` :class:`~doberman.models.EffectSet` state (ADR 0094),
    for a caller that must not even try a walk: a delete-class command whose
    operand list can't be trusted (e.g. a live shell substitution among the
    operands — see ``engine/rules/commands.py::delete_class_operands_and_dynamic``'s
    ``dynamic`` return value) rather than a walk that started and then
    failed. Same sentinel digest as an OS-error/cap/timeout failure — both
    are equally "not what was shown"
    for the TOCTOU compare in ``proxy/executor.py``.
    """
    return _unknown(hits_git=False, hits_outside_repo=False)


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
    # C2 cleanup (#558): this walked-descendant relpath used to be built
    # against `root` above (os.path.abspath — never resolves symlinks), while
    # a direct operand's canon.relposix (below) is built against the shared
    # canonicalize() helper's RESOLVED root. On a symlinked repo root (e.g.
    # macOS's /tmp -> /private/tmp) the two disagreed, corrupting a walked
    # descendant's digest entry. Resolve once, the same way canonicalize()
    # resolves its own root, so every entry in `files`/`dirs` shares one
    # basis. `root` above stays unresolved for the actual filesystem-access
    # joins just below (os.path.islink()/os.path.join()) — the OS follows a
    # root-level symlink transparently there regardless.
    _resolved_root = canonicalize(root, root=root).resolved
    files: set[str] = set()
    dirs: set[str] = set()
    hits_git = False
    hits_outside_repo = False

    def _relposix(abs_path: str) -> str:
        # C2 cleanup (#558): fold case to match canon.relposix, so walked
        # descendants produce consistent digest entries across all platforms.
        return os.path.relpath(abs_path, _resolved_root).replace(os.sep, "/").lower()

    for operand in operands:
        # C1 (C2 final review): the bounds above only ever fired inside
        # os.walk. The per-operand work itself (islink, canonicalize,
        # Path.exists()/is_file(), and a bare `files.add()` for a FILE
        # operand — no os.walk involved at all) was unbounded: 20,000
        # nonexistent operands took 15.4s against a 0.25s budget, and 3,000
        # existing-file operands sailed past a cap=1000 reporting
        # capped=False. Check both bounds once per operand, before any work
        # on it starts.
        if time.monotonic() > deadline:
            return _unknown(hits_git, hits_outside_repo)
        if len(files) + len(dirs) >= cap:
            return _cap_hit(len(files), len(dirs), hits_git, hits_outside_repo)
        try:
            # A NUL byte can never appear in a real path component on any
            # filesystem, so an operand containing one cannot denote a real
            # target. canonicalize()'s internal fallback and Path.exists()
            # both swallow the resulting ValueError rather than raise it, so
            # left unguarded this would silently fall through to the
            # "doesn't exist" branch and render as a confident zero — the
            # exact false-safe empty preview ADR 0094 clause 3 forbids. Fail
            # toward unknown here, before any path work starts.
            if "\x00" in operand:
                return _unknown(hits_git, hits_outside_repo)
            # Confinement FIRST (I1, C2 final review): os.path.join(root, operand)
            # passes an absolute or UNC operand through UNCHANGED (os.path.join
            # drops the root when the second argument is itself absolute), so an
            # os.path.islink() call on that raw join BEFORE escapes_root is
            # checked could reach an attacker-controlled path (e.g. a UNC host,
            # \\evil-host\share\x) straight from the decision path. Only a
            # CONFINED operand reaches the islink() call below.
            canon = canonicalize(operand, root=repo_root)
            if canon.escapes_root:
                hits_outside_repo = True
                continue  # never walk outside the confined root
            # Check the RAW, unresolved (but now confirmed-confined) operand for
            # symlink-ness: canonicalize()/Path.resolve() resolve symlinks, so an
            # in-repo symlink target (rm -rf link, link -> real_dir/, both inside
            # the repo) would otherwise sail past an is_symlink() check performed
            # on the already-resolved path and have its TARGET walked and counted
            # — but `rm` removes the link entry, never the target's contents
            # (Task 3 review fix, ADR 0094). Confinement still goes through the
            # one shared canonicalizer above (no second path resolver).
            is_link_operand = os.path.islink(os.path.join(root, operand))
            if is_link_operand:
                # A symlink operand is exactly one filesystem entry — never
                # descended, and never reported under the resolved target's
                # path (that would misattribute the target's identity to the
                # link being deleted).
                link_relposix = _relposix(os.path.join(root, operand))
                if _touches_git(link_relposix):
                    hits_git = True
                files.add(link_relposix)
                if len(files) + len(dirs) >= cap:
                    return _cap_hit(len(files), len(dirs), hits_git, hits_outside_repo)
                continue
            if _touches_git(canon.relposix):
                hits_git = True
            target = Path(canon.resolved)
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
                    full = os.path.join(dirpath, d)
                    if os.path.islink(full):
                        # Consistent with the filenames skip just below: never
                        # counted, never descended (followlinks=False already
                        # stops recursion into it).
                        continue
                    rel = _relposix(full)
                    if _touches_git(rel):
                        hits_git = True
                    dirs.add(rel)
                    if len(files) + len(dirs) >= cap:
                        return _cap_hit(len(files), len(dirs), hits_git, hits_outside_repo)
                for f in filenames:
                    full = os.path.join(dirpath, f)
                    if os.path.islink(full):
                        continue
                    rel = _relposix(full)
                    if _touches_git(rel):
                        hits_git = True
                    files.add(rel)
                    if len(files) + len(dirs) >= cap:
                        return _cap_hit(len(files), len(dirs), hits_git, hits_outside_repo)
        except (OSError, ValueError):
            return _unknown(hits_git, hits_outside_repo)

    return EffectSet(
        file_count=len(files),
        dir_count=len(dirs),
        capped=False,
        hits_git=hits_git,
        hits_outside_repo=hits_outside_repo,
        digest=_digest(files | dirs),
    )
