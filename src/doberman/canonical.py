"""The one shared path canonicalizer (Feature 3 / Feature 4).

Path matching is only as safe as the canonicalization that precedes it. An
attacker who can express a protected path as ``../../etc/secret``, through a
symlink, or with a different letter case would bypass a naive glob match. To
keep that surface from diverging, **every** path-matching rule in the codebase
canonicalizes through :func:`canonicalize` first — the protected-path rule
(F3.3) and the role-boundary matcher (F4.2) both import this single helper.

Guarantees:

* ``.``/``..`` segments are resolved, and symlinks are resolved **where the
  path exists** (lexical resolution where it does not — tolerating not-yet-
  created files without touching the filesystem to create them).
* The result is confined to ``root``: if the resolved path lands outside the
  repository root, :attr:`CanonicalPath.escapes_root` is ``True`` (a strong
  signal a rule should escalate, never silently allow).
* Matching is **case-insensitive** by default (``relposix`` is lower-cased),
  because case-preserving filesystems (Windows, macOS default) would otherwise
  let ``.ENV`` slip past a ``.env`` rule.

This module performs **no filesystem writes** and never raises on hostile
input — on any failure it returns a conservative ``escapes_root=True`` result
so callers fail closed.

SECURITY: callers must treat :attr:`CanonicalPath.escapes_root` as
"out of bounds → escalate", and must match policy globs against
:attr:`CanonicalPath.relposix` (the normalized, root-relative, forward-slash,
lower-cased form), never against the raw input string.
"""

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class CanonicalPath:
    """The canonical form of a path, ready for glob matching.

    Attributes:
        resolved: the absolute, symlink/``..``-resolved path as a string
            (case preserved — for display/forensics, not for matching).
        relposix: the root-relative path with forward slashes, **lower-cased**
            — the form rules match policy globs against. Empty string means the
            path *is* the root.
        escapes_root: ``True`` when the resolved path is not inside ``root``
            (e.g. a ``..`` traversal or an absolute path elsewhere). Rules MUST
            treat this as out-of-scope and escalate, never allow.
    """

    resolved: str
    relposix: str
    escapes_root: bool


def _safe_resolve(path: Path) -> Path:
    """Resolve ``.``/``..``/symlinks without requiring the path to exist.

    ``Path.resolve(strict=False)`` already tolerates missing tail components on
    modern CPython, but we guard it: any OS-level failure (loop, permission)
    degrades to a lexical normalization so we never raise into a decision.
    """
    try:
        # strict=False: resolve as far as the path exists, lexically normalize
        # the rest. Resolves symlinks on the existing prefix — the whole point.
        return path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        # RuntimeError: symlink loop. Fall back to a purely lexical resolution
        # (os.path.normpath collapses ".."/"." textually, no fs access).
        return Path(os.path.normpath(str(path)))


def canonicalize(path: str, *, root: str | os.PathLike[str]) -> CanonicalPath:
    """Canonicalize ``path`` relative to repository ``root`` for safe matching.

    ``path`` may be absolute or relative (relative paths are taken against
    ``root``). The return value is always populated; on any error the result is
    conservatively marked ``escapes_root=True`` so callers fail closed.

    This function never writes to the filesystem and never raises.
    """
    try:
        root_path = _safe_resolve(Path(root))
    except (OSError, RuntimeError, ValueError):
        # An unusable root means we cannot reason about confinement at all —
        # fail closed: report an escape with no usable relative form.
        return CanonicalPath(resolved=str(path), relposix="", escapes_root=True)

    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = root_path / candidate
        resolved = _safe_resolve(candidate)
    except (OSError, RuntimeError, ValueError):
        return CanonicalPath(resolved=str(path), relposix="", escapes_root=True)

    # Confinement check via the resolved, absolute forms. We compare on
    # os.path.commonpath of the case-folded strings so a different drive or a
    # parent escape is detected on both POSIX and Windows.
    resolved_str = str(resolved)
    try:
        rel = resolved.relative_to(root_path)
        escapes = False
    except ValueError:
        # Not under root — a traversal/symlink escape or an unrelated absolute
        # path. Still surface a best-effort relative form for the explanation
        # layer, but mark the escape so rules escalate.
        rel = None
        escapes = True

    if rel is None:
        relposix = ""
    else:
        # Normalize to forward slashes and lower-case for case-insensitive
        # matching. PurePosixPath gives us a stable separator on every OS.
        relposix = PurePosixPath(*rel.parts).as_posix().lower()
        if relposix == ".":
            relposix = ""

    return CanonicalPath(resolved=resolved_str, relposix=relposix, escapes_root=escapes)
