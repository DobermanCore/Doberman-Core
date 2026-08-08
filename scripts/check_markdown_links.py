#!/usr/bin/env python3
"""Offline checker for repository-local Markdown links and heading anchors.

Scans maintained documentation, resolves relative targets from the file that
contains each link, and exits nonzero when a checked link is broken. External
schemes (http, https, mailto, …) are skipped without network access. Link-like
text inside fenced code blocks is ignored. Paths that escape the repository
root are reported as errors.

Usage:
  python scripts/check_markdown_links.py
  python scripts/check_markdown_links.py --root .
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

# Default documentation surfaces to check (deterministic order).
DEFAULT_GLOBS: tuple[str, ...] = (
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "CONTRIBUTORS.md",
    "RELEASING.md",
    "AGENTS.md",
    "CLAUDE.md",
    "docs/**/*.md",
)

# Schemes we never fetch or resolve as local paths.
_EXTERNAL_SCHEMES = (
    "http://",
    "https://",
    "mailto:",
    "tel:",
    "data:",
    "ftp://",
    "ftps://",
    "javascript:",
)

# Fenced code blocks: opening fence of 3+ backticks or tildes, optional info string.
_FENCE_RE = re.compile(r"^(?P<fence>`{3,}|~{3,})(?P<info>[^\n]*)\n", re.MULTILINE)

# Inline markdown links / images: ![alt](target) or [text](target).
# Target may be wrapped in <...>; title after the destination is ignored.
_LINK_RE = re.compile(
    r"""
    !?\[                   # [text] or ![alt]
      (?:[^\]\\]|\\.)*     # link text (allow escapes)
    \]
    \(
      \s*
      (?:<([^>\n]+)>|([^)\s]+))  # <target> or bare target
      (?:
        \s+
        (?:"[^"]*"|'[^']*'|\([^)]*\))  # optional title
      )?
      \s*
    \)
    """,
    re.VERBOSE,
)

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)
# Explicit HTML anchors used in these docs: <a name="…"> / <a id="…"> / id="…"
_HTML_ANCHOR_RE = re.compile(
    r"""(?ix)
    <a\b[^>]*\b(?:name|id)\s*=\s*["']([^"']+)["']
    |
    \bid\s*=\s*["']([^"']+)["']
    """
)


@dataclass(frozen=True)
class LinkRef:
    """One markdown link occurrence."""

    source: Path
    line: int
    target: str


@dataclass(frozen=True)
class LinkIssue:
    """A single diagnostic for a broken or unsafe link."""

    source: Path
    line: int
    target: str
    reason: str

    def format(self, root: Path) -> str:
        try:
            rel = self.source.resolve().relative_to(root.resolve())
        except ValueError:
            rel = self.source
        return f"{rel}:{self.line}: {self.reason}: {self.target}"


def is_external_target(target: str) -> bool:
    """Return True when target should be skipped (no network)."""
    stripped = target.strip()
    if not stripped or stripped.startswith("#"):
        return False
    lower = stripped.lower()
    if lower.startswith(_EXTERNAL_SCHEMES):
        return True
    # Protocol-relative URLs
    if stripped.startswith("//"):
        return True
    # scheme:something (but not Windows drive letters like C:\ — we are on posix paths in CI)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", stripped) and not stripped[1:2] == "\\":
        # Allow pure fragment already handled; treat other schemes as external.
        scheme = stripped.split(":", 1)[0].lower()
        if scheme not in {"file"}:
            return True
    return False


def strip_fenced_code_blocks(text: str) -> str:
    """Replace fenced code block interiors with blank lines (keep line numbers)."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        fence_match = re.match(r"^(`{3,}|~{3,})", line)
        if fence_match:
            fence = fence_match.group(1)
            # Keep the fence line blanked so content inside cannot match links.
            out.append("\n" if line.endswith("\n") else "")
            i += 1
            while i < len(lines):
                out.append("\n" if lines[i].endswith("\n") else "")
                if lines[i].startswith(fence) and lines[i].strip() == fence:
                    i += 1
                    break
                i += 1
            continue
        out.append(line)
        i += 1
    return "".join(out)


def iter_markdown_links(text: str, source: Path) -> Iterator[LinkRef]:
    """Yield links from text that is already free of fenced code interiors."""
    for match in _LINK_RE.finditer(text):
        target = match.group(1) if match.group(1) is not None else match.group(2)
        target = target.strip()
        if not target:
            continue
        line = text.count("\n", 0, match.start()) + 1
        yield LinkRef(source=source, line=line, target=target)


def github_heading_slug(heading_text: str) -> str:
    """Approximate GitHub / GFM heading id generation.

    Mirrors the common github-slugger behaviour used for README anchors:
    strip markup, lowercase, drop non-word characters (keeping hyphens),
    collapse whitespace runs to a single hyphen.
    """
    text = heading_text.strip()
    # Drop HTML tags embedded in headings (e.g. <a name="…">).
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[*~]+", "", text)
    text = text.lower()
    # Word chars + latin supplements + spaces + hyphens (github-slugger-ish).
    text = re.sub(r"[^\w\u00c0-\u024f\u1e00-\u1eff\s-]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "-", text.strip())
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text


def collect_heading_slugs(text: str) -> set[str]:
    """Return heading slugs plus explicit HTML name/id anchors."""
    counts: dict[str, int] = {}
    slugs: set[str] = set()
    # Headings / anchors inside fenced code should not count.
    body = strip_fenced_code_blocks(text)
    for match in _HEADING_RE.finditer(body):
        base = github_heading_slug(match.group(2))
        if not base:
            continue
        n = counts.get(base, 0)
        counts[base] = n + 1
        slug = base if n == 0 else f"{base}-{n}"
        slugs.add(slug)
    for match in _HTML_ANCHOR_RE.finditer(body):
        anchor = match.group(1) or match.group(2)
        if anchor:
            slugs.add(anchor)
    return slugs


def discover_markdown_files(root: Path, globs: Sequence[str] = DEFAULT_GLOBS) -> list[Path]:
    """Return sorted unique markdown paths under root matching globs."""
    found: set[Path] = set()
    for pattern in globs:
        for path in root.glob(pattern):
            if path.is_file() and path.suffix.lower() == ".md":
                found.add(path.resolve())
    return sorted(found)


def resolve_local_target(
    root: Path,
    source: Path,
    target: str,
) -> tuple[Path | None, str | None, str | None]:
    """Resolve a local markdown target.

    Returns (path_or_none, anchor_or_none, error_reason_or_none).
    path is None when the link is anchor-only (same file).
    """
    raw = target.strip()
    if raw.startswith("#"):
        return source.resolve(), raw[1:], None

    path_part, anchor = raw, None
    if "#" in raw:
        path_part, anchor = raw.split("#", 1)

    # URL-decode minimal escapes for spaces
    path_part = path_part.replace("%20", " ")
    if not path_part:
        return source.resolve(), anchor, None

    candidate = (source.parent / path_part).resolve()
    root_resolved = root.resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return None, anchor, "target escapes repository root"

    return candidate, anchor, None


def check_link(
    root: Path,
    link: LinkRef,
    heading_cache: dict[Path, set[str]],
) -> LinkIssue | None:
    """Validate one link; return an issue or None if ok / skipped."""
    if is_external_target(link.target):
        return None

    path, anchor, err = resolve_local_target(root, link.source, link.target)
    if err:
        return LinkIssue(link.source, link.line, link.target, err)
    if path is None:
        return LinkIssue(link.source, link.line, link.target, "unresolved target")

    if not path.exists():
        return LinkIssue(link.source, link.line, link.target, "missing target path")

    if anchor is not None and anchor != "":
        if path.is_dir():
            return LinkIssue(
                link.source,
                link.line,
                link.target,
                "anchor on directory target",
            )
        if path.suffix.lower() != ".md":
            # Non-markdown assets: only existence is checked; anchors not defined.
            return LinkIssue(
                link.source,
                link.line,
                link.target,
                "anchor on non-markdown target",
            )
        if path not in heading_cache:
            heading_cache[path] = collect_heading_slugs(path.read_text(encoding="utf-8"))
        if anchor not in heading_cache[path]:
            return LinkIssue(link.source, link.line, link.target, "missing heading anchor")

    return None


def check_files(root: Path, files: Iterable[Path]) -> list[LinkIssue]:
    """Check all links in the given markdown files."""
    root = root.resolve()
    heading_cache: dict[Path, set[str]] = {}
    issues: list[LinkIssue] = []
    for source in files:
        text = source.read_text(encoding="utf-8")
        body = strip_fenced_code_blocks(text)
        for link in iter_markdown_links(body, source):
            issue = check_link(root, link, heading_cache)
            if issue is not None:
                issues.append(issue)
    return issues


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline checker for repository-local Markdown links and anchors.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repository root (default: parent of scripts/).",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Optional explicit markdown files (default: maintained docs globs).",
    )
    args = parser.parse_args(argv)

    script_dir = Path(__file__).resolve().parent
    root = (args.root or script_dir.parent).resolve()

    if args.paths:
        files = sorted({p.resolve() for p in args.paths if p.is_file()})
    else:
        files = discover_markdown_files(root)

    if not files:
        print("check_markdown_links: no markdown files to check", file=sys.stderr)
        return 2

    issues = check_files(root, files)
    if issues:
        for issue in issues:
            print(issue.format(root), file=sys.stderr)
        print(
            f"check_markdown_links: {len(issues)} broken link(s) in {len(files)} file(s)",
            file=sys.stderr,
        )
        return 1

    print(f"check_markdown_links: ok ({len(files)} file(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
