"""Check repository-local Markdown links and heading anchors without network access."""

from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from urllib.parse import unquote, urlsplit

SKIP_DIRECTORIES = frozenset({".git", ".venv", "__pycache__", "build", "dist", "node_modules"})
FENCE_RE = re.compile(r"^[ \t]{0,3}(?P<marker>`{3,}|~{3,})")
ATX_HEADING_RE = re.compile(r"^[ \t]{0,3}#{1,6}(?:[ \t]+(?P<text>.*?)|)[ \t]*$")
SETEXT_HEADING_RE = re.compile(r"^[ \t]{0,3}(?:=+|-+)[ \t]*$")
HTML_ANCHOR_RE = re.compile(r"<a\b[^>]*\b(?:name|id)\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
INLINE_LINK_RE = re.compile(r"(?<!!)\[(?P<label>[^\]\n]*)\]\(\s*(?P<destination><[^>\n]*>|[^\s)]+)")
REFERENCE_DEFINITION_RE = re.compile(
    r"^[ \t]{0,3}\[(?P<label>[^\]\n]+)\]:[ \t]*(?P<destination><[^>\n]*>|[^\s]+)"
)
REFERENCE_LINK_RE = re.compile(r"(?<!!)\[(?P<label>[^\]\n]+)\]\[(?P<reference>[^\]\n]*)\]")


@dataclass(frozen=True)
class LinkOccurrence:
    source: Path
    line_number: int
    target: str
    unresolved_reference: str | None = None


@dataclass(frozen=True)
class Diagnostic:
    source: Path
    line_number: int
    target: str
    reason: str


@dataclass(frozen=True)
class CheckResult:
    files_scanned: int
    diagnostics: tuple[Diagnostic, ...]


def iter_markdown_files(root: Path) -> list[Path]:
    """Return all maintained Markdown files below *root* in stable order."""

    files: list[Path] = []
    for current, directories, filenames in os.walk(root):
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRECTORIES)
        for filename in filenames:
            path = Path(current) / filename
            if path.suffix.casefold() == ".md":
                files.append(path)
    return sorted(
        files,
        key=lambda path: (
            path.relative_to(root).as_posix().casefold(),
            path.relative_to(root).as_posix(),
        ),
    )


def _visible_lines(lines: list[str]) -> list[str | None]:
    """Replace fenced-code lines with None while preserving line positions."""

    visible: list[str | None] = []
    fence_character: str | None = None
    fence_length = 0

    for line in lines:
        marker_match = FENCE_RE.match(line)
        if fence_character is not None:
            marker = marker_match.group("marker") if marker_match else ""
            if marker and marker[0] == fence_character and len(marker) >= fence_length:
                if line[len(line) - len(line.lstrip()) :].strip() == marker:
                    fence_character = None
                    fence_length = 0
            visible.append(None)
            continue

        if marker_match:
            marker = marker_match.group("marker")
            fence_character = marker[0]
            fence_length = len(marker)
            visible.append(None)
        else:
            visible.append(line)

    return visible


def _clean_destination(destination: str) -> str:
    destination = destination.strip()
    if destination.startswith("<") and destination.endswith(">"):
        return destination[1:-1]
    return destination


def _reference_key(label: str) -> str:
    return " ".join(unescape(label).casefold().split())


def extract_links(source: Path, lines: list[str]) -> list[LinkOccurrence]:
    """Extract inline and defined-reference links from non-fenced lines."""

    visible = _visible_lines(lines)
    definitions: dict[str, str] = {}
    for line in visible:
        if line is None:
            continue
        definition_match = REFERENCE_DEFINITION_RE.match(line)
        if definition_match:
            definitions[_reference_key(definition_match.group("label"))] = _clean_destination(
                definition_match.group("destination")
            )

    occurrences: list[LinkOccurrence] = []
    for index, line in enumerate(visible, start=1):
        if line is None:
            continue

        for match in INLINE_LINK_RE.finditer(line):
            occurrences.append(
                LinkOccurrence(source, index, _clean_destination(match.group("destination")))
            )

        for match in REFERENCE_LINK_RE.finditer(line):
            label = match.group("label")
            reference = match.group("reference") or label
            key = _reference_key(reference)
            target = definitions.get(key)
            occurrences.append(
                LinkOccurrence(
                    source,
                    index,
                    target or f"[{reference}]",
                    unresolved_reference=None if target is not None else reference,
                )
            )

    return occurrences


def _github_slug(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", unescape(value)).casefold()
    kept = "".join(
        character for character in normalized if character.isalnum() or character in " _-"
    )
    return re.sub(r"\s+", "-", kept).strip("-")


def _heading_text(value: str) -> str:
    for match in reversed(list(INLINE_LINK_RE.finditer(value))):
        closing_parenthesis = value.find(")", match.end())
        if closing_parenthesis == -1:
            continue
        value = value[: match.start()] + match.group("label") + value[closing_parenthesis + 1 :]
    value = REFERENCE_LINK_RE.sub(lambda match: match.group("label"), value)
    return re.sub(r"<[^>\n]+>", "", value)


def heading_anchors(lines: list[str]) -> set[str]:
    """Return GitHub-style anchors for ATX and Setext headings."""

    visible = _visible_lines(lines)
    anchors: set[str] = set()
    for index, line in enumerate(visible):
        if line is None:
            continue

        for anchor_match in HTML_ANCHOR_RE.finditer(line):
            explicit_anchor = unescape(anchor_match.group(1))
            anchors.add(explicit_anchor)
            normalized_anchor = _github_slug(explicit_anchor)
            if normalized_anchor:
                anchors.add(normalized_anchor)

        heading_match = ATX_HEADING_RE.match(line)
        if heading_match:
            heading_text = _heading_text(heading_match.group("text") or "")
            heading_text = re.sub(r"[ \t]+#+[ \t]*$", "", heading_text)
            base = _github_slug(heading_text)
            if base:
                anchors.add(_unique_anchor(base, anchors))
            continue

        if (
            line.strip()
            and index + 1 < len(visible)
            and visible[index + 1] is not None
            and SETEXT_HEADING_RE.match(visible[index + 1] or "")
        ):
            base = _github_slug(_heading_text(line.strip()))
            if base:
                anchors.add(_unique_anchor(base, anchors))

    return anchors


def _unique_anchor(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 0
    while candidate in used:
        suffix += 1
        candidate = f"{base}-{suffix}"
    return candidate


def _is_external(target: str) -> bool:
    if target.startswith("//"):
        return True
    try:
        parsed = urlsplit(target)
    except ValueError:
        return False
    return bool(parsed.scheme or parsed.netloc)


def _relative_display(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _diagnostic(
    occurrence: LinkOccurrence,
    root: Path,
    target: str,
    reason: str,
) -> Diagnostic:
    return Diagnostic(occurrence.source, occurrence.line_number, target, reason)


def _validate_occurrence(
    occurrence: LinkOccurrence,
    root: Path,
    anchors_by_path: dict[Path, set[str]],
) -> Diagnostic | None:
    if occurrence.unresolved_reference is not None:
        return _diagnostic(
            occurrence,
            root,
            occurrence.target,
            f"reference link '[{occurrence.unresolved_reference}]' has no definition",
        )

    target = occurrence.target
    if not target or _is_external(target):
        return None

    parsed = urlsplit(target)
    raw_path = unquote(parsed.path)
    fragment = unquote(parsed.fragment)
    candidate = (occurrence.source.parent / raw_path if raw_path else occurrence.source).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return _diagnostic(occurrence, root, target, "path resolves outside repository root")

    if candidate.suffix.casefold() != ".md":
        return None
    if not candidate.is_file():
        return _diagnostic(occurrence, root, target, "target Markdown file does not exist")

    if fragment:
        anchors = anchors_by_path.get(candidate)
        if anchors is None:
            try:
                anchors = heading_anchors(candidate.read_text(encoding="utf-8").splitlines())
            except (OSError, UnicodeError):
                anchors = set()
            anchors_by_path[candidate] = anchors
        normalized_fragment = _github_slug(fragment)
        if normalized_fragment not in anchors:
            return _diagnostic(
                occurrence,
                root,
                target,
                f"anchor '#{fragment}' not found in {_relative_display(candidate, root)}",
            )

    return None


def check_repository(root: Path) -> CheckResult:
    """Check all repository Markdown documents and return sorted diagnostics."""

    root = root.resolve()
    markdown_files = iter_markdown_files(root)
    anchors_by_path: dict[Path, set[str]] = {}
    diagnostics: list[Diagnostic] = []

    for source in markdown_files:
        try:
            lines = source.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            diagnostics.append(
                Diagnostic(
                    source,
                    1,
                    _relative_display(source, root),
                    f"could not read Markdown file: {type(error).__name__}",
                )
            )
            continue

        anchors_by_path[source] = heading_anchors(lines)
        for occurrence in extract_links(source, lines):
            diagnostic = _validate_occurrence(occurrence, root, anchors_by_path)
            if diagnostic is not None:
                diagnostics.append(diagnostic)

    diagnostics.sort(
        key=lambda diagnostic: (
            _relative_display(diagnostic.source, root).casefold(),
            _relative_display(diagnostic.source, root),
            diagnostic.line_number,
            diagnostic.target,
        )
    )
    return CheckResult(len(markdown_files), tuple(diagnostics))


def _format_diagnostic(diagnostic: Diagnostic, root: Path) -> str:
    source = _relative_display(diagnostic.source, root)
    return f"{source}:{diagnostic.line_number}: broken Markdown link '{diagnostic.target}': {diagnostic.reason}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root to scan (default: current working directory)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"repository root is not a directory: {root}")

    result = check_repository(root)
    for diagnostic in result.diagnostics:
        print(_format_diagnostic(diagnostic, root), file=sys.stderr)
    if result.diagnostics:
        return 1

    print(f"Checked {result.files_scanned} Markdown files; no broken internal links.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
