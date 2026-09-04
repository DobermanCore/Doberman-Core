"""Compile pending changelog fragments into ``CHANGELOG.md``."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PLACEHOLDER = "_Nothing yet._"
EM_DASH = "—"
VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+$")
PR_REF_RE = re.compile(r"#(\d+)")

# Order doubles as the fixed output-section order.
FRAGMENT_TYPES = ("security", "added", "changed", "fixed", "docs", "removed")


@dataclass(frozen=True)
class Fragment:
    number: int
    path: Path
    content: str
    type: str


def _parse_fragment_name(path: Path) -> tuple[int, str]:
    parts = path.stem.split(".", 1)
    if len(parts) != 2 or not parts[0].isdigit() or parts[1] not in FRAGMENT_TYPES:
        raise ValueError(
            f"{path}: fragment names must be <PR>.<type>.md, type one of "
            f"{', '.join(FRAGMENT_TYPES)} (e.g. 456.added.md)"
        )
    return int(parts[0]), parts[1]


def _split_bullets(content: str) -> list[str]:
    """Split fragment content into verbatim bullets (continuation lines included)."""

    bullets: list[str] = []
    current: list[str] = []
    for line in content.splitlines():
        if line.startswith("- "):
            if current:
                bullets.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        bullets.append("\n".join(current))
    return bullets


def collect_fragments(fragment_dir: Path) -> list[Fragment]:
    """Load, name-check, and bullet-validate every pending fragment.

    Every problem across every fragment is collected before raising, so one
    run reports everything wrong rather than one file at a time.
    """

    problems: list[str] = []
    fragments: list[Fragment] = []

    for path in sorted(fragment_dir.glob("*.md")):
        if path.name.casefold() == "readme.md":
            continue

        try:
            number, frag_type = _parse_fragment_name(path)
        except ValueError as error:
            problems.append(str(error))
            continue

        content = path.read_text(encoding="utf-8").strip()
        if not content or not content.startswith("- "):
            problems.append(f"{path}: fragment must be one or more Markdown bullets ('- ...')")
            continue

        for bullet in _split_bullets(content):
            collapsed = " ".join(bullet.split())
            if len(collapsed) > 220:
                problems.append(f"{path}: bullet exceeds 220 characters: {collapsed[:60]!r}")
            if f"#{number}" not in collapsed:
                problems.append(f"{path}: bullet must reference #{number}: {collapsed[:60]!r}")

        fragments.append(Fragment(number, path, content, frag_type))

    if problems:
        raise ValueError("\n".join(problems))

    return sorted(
        fragments, key=lambda fragment: (FRAGMENT_TYPES.index(fragment.type), fragment.number)
    )


def _bullet_pr_number(bullet: str) -> int:
    match = PR_REF_RE.search(bullet)
    return int(match.group(1)) if match else 0


def _parse_existing_groups(body: str) -> dict[str, list[str]]:
    """Parse an Unreleased body's ``### `` groups; ungrouped bullets count as changed."""

    groups: dict[str, list[str]] = {frag_type: [] for frag_type in FRAGMENT_TYPES}
    if not body or body == PLACEHOLDER:
        return groups

    current_type = "changed"
    current_bullet: list[str] | None = None

    def flush() -> None:
        if current_bullet:
            groups[current_type].append("\n".join(current_bullet))

    for line in body.splitlines():
        if line.startswith("### "):
            flush()
            current_bullet = None
            heading = line[4:].strip().casefold()
            current_type = heading if heading in FRAGMENT_TYPES else "changed"
        elif line.startswith("- "):
            flush()
            current_bullet = [line]
        elif current_bullet is not None:
            current_bullet.append(line)
    flush()

    return groups


def compile_changelog(changelog: str, fragments: list[Fragment]) -> str:
    """Return *changelog* with fragment bullets merged into grouped Unreleased sections."""

    if not fragments:
        return changelog

    lines = changelog.splitlines(keepends=True)
    heading_index = next(
        (i for i, line in enumerate(lines) if line.rstrip() == "## Unreleased"), None
    )
    if heading_index is None:
        first_version_index = next(
            (i for i, line in enumerate(lines) if line.startswith("## v")), len(lines)
        )
        lines.insert(first_version_index, "## Unreleased\n")
        heading_index = first_version_index

    body_start = heading_index + 1
    body_end = len(lines)
    for index in range(body_start, len(lines)):
        if lines[index].startswith("## "):
            body_end = index
            break

    existing_body = "".join(lines[body_start:body_end]).strip()
    groups = _parse_existing_groups(existing_body)

    for fragment in fragments:
        groups[fragment.type].extend(_split_bullets(fragment.content))

    group_texts = []
    for frag_type in FRAGMENT_TYPES:
        bullets = sorted(groups[frag_type], key=_bullet_pr_number)
        if bullets:
            group_texts.append(f"### {frag_type.title()}\n" + "\n".join(bullets))

    compiled_body = "\n\n".join(group_texts)
    return "".join(lines[:body_start]) + f"\n{compiled_body}\n\n" + "".join(lines[body_end:])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    parser.add_argument(
        "--write",
        action="store_true",
        help="update CHANGELOG.md and remove compiled fragments; default is a dry run",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate every fragment and exit; never touches files",
    )
    parser.add_argument("--release", metavar="vX.Y.Z", help="rename Unreleased to this version")
    parser.add_argument("--date", help="release date YYYY-MM-DD, default today UTC")
    parser.add_argument("--headline", help="one-line release headline, required with --release")
    args = parser.parse_args(argv)

    if args.release:
        if not args.write:
            print("--release requires --write", file=sys.stderr)
            return 1
        if not args.headline:
            print("--headline is required with --release", file=sys.stderr)
            return 1
        if not VERSION_RE.match(args.release):
            print(f"--release must look like vX.Y.Z, got {args.release!r}", file=sys.stderr)
            return 1

    root = args.root.resolve()
    changelog_path = root / "CHANGELOG.md"
    fragment_dir = root / "changelog.d"

    try:
        fragments = collect_fragments(fragment_dir)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    if args.check:
        print(f"ok: {len(fragments)} fragments")
        return 0

    if not fragments:
        print("No changelog fragments to compile.")
        return 0

    changelog = changelog_path.read_text(encoding="utf-8")

    if args.release:
        version_heading_re = re.compile(rf"^## {re.escape(args.release)}(\s|$)")
        if any(version_heading_re.match(line) for line in changelog.splitlines()):
            print(f"{changelog_path}: {args.release} already exists", file=sys.stderr)
            return 1

    try:
        compiled = compile_changelog(changelog, fragments)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    if args.release:
        date = args.date or datetime.now(timezone.utc).date().isoformat()
        compiled = compiled.replace(
            "## Unreleased\n",
            f"## {args.release} {EM_DASH} {date}\n{args.headline}\n",
            1,
        )

    numbers = ", ".join(f"#{fragment.number}" for fragment in fragments)

    if not args.write:
        print(f"Ready to compile {numbers} into CHANGELOG.md.")
        return 0

    changelog_path.write_text(compiled, encoding="utf-8")
    for fragment in fragments:
        fragment.path.unlink()

    print(f"Compiled {numbers} into CHANGELOG.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
