"""Compile pending changelog fragments into ``CHANGELOG.md``."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

PLACEHOLDER = "_Nothing yet._"


@dataclass(frozen=True)
class Fragment:
    number: int
    path: Path
    content: str


def _fragment_number(path: Path) -> int:
    if not path.stem.isdigit():
        raise ValueError(f"{path}: fragment names must be a PR number, such as 456.md")
    return int(path.stem)


def collect_fragments(fragment_dir: Path) -> list[Fragment]:
    """Load and order the PR fragments pending compilation."""

    fragments: list[Fragment] = []
    for path in sorted(fragment_dir.glob("*.md")):
        if path.name.casefold() == "readme.md":
            continue

        content = path.read_text(encoding="utf-8").strip()
        if not content:
            raise ValueError(f"{path}: fragment is empty")
        if not content.startswith("- "):
            raise ValueError(f"{path}: fragments must start with a Markdown bullet")

        fragments.append(Fragment(_fragment_number(path), path, content))

    return sorted(fragments, key=lambda fragment: fragment.number)


def compile_changelog(changelog: str, fragments: list[Fragment]) -> str:
    """Return *changelog* with fragment bullets inserted under Unreleased."""

    ordered_fragments = sorted(fragments, key=lambda fragment: fragment.number)
    if not ordered_fragments:
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

    existing = "".join(lines[body_start:body_end]).strip()
    if existing == PLACEHOLDER:
        existing = ""

    sections = [fragment.content for fragment in ordered_fragments]
    if existing:
        sections.append(existing)

    compiled_body = "\n\n".join(sections)
    return "".join(lines[:body_start]) + f"\n\n{compiled_body}\n" + "".join(lines[body_end:])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    parser.add_argument(
        "--write",
        action="store_true",
        help="update CHANGELOG.md and remove compiled fragments; default is a dry run",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    changelog_path = root / "CHANGELOG.md"
    fragment_dir = root / "changelog.d"
    try:
        fragments = collect_fragments(fragment_dir)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    if not fragments:
        print("No changelog fragments to compile.")
        return 0

    changelog = changelog_path.read_text(encoding="utf-8")
    try:
        compiled = compile_changelog(changelog, fragments)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
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
