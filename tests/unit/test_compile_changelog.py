from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from scripts.compile_changelog import (
    Fragment,
    collect_fragments,
    compile_changelog,
    main,
)


def run_compiler(root: Path, *, write: bool = False) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    argv = ["--root", str(root)]
    if write:
        argv.append("--write")

    with redirect_stdout(stdout), redirect_stderr(stderr):
        returncode = main(argv)
    return returncode, stdout.getvalue(), stderr.getvalue()


def test_compile_replaces_placeholder_with_number_ordered_fragments() -> None:
    changelog = "# Changelog\n\n## Unreleased\n\n_Nothing yet._\n\n## v1.0.0\n\n- Shipped.\n"
    fragments = [
        Fragment(457, Path("457.md"), "- Later contribution.\n"),
        Fragment(456, Path("456.md"), "- First contribution.\n"),
    ]

    result = compile_changelog(changelog, fragments)

    assert result.index("- First contribution.") < result.index("- Later contribution.")
    assert "_Nothing yet._" not in result
    assert "- Shipped." in result
    assert "## v1.0.0" in result


def test_cli_rejects_non_numeric_fragment_name(tmp_path: Path) -> None:
    root = tmp_path
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n", encoding="utf-8")
    fragment = root / "changelog.d" / "feature.md"
    fragment.parent.mkdir()
    fragment.write_text("- New contribution.\n", encoding="utf-8")

    returncode, _, stderr = run_compiler(root)

    assert returncode != 0
    assert "must be a PR number" in stderr


def test_cli_creates_missing_unreleased_heading(tmp_path: Path) -> None:
    root = tmp_path
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## v1.0.0\n", encoding="utf-8")
    fragment = root / "changelog.d" / "456.md"
    fragment.parent.mkdir()
    fragment.write_text("- New contribution.\n", encoding="utf-8")

    returncode, _, stderr = run_compiler(root, write=True)

    assert returncode == 0, stderr
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert changelog.index("## Unreleased") < changelog.index("## v1.0.0")
    assert "- New contribution." in changelog


def test_compile_preserves_existing_unreleased_entries(tmp_path: Path) -> None:
    root = tmp_path
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n- Already merged.\n\n## v1.0.0\n", encoding="utf-8"
    )
    fragment_dir = root / "changelog.d"
    fragment_dir.mkdir()
    (fragment_dir / "456.md").write_text("- New contribution.\n", encoding="utf-8")

    fragments = collect_fragments(fragment_dir)
    original = (root / "CHANGELOG.md").read_text(encoding="utf-8")

    result = compile_changelog(original, fragments)

    assert result.index("- New contribution.") < result.index("- Already merged.")
    assert "## v1.0.0" in result


def test_cli_write_compiles_and_removes_fragments(tmp_path: Path) -> None:
    root = tmp_path
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n_Nothing yet._\n", encoding="utf-8"
    )
    fragment = root / "changelog.d" / "456.md"
    fragment.parent.mkdir()
    fragment.write_text("- New contribution.\n", encoding="utf-8")

    returncode, _, stderr = run_compiler(root, write=True)

    assert returncode == 0, stderr
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "- New contribution." in changelog
    assert not fragment.exists()


def test_cli_dry_run_preserves_files(tmp_path: Path) -> None:
    root = tmp_path
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n_Nothing yet._\n", encoding="utf-8"
    )
    fragment = root / "changelog.d" / "456.md"
    fragment.parent.mkdir()
    fragment.write_text("- New contribution.\n", encoding="utf-8")

    returncode, stdout, stderr = run_compiler(root)

    assert returncode == 0, stderr
    assert "Ready to compile #456" in stdout
    assert fragment.exists()
    assert "_Nothing yet._" in (root / "CHANGELOG.md").read_text(encoding="utf-8")
