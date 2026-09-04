from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import pytest

from scripts.compile_changelog import (
    Fragment,
    collect_fragments,
    compile_changelog,
    main,
)


def run_compiler(root: Path, *args: str) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    argv = ["--root", str(root), *args]

    with redirect_stdout(stdout), redirect_stderr(stderr):
        returncode = main(argv)
    return returncode, stdout.getvalue(), stderr.getvalue()


def write_fragment(root: Path, name: str, content: str) -> Path:
    fragment_dir = root / "changelog.d"
    fragment_dir.mkdir(exist_ok=True)
    path = fragment_dir / name
    path.write_text(content, encoding="utf-8")
    return path


def write_changelog(root: Path, body: str) -> None:
    (root / "CHANGELOG.md").write_text(body, encoding="utf-8")


# --- typed names ------------------------------------------------------------


def test_typed_fragment_name_accepted(tmp_path: Path) -> None:
    write_fragment(tmp_path, "456.added.md", "- New thing (#456).\n")

    fragments = collect_fragments(tmp_path / "changelog.d")

    assert len(fragments) == 1
    assert fragments[0].number == 456
    assert fragments[0].type == "added"


def test_untyped_fragment_name_rejected(tmp_path: Path) -> None:
    write_fragment(tmp_path, "456.md", "- New thing (#456).\n")

    with pytest.raises(ValueError, match=r"456\.md"):
        collect_fragments(tmp_path / "changelog.d")


def test_unknown_type_rejected(tmp_path: Path) -> None:
    write_fragment(tmp_path, "456.feature.md", "- New thing (#456).\n")

    with pytest.raises(ValueError, match="456.feature.md"):
        collect_fragments(tmp_path / "changelog.d")


def test_readme_skipped(tmp_path: Path) -> None:
    write_fragment(tmp_path, "README.md", "not a fragment at all, no bullet")

    fragments = collect_fragments(tmp_path / "changelog.d")

    assert fragments == []


# --- bullet validation -------------------------------------------------------


def test_long_bullet_rejected(tmp_path: Path) -> None:
    long_bullet = "- " + ("x" * 221) + " (#456)\n"
    write_fragment(tmp_path, "456.added.md", long_bullet)

    with pytest.raises(ValueError, match="220 characters"):
        collect_fragments(tmp_path / "changelog.d")


def test_missing_pr_reference_rejected(tmp_path: Path) -> None:
    write_fragment(tmp_path, "456.added.md", "- New thing, no PR ref.\n")

    with pytest.raises(ValueError, match="#456"):
        collect_fragments(tmp_path / "changelog.d")


def test_all_problems_reported_at_once(tmp_path: Path) -> None:
    write_fragment(tmp_path, "456.added.md", "- Missing the PR ref.\n")
    write_fragment(tmp_path, "unnamed.md", "- Bad file name (#457).\n")

    with pytest.raises(ValueError) as excinfo:
        collect_fragments(tmp_path / "changelog.d")

    message = str(excinfo.value)
    assert "456.added.md" in message
    assert "unnamed.md" in message


def test_bullet_over_word_limit_rejected(tmp_path: Path) -> None:
    words = " ".join(f"word{i}" for i in range(26))
    write_fragment(tmp_path, "456.added.md", f"- {words} (#456)\n")

    with pytest.raises(ValueError, match=r"is 26 words \(max 25\)"):
        collect_fragments(tmp_path / "changelog.d")


def test_bullet_at_word_limit_with_long_citation_accepted(tmp_path: Path) -> None:
    words = " ".join(f"word{i}" for i in range(25))
    write_fragment(tmp_path, "456.added.md", f"- {words} (#456, thanks @someone-long)\n")

    fragments = collect_fragments(tmp_path / "changelog.d")

    assert len(fragments) == 1


def test_multi_bullet_fragment_all_validated(tmp_path: Path) -> None:
    write_fragment(
        tmp_path,
        "456.added.md",
        "- First bullet (#456).\n- Second bullet, missing ref.\n",
    )

    with pytest.raises(ValueError, match="Second bullet"):
        collect_fragments(tmp_path / "changelog.d")


def test_continuation_lines_kept_with_bullet(tmp_path: Path) -> None:
    write_fragment(
        tmp_path,
        "456.added.md",
        "- New thing that needs\n  a second line (#456).\n",
    )

    fragments = collect_fragments(tmp_path / "changelog.d")

    assert "a second line" in fragments[0].content


# --- grouped output -----------------------------------------------------------


def test_groups_emitted_in_fixed_order_and_only_when_nonempty(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## v1.0.0\n\n- Shipped.\n")
    write_fragment(tmp_path, "456.fixed.md", "- Fixed thing (#456).\n")
    write_fragment(tmp_path, "457.security.md", "- Closed a bypass (#457).\n")

    fragments = collect_fragments(tmp_path / "changelog.d")
    changelog = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")

    result = compile_changelog(changelog, fragments)

    assert result.index("### Security") < result.index("### Fixed")
    assert "### Added" not in result
    assert "### Changed" not in result


def test_bullets_ordered_by_pr_number_within_group() -> None:
    changelog = "# Changelog\n\n## Unreleased\n\n## v1.0.0\n\n- Shipped.\n"
    fragments = [
        Fragment(457, Path("457.added.md"), "- Later contribution (#457).\n", "added"),
        Fragment(456, Path("456.added.md"), "- First contribution (#456).\n", "added"),
    ]

    result = compile_changelog(changelog, fragments)

    assert result.index("First contribution") < result.index("Later contribution")
    assert "## v1.0.0" in result


def test_existing_ungrouped_unreleased_bullets_land_under_changed(tmp_path: Path) -> None:
    write_changelog(
        tmp_path,
        "# Changelog\n\n## Unreleased\n\n- Already merged (#440).\n\n## v1.0.0\n",
    )
    write_fragment(tmp_path, "456.added.md", "- New thing (#456).\n")

    fragments = collect_fragments(tmp_path / "changelog.d")
    original = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")

    result = compile_changelog(original, fragments)

    assert "### Changed" in result
    assert "Already merged" in result
    assert "### Added" in result
    assert "New thing" in result


def test_placeholder_dropped_on_compile(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n_Nothing yet._\n\n## v1.0.0\n")
    write_fragment(tmp_path, "456.added.md", "- New thing (#456).\n")

    fragments = collect_fragments(tmp_path / "changelog.d")
    original = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")

    result = compile_changelog(original, fragments)

    assert "_Nothing yet._" not in result


def test_existing_grouped_bullets_survive_compile(tmp_path: Path) -> None:
    write_changelog(
        tmp_path,
        "# Changelog\n\n## Unreleased\n\n### Security\n- Old fix (#440).\n\n## v1.0.0\n",
    )
    write_fragment(tmp_path, "456.security.md", "- New fix (#456).\n")

    fragments = collect_fragments(tmp_path / "changelog.d")
    original = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")

    result = compile_changelog(original, fragments)

    assert "Old fix" in result
    assert "New fix" in result
    assert result.count("### Security") == 1


# --- CLI: --check -------------------------------------------------------------


def test_check_passes_with_zero_fragments(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n")
    (tmp_path / "changelog.d").mkdir()

    returncode, stdout, stderr = run_compiler(tmp_path, "--check")

    assert returncode == 0, stderr
    assert "ok: 0 fragments" in stdout


def test_check_exits_nonzero_and_lists_problems(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n")
    write_fragment(tmp_path, "456.added.md", "- No PR ref here.\n")

    returncode, stdout, stderr = run_compiler(tmp_path, "--check")

    assert returncode == 1
    assert "#456" in stderr


def test_check_never_writes_files(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n")
    fragment = write_fragment(tmp_path, "456.added.md", "- New thing (#456).\n")
    before = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")

    returncode, stdout, stderr = run_compiler(tmp_path, "--check")

    assert returncode == 0, stderr
    assert fragment.exists()
    assert (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8") == before


# --- CLI: --release -----------------------------------------------------------


def test_release_renames_heading_with_headline_and_date(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n")
    write_fragment(tmp_path, "456.added.md", "- New thing (#456).\n")

    returncode, stdout, stderr = run_compiler(
        tmp_path,
        "--write",
        "--release",
        "v1.2.3",
        "--date",
        "2026-09-04",
        "--headline",
        "A quiet release",
    )

    assert returncode == 0, stderr
    changelog = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## v1.2.3 — 2026-09-04" in changelog
    assert "A quiet release" in changelog
    assert "## Unreleased" not in changelog
    assert "### Added" in changelog


def test_release_refuses_duplicate_version(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n## v1.2.3 — 2026-01-01\n\n- Old.\n")
    write_fragment(tmp_path, "456.added.md", "- New thing (#456).\n")

    returncode, stdout, stderr = run_compiler(
        tmp_path, "--write", "--release", "v1.2.3", "--headline", "Again"
    )

    assert returncode == 1
    assert "v1.2.3" in stderr


def test_release_requires_write() -> None:
    returncode, stdout, stderr = run_compiler(Path("."), "--release", "v1.2.3", "--headline", "x")
    assert returncode != 0


def test_release_requires_headline() -> None:
    returncode, stdout, stderr = run_compiler(Path("."), "--write", "--release", "v1.2.3")
    assert returncode != 0


def test_release_rejects_malformed_version(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n")
    write_fragment(tmp_path, "456.added.md", "- New thing (#456).\n")

    returncode, stdout, stderr = run_compiler(
        tmp_path, "--write", "--release", "1.2.3", "--headline", "x"
    )

    assert returncode != 0


# --- adapted originals ---------------------------------------------------------


def test_cli_rejects_untyped_fragment_name(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n")
    write_fragment(tmp_path, "feature.md", "- New contribution (#1).\n")

    returncode, _, stderr = run_compiler(tmp_path)

    assert returncode != 0
    assert "feature.md" in stderr


def test_cli_creates_missing_unreleased_heading(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## v1.0.0\n")
    write_fragment(tmp_path, "456.added.md", "- New contribution (#456).\n")

    returncode, _, stderr = run_compiler(tmp_path, "--write")

    assert returncode == 0, stderr
    changelog = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")
    assert changelog.index("## Unreleased") < changelog.index("## v1.0.0")
    assert "New contribution" in changelog


def test_cli_write_compiles_and_removes_fragments(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n_Nothing yet._\n")
    fragment = write_fragment(tmp_path, "456.added.md", "- New contribution (#456).\n")

    returncode, _, stderr = run_compiler(tmp_path, "--write")

    assert returncode == 0, stderr
    changelog = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "New contribution" in changelog
    assert not fragment.exists()


def test_cli_dry_run_preserves_files(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## Unreleased\n\n_Nothing yet._\n")
    fragment = write_fragment(tmp_path, "456.added.md", "- New contribution (#456).\n")

    returncode, stdout, stderr = run_compiler(tmp_path)

    assert returncode == 0, stderr
    assert "Ready to compile #456" in stdout
    assert fragment.exists()
    assert "_Nothing yet._" in (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")


def test_cli_write_keeps_one_blank_line_around_the_compiled_block(tmp_path: Path) -> None:
    write_changelog(tmp_path, "# Changelog\n\n## v1.0.0\n\n- Shipped.\n")
    write_fragment(tmp_path, "456.added.md", "- First (#456).\n")
    write_fragment(tmp_path, "457.added.md", "- Second (#457).\n")

    returncode, _, stderr = run_compiler(tmp_path, "--write")

    assert returncode == 0, stderr
    assert (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8") == (
        "# Changelog\n\n## Unreleased\n\n### Added\n- First (#456).\n- Second (#457).\n\n"
        "## v1.0.0\n\n- Shipped.\n"
    )
