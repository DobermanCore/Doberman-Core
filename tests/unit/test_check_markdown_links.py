"""Tests for scripts/check_markdown_links.py (offline markdown link checker)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "check_markdown_links.py"
_SPEC = importlib.util.spec_from_file_location("check_markdown_links", _SCRIPTS)
assert _SPEC and _SPEC.loader
_mod = importlib.util.module_from_spec(_SPEC)
sys.modules["check_markdown_links"] = _mod
_SPEC.loader.exec_module(_mod)

check_files = _mod.check_files
collect_heading_slugs = _mod.collect_heading_slugs
github_heading_slug = _mod.github_heading_slug
is_external_target = _mod.is_external_target
iter_markdown_links = _mod.iter_markdown_links
main = _mod.main
strip_fenced_code_blocks = _mod.strip_fenced_code_blocks


def test_is_external_target_skips_common_schemes() -> None:
    assert is_external_target("https://example.com/a")
    assert is_external_target("http://example.com")
    assert is_external_target("mailto:a@b.c")
    assert is_external_target("//cdn.example/x")
    assert not is_external_target("./local.md")
    assert not is_external_target("../README.md#anchor")
    assert not is_external_target("#local-anchor")
    assert not is_external_target("docs/SETUP.md")


def test_strip_fenced_code_blocks_removes_link_like_text() -> None:
    text = "before [ok](./a.md)\n```\nnot a link [broken](./missing.md)\n```\nafter [ok2](./b.md)\n"
    stripped = strip_fenced_code_blocks(text)
    assert "[ok](./a.md)" in stripped
    assert "[ok2](./b.md)" in stripped
    assert "missing.md" not in stripped
    # Line count preserved so diagnostics stay accurate.
    assert stripped.count("\n") == text.count("\n")


def test_github_heading_slug_basic() -> None:
    assert github_heading_slug("Quick Start") == "quick-start"
    assert github_heading_slug("Why Doberman?") == "why-doberman"
    assert github_heading_slug("1. Install") == "1-install"


def test_collect_heading_slugs_dedupes() -> None:
    text = "# Foo\n\n## Foo\n\n### Bar\n"
    slugs = collect_heading_slugs(text)
    assert "foo" in slugs
    assert "foo-1" in slugs
    assert "bar" in slugs


def test_valid_relative_link_and_anchor(tmp_path: Path) -> None:
    root = tmp_path
    (root / "docs").mkdir()
    target = root / "docs" / "SETUP.md"
    target.write_text("# Quick Start\n\n## Details\n", encoding="utf-8")
    src = root / "README.md"
    src.write_text(
        "See [setup](docs/SETUP.md) and [anchor](docs/SETUP.md#quick-start).\n",
        encoding="utf-8",
    )
    issues = check_files(root, [src])
    assert issues == []


def test_missing_file_reports_line(tmp_path: Path) -> None:
    root = tmp_path
    src = root / "README.md"
    src.write_text("broken [x](./nope.md)\n", encoding="utf-8")
    issues = check_files(root, [src])
    assert len(issues) == 1
    assert issues[0].reason == "missing target path"
    assert issues[0].line == 1
    assert "nope.md" in issues[0].target


def test_missing_anchor(tmp_path: Path) -> None:
    root = tmp_path
    page = root / "page.md"
    page.write_text("# Present\n", encoding="utf-8")
    src = root / "README.md"
    src.write_text("[go](page.md#absent)\n", encoding="utf-8")
    issues = check_files(root, [src])
    assert len(issues) == 1
    assert issues[0].reason == "missing heading anchor"


def test_valid_same_file_anchor(tmp_path: Path) -> None:
    root = tmp_path
    src = root / "README.md"
    src.write_text("# Roadmap\n\n[jump](#roadmap)\n", encoding="utf-8")
    issues = check_files(root, [src])
    assert issues == []


def test_external_links_are_skipped(tmp_path: Path) -> None:
    root = tmp_path
    src = root / "README.md"
    src.write_text(
        "[a](https://example.com/missing)\n[b](http://example.com)\n[c](mailto:x@y.z)\n",
        encoding="utf-8",
    )
    issues = check_files(root, [src])
    assert issues == []


def test_fenced_code_links_are_skipped(tmp_path: Path) -> None:
    root = tmp_path
    src = root / "README.md"
    src.write_text(
        "```md\n[broken](./does-not-exist.md)\n```\n\n[ok](#ok)\n\n# Ok\n",
        encoding="utf-8",
    )
    issues = check_files(root, [src])
    assert issues == []


def test_path_escaping_repo_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    src = root / "README.md"
    # Escape via parent traversal past the repository root.
    src.write_text("[out](../../../../../../../../etc/passwd)\n", encoding="utf-8")
    issues = check_files(root, [src])
    assert len(issues) == 1
    assert issues[0].reason == "target escapes repository root"


def test_main_ok_on_fixture_tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path
    (root / "docs").mkdir()
    (root / "docs" / "a.md").write_text("# A\n", encoding="utf-8")
    (root / "README.md").write_text("[a](docs/a.md#a)\n", encoding="utf-8")
    code = main(["--root", str(root), str(root / "README.md")])
    assert code == 0
    assert "ok" in capsys.readouterr().out


def test_main_nonzero_on_broken(tmp_path: Path) -> None:
    root = tmp_path
    src = root / "README.md"
    src.write_text("[x](missing.md)\n", encoding="utf-8")
    code = main(["--root", str(root), str(src)])
    assert code == 1


def test_iter_markdown_links_images_and_titles() -> None:
    text = '![logo](./img.png "t")\n[doc](<./a.md>)\n'
    links = list(iter_markdown_links(text, Path("x.md")))
    assert [ln.target for ln in links] == ["./img.png", "./a.md"]
