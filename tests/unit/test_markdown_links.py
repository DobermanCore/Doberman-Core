from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from scripts.check_markdown_links import main


def run_checker(root: Path) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        returncode = main(["--root", str(root)])
    return returncode, stdout.getvalue(), stderr.getvalue()


def write_markdown(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_valid_internal_links_and_skips(tmp_path: Path) -> None:
    write_markdown(
        tmp_path / "README.md",
        """[guide](docs/guide.md#installation)

[home](#top)

[web](https://example.test/missing.md)
[mail](mailto:docs@example.test)
[other](ftp://example.test/missing.md)
[protocol-relative](//example.test/missing.md)
[asset](docs/image.png)

```markdown
[ignored](missing.md#missing)
```

# Top
""",
    )
    write_markdown(tmp_path / "docs" / "guide.md", "# Installation\n")

    returncode, _, stderr = run_checker(tmp_path)

    assert returncode == 0, stderr
    assert stderr == ""


def test_missing_file_and_anchor_are_reported(tmp_path: Path) -> None:
    write_markdown(
        tmp_path / "README.md",
        """[missing](docs/missing.md)
[bad-anchor](docs/guide.md#does-not-exist)
""",
    )
    write_markdown(tmp_path / "docs" / "guide.md", "# Present\n")

    returncode, _, stderr = run_checker(tmp_path)

    assert returncode != 0
    assert "README.md:1" in stderr
    assert "docs/missing.md" in stderr
    assert "README.md:2" in stderr
    assert "docs/guide.md#does-not-exist" in stderr
    assert "missing" in stderr.lower()


def test_path_escape_is_rejected(tmp_path: Path) -> None:
    write_markdown(tmp_path / "docs" / "README.md", "[escape](../../outside.md)\n")

    returncode, _, stderr = run_checker(tmp_path)

    assert returncode != 0
    assert "docs/README.md:1" in stderr
    assert "outside repository root" in stderr


def test_github_style_heading_slugs_and_duplicates(tmp_path: Path) -> None:
    write_markdown(
        tmp_path / "README.md",
        """[first](guide.md#release-notes)
[second](guide.md#release-notes-1)
""",
    )
    write_markdown(
        tmp_path / "guide.md",
        """## Release notes!
## Release notes!
""",
    )

    returncode, _, stderr = run_checker(tmp_path)

    assert returncode == 0, stderr


def test_explicit_html_anchors_and_punctuation_slugs(tmp_path: Path) -> None:
    write_markdown(
        tmp_path / "README.md",
        """[named](guide.md#stable-anchor)
[heading](guide.md#4-check-its-healthy-doberman-doctor)
""",
    )
    write_markdown(
        tmp_path / "guide.md",
        """<a name="stable-anchor"></a>
### 4. Check it's healthy — `doberman doctor`
""",
    )

    returncode, _, stderr = run_checker(tmp_path)

    assert returncode == 0, stderr


def test_inline_links_in_headings_use_rendered_text(tmp_path: Path) -> None:
    write_markdown(tmp_path / "README.md", "[heading](guide.md#linked-heading)\n")
    write_markdown(tmp_path / "guide.md", "### [Linked heading](https://example.test)\n")

    returncode, _, stderr = run_checker(tmp_path)

    assert returncode == 0, stderr


def test_diagnostics_are_sorted_by_relative_path_and_line(tmp_path: Path) -> None:
    write_markdown(tmp_path / "z.md", "[late](missing.md)\n")
    write_markdown(tmp_path / "a.md", "[early](missing.md)\n")

    returncode, _, stderr = run_checker(tmp_path)

    assert returncode != 0
    diagnostics = [line for line in stderr.splitlines() if ": broken Markdown link " in line]
    assert [line.split(":", 1)[0] for line in diagnostics] == ["a.md", "z.md"]
