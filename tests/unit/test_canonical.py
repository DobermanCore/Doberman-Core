"""Slice 3.3 (shared helper) — the path canonicalizer is the safety backbone.

Covers: ``..`` traversal resolution, symlink resolution, case normalization,
root confinement (escapes flagged), absolute vs relative inputs, non-existent
paths tolerated, and hostile input never raising. If this helper is wrong, every
path rule is bypassable — so the bypass cases are exhaustive here.
"""

import os

import pytest

from doberman.canonical import canonicalize


def test_relative_path_is_root_relative_and_lowercased(tmp_path):
    result = canonicalize("Frontend/Button.TSX", root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == "frontend/button.tsx"


def test_dot_and_dotdot_segments_are_resolved(tmp_path):
    # a/b/../../.env collapses to .env relative to root.
    result = canonicalize("a/b/../../.env", root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == ".env"


def test_traversal_outside_root_is_flagged_as_escape(tmp_path):
    result = canonicalize("../../../etc/passwd", root=tmp_path)
    assert result.escapes_root is True


def test_absolute_path_outside_root_is_escape(tmp_path):
    other = tmp_path.parent / "somewhere-else" / "secret.txt"
    result = canonicalize(str(other), root=tmp_path)
    assert result.escapes_root is True


def test_absolute_path_inside_root_is_confined(tmp_path):
    inside = tmp_path / "src" / "main.py"
    result = canonicalize(str(inside), root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == "src/main.py"


def test_case_insensitive_matching_form(tmp_path):
    # The relposix form is always lower-cased so .ENV and .env collide.
    assert canonicalize(".ENV", root=tmp_path).relposix == ".env"


def test_nonexistent_path_is_tolerated_no_filesystem_write(tmp_path):
    target = tmp_path / "does" / "not" / "exist.txt"
    result = canonicalize(str(target), root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == "does/not/exist.txt"
    assert not target.exists()  # canonicalize must not create anything


@pytest.mark.skipif(os.name == "nt", reason="symlink creation may require privilege on Windows")
def test_symlink_escape_is_resolved_and_flagged(tmp_path):
    # A symlink inside root pointing outside it must resolve to outside → escape.
    outside_dir = tmp_path.parent / "outside-target"
    outside_dir.mkdir(exist_ok=True)
    secret = outside_dir / "secret.txt"
    secret.write_text("x")
    link = tmp_path / "link-to-outside"
    link.symlink_to(secret)
    result = canonicalize(str(link), root=tmp_path)
    assert result.escapes_root is True


@pytest.mark.skipif(os.name == "nt", reason="symlink creation may require privilege on Windows")
def test_symlink_inside_root_is_not_an_escape(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("x")
    link = tmp_path / "alias.txt"
    link.symlink_to(target)
    result = canonicalize(str(link), root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == "real.txt"


def test_root_itself_has_empty_relposix(tmp_path):
    result = canonicalize(".", root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == ""


def test_hostile_input_never_raises(tmp_path):
    for bad in ("\x00", "://://", "C:\\\\nope", "~" * 5000, "", "..\\..\\.."):
        result = canonicalize(bad, root=tmp_path)
        # Always returns a populated result; never raises.
        assert isinstance(result.relposix, str)


def test_unusable_root_never_raises():
    # A hostile root must never crash the canonicalizer; it returns a populated
    # result. (Where the OS rejects the root outright, the result is a
    # conservative escape; some platforms tolerate odd bytes lexically.)
    result = canonicalize("x", root="\x00bad")
    assert isinstance(result.relposix, str)
    assert isinstance(result.escapes_root, bool)


def test_resolved_is_absolute(tmp_path):
    result = canonicalize("src/x.py", root=tmp_path)
    assert os.path.isabs(result.resolved)


# --- Trailing dot/space normalization ---------------------------------------
# Windows treats trailing dots/spaces in a filename as insignificant and
# strips them when the file is opened, so ".env " and ".env." are the SAME
# on-disk file as ".env" — the matching form must collapse them the same way.


def test_trailing_space_is_stripped_from_matching_form(tmp_path):
    result = canonicalize(".env ", root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == ".env"


def test_multiple_trailing_spaces_are_stripped(tmp_path):
    result = canonicalize(".env  ", root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == ".env"


def test_trailing_dot_is_stripped_from_matching_form(tmp_path):
    result = canonicalize("certs/server.pem.", root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == "certs/server.pem"


def test_nested_trailing_space_component_is_stripped(tmp_path):
    result = canonicalize("packages/app/.env ", root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == "packages/app/.env"


def test_padded_directory_component_is_stripped(tmp_path):
    # The padding is on a DIRECTORY component, not just the leaf filename.
    result = canonicalize(".circleci /config.yml", root=tmp_path)
    assert not result.escapes_root
    assert result.relposix == ".circleci/config.yml"


def test_resolved_field_is_left_unnormalized(tmp_path):
    # The case-preserving `resolved` field is for display/forensics only and
    # must not be touched by the matching-form normalization.
    result = canonicalize(".env ", root=tmp_path)
    assert result.resolved.endswith(".env ")


def test_component_that_is_only_dots_and_spaces_fails_closed(tmp_path):
    # A component with no safe reduced form (e.g. "..." or " . ") must not be
    # silently dropped or emptied — conservatively flag it as an escape.
    for hostile in ("foo/... /bar", "foo/...", "foo/ . /bar"):
        result = canonicalize(hostile, root=tmp_path)
        assert result.escapes_root is True, hostile


def test_interior_dot_and_space_are_unaffected(tmp_path):
    # Only TRAILING dots/spaces are stripped; interior ones are a real part
    # of a benign filename and must survive untouched.
    assert canonicalize("docs/my notes.md", root=tmp_path).relposix == "docs/my notes.md"
    assert canonicalize("src/a.b.c.ts", root=tmp_path).relposix == "src/a.b.c.ts"
