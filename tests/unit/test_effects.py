"""C2 — bounded, read-only filesystem effect enumeration (ADR 0094)."""

import os
import sys
import time
from pathlib import Path

import pytest

from doberman.auth.challenge import format_effect_set
from doberman.engine.effects import compute_delete_effects
from doberman.models import EffectSet


def _touch(path: Path, content: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_no_operands_is_a_clean_zero(tmp_path):
    effects = compute_delete_effects([], str(tmp_path))
    assert effects.file_count == 0
    assert effects.dir_count == 0
    assert effects.capped is False


def test_known_counts_over_a_fixture_tree(tmp_path):
    _touch(tmp_path / "target" / "a.txt")
    _touch(tmp_path / "target" / "b.txt")
    _touch(tmp_path / "target" / "sub" / "c.txt")
    effects = compute_delete_effects(["target"], str(tmp_path))
    assert effects.capped is False
    assert effects.file_count == 3
    assert effects.dir_count == 2  # target/ itself + target/sub/
    assert effects.hits_git is False
    assert effects.hits_outside_repo is False


def test_single_file_operand(tmp_path):
    _touch(tmp_path / "lonely.txt")
    effects = compute_delete_effects(["lonely.txt"], str(tmp_path))
    assert effects.file_count == 1
    assert effects.dir_count == 0
    assert effects.capped is False


def test_nonexistent_literal_operand_counts_as_nothing(tmp_path):
    effects = compute_delete_effects(["never-existed"], str(tmp_path))
    assert effects.file_count == 0
    assert effects.capped is False


def test_dot_git_presence_sets_hits_git(tmp_path):
    _touch(tmp_path / "target" / ".git" / "HEAD", "ref: refs/heads/main")
    _touch(tmp_path / "target" / "real.txt")
    effects = compute_delete_effects(["target"], str(tmp_path))
    assert effects.hits_git is True


def test_operand_outside_repo_root_sets_hits_outside_repo_and_is_not_walked(tmp_path):
    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    _touch(outside / "secret.txt")
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)  # tests/conftest.py's autouse isolated_executor_repo_root
    # fixture already creates tmp_path/"repo" for every test — this is not a
    # collision with anything this test does, just the same empty dir twice.
    try:
        effects = compute_delete_effects(["../" + outside.name], str(repo))
        assert effects.hits_outside_repo is True
        assert effects.file_count == 0  # never counted — never walked
    finally:
        import shutil

        shutil.rmtree(outside, ignore_errors=True)


def test_symlink_operand_itself_is_not_followed(tmp_path):
    if sys.platform == "win32":
        pytest.skip("symlink creation needs elevation on Windows")
    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    _touch(outside / "a.txt")
    _touch(outside / "b.txt")
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)  # see note above
    link = repo / "link"
    link.symlink_to(outside, target_is_directory=True)
    effects = compute_delete_effects(["link"], str(repo))
    assert effects.file_count == 0
    assert effects.dir_count == 0


def test_symlink_operand_with_in_repo_target_counts_as_one_entry_not_descended(tmp_path):
    # Task 3 review fix: an in-repo symlink target used to be resolved before
    # the is_symlink() check, so `rm -rf link` (link -> real_dir/, both inside
    # the repo) walked and counted real_dir/'s CONTENTS. `rm` removes the link
    # entry, not the target — the link must count as exactly one entry and
    # never be descended into.
    if sys.platform == "win32":
        pytest.skip("symlink creation needs elevation on Windows")
    real_dir = tmp_path / "real_dir"
    _touch(real_dir / "a.txt")
    _touch(real_dir / "b.txt")
    link = tmp_path / "link"
    link.symlink_to(real_dir, target_is_directory=True)
    effects = compute_delete_effects(["link"], str(tmp_path))
    assert effects.file_count == 1  # the link itself only
    assert effects.dir_count == 0
    assert effects.capped is False


def test_symlinked_directory_inside_the_walk_is_skipped_like_a_symlinked_file(tmp_path):
    # A symlinked dir encountered *during* the walk must be as inert as the
    # existing symlinked-file skip in the filenames loop: never counted, never
    # descended (followlinks=False already stops recursion; this stops the count).
    if sys.platform == "win32":
        pytest.skip("symlink creation needs elevation on Windows")
    outside = tmp_path.parent / f"outside-dir-{tmp_path.name}"
    _touch(outside / "secret.txt")
    target = tmp_path / "target"
    _touch(target / "real.txt")
    (target / "linked_dir").symlink_to(outside, target_is_directory=True)
    try:
        effects = compute_delete_effects(["target"], str(tmp_path))
        assert effects.file_count == 1  # real.txt only
        assert effects.dir_count == 1  # target/ itself only — linked_dir/ not counted
    finally:
        import shutil

        shutil.rmtree(outside, ignore_errors=True)


def test_symlink_loop_inside_the_walk_does_not_hang(tmp_path):
    if sys.platform == "win32":
        pytest.skip("symlink creation needs elevation on Windows")
    target = tmp_path / "target"
    target.mkdir()
    _touch(target / "a.txt")
    (target / "loop").symlink_to(target, target_is_directory=True)
    started = time.monotonic()
    effects = compute_delete_effects(["target"], str(tmp_path), budget_s=0.25)
    assert time.monotonic() - started < 2.0
    assert effects.file_count == 1  # loop/ never descended into (followlinks=False)


@pytest.mark.skipif(sys.platform == "win32", reason="chmod 000 is a no-op on Windows")
def test_unreadable_directory_yields_unknown_never_a_partial_count(tmp_path):
    target = tmp_path / "target"
    _touch(target / "visible.txt")
    locked = target / "locked"
    locked.mkdir()
    _touch(locked / "hidden.txt")
    os.chmod(locked, 0o000)
    try:
        effects = compute_delete_effects(["target"], str(tmp_path))
        assert effects.capped is True
        assert effects.file_count is None
        assert effects.dir_count is None
    finally:
        os.chmod(locked, 0o700)  # let tmp_path cleanup succeed


def test_hitting_cap_reports_a_lower_bound_not_a_silent_zero(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    for i in range(50):
        _touch(target / f"f{i}.txt")
    effects = compute_delete_effects(["target"], str(tmp_path), cap=10)
    assert effects.capped is True
    assert effects.file_count == 10  # the cap value — "at least 10"
    assert effects.dir_count is None


def test_wide_tree_returns_within_budget_capped(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    for i in range(10_000):
        _touch(target / f"f{i}.txt")
    started = time.monotonic()
    effects = compute_delete_effects(["target"], str(tmp_path), cap=1000, budget_s=0.25)
    elapsed = time.monotonic() - started
    assert effects.capped is True
    assert elapsed < 2.0  # generous CI margin; the point is "doesn't run to completion"


def test_unresolved_glob_operand_is_unknown_never_a_silent_zero(tmp_path):
    # No file literally named "*.log" — and no glob engine here (ponytail) —
    # so this must fail toward unknown, not toward "nothing to delete".
    effects = compute_delete_effects(["*.log"], str(tmp_path))
    assert effects.capped is True
    assert effects.file_count is None


def test_digest_stable_across_two_runs_on_an_unchanged_tree(tmp_path):
    _touch(tmp_path / "target" / "a.txt")
    _touch(tmp_path / "target" / "b.txt")
    first = compute_delete_effects(["target"], str(tmp_path))
    second = compute_delete_effects(["target"], str(tmp_path))
    assert first.digest == second.digest


def test_digest_differs_after_a_file_is_added(tmp_path):
    _touch(tmp_path / "target" / "a.txt")
    before = compute_delete_effects(["target"], str(tmp_path))
    _touch(tmp_path / "target" / "b.txt")
    after = compute_delete_effects(["target"], str(tmp_path))
    assert before.digest != after.digest


def test_unknown_and_cap_hit_share_the_same_sentinel_digest(tmp_path):
    # A known->unknown OR known->cap-hit transition must always be detectable
    # by a plain digest inequality in the proxy's TOCTOU check — both
    # non-authoritative shades therefore share one sentinel.
    target = tmp_path / "target"
    target.mkdir()
    for i in range(5):
        _touch(target / f"f{i}.txt")
    cap_hit = compute_delete_effects(["target"], str(tmp_path), cap=2)
    unknown = compute_delete_effects(["*.log"], str(tmp_path))
    assert cap_hit.digest == unknown.digest


def test_nul_byte_operand_yields_unknown_never_a_confident_zero(tmp_path):
    # A NUL byte can never appear in a real path component on any filesystem.
    # canonicalize()/Path.exists() already swallow the resulting ValueError
    # internally (stdlib genericpath does this since 3.8) rather than raise
    # it, so left unguarded this operand would fall through the "doesn't
    # exist" branch and render as a confident file_count=0 — exactly the
    # false-safe empty preview ADR 0094 clause 3 forbids. Must degrade to
    # unknown instead.
    effects = compute_delete_effects(["evil\x00operand"], str(tmp_path))
    assert effects.capped is True
    assert effects.file_count is None


def test_format_effect_set_none_is_none():
    assert format_effect_set(None) is None


def test_format_effect_set_normal_counts():
    effects = EffectSet(
        file_count=4812,
        dir_count=37,
        capped=False,
        hits_git=False,
        hits_outside_repo=False,
        digest="d",
    )
    assert format_effect_set(effects) == "4,812 files in 37 directories"


def test_format_effect_set_single_file_no_directories():
    effects = EffectSet(
        file_count=1,
        dir_count=0,
        capped=False,
        hits_git=False,
        hits_outside_repo=False,
        digest="d",
    )
    assert format_effect_set(effects) == "1 file"


def test_format_effect_set_cap_hit():
    effects = EffectSet(
        file_count=1000,
        dir_count=None,
        capped=True,
        hits_git=False,
        hits_outside_repo=False,
        digest="d",
    )
    assert format_effect_set(effects) == "1000+ files"


def test_format_effect_set_hard_unknown():
    effects = EffectSet(
        file_count=None,
        dir_count=None,
        capped=True,
        hits_git=False,
        hits_outside_repo=False,
        digest="d",
    )
    assert format_effect_set(effects) == "unknown — count unavailable"


def test_format_effect_set_never_contains_a_path():
    # Redaction smoke test: whatever the formatter emits, it can only be
    # built from counts/booleans — there is no path field to leak.
    effects = EffectSet(
        file_count=3,
        dir_count=1,
        capped=False,
        hits_git=True,
        hits_outside_repo=False,
        digest="d",
    )
    rendered = format_effect_set(effects)
    assert "/" not in rendered
    assert "\\" not in rendered
