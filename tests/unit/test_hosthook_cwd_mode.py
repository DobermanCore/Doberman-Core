"""#51: the host-hook strictness mode must not silently fall back to a *weaker*
mode read from the hook process's working directory when a payload omits ``cwd``.

The bug: ``repo_root = cwd or "."`` then ``load_mode(repo_root)`` meant a missing
``cwd`` read whatever ``.doberman/policies.yaml`` sat in the process CWD — a
different project's policy (possibly Light) or none — instead of the real
project's mode. The fix floors to the recommended default on a missing/invalid
``cwd``. These tests pin that: they FAIL on the old behavior (which returns the
process-dir's "light") and pass on the fix.
"""

import pytest

from doberman.config import save_mode
from doberman.hosthooks.claude_code import _resolve_root_and_mode
from doberman.policy.modes import DEFAULT_MODE


def test_valid_cwd_reads_that_projects_saved_mode(tmp_path):
    # With a real cwd, the project's own saved mode is honored (unchanged behavior).
    save_mode("strict", str(tmp_path))
    repo_root, mode = _resolve_root_and_mode(str(tmp_path))
    assert repo_root == str(tmp_path)
    assert mode == "strict"


@pytest.mark.parametrize("bad_cwd", [None, "", 123, {}])
def test_missing_or_invalid_cwd_uses_safe_default_not_process_dir_policy(
    bad_cwd, tmp_path, monkeypatch
):
    # A *different* project's weaker (Light) policy sits in the process CWD…
    save_mode("light", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    # …but with no usable cwd in the payload we must NOT pick it up. Fail safe to
    # the recommended default, never the weaker Light mode (the #51 defect).
    _, mode = _resolve_root_and_mode(bad_cwd)
    assert mode == DEFAULT_MODE.value
    assert mode != "light"
