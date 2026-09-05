"""Slice 4.1 — built-in role definitions, schema, and active-role config.

Covers: the built-ins load and validate; globs are normalized (lower-cased,
whole-tree dropped); empty `allowed` means nothing is implicitly in scope; and
`config.load_active_role` resolves named/inline/unknown/missing roles with the
fail-toward-restriction rule.
"""

import os

import pytest

from doberman import config
from doberman.roles.roles import (
    MOST_RESTRICTIVE_ROLE,
    RoleDefinition,
    load_builtin_roles,
)

EXPECTED_ROLES = {"frontend", "backend", "fullstack", "devops", "docs", "test", "default"}


def test_builtins_load_and_validate():
    roles = load_builtin_roles()
    assert set(roles) == EXPECTED_ROLES
    assert all(isinstance(r, RoleDefinition) for r in roles.values())
    assert all(r.description for r in roles.values())


def test_frontend_role_has_expected_scope():
    roles = load_builtin_roles()
    fe = roles["frontend"]
    assert "frontend/**" in fe.allowed
    assert "backend/auth/**" in fe.suspicious  # out of scope → AUTH, not blocked
    assert fe.blocked == ()


def test_globs_are_normalized_lowercased_and_tupled():
    role = RoleDefinition(name="x", allowed=["Frontend/**", "  SRC/Pages/**  "])
    assert role.allowed == ("frontend/**", "src/pages/**")
    assert isinstance(role.allowed, tuple)


def test_whole_tree_globs_are_dropped():
    # A blocked "**" would block everything — it must be dropped, not honored.
    role = RoleDefinition(name="x", blocked=["**", "*", "secrets/**"])
    assert role.blocked == ("secrets/**",)


def test_empty_allowed_means_nothing_in_scope():
    assert MOST_RESTRICTIVE_ROLE.allowed == ()
    assert MOST_RESTRICTIVE_ROLE.suspicious == ()
    assert MOST_RESTRICTIVE_ROLE.blocked == ()


def test_role_definition_rejects_empty_name():
    with pytest.raises(ValueError):
        RoleDefinition(name="")


def test_load_active_role_returns_none_when_unconfigured(tmp_path):
    # No .doberman/role.yaml → None (role enforcement is opt-in).
    assert config.load_active_role(str(tmp_path)) is None


def test_load_active_role_resolves_a_named_builtin(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text("role: backend\n", encoding="utf-8")
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.name == "backend"
    assert "backend/**" in role.allowed


def test_unknown_role_name_falls_back_to_most_restrictive(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text("role: wizard\n", encoding="utf-8")
    assert config.load_active_role(str(tmp_path)) is MOST_RESTRICTIVE_ROLE


def test_inline_custom_role_is_honored(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text(
        "role: custom\nallowed: ['app/**']\nblocked: ['app/secret/**']\n", encoding="utf-8"
    )
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.allowed == ("app/**",)
    assert role.blocked == ("app/secret/**",)


def test_malformed_role_file_fails_closed_to_restrictive(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    assert config.load_active_role(str(tmp_path)) is MOST_RESTRICTIVE_ROLE


# --- #199: protected_branches role.yaml key ---


def test_protected_branches_key_parses_for_a_named_builtin_role(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text(
        "role: backend\nprotected_branches: [staging, prod]\n", encoding="utf-8"
    )
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.name == "backend"
    assert role.protected_branches == ("staging", "prod")
    # The named builtin's own path scope is untouched by the addition.
    assert "backend/**" in role.allowed


def test_protected_branches_key_parses_for_an_inline_role(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text(
        "role: custom\nallowed: ['app/**']\nprotected_branches: ['staging']\n", encoding="utf-8"
    )
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.protected_branches == ("staging",)


def test_protected_branches_entries_are_normalized(tmp_path):
    # #199 review: the pushed ref is stripped of a 'refs/heads/' prefix and
    # lower-cased before matching (commands.py), so a configured entry must
    # be normalized the same way at parse time or it silently never matches.
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text(
        "role: backend\nprotected_branches: ['refs/heads/Staging', '  Prod ']\n",
        encoding="utf-8",
    )
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.protected_branches == ("staging", "prod")


def test_protected_branches_blank_after_normalization_fails_closed(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text("role: backend\nprotected_branches: ['   ']\n", encoding="utf-8")
    assert config.load_active_role(str(tmp_path)) is MOST_RESTRICTIVE_ROLE


def test_protected_branches_refs_heads_only_fails_closed(tmp_path):
    # 'refs/heads/' with nothing after it normalizes to blank too.
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text(
        "role: backend\nprotected_branches: ['refs/heads/']\n", encoding="utf-8"
    )
    assert config.load_active_role(str(tmp_path)) is MOST_RESTRICTIVE_ROLE


def test_protected_branches_empty_list_is_fine(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text("role: backend\nprotected_branches: []\n", encoding="utf-8")
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.protected_branches == ()


def test_protected_branches_key_absent_defaults_to_empty(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text("role: backend\n", encoding="utf-8")
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.protected_branches == ()


def test_protected_branches_non_list_value_fails_closed_to_restrictive(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text(
        'role: backend\nprotected_branches: "staging"\n', encoding="utf-8"
    )
    assert config.load_active_role(str(tmp_path)) is MOST_RESTRICTIVE_ROLE


def test_protected_branches_non_string_entry_fails_closed_to_restrictive(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text(
        "role: backend\nprotected_branches: [staging, 1]\n", encoding="utf-8"
    )
    assert config.load_active_role(str(tmp_path)) is MOST_RESTRICTIVE_ROLE


def test_protected_branches_defaults_to_empty_tuple_on_role_definition():
    role = RoleDefinition(name="x")
    assert role.protected_branches == ()


def test_load_builtin_roles_is_cached_across_many_calls():
    # Finding (#552): load_builtin_roles() re-read and re-parsed the packaged
    # builtin_roles.yaml on every call -- and it is called from
    # config.load_active_role() on every decided action (both the host-hook
    # and proxy hot paths). Now lru_cache(maxsize=1), the same mechanism as
    # #547's fingerprint-key cache: the real (disk-touching) loader must run
    # exactly once no matter how many load_builtin_roles() calls follow.
    load_builtin_roles.cache_clear()

    for _ in range(50):
        load_builtin_roles()

    info = load_builtin_roles.cache_info()
    assert info.misses == 1
    assert info.hits == 49


def test_load_active_role_named_role_parses_once_for_unchanged_content(tmp_path):
    # Finding (#552): load_active_role() re-read and re-parsed role.yaml from
    # disk on EVERY call with zero caching, and it is called once per decided
    # action on both hot paths (hosthooks/spine.py, proxy/executor.py).
    # Instrumented count (test-logs/issue-552-count-role-reads.py, BEFORE this
    # fix): 20 decided actions through spine.evaluate_action -> 20 role.yaml
    # reads. Now content-keyed: the read still happens every call (the file is
    # tiny), but the expensive parse+validate must run exactly once for N
    # calls against unchanged content.
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "role.yaml").write_text("role: backend\n", encoding="utf-8")
    config._parse_role_yaml_data.cache_clear()

    for _ in range(20):
        role = config.load_active_role(str(tmp_path))
        assert role is not None
        assert role.name == "backend"

    info = config._parse_role_yaml_data.cache_info()
    assert info.misses == 1  # the real (disk-touching) parse ran exactly once
    assert info.hits == 19


def test_load_active_role_picks_up_a_mid_process_role_yaml_edit(tmp_path):
    # The cache must NOT go stale the way a naive full-process cache would: a
    # human (or `doberman role enable-default`) can edit role.yaml while a
    # long-lived process (the RB proxy) keeps deciding actions, so the very
    # next decision must see the new role. This reproduces the real race a
    # (path, mtime_ns) key missed (#552 review): force the rewrite to land at
    # the EXACT SAME mtime as the first write (coarse filesystem clock
    # resolution can do this for real) rather than dodging it with a +5s
    # bump -- content-based keying must not depend on the clock at all.
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    role_path = cfg / "role.yaml"
    role_path.write_text("role: backend\n", encoding="utf-8")
    config._parse_role_yaml_data.cache_clear()

    first = config.load_active_role(str(tmp_path))
    assert first is not None
    assert first.name == "backend"

    stat_before = role_path.stat()
    role_path.write_text("role: frontend\n", encoding="utf-8")
    os.utime(role_path, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
    assert role_path.stat().st_mtime_ns == stat_before.st_mtime_ns  # same-tick, by construction

    second = config.load_active_role(str(tmp_path))
    assert second is not None
    assert second.name == "frontend"
