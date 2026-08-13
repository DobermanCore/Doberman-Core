"""Slice 4.1 — built-in role definitions, schema, and active-role config.

Covers: the built-ins load and validate; globs are normalized (lower-cased,
whole-tree dropped); empty `allowed` means nothing is implicitly in scope; and
`config.load_active_role` resolves named/inline/unknown/missing roles with the
fail-toward-restriction rule.
"""

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
