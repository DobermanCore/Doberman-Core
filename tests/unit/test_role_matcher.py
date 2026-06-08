"""Slice 4.2 — role-boundary matcher (classify).

Covers: allowed/suspicious classification; unmatched-by-allowed → suspicious;
blocked precedence (blocked wins on overlap); non-path → unknown; escapes-root →
blocked; and that classification goes through the shared canonicalizer so a
`..` traversal cannot dodge a boundary.
"""

from doberman.roles.roles import RoleBoundary, RoleDefinition, classify, load_builtin_roles

ROLES = load_builtin_roles()
FRONTEND = ROLES["frontend"]


def test_allowed_path_classifies_allowed(tmp_path):
    assert classify(FRONTEND, "frontend/Button.tsx", root=str(tmp_path)) is RoleBoundary.allowed


def test_out_of_scope_path_classifies_suspicious(tmp_path):
    assert (
        classify(FRONTEND, "backend/auth/session.ts", root=str(tmp_path)) is RoleBoundary.suspicious
    )


def test_unmatched_by_allowed_defaults_to_suspicious(tmp_path):
    # A path in none of the role's sets is out of scope → suspicious (safe default).
    assert classify(FRONTEND, "random/notes.txt", root=str(tmp_path)) is RoleBoundary.suspicious


def test_blocked_wins_on_overlap(tmp_path):
    role = RoleDefinition(name="x", allowed=["src/**"], blocked=["src/secret/**"])
    assert classify(role, "src/secret/key.txt", root=str(tmp_path)) is RoleBoundary.blocked
    assert classify(role, "src/app.py", root=str(tmp_path)) is RoleBoundary.allowed


def test_non_path_action_is_unknown(tmp_path):
    assert classify(FRONTEND, None, root=str(tmp_path)) is RoleBoundary.unknown


def test_path_escaping_repo_root_is_blocked(tmp_path):
    assert classify(FRONTEND, "../../etc/passwd", root=str(tmp_path)) is RoleBoundary.blocked


def test_traversal_is_canonicalized_before_matching(tmp_path):
    # "frontend/../backend/auth/x" canonicalizes to backend/auth/x → suspicious,
    # i.e. the traversal cannot launder an out-of-scope path into an allowed one.
    result = classify(FRONTEND, "frontend/../backend/auth/x.ts", root=str(tmp_path))
    assert result is RoleBoundary.suspicious


def test_case_insensitive_matching(tmp_path):
    assert classify(FRONTEND, "FRONTEND/Button.TSX", root=str(tmp_path)) is RoleBoundary.allowed
