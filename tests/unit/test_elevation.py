"""Slice 7.4 — narrow/temporary/single-use elevation model + storage."""

from datetime import datetime, timedelta, timezone

from doberman.auth.elevation import (
    ElevationGrant,
    find_cover,
    scope_for_target,
)
from doberman.storage.db import (
    active_elevations,
    db_path,
    grant_elevation,
    mark_used,
    revoke_elevation,
)

_NOW = datetime(2026, 6, 8, 12, 0, 0, tzinfo=timezone.utc)


def _grant(scope, *, ttl=900, single_use=False, used=False, revoked=False):
    return ElevationGrant(
        id="g1",
        scope_glob=scope,
        task_id="t1",
        granted_at=_NOW,
        expires_at=_NOW + timedelta(seconds=ttl),
        single_use=single_use,
        used=used,
        revoked=revoked,
    )


# --- pure model -----------------------------------------------------------


def test_scope_for_target_is_narrow_and_canonical():
    assert scope_for_target("backend/api.ts", root=".") == "backend/api.ts"
    assert scope_for_target("BACKEND/API.ts", root=".") == "backend/api.ts"


def test_scope_refuses_non_path_and_escapes_and_whole_tree():
    assert scope_for_target(None, root=".") is None
    assert scope_for_target("../../etc/passwd", root=".") is None
    assert scope_for_target(".", root=".") is None


def test_grant_is_active_window():
    g = _grant("backend/api.ts")
    assert g.is_active(_NOW) is True
    assert g.is_active(_NOW + timedelta(seconds=1000)) is False  # past TTL


def test_revoked_and_spent_grants_are_inactive():
    assert _grant("x", revoked=True).is_active(_NOW) is False
    assert _grant("x", single_use=True, used=True).is_active(_NOW) is False
    assert _grant("x", single_use=True, used=False).is_active(_NOW) is True


def test_covers_matches_exact_path_only_and_never_whole_tree():
    g = _grant("backend/api.ts")
    assert g.covers("backend/api.ts") is True
    assert g.covers("backend/other.ts") is False
    assert _grant("**").covers("anything") is False  # whole-tree never covers


# H3 — elevation scope must not glob-widen -------------------------------


def test_scope_for_target_escapes_glob_metacharacters():
    # A target containing fnmatch metacharacters must come back with those
    # characters escaped, so the stored scope matches only the literal path.
    assert scope_for_target("secret*", root=".") == "secret[*]"
    assert scope_for_target("report[1].txt", root=".") == "report[[]1].txt"


def test_elevation_scoped_to_star_target_does_not_cover_other_paths():
    scope = scope_for_target("secret*", root=".")
    g = _grant(scope)
    assert g.covers("secret*") is True  # the literal target still covers itself
    assert g.covers("secretsauce.txt") is False  # '*' must not act as a wildcard
    assert g.covers("secret") is False


def test_elevation_scoped_to_bracket_target_does_not_cover_other_paths():
    scope = scope_for_target("report[1].txt", root=".")
    g = _grant(scope)
    assert g.covers("report[1].txt") is True  # the literal target still covers itself
    assert g.covers("report1.txt") is False  # '[1]' must not act as a character class


def test_elevation_literal_target_still_covers_itself_and_nothing_else():
    scope = scope_for_target("backend/api.ts", root=".")
    g = _grant(scope)
    assert g.covers("backend/api.ts") is True
    assert g.covers("backend/other.ts") is False


def test_find_cover_canonicalizes_target():
    grants = (_grant("backend/api.ts"),)
    assert find_cover("backend/api.ts", grants, root=".") is not None
    assert find_cover("backend/../backend/api.ts", grants, root=".") is not None
    assert find_cover("backend/other.ts", grants, root=".") is None


# --- storage --------------------------------------------------------------


async def test_grant_then_active(tmp_path):
    root = str(tmp_path)
    grant = await grant_elevation(root, "backend/api.ts", "task-1", now=_NOW)
    active = await active_elevations(root, _NOW)
    assert [g.id for g in active] == [grant.id]
    assert active[0].scope_glob == "backend/api.ts"


async def test_active_excludes_expired(tmp_path):
    root = str(tmp_path)
    await grant_elevation(root, "backend/api.ts", "t", now=_NOW, ttl_seconds=60)
    assert await active_elevations(root, _NOW + timedelta(seconds=120)) == []


async def test_revoke_makes_inactive(tmp_path):
    root = str(tmp_path)
    grant = await grant_elevation(root, "backend/api.ts", "t", now=_NOW)
    assert await revoke_elevation(root, grant.id) is True
    assert await active_elevations(root, _NOW) == []
    # Revoking an unknown id reports no row changed.
    assert await revoke_elevation(root, "nope") is False


async def test_single_use_consumed_by_mark_used(tmp_path):
    root = str(tmp_path)
    grant = await grant_elevation(root, "backend/api.ts", "t", now=_NOW, single_use=True)
    assert len(await active_elevations(root, _NOW)) == 1
    await mark_used(root, grant.id)
    assert await active_elevations(root, _NOW) == []


async def test_active_short_circuits_without_a_db(tmp_path):
    root = str(tmp_path)
    assert not db_path(root).exists()
    assert await active_elevations(root, _NOW) == []
    assert not db_path(root).exists()  # no DB created by a read
