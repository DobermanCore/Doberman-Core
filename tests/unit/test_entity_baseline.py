"""Slice SL4.1 — per-entity streaming baseline, transitions, and schema v3.

Load-bearing properties: entity A's observations never shift entity B's
baseline; feature keys are classes (and the entity id is an HMAC, never the
raw role/path); cardinality is bounded; a schema-changed tool's familiarity is
forgotten; the v2→v3 migration re-keys baselines (dropping old global rows is
raise-safe: colder = more step-ups) and adds decisions.entity_id.
"""

from datetime import datetime, timezone

import aiosqlite

from doberman.models import ActionType, Algebra, Capability, SecurityObject, TargetClass
from doberman.storage.db import SCHEMA_VERSION, db_path, open_db
from doberman.subjective.baseline import (
    MAX_FEATURE_KEYS,
    OVERFLOW_KEY,
    entity_id,
    frequency,
    markov_state,
    numeric_stats,
    observe,
    reset_tool_contribution,
    scoring_keys,
    total_observations,
    transition_counts,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


def _file(target, tool="fs_write", action_type=ActionType.file_write, **kw):
    algebra = kw.pop(
        "algebra",
        Algebra(
            capability=Capability.mutate,
            target_class=TargetClass.internal,
            classification_confidence=0.8,
        ),
    )
    return SecurityObject(
        id="eb-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=action_type,
        tool_name=tool,
        target=target,
        algebra=algebra,
        **kw,
    )


async def _seed(root, eid, action, times):
    for _ in range(times):
        await observe(action, entity_id=eid, repo_root=root, now=_NOW)


# --- entity identity -------------------------------------------------------------


def test_entity_id_is_keyed_and_leaks_nothing(tmp_path):
    eid = entity_id("frontend", str(tmp_path))
    assert eid.startswith("hmac:")
    assert "frontend" not in eid
    assert str(tmp_path) not in eid
    # Deterministic per (role, root); different roots → different entities.
    assert eid == entity_id("frontend", str(tmp_path))
    other = tmp_path / "other"
    other.mkdir()
    assert eid != entity_id("frontend", str(other))


# --- per-entity isolation ----------------------------------------------------------


async def test_entities_are_isolated(tmp_path):
    root = str(tmp_path)
    await _seed(root, "hmac:aaa", _file("frontend/Button.tsx"), 3)
    assert await frequency("target:internal", entity_id="hmac:aaa", repo_root=root) == 3
    assert await frequency("target:internal", entity_id="hmac:bbb", repo_root=root) == 0
    assert await total_observations(entity_id="hmac:bbb", repo_root=root) == 0


async def test_observe_increments_class_level_keys(tmp_path):
    root = str(tmp_path)
    action = _file("frontend/Button.tsx")
    await _seed(root, "hmac:aaa", action, 2)
    keys = scoring_keys(action)
    assert "capability:mutate" in keys
    assert "tool:fs_write" in keys
    assert "path_class:frontend/*.tsx" in keys
    for key in keys:
        assert await frequency(key, entity_id="hmac:aaa", repo_root=root) == 2
    assert await total_observations(entity_id="hmac:aaa", repo_root=root) == 2


# --- transitions ----------------------------------------------------------------


async def test_transition_counts_advance(tmp_path):
    root = str(tmp_path)
    read = _file(
        "a.py",
        tool="fs_read",
        action_type=ActionType.file_read,
        algebra=Algebra(
            capability=Capability.read,
            target_class=TargetClass.internal,
            classification_confidence=0.8,
        ),
    )
    write = _file("a.py")
    await observe(read, entity_id="hmac:aaa", repo_root=root, now=_NOW)
    await observe(write, entity_id="hmac:aaa", repo_root=root, now=_NOW)
    await observe(read, entity_id="hmac:aaa", repo_root=root, now=_NOW)
    first_order = await transition_counts(
        f"1:{markov_state(read)}", entity_id="hmac:aaa", repo_root=root
    )
    assert first_order.get(markov_state(write)) == 1
    second_order = await transition_counts(
        f"2:{markov_state(read)}>{markov_state(write)}", entity_id="hmac:aaa", repo_root=root
    )
    assert second_order.get(markov_state(read)) == 1
    # Transitions are entity-scoped too.
    assert (
        await transition_counts(f"1:{markov_state(read)}", entity_id="hmac:bbb", repo_root=root)
        == {}
    )


# --- numeric stats ----------------------------------------------------------------


async def test_volume_stats_track_welford_mean(tmp_path):
    root = str(tmp_path)
    small = _file("a.txt", metadata={"target_count": 2})
    large = _file("b.txt", metadata={"target_count": 10})
    await observe(small, entity_id="hmac:aaa", repo_root=root, now=_NOW)
    await observe(large, entity_id="hmac:aaa", repo_root=root, now=_NOW)
    stats = await numeric_stats("num:volume", entity_id="hmac:aaa", repo_root=root)
    assert stats is not None
    count, mean, m2, ewma_var = stats
    assert count == 2
    assert mean == 6.0  # (2 + 10) / 2
    assert m2 > 0
    assert ewma_var > 0


# --- cardinality bound ------------------------------------------------------------


async def test_cardinality_is_bounded(tmp_path):
    root = str(tmp_path)
    for i in range(MAX_FEATURE_KEYS + 60):
        await observe(
            _file(f"dir{i}/f{i}.x{i % 97}", tool=f"tool_{i}"),
            entity_id="hmac:aaa",
            repo_root=root,
            now=_NOW,
        )
    async with open_db(root) as conn:
        async with conn.execute(
            "SELECT COUNT(*) FROM baseline_counts WHERE entity_id = ?", ("hmac:aaa",)
        ) as cur:
            row = await cur.fetchone()
    distinct = int(row[0])
    assert distinct <= MAX_FEATURE_KEYS + len(scoring_keys(_file("x.y"))) + 2
    assert await frequency(OVERFLOW_KEY, entity_id="hmac:aaa", repo_root=root) > 0


# --- rug-pull tie-in --------------------------------------------------------------


async def test_schema_change_resets_only_that_tools_contribution(tmp_path):
    root = str(tmp_path)
    await _seed(root, "hmac:aaa", _file("a.txt", tool="fs_write"), 5)
    await _seed(root, "hmac:aaa", _file("b.txt", tool="net_post"), 5)
    await reset_tool_contribution("fs_write", entity_id="hmac:aaa", repo_root=root)
    assert await frequency("tool:fs_write", entity_id="hmac:aaa", repo_root=root) == 0
    assert await frequency("tool:net_post", entity_id="hmac:aaa", repo_root=root) == 5


# --- migration ----------------------------------------------------------------


async def test_v2_database_migrates_to_current(tmp_path):
    root = str(tmp_path)
    path = db_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Hand-build a v2-shaped DB: global baseline_counts + decisions without entity_id.
    conn = await aiosqlite.connect(str(path))
    await conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version (version) VALUES (2);
        CREATE TABLE baseline_counts (
            feature_key TEXT PRIMARY KEY,
            count       INTEGER NOT NULL DEFAULT 0,
            first_seen  TEXT,
            last_seen   TEXT
        );
        INSERT INTO baseline_counts (feature_key, count) VALUES ('path_class:src/*.py', 7);
        CREATE TABLE decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            action_id TEXT NOT NULL,
            final_verdict TEXT NOT NULL
        );
        INSERT INTO decisions (ts, action_id, final_verdict) VALUES ('t', 'a1', 'PASS');
        """
    )
    await conn.commit()
    await conn.close()

    # Opening through the schema layer migrates in place.
    async with open_db(root) as conn:
        async with conn.execute("PRAGMA table_info(baseline_counts)") as cur:
            count_cols = [row[1] for row in await cur.fetchall()]
        async with conn.execute("PRAGMA table_info(decisions)") as cur:
            decision_cols = [row[1] for row in await cur.fetchall()]
        async with conn.execute("SELECT COUNT(*) FROM baseline_counts") as cur:
            remaining = (await cur.fetchone())[0]
        async with conn.execute("SELECT version FROM schema_version") as cur:
            version = (await cur.fetchone())[0]
        async with conn.execute("SELECT action_id FROM decisions") as cur:
            decisions = await cur.fetchall()

    assert "entity_id" in count_cols  # re-keyed
    assert remaining == 0  # old global rows dropped (raise-safe: relearning is colder)
    assert "entity_id" in decision_cols  # additive column (v2→v3)
    assert "session_id" in decision_cols  # additive column (v3→v4, HK.5.1)
    assert decisions == [("a1",)]  # existing decision rows preserved
    assert version == SCHEMA_VERSION


async def test_fresh_database_starts_at_current_version(tmp_path):
    root = str(tmp_path)
    async with open_db(root) as conn:
        async with conn.execute("SELECT version FROM schema_version") as cur:
            version = (await cur.fetchone())[0]
        for table in (
            "baseline_transitions",
            "score_history",
            "preference_feedback",
            "session_taint",
        ):
            async with conn.execute(f"SELECT COUNT(*) FROM {table}") as cur:  # noqa: S608
                assert (await cur.fetchone())[0] == 0
    assert version == SCHEMA_VERSION


async def test_observe_never_raises_on_broken_db(tmp_path, monkeypatch):
    # Point the DB at an unwritable location: observe must swallow, reads return 0.
    import doberman.subjective.baseline as bl

    def _boom(*args, **kwargs):
        raise OSError("disk gone")

    monkeypatch.setattr(bl, "open_db", _boom)
    await observe(_file("a.txt"), entity_id="hmac:aaa", repo_root=str(tmp_path), now=_NOW)
    assert await frequency("target:internal", entity_id="hmac:aaa", repo_root=str(tmp_path)) == 0
