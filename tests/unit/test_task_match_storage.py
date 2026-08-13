"""D2 — the task-match ledger storage layer (`doberman.storage.task_match`).

Mirrors `test_taint_storage.py`'s own shape: a real (tmp_path) SQLite DB,
record/read round-trips, scoping, capping, and fail-closed reads.
"""

from doberman.storage.task_match import MAX_TASK_HOSTS, record_task_hosts, task_hosts_for


async def test_record_and_read_round_trip(tmp_path):
    repo_root = str(tmp_path)
    await record_task_hosts(repo_root, "sess-1", ["stripe.com", "api.stripe.com"])

    hosts = await task_hosts_for(repo_root, "sess-1")
    assert set(hosts) == {"stripe.com", "api.stripe.com"}


async def test_scopes_are_isolated(tmp_path):
    repo_root = str(tmp_path)
    await record_task_hosts(repo_root, "sess-a", ["stripe.com"])
    await record_task_hosts(repo_root, "sess-b", ["evil.example"])

    assert await task_hosts_for(repo_root, "sess-a") == ["stripe.com"]
    assert await task_hosts_for(repo_root, "sess-b") == ["evil.example"]


async def test_read_with_no_matching_scope_is_empty(tmp_path):
    repo_root = str(tmp_path)
    await record_task_hosts(repo_root, "sess-1", ["stripe.com"])

    assert await task_hosts_for(repo_root, "nobody") == []


async def test_read_with_no_db_yet_fails_closed_to_empty(tmp_path):
    assert await task_hosts_for(str(tmp_path), "sess-1") == []


async def test_record_is_capped_at_max_task_hosts(tmp_path):
    repo_root = str(tmp_path)
    hosts = [f"host{i}.example.com" for i in range(MAX_TASK_HOSTS + 10)]

    await record_task_hosts(repo_root, "sess-1", hosts)

    stored = await task_hosts_for(repo_root, "sess-1")
    assert len(stored) <= MAX_TASK_HOSTS


async def test_record_empty_scope_or_hosts_is_a_noop(tmp_path):
    repo_root = str(tmp_path)
    await record_task_hosts(repo_root, "", ["stripe.com"])
    await record_task_hosts(repo_root, "sess-1", [])

    assert await task_hosts_for(repo_root, "") == []
    assert await task_hosts_for(repo_root, "sess-1") == []


async def test_record_never_stores_anything_resembling_the_raw_prompt(tmp_path):
    # Redaction proof: only the caller-supplied HOST tokens land in the DB --
    # nothing about a hypothetical raw prompt (secrets, free text) leaks in
    # just because the row exists. (The extraction-time discipline that keeps
    # secret-shaped text OUT of `hosts` in the first place is proven
    # separately in test_task_tokens_extraction.py; this test proves the
    # storage layer itself persists exactly what it was given, nothing more.)
    repo_root = str(tmp_path)
    marker = "sk-distinctive-secret-marker-9f3a1c7e"
    await record_task_hosts(repo_root, "sess-1", ["stripe.com"])

    import sqlite3

    conn = sqlite3.connect(str(tmp_path / ".doberman" / "doberman.db"))
    try:
        rows = conn.execute("SELECT scope, host FROM session_task_hosts").fetchall()
    finally:
        conn.close()

    assert rows == [("sess-1", "stripe.com")]
    assert not any(marker in str(cell) for row in rows for cell in row)
