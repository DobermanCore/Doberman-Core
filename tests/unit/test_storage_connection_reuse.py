"""Connection ownership invariants for the local SQLite store."""

import asyncio
import contextvars

from doberman.auth.challenge import _run_with_deadline
from doberman.storage.db import open_db


async def test_nested_same_repo_reuses_connection_and_restores_outer_scope(tmp_path):
    async with open_db(str(tmp_path / "one")) as outer:
        async with open_db(str(tmp_path / "one")) as nested:
            assert nested is outer

        async with open_db(str(tmp_path / "two")) as other_repo:
            assert other_repo is not outer

        async with open_db(str(tmp_path / "one")) as restored:
            assert restored is outer


async def test_concurrent_top_level_scopes_do_not_share_connections(tmp_path):
    ready = asyncio.Event()
    both_open = asyncio.Event()
    connections = []

    async def hold_connection():
        async with open_db(str(tmp_path)) as conn:
            connections.append(conn)
            if len(connections) == 2:
                both_open.set()
            ready.set()
            await both_open.wait()

    first = asyncio.create_task(hold_connection())
    await ready.wait()
    second = asyncio.create_task(hold_connection())
    await asyncio.gather(first, second)

    assert len(connections) == 2
    assert connections[0] is not connections[1]


async def test_auth_challenge_worker_uses_its_own_loop_connection(tmp_path):
    async with open_db(str(tmp_path)) as outer:

        async def approval_query():
            async with open_db(str(tmp_path)) as worker_connection:
                assert worker_connection is not outer
                cursor = await worker_connection.execute("SELECT 1")
                assert await cursor.fetchone() == (1,)

        await asyncio.to_thread(
            _run_with_deadline,
            lambda: asyncio.run(approval_query()),
            timeout_s=5,
            on_timeout=lambda: (_ for _ in ()).throw(AssertionError("worker timed out")),
            label="connection-test",
        )
        async with open_db(str(tmp_path)) as restored:
            assert restored is outer


async def test_copied_context_outliving_outer_connection_opens_fresh(tmp_path):
    async with open_db(str(tmp_path)) as outer:
        copied = contextvars.copy_context()

    async def late_query():
        async with open_db(str(tmp_path)) as connection:
            assert connection is not outer
            cursor = await connection.execute("SELECT 1")
            assert await cursor.fetchone() == (1,)

    await asyncio.to_thread(copied.run, asyncio.run, late_query())
