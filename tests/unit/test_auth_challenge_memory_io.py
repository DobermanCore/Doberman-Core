"""The sync approval-memory bridge is bounded: a storage call that never
answers falls back to no-memory (full-tier prompting) instead of hanging."""

from __future__ import annotations

import asyncio
import time

from doberman.auth import challenge


def test_memory_io_bridge_times_out_to_no_memory(monkeypatch):
    monkeypatch.setattr(challenge, "_MEMORY_IO_TIMEOUT_S", 0.05)

    async def _never():
        await asyncio.sleep(60)

    started = time.monotonic()
    assert challenge._run_memory_io(_never) is None
    assert time.monotonic() - started < 5


def test_memory_io_bridge_returns_a_prompt_answer():
    async def _hit():
        return "hit"

    assert challenge._run_memory_io(_hit) == "hit"
