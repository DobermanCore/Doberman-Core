"""Feature CB.1 — CostEvent model + local cost meter.

Covers the model's redaction-safe / non-negative / frozen guarantees, the
append-only ledger writes and aggregate reads, and the two safety invariants:
the meter is off the decision path (recording never touches ``decisions`` and
never raises) and a meter read never raises.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from doberman.models import CostEvent, CostKind
from doberman.storage.cost import read_breakdown, read_total, record_cost_event

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _event(
    units: int, *, kind: CostKind = CostKind.tokens_in, entity_id: str | None = "e1"
) -> CostEvent:
    return CostEvent(action_id="a1", ts=_NOW, kind=kind, units=units, entity_id=entity_id)


# ---- model guarantees -------------------------------------------------------


def test_units_cannot_be_negative():
    with pytest.raises(ValidationError):
        CostEvent(action_id="a1", ts=_NOW, units=-1)


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        CostEvent(action_id="a1", ts=datetime(2026, 1, 1, 12, 0))  # no tzinfo


def test_event_is_frozen():
    ev = _event(10)
    with pytest.raises(ValidationError):
        ev.units = 99  # type: ignore[misc]


def test_model_has_no_payload_bearing_field():
    # Redaction by construction: the schema exposes counts + coarse classes only.
    forbidden = {"content", "prompt", "response", "payload", "text", "target", "raw_args"}
    assert set(CostEvent.model_fields) & forbidden == set()


def test_model_fields_are_an_exact_scalar_allowlist():
    """Ratchet: CostEvent may carry ONLY these scalar fields.

    A free-form mapping (e.g. ``metadata: dict[str, Any]``) passes the
    forbidden-name check above yet can hold arbitrary payload in memory and
    would leak if ever logged/serialized — exactly the redaction-safe-by-
    construction hole flagged in review. Pinning the exact field set means any
    new field — especially a payload-capable one — fails CI until it is added
    here deliberately (with justification), never slips in silently.
    """
    assert set(CostEvent.model_fields) == {"action_id", "ts", "kind", "units", "model", "entity_id"}


# ---- ledger writes + aggregate reads ---------------------------------------


async def test_record_then_total(tmp_path):
    root = str(tmp_path)
    await record_cost_event(_event(100), repo_root=root)
    await record_cost_event(_event(50, kind=CostKind.tokens_out), repo_root=root)
    assert await read_total(root) == 150


async def test_total_scopes_by_entity_and_kind(tmp_path):
    root = str(tmp_path)
    await record_cost_event(_event(100, entity_id="e1"), repo_root=root)
    await record_cost_event(_event(40, entity_id="e2"), repo_root=root)
    await record_cost_event(_event(7, kind=CostKind.tool_call, entity_id="e1"), repo_root=root)
    assert await read_total(root, entity_id="e1") == 107
    assert await read_total(root, kind=CostKind.tokens_in) == 140
    assert await read_total(root, entity_id="e1", kind=CostKind.tool_call) == 7


async def test_breakdown_groups_by_kind(tmp_path):
    root = str(tmp_path)
    await record_cost_event(_event(100, kind=CostKind.tokens_in), repo_root=root)
    await record_cost_event(_event(30, kind=CostKind.tokens_out), repo_root=root)
    await record_cost_event(_event(2, kind=CostKind.tool_call), repo_root=root)
    assert await read_breakdown(root) == {
        CostKind.tokens_in: 100,
        CostKind.tokens_out: 30,
        CostKind.tool_call: 2,
    }


async def test_total_on_empty_ledger_is_zero(tmp_path):
    assert await read_total(str(tmp_path)) == 0


# ---- safety invariants ------------------------------------------------------


async def test_recording_cost_does_not_touch_decisions_table(tmp_path):
    from doberman.storage.db import open_db

    root = str(tmp_path)
    await record_cost_event(_event(100), repo_root=root)
    async with open_db(root) as conn:
        async with conn.execute("SELECT COUNT(*) FROM decisions") as cur:
            decisions = (await cur.fetchone())[0]
        async with conn.execute("SELECT COUNT(*) FROM cost_events") as cur:
            costs = (await cur.fetchone())[0]
    assert decisions == 0  # cost observability never writes a verdict
    assert costs == 1


async def test_record_never_raises_on_unwritable_root(tmp_path):
    # A regular file where the repo root should be makes open_db's mkdir fail;
    # the meter must swallow it (off the decision path → never break execution).
    bad = tmp_path / "not_a_dir"
    bad.write_text("x")
    await record_cost_event(_event(100), repo_root=str(bad))  # must not raise


async def test_read_never_raises_on_unwritable_root(tmp_path):
    bad = tmp_path / "not_a_dir"
    bad.write_text("x")
    assert await read_total(str(bad)) == 0
    assert await read_breakdown(str(bad)) == {}
