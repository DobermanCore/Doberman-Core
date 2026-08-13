"""Feature CB.3 — loop-anomaly detector over the cost ledger.

Covers:
* empty ledger / calm window -> no anomaly
* a call burst over the window threshold -> ``call_burst``
* a token burst over the window threshold -> ``token_burst``
* events outside the rolling window are ignored
* the exact threshold boundary (calls == max_calls is NOT an anomaly)
* per-entity scoping: one entity's burst never flags another
* the readout is advisory (never a verdict) and fail-safe: a broken DB, a naive
  ``now``, and a legacy naive-timestamp row all report calm and never raise
* the explanation is redaction-safe: counts/classes only, no raw entity id
"""

from datetime import datetime, timedelta, timezone

from doberman.models import CostEvent, CostKind
from doberman.storage.cost import (
    LoopAnomaly,
    detect_loop_anomaly,
    record_cost_event,
)
from doberman.storage.db import open_db

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _event(units: int, *, ts: datetime, kind: CostKind = CostKind.tool_call, entity_id="e1"):
    return CostEvent(action_id="a1", ts=ts, kind=kind, units=units, entity_id=entity_id)


async def _seed(root, events):
    for ev in events:
        await record_cost_event(ev, repo_root=root)


# --- empty / calm ------------------------------------------------------------


async def test_empty_ledger_is_calm(tmp_path):
    result = await detect_loop_anomaly(str(tmp_path), entity_id="e1", now=_NOW)
    assert isinstance(result, LoopAnomaly)
    assert result.is_anomaly is False
    assert result.signal == ""
    assert result.calls == 0 and result.units == 0


async def test_activity_below_threshold_is_calm(tmp_path):
    root = str(tmp_path)
    await _seed(root, [_event(10, ts=_NOW - timedelta(seconds=i)) for i in range(5)])
    result = await detect_loop_anomaly(root, entity_id="e1", now=_NOW, max_calls=40)
    assert result.is_anomaly is False
    assert result.calls == 5


# --- call burst --------------------------------------------------------------


async def test_call_burst_over_threshold_flags(tmp_path):
    root = str(tmp_path)
    # 30 events inside a 60s window, threshold 20 -> call_burst.
    await _seed(root, [_event(1, ts=_NOW - timedelta(seconds=i % 60)) for i in range(30)])
    result = await detect_loop_anomaly(root, entity_id="e1", now=_NOW, max_calls=20)
    assert result.is_anomaly is True
    assert result.signal == "call_burst"
    assert result.calls == 30


# --- exact threshold boundary ------------------------------------------------


async def test_exact_threshold_is_not_an_anomaly(tmp_path):
    root = str(tmp_path)
    # calls == max_calls must NOT flag: the predicate is strictly ``> max_calls``.
    await _seed(root, [_event(1, ts=_NOW - timedelta(seconds=i % 60)) for i in range(20)])
    at_limit = await detect_loop_anomaly(root, entity_id="e1", now=_NOW, max_calls=20)
    assert at_limit.calls == 20
    assert at_limit.is_anomaly is False

    # One more event crosses it.
    await _seed(root, [_event(1, ts=_NOW)])
    over = await detect_loop_anomaly(root, entity_id="e1", now=_NOW, max_calls=20)
    assert over.calls == 21
    assert over.is_anomaly is True
    assert over.signal == "call_burst"


# --- token burst -------------------------------------------------------------


async def test_token_burst_over_threshold_flags(tmp_path):
    root = str(tmp_path)
    # Few calls, but huge token burn -> token_burst (not a call burst).
    await _seed(
        root,
        [_event(50_000, ts=_NOW - timedelta(seconds=i), kind=CostKind.tokens_in) for i in range(4)],
    )
    result = await detect_loop_anomaly(
        root, entity_id="e1", now=_NOW, max_calls=40, max_units=100_000
    )
    assert result.is_anomaly is True
    assert result.signal == "token_burst"
    assert result.units == 200_000
    assert result.calls == 0  # token rows are not tool calls


async def test_call_burst_takes_precedence_over_token_burst(tmp_path):
    root = str(tmp_path)
    # Genuinely cross BOTH thresholds: 30 tool calls (> max_calls) AND 200k tokens
    # (> max_units). The label must be the call burst.
    await _seed(root, [_event(1, ts=_NOW - timedelta(seconds=i % 30)) for i in range(30)])
    await _seed(
        root,
        [
            _event(10_000, ts=_NOW - timedelta(seconds=i % 30), kind=CostKind.tokens_in)
            for i in range(20)
        ],
    )
    result = await detect_loop_anomaly(
        root, entity_id="e1", now=_NOW, max_calls=20, max_units=100_000
    )
    assert result.is_anomaly is True
    assert result.signal == "call_burst"
    assert result.calls == 30
    assert result.units == 200_000


# --- signal calibration: which kinds feed which signal -----------------------


async def test_token_kinds_do_not_count_as_tool_calls(tmp_path):
    root = str(tmp_path)
    # 30 token rows, but zero tool calls -> no call_burst (calls stays 0).
    await _seed(
        root,
        [
            _event(1, ts=_NOW - timedelta(seconds=i % 60), kind=CostKind.tokens_in)
            for i in range(30)
        ],
    )
    result = await detect_loop_anomaly(
        root, entity_id="e1", now=_NOW, max_calls=20, max_units=10_000_000
    )
    assert result.calls == 0
    assert result.is_anomaly is False


async def test_tool_call_units_do_not_count_as_token_burn(tmp_path):
    root = str(tmp_path)
    # tool_call rows carrying large `units` must NOT be summed as token burn.
    await _seed(root, [_event(50_000, ts=_NOW - timedelta(seconds=i)) for i in range(4)])
    result = await detect_loop_anomaly(
        root, entity_id="e1", now=_NOW, max_calls=40, max_units=100_000
    )
    assert result.units == 0  # tool_call units are not token units
    assert result.is_anomaly is False


async def test_now_defaults_to_current_utc_time(tmp_path):
    # Omitting `now` must not raise (default = current UTC). Rows dated far in the
    # past fall outside the default window -> calm, no exception.
    root = str(tmp_path)
    await _seed(root, [_event(1, ts=_NOW - timedelta(days=365)) for _ in range(30)])
    result = await detect_loop_anomaly(root, entity_id="e1", max_calls=20)
    assert isinstance(result, LoopAnomaly)
    assert result.is_anomaly is False


# --- window boundary ---------------------------------------------------------


async def test_events_outside_window_are_ignored(tmp_path):
    root = str(tmp_path)
    # 30 events, but all older than the 60s window -> calm.
    await _seed(root, [_event(1, ts=_NOW - timedelta(seconds=300 + i)) for i in range(30)])
    result = await detect_loop_anomaly(
        root, entity_id="e1", now=_NOW, window_seconds=60, max_calls=20
    )
    assert result.is_anomaly is False
    assert result.calls == 0


async def test_future_events_are_ignored(tmp_path):
    root = str(tmp_path)
    await _seed(root, [_event(1, ts=_NOW + timedelta(seconds=10 + i)) for i in range(30)])
    result = await detect_loop_anomaly(root, entity_id="e1", now=_NOW, max_calls=20)
    assert result.is_anomaly is False
    assert result.calls == 0


async def test_nonpositive_window_is_calm(tmp_path):
    root = str(tmp_path)
    await _seed(root, [_event(1, ts=_NOW) for _ in range(30)])
    result = await detect_loop_anomaly(root, entity_id="e1", now=_NOW, window_seconds=0)
    assert result.is_anomaly is False


# --- per-entity scoping ------------------------------------------------------


async def test_burst_is_scoped_to_its_entity(tmp_path):
    root = str(tmp_path)
    await _seed(
        root, [_event(1, ts=_NOW - timedelta(seconds=i % 60), entity_id="e1") for i in range(30)]
    )
    # e2 did nothing; its readout is calm even though e1 is bursting.
    result = await detect_loop_anomaly(root, entity_id="e2", now=_NOW, max_calls=20)
    assert result.is_anomaly is False
    assert result.calls == 0
    # e1's own readout flags.
    hot = await detect_loop_anomaly(root, entity_id="e1", now=_NOW, max_calls=20)
    assert hot.is_anomaly is True


# --- advisory + fail-safe ----------------------------------------------------


def test_loop_anomaly_is_not_a_verdict():
    # Structural guard: the advisory readout carries no verdict/risk field, so it
    # cannot be mistaken for (or wired into) a decision.
    fields = LoopAnomaly.__dataclass_fields__
    assert "verdict" not in fields and "risk" not in fields


async def test_broken_db_reports_calm_and_never_raises(tmp_path, monkeypatch):
    import doberman.storage.cost as cost_mod

    def _boom(*args, **kwargs):
        raise OSError("disk gone")

    monkeypatch.setattr(cost_mod, "open_db", _boom)
    result = await detect_loop_anomaly(str(tmp_path), entity_id="e1", now=_NOW)
    assert result.is_anomaly is False
    assert result.signal == ""


async def test_naive_now_reports_calm_and_never_raises(tmp_path):
    # A caller passing a bare (tz-naive) datetime.now() must not trigger a
    # TypeError against the ledger's aware timestamps — it reports calm instead.
    root = str(tmp_path)
    await _seed(root, [_event(1, ts=_NOW - timedelta(seconds=i % 60)) for i in range(30)])
    naive_now = datetime(2026, 1, 1, 12, 0)  # no tzinfo
    result = await detect_loop_anomaly(root, entity_id="e1", now=naive_now, max_calls=20)
    assert result.is_anomaly is False
    assert result.calls == 0


async def test_legacy_naive_row_is_skipped_not_raised(tmp_path):
    # A hand-written / pre-migration row with a NAIVE iso timestamp must not crash
    # the readout (aware-vs-naive comparison would TypeError). It is skipped.
    root = str(tmp_path)
    # A valid, in-window aware row so there is something to count.
    await _seed(root, [_event(1, ts=_NOW)])
    # Inject a naive-timestamp row directly, bypassing the aware-only model.
    async with open_db(root) as conn:
        await conn.execute(
            "INSERT INTO cost_events (ts, action_id, kind, units, model, entity_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("2026-01-01T12:00:00", "legacy", CostKind.tool_call.value, 1, None, "e1"),
        )
        await conn.commit()
    result = await detect_loop_anomaly(root, entity_id="e1", now=_NOW, max_calls=0)
    # Did not raise; the naive row was skipped, only the one aware row counted.
    assert result.calls == 1


# --- redaction ---------------------------------------------------------------


async def test_explanation_is_redaction_safe(tmp_path):
    root = str(tmp_path)
    distinctive = "hmac:super-distinctive-entity-fingerprint"
    await _seed(
        root,
        [_event(1, ts=_NOW - timedelta(seconds=i % 60), entity_id=distinctive) for i in range(30)],
    )
    result = await detect_loop_anomaly(root, entity_id=distinctive, now=_NOW, max_calls=20)
    assert result.is_anomaly is True
    # The raw entity fingerprint never appears in the human explanation.
    assert "super-distinctive-entity-fingerprint" not in result.explanation
    assert distinctive not in result.explanation
