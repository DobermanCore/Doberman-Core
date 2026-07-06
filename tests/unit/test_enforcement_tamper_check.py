"""Issue #81 — ledger-verified ``effective_enforcement`` (on-disk tamper defense).

Once the engine honors ``PolicyDoc.enforcement``, hand-editing
``.doberman/policies.yaml`` to ``enforcement: off`` would silently bypass the
``apply_enforcement_change`` gate. ``effective_enforcement`` is the read-side
clamp: a soften (``monitor``/``off``) is honored **only** when the append-only
ledger holds a matching APPROVED change for it — anything else fails closed to
``enforce`` and raises a redacted anomaly.

Security invariants asserted here: raise-only (never returns weaker than the
on-disk claim), fails closed on any mismatch/missing-ledger/DB error, the anomaly
emission never raises and never alters the return value, and the timer never
reverts to a weaker-than-current target. Ledger rows are written through the real
``apply_enforcement_change`` (fake prompters) so the string comparison is honest.
"""

from datetime import datetime, timezone

from doberman.policy.drift import apply_enforcement_change, effective_enforcement

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)  # ~1_767_225_600 epoch
_PAST = 1000.0  # long before _NOW
_FUTURE = 2_000_000_000.0  # 2033 — comfortably after _NOW


# --- fakes -----------------------------------------------------------------


class _Approve:
    """Present human who confirms (and supplies a code if 2FA is enrolled)."""

    def confirm(self, message):
        return True

    def read_code(self, message):
        return "999999"


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover — never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


class RecordingObserver:
    def __init__(self):
        self.events: list[dict] = []

    def on_change(self, event):
        self.events.append(event)


class ExplodingObserver:
    def on_change(self, event):
        raise RuntimeError("observer boom")


def _register(monkeypatch, *observers):
    monkeypatch.setattr(
        "doberman.engine.registry.discover_drift_observers", lambda: list(observers)
    )


# --- honored: a ledger-approved soften is trusted --------------------------


async def test_approved_soften_is_honored(tmp_path):
    # Real gate: enforce→monitor approved via confirm (no 2FA enrolled in tests).
    out = await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor"},
        "quiet hours",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )
    assert out.approved is True
    assert await effective_enforcement(str(tmp_path), enforcement="monitor", now=_NOW) == "monitor"


# --- clamped: tamper / no legitimizing ledger row --------------------------


async def test_hand_edit_without_ledger_row_is_clamped(tmp_path, monkeypatch):
    obs = RecordingObserver()
    _register(monkeypatch, obs)
    # Nothing ever went through the gate → the on-disk "off" is unbacked.
    assert await effective_enforcement(str(tmp_path), enforcement="off", now=_NOW) == "enforce"
    assert obs.events, "the tamper anomaly must reach registered observers"
    assert obs.events[0]["event"] == "enforcement_tamper_suspected"
    assert obs.events[0]["on_disk"] == "off"


async def test_denied_soften_only_is_clamped(tmp_path):
    # A declined attempt lands as approved=0; it must NOT legitimize the disk state.
    out = await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor"},
        "attempt",
        repo_root=str(tmp_path),
        prompter=_Decline(),
        now=_NOW,
    )
    assert out.approved is False
    assert await effective_enforcement(str(tmp_path), enforcement="monitor", now=_NOW) == "enforce"


async def test_state_mismatch_is_clamped(tmp_path):
    # Ledger approved "monitor" but the disk claims "off" — a mismatch is tampering.
    await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor"},
        "approved monitor",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )
    assert await effective_enforcement(str(tmp_path), enforcement="off", now=_NOW) == "enforce"


async def test_garbage_state_is_clamped_with_anomaly(tmp_path, monkeypatch):
    obs = RecordingObserver()
    _register(monkeypatch, obs)
    result = await effective_enforcement(str(tmp_path), enforcement="banana", now=_NOW)
    assert result == "enforce"
    assert obs.events[0]["event"] == "enforcement_tamper_suspected"
    assert obs.events[0]["on_disk"] == "banana"


async def test_hand_deleted_expiry_after_temporary_soften_is_clamped(tmp_path):
    # The gate approved "monitor until _PAST". Hand-deleting enforcement_expires_at
    # from the yaml would make the soften permanent — the expiry check is two-way.
    await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor", "enforcement_expires_at": _PAST},
        "temporary",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )
    assert await effective_enforcement(str(tmp_path), enforcement="monitor", now=_NOW) == "enforce"


async def test_gate_approved_expiry_clear_is_honored(tmp_path):
    # Clearing the expiry THROUGH the gate writes an approved "None" row — the
    # on-disk expiry-less soften is then legitimate, not a tamper.
    await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor", "enforcement_expires_at": _FUTURE},
        "temporary",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )
    await apply_enforcement_change(
        {"enforcement": "monitor", "enforcement_expires_at": _FUTURE},
        {"enforcement": "monitor", "enforcement_expires_at": None},
        "make permanent",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )
    assert await effective_enforcement(str(tmp_path), enforcement="monitor", now=_NOW) == "monitor"


# --- the common path stays free --------------------------------------------


async def test_enforce_returns_instantly_without_db(tmp_path):
    # "enforce" must resolve with zero I/O — a nonexistent repo_root can't raise.
    missing = str(tmp_path / "does-not-exist")
    assert await effective_enforcement(missing, enforcement="enforce") == "enforce"


# --- the auto-revert timer -------------------------------------------------


async def test_expired_soften_reverts_to_verified_revert(tmp_path):
    await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor", "enforcement_expires_at": _PAST},
        "temporary",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )
    result = await effective_enforcement(
        str(tmp_path), enforcement="monitor", expires_at=_PAST, revert="enforce", now=_NOW
    )
    assert result == "enforce"  # past the deadline → reverts


async def test_expired_soften_with_off_revert_is_clamped_up(tmp_path):
    # revert="off" is ledger-approved but weaker than the current state; on expiry it
    # must clamp UP to enforce, never down to off (raise-only).
    await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor", "enforcement_expires_at": _PAST, "enforcement_revert": "off"},
        "temporary with off revert",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )
    result = await effective_enforcement(
        str(tmp_path), enforcement="monitor", expires_at=_PAST, revert="off", now=_NOW
    )
    assert result == "enforce"


async def test_future_expiry_keeps_the_soften(tmp_path):
    await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor", "enforcement_expires_at": _FUTURE},
        "still active",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )
    result = await effective_enforcement(
        str(tmp_path), enforcement="monitor", expires_at=_FUTURE, revert="enforce", now=_NOW
    )
    assert result == "monitor"  # deadline not yet reached


# --- fail closed on infrastructure failure ---------------------------------


async def test_db_explosion_fails_closed(tmp_path, monkeypatch):
    # A real approved soften exists, but reading the ledger blows up → enforce, no raise.
    await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor"},
        "ok",
        repo_root=str(tmp_path),
        prompter=_Approve(),
        now=_NOW,
    )

    def _boom(*args, **kwargs):
        raise RuntimeError("db exploded")

    monkeypatch.setattr("doberman.policy.drift.open_db", _boom)
    assert await effective_enforcement(str(tmp_path), enforcement="monitor", now=_NOW) == "enforce"


async def test_observer_raising_during_anomaly_still_clamps(tmp_path, monkeypatch):
    # An observer that raises inside the tamper anomaly can't break the clamp.
    _register(monkeypatch, ExplodingObserver())
    assert await effective_enforcement(str(tmp_path), enforcement="off", now=_NOW) == "enforce"
