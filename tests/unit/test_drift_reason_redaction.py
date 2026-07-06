"""Issue #80 — the free-text ``reason`` on a policy-drift change must never carry a
secret into the append-only ledger or out to a registered :class:`DriftObserver`.

Covers ``_redact_reason`` directly (pass-through, truncation, fail-safe fallback) and
end-to-end through all three chokepoints (``apply_change``, ``apply_enforcement_change``,
``log_change``): a synthetic AWS-style key and a high-entropy token embedded in a
reason must never appear in a ledger row or an observer event.
"""

from datetime import datetime, timezone

from doberman.policy.drift import (
    _redact_reason,
    apply_change,
    apply_enforcement_change,
    log_change,
    read_policy_changes,
)

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)

# AWS docs' own canonical example access-key shape: AKIA + 16 chars — matches the
# STRONG credential pattern regardless of the "EXAMPLE" fixture marker (that marker
# only ever suppresses the WEAK entropy path, never a strong credential match).
_FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105
# 32 distinct characters -> ~5 bits/char Shannon entropy, comfortably above the
# high-entropy-secret threshold (3.6 bits/char) used by the weak-path heuristic.
_FAKE_HIGH_ENTROPY_TOKEN = "Zk9mQ2vL7bN4wJ8pR1sT6yC3dF0gH5xU"  # noqa: S105 — synthetic, not a real credential


class RecordingObserver:
    def __init__(self):
        self.events: list[dict] = []

    def on_change(self, event):
        self.events.append(event)


class _Decline:
    """Refuses every confirmation (used to exercise the softened/denied path)."""

    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover — never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


def _install_observer(monkeypatch) -> RecordingObserver:
    obs = RecordingObserver()
    monkeypatch.setattr("doberman.engine.registry.discover_drift_observers", lambda: [obs])
    return obs


# --- _redact_reason unit behavior -------------------------------------------


def test_redact_reason_scrubs_credential_and_high_entropy_matches():
    reason = f"rotating creds: {_FAKE_AWS_KEY} / {_FAKE_HIGH_ENTROPY_TOKEN}"
    scrubbed = _redact_reason(reason)
    assert _FAKE_AWS_KEY not in scrubbed
    assert _FAKE_HIGH_ENTROPY_TOKEN not in scrubbed
    assert "[redacted]" in scrubbed


def test_redact_reason_passes_through_normal_text_unchanged():
    reason = "tightening the block rule for CI"
    assert _redact_reason(reason) == reason


def test_redact_reason_truncates_over_cap():
    long_reason = "a" * 400
    scrubbed = _redact_reason(long_reason)
    assert scrubbed == "a" * 300 + "…"


def test_redact_reason_empty_string_passes_through():
    assert _redact_reason("") == ""


def test_redact_reason_failure_falls_back_to_placeholder(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("doberman.engine.rules.secrets._looks_high_entropy_secret", _boom)
    # Needs a >=24-char entropy-charset run to reach the patched function at all.
    reason = "leak attempt: " + "x" * 30
    assert _redact_reason(reason) == "[reason redaction failed]"


# --- end-to-end: ledger + observer never see the raw secret -----------------


async def test_apply_change_redacts_reason_for_ledger_and_observers(tmp_path, monkeypatch):
    obs = _install_observer(monkeypatch)
    reason = f"tightening after incident, leaked key was {_FAKE_AWS_KEY}"

    outcome = await apply_change(
        {"r": "auth"}, {"r": "block"}, reason, repo_root=str(tmp_path), now=_NOW
    )
    assert outcome.approved is True  # strengthen: auto-approved, no prompter needed

    rows = await read_policy_changes(str(tmp_path))
    assert rows and _FAKE_AWS_KEY not in str(rows)
    assert "[redacted]" in rows[0]["reason"]

    assert obs.events and _FAKE_AWS_KEY not in str(obs.events)
    assert "[redacted]" in obs.events[0]["reason"]


async def test_apply_enforcement_change_redacts_reason_for_ledger_and_observers(
    tmp_path, monkeypatch
):
    obs = _install_observer(monkeypatch)
    reason = f"softening enforcement, token={_FAKE_HIGH_ENTROPY_TOKEN}"

    outcome = await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "monitor"},
        reason,
        repo_root=str(tmp_path),
        prompter=_Decline(),
        now=_NOW,
    )
    assert outcome.approved is False  # denial is still recorded — the attack signal

    rows = await read_policy_changes(str(tmp_path))
    assert rows and _FAKE_HIGH_ENTROPY_TOKEN not in str(rows)
    assert "[redacted]" in rows[0]["reason"]

    assert obs.events and _FAKE_HIGH_ENTROPY_TOKEN not in str(obs.events)
    assert "[redacted]" in obs.events[0]["reason"]


async def test_log_change_redacts_reason_for_ledger_and_observers(tmp_path, monkeypatch):
    obs = _install_observer(monkeypatch)
    reason = f"relaxing for exploration, backup key {_FAKE_AWS_KEY}"

    outcome = await log_change(
        {"mode": "strict"}, {"mode": "light"}, reason, repo_root=str(tmp_path), now=_NOW
    )
    assert outcome.method == "logged"

    rows = await read_policy_changes(str(tmp_path))
    assert rows and _FAKE_AWS_KEY not in str(rows)
    assert "[redacted]" in rows[0]["reason"]

    assert obs.events and _FAKE_AWS_KEY not in str(obs.events)
    assert "[redacted]" in obs.events[0]["reason"]


async def test_apply_change_reason_redaction_failure_stores_placeholder(tmp_path, monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("doberman.engine.rules.secrets._looks_high_entropy_secret", _boom)
    reason = "leak attempt: " + "x" * 30

    outcome = await apply_change(
        {"r": "auth"}, {"r": "block"}, reason, repo_root=str(tmp_path), now=_NOW
    )
    assert outcome.approved is True  # redaction failure must not block the change

    rows = await read_policy_changes(str(tmp_path))
    assert rows[0]["reason"] == "[reason redaction failed]"
