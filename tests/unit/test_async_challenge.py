"""Tests for the non-blocking async auth-challenge mechanism (issue #144).

Contracts under test
--------------------
* :func:`issue_challenge` selects the correct tier and returns a
  :class:`ChallengeHandle` without blocking; the handle is action-bound and
  carries an expiry timestamp.
* :func:`resolve_challenge` records a human decision exactly once (single-use,
  race-safe); a second resolve returns the FIRST result unchanged.
* Expiry: a handle past its ``expires_at`` resolves to a non-approved result
  tagged ``ASYNC_TIMEOUT_METHOD`` even when ``approved=True`` is passed.
* Tier enforcement: ``two_factor`` and ``role_elevation`` tiers require a TOTP
  code; omitting it denies (fail closed) regardless of the ``approved`` flag.
* TOTP path: a valid code on a two-factor handle approves; an invalid code
  denies (fail closed).
* Fail-closed: :func:`issue_challenge` raises ``ValueError`` when ``decision``
  is not an ``AUTH`` (mirrors :func:`select_tier`).
* Action-ID binding: :func:`resolve_challenge` raises ``ValueError`` when the
  handle's stored ``action_id`` does not match the record (tamper protection).
* :meth:`ChallengeHandle.wait` blocks until resolved and returns the result.
* :meth:`ChallengeHandle.wait` with a short timeout returns a synthesised
  timeout result without marking the handle resolved.
* :meth:`InMemoryAsyncBackend.expire_stale` settles unresolved expired handles
  and returns an accurate count; already-resolved handles are left untouched.
* The ``active_async_backend`` registry falls back to the built-in in-memory
  backend when no entry-point is installed.
* A registered custom backend is preferred over the built-in (registry seam).
* A non-backend-shaped registration is skipped (defensive loading).
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from doberman.auth import totp as totp_mod
from doberman.auth.async_challenge import (
    ASYNC_DENIED_METHOD,
    ASYNC_TIMEOUT_METHOD,
    ChallengeHandle,
    InMemoryAsyncBackend,
    active_async_backend,
    issue_challenge,
    resolve_challenge,
)
from doberman.auth.challenge import AuthTier
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 7, 22, 12, 0, 0, tzinfo=timezone.utc)


def _action(action_id: str = "act-async-1", target: str = "src/main.py") -> SecurityObject:
    return SecurityObject(
        id=action_id,
        ts=_NOW,
        agent_role="dev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=target,
    )


def _auth_decision(
    action_id: str = "act-async-1",
    risk: Risk = Risk.medium,
    reasons: tuple[ReasonCode, ...] = (ReasonCode.sensitive_path_access,),
) -> Decision:
    gr = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=risk,
        reason_codes=list(reasons),
        explanation="test",
    )
    return Decision(
        action_id=action_id,
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=gr,
        reason_codes=list(reasons),
        explanation="test",
        decided_at=_NOW,
    )


def _pass_decision(action_id: str = "act-pass") -> Decision:
    gr = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low, reason_codes=[], explanation="ok")
    return Decision(
        action_id=action_id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=gr,
        reason_codes=[],
        explanation="ok",
        decided_at=_NOW,
    )


@pytest.fixture
def backend() -> InMemoryAsyncBackend:
    return InMemoryAsyncBackend()


# ---------------------------------------------------------------------------
# issue_challenge — basic contracts
# ---------------------------------------------------------------------------


def test_issue_returns_handle_without_blocking(backend):
    """issue_challenge must return immediately — no waiting for human input."""
    handle = issue_challenge(_auth_decision(), _action(), backend=backend)
    assert isinstance(handle, ChallengeHandle)
    assert handle.action_id == "act-async-1"
    assert not handle.is_resolved
    assert not handle.is_expired


def test_issue_selects_tier_from_decision(backend):
    """The tier must come from select_tier(), not be hardcoded."""
    # sensitive_path_access floors at local_auth (medium risk)
    h = issue_challenge(
        _auth_decision(reasons=(ReasonCode.sensitive_path_access,), risk=Risk.medium),
        _action(),
        backend=backend,
    )
    assert h.tier is AuthTier.local_auth

    # policy_source_sensitive floors at two_factor
    h2 = issue_challenge(
        _auth_decision(
            action_id="act-2",
            reasons=(ReasonCode.policy_source_sensitive,),
            risk=Risk.medium,
        ),
        _action(action_id="act-2"),
        backend=backend,
    )
    assert h2.tier is AuthTier.two_factor


def test_issue_raises_for_non_auth_decision(backend):
    """A PASS/BLOCK decision is not a challenge — fail loudly (matches select_tier)."""
    with pytest.raises(ValueError):
        issue_challenge(_pass_decision(), _action(action_id="act-pass"), backend=backend)


def test_issue_sets_expiry_ttl(backend):
    """expires_at should be approximately issued_at + ttl_s."""
    ttl = 300.0
    handle = issue_challenge(_auth_decision(), _action(), ttl_s=ttl, at=_NOW, backend=backend)
    expected_expiry = _NOW + timedelta(seconds=ttl)
    assert handle.expires_at == expected_expiry


def test_handle_id_is_unique_per_call(backend):
    """Two calls on the same action must yield distinct handle IDs."""
    h1 = issue_challenge(_auth_decision(), _action(), backend=backend)
    h2 = issue_challenge(_auth_decision(), _action(), backend=backend)
    assert h1.handle_id != h2.handle_id


# ---------------------------------------------------------------------------
# resolve_challenge — approval path
# ---------------------------------------------------------------------------


def test_resolve_approves_soft_confirm_tier(backend):
    # Risk.low with a reason that carries no tier floor → soft_confirm
    handle = issue_challenge(
        _auth_decision(reasons=(ReasonCode.unknown_tool,), risk=Risk.low),
        _action(),
        backend=backend,
    )
    assert handle.tier is AuthTier.soft_confirm
    result = resolve_challenge(handle, approved=True, backend=backend)
    assert result.approved is True
    assert result.action_id == "act-async-1"
    assert result.method == AuthTier.soft_confirm.value


def test_resolve_denies_when_approved_false(backend):
    handle = issue_challenge(_auth_decision(), _action(), backend=backend)
    result = resolve_challenge(handle, approved=False, backend=backend)
    assert result.approved is False
    assert result.method == ASYNC_DENIED_METHOD


def test_resolve_is_single_use(backend):
    """A second resolve must return the FIRST result unchanged."""
    handle = issue_challenge(
        _auth_decision(reasons=(ReasonCode.sensitive_path_access,), risk=Risk.low),
        _action(),
        backend=backend,
    )
    first = resolve_challenge(handle, approved=True, backend=backend)
    second = resolve_challenge(handle, approved=False, backend=backend)  # tries to deny
    assert second.approved is True  # first answer wins
    assert second.method == first.method


def test_resolve_marks_handle_as_resolved(backend):
    handle = issue_challenge(_auth_decision(), _action(), backend=backend)
    assert not handle.is_resolved
    resolve_challenge(handle, approved=False, backend=backend)
    assert handle.is_resolved


def test_resolve_unknown_handle_raises(backend):
    """A handle that was never issued must never approve (fail closed)."""
    orphan = ChallengeHandle(
        handle_id="not-a-real-id",
        action_id="act-async-1",
        tier=AuthTier.local_auth,
        issued_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )
    with pytest.raises(KeyError):
        backend.resolve(orphan, approved=True)


def test_resolve_wrong_action_id_raises(backend):
    """Tamper protection: a mismatched action_id must raise (fail closed)."""
    handle = issue_challenge(_auth_decision(), _action(), backend=backend)
    tampered = ChallengeHandle(
        handle_id=handle.handle_id,
        action_id="totally-different-action",  # ← mismatch
        tier=handle.tier,
        issued_at=handle.issued_at,
        expires_at=handle.expires_at,
    )
    with pytest.raises(ValueError, match="act-async-1"):
        backend.resolve(tampered, approved=True)


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


def test_expired_handle_denies_on_resolve(backend):
    """Resolving a handle after its expiry yields a non-approved timeout result."""
    handle = issue_challenge(_auth_decision(), _action(), ttl_s=0.0, at=_NOW, backend=backend)
    # expires_at == issued_at, so it's already expired
    result = backend.resolve(handle, approved=True, at=_NOW + timedelta(seconds=1))
    assert result.approved is False
    assert result.method == ASYNC_TIMEOUT_METHOD
    assert result.action_id == "act-async-1"


def test_is_expired_property(backend):
    past = _NOW - timedelta(hours=1)
    handle = issue_challenge(_auth_decision(), _action(), ttl_s=0.0, at=past, backend=backend)
    assert handle.is_expired


# ---------------------------------------------------------------------------
# TOTP / two-factor tier
# ---------------------------------------------------------------------------


def test_two_factor_requires_code_approves_with_valid_code(backend):
    totp_mod.enroll()
    secret = totp_mod._read_secret()
    valid_code = pyotp.TOTP(secret).now()

    handle = issue_challenge(
        _auth_decision(
            reasons=(ReasonCode.policy_source_sensitive,),
            risk=Risk.medium,
        ),
        _action(),
        backend=backend,
    )
    assert handle.tier is AuthTier.two_factor

    result = resolve_challenge(handle, approved=True, totp_code=valid_code, backend=backend)
    assert result.approved is True
    assert result.method == "totp"


def test_two_factor_denies_with_invalid_code(backend):
    totp_mod.enroll()
    handle = issue_challenge(
        _auth_decision(
            reasons=(ReasonCode.policy_source_sensitive,),
            risk=Risk.medium,
        ),
        _action(),
        backend=backend,
    )
    result = resolve_challenge(handle, approved=True, totp_code="000000", backend=backend)
    assert result.approved is False


def test_two_factor_denies_when_no_code_supplied(backend):
    """Missing TOTP code on a 2FA tier must deny (fail closed)."""
    handle = issue_challenge(
        _auth_decision(
            reasons=(ReasonCode.policy_source_sensitive,),
            risk=Risk.medium,
        ),
        _action(),
        backend=backend,
    )
    result = resolve_challenge(handle, approved=True, totp_code=None, backend=backend)
    assert result.approved is False
    assert result.method == "denied_no_code"


# ---------------------------------------------------------------------------
# ChallengeHandle.wait()
# ---------------------------------------------------------------------------


def test_wait_blocks_until_resolved(backend):
    """wait() must return the result once resolve_challenge() is called."""
    handle = issue_challenge(_auth_decision(), _action(), backend=backend)

    def _resolver():
        time.sleep(0.05)
        resolve_challenge(handle, approved=False, backend=backend)

    t = threading.Thread(target=_resolver, daemon=True)
    t.start()
    result = handle.wait(timeout=5.0)
    t.join(timeout=5.0)
    assert result.approved is False


def test_wait_short_timeout_returns_synthetic_timeout(backend):
    """wait() with a very short timeout must return a non-approved result WITHOUT
    marking the handle as resolved — a concurrent resolver can still settle it."""
    handle = issue_challenge(_auth_decision(), _action(), backend=backend)
    result = handle.wait(timeout=0.01)
    assert result.approved is False
    assert result.method == ASYNC_TIMEOUT_METHOD
    # Handle is NOT marked resolved — a real human could still answer later.
    assert not handle.is_resolved


def test_wait_returns_immediately_if_already_resolved(backend):
    handle = issue_challenge(_auth_decision(), _action(), backend=backend)
    resolve_challenge(handle, approved=False, backend=backend)
    result = handle.wait(timeout=0.0)
    assert result.approved is False
    assert result.method == ASYNC_DENIED_METHOD


# ---------------------------------------------------------------------------
# expire_stale
# ---------------------------------------------------------------------------


def test_expire_stale_settles_unresolved_expired_handles(backend):
    past = _NOW - timedelta(hours=2)
    h1 = issue_challenge(_auth_decision(), _action("a1"), ttl_s=0.0, at=past, backend=backend)
    h2 = issue_challenge(
        _auth_decision(action_id="a2"), _action("a2"), ttl_s=0.0, at=past, backend=backend
    )
    count = backend.expire_stale(now=_NOW)
    assert count == 2
    assert h1.is_resolved
    assert h2.is_resolved
    assert h1.result is not None and h1.result.method == ASYNC_TIMEOUT_METHOD
    assert h2.result is not None and h2.result.method == ASYNC_TIMEOUT_METHOD


def test_expire_stale_leaves_resolved_handles_untouched(backend):
    # Issue a live handle with a generous TTL, resolve it (human denies),
    # then confirm expire_stale does not touch it.
    handle = issue_challenge(_auth_decision(), _action(), ttl_s=3600.0, backend=backend)
    resolve_challenge(handle, approved=False, backend=backend)
    assert handle.is_resolved
    first_result = handle.result

    count = backend.expire_stale()
    assert count == 0  # already-resolved handles are never re-settled
    assert handle.result is first_result  # original result object is unchanged
    assert handle.result.method == ASYNC_DENIED_METHOD


def test_expire_stale_ignores_unexpired_handles(backend):
    handle = issue_challenge(_auth_decision(), _action(), ttl_s=3600.0, backend=backend)
    count = backend.expire_stale()
    assert count == 0
    assert not handle.is_resolved


# ---------------------------------------------------------------------------
# Race-safety: concurrent resolvers
# ---------------------------------------------------------------------------


def test_concurrent_resolvers_only_one_wins(backend):
    """Two threads simultaneously resolving the same handle: exactly one wins,
    both receive the same (winning) result."""
    handle = issue_challenge(
        _auth_decision(reasons=(ReasonCode.sensitive_path_access,), risk=Risk.low),
        _action(),
        backend=backend,
    )
    results: list = []
    barrier = threading.Barrier(2)

    def _resolve(approved: bool) -> None:
        barrier.wait()
        results.append(resolve_challenge(handle, approved=approved, backend=backend))

    t1 = threading.Thread(target=_resolve, args=(True,), daemon=True)
    t2 = threading.Thread(target=_resolve, args=(False,), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert len(results) == 2
    # Both results must be identical (the first-writer-wins value).
    assert results[0].approved == results[1].approved
    assert results[0].method == results[1].method


# ---------------------------------------------------------------------------
# Registry / active_async_backend
# ---------------------------------------------------------------------------


def test_default_backend_is_in_memory():
    """With no entry-points installed, the built-in in-memory backend is used."""
    from doberman.auth.async_challenge import IN_MEMORY_BACKEND

    assert active_async_backend() is IN_MEMORY_BACKEND


def test_registered_backend_is_preferred(monkeypatch):
    """A registered custom backend shadows the built-in."""

    class StubBackend:
        name = "stub"
        sentinel = object()

        def issue(self, decision, action, tier, *, ttl_s, at=None):
            return self.sentinel

        def resolve(self, handle, *, approved, totp_code=None, at=None):
            return self.sentinel

        def expire_stale(self, *, now=None):
            return 0

    stub = StubBackend()
    monkeypatch.setattr(
        "doberman.engine.registry._iter_entry_points",
        lambda group: [_FakeEntryPoint(stub)],
    )
    from doberman.auth import async_challenge as ac

    assert ac.active_async_backend() is stub


def test_non_backend_shaped_registration_is_skipped(monkeypatch):
    """An object missing 'issue'/'resolve' must be skipped; fallback to built-in."""
    monkeypatch.setattr(
        "doberman.engine.registry._iter_entry_points",
        lambda group: [_FakeEntryPoint(object())],
    )
    from doberman.auth.async_challenge import IN_MEMORY_BACKEND

    assert active_async_backend() is IN_MEMORY_BACKEND


# ---------------------------------------------------------------------------
# Helpers for registry tests
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    """A minimal importlib.metadata EntryPoint stand-in that returns a fixed object.

    ``_load_and_construct`` calls ``entry_point.load()``.  If the result is a
    class, it instantiates it.  If the result is already an instance, it uses it
    directly.  We return the instance directly so we can pin the identity.
    """

    name = "fake"

    def __init__(self, obj):
        self._obj = obj

    def load(self):
        # Return the instance directly (not the class) so _load_and_construct
        # uses it as-is without constructing a new one.
        return self._obj
