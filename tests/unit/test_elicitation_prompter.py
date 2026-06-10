"""Unit tests for the MCP elicitation prompter — the challenge rendered IN the agent client.

When the agent client (Claude Code, etc.) supports MCP elicitation, a confirm-tier AUTH
challenge should render natively inside the client UI instead of an OS dialog. Contracts:

* ``accept`` approves; ``decline``/``cancel`` deny — and a denial is FINAL (the chain
  must never re-ask on another channel).
* A client without the elicitation capability, no active request context, or a
  method-not-found error → :class:`PrompterUnavailableError` (fall through to the GUI).
* ``read_code`` ALWAYS raises ``PrompterUnavailableError``: the MCP spec forbids
  requesting sensitive information via elicitation, so one-time codes never transit
  the agent client — they stay on the out-of-band channels.
* The prompter must refuse to run on the event-loop thread (it would deadlock the
  session that has to carry the elicitation answer), and the executor must therefore
  run challenges OFF the loop.
* No schema fields are requested (buttons only) — no data transits the client.
"""

import asyncio
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from mcp import types
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, METHOD_NOT_FOUND, ErrorData

from doberman.auth import elicitation_prompter as ep_mod
from doberman.auth.elicitation_prompter import ElicitationPrompter
from doberman.auth.gui_prompter import FallbackPrompter, PrompterUnavailableError

_CHALLENGE = "Doberman authentication required [local_auth]\nApprove THIS exact action?"


class _FakeSession:
    """Scripted ServerSession stand-in; records the elicitation traffic."""

    def __init__(self, *, supports=True, action="accept", error=None, hang=False):
        self._supports = supports
        self._action = action
        self._error = error
        self._hang = hang
        self.messages: list[str] = []
        self.schemas: list[dict] = []

    def check_client_capability(self, capability) -> bool:
        assert capability.elicitation is not None  # we must ask for the right capability
        return self._supports

    async def elicit_form(self, message, requestedSchema, related_request_id=None):
        self.messages.append(message)
        self.schemas.append(requestedSchema)
        if self._hang:
            await asyncio.Event().wait()
        if self._error is not None:
            raise self._error
        return types.ElicitResult(action=self._action)


class _FakeServer:
    """Exposes ``request_context.session`` the way ``mcp.server.lowlevel.Server`` does."""

    def __init__(self, session: _FakeSession | None):
        self._session = session

    @property
    def request_context(self):
        if self._session is None:
            raise LookupError("called outside of a request context")
        return SimpleNamespace(session=self._session)


@pytest.fixture
def loop() -> Iterator[asyncio.AbstractEventLoop]:
    """A real event loop on a background thread — the bridge under test is threading."""
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=5)
    loop.close()


def _prompter(session: _FakeSession | None, loop) -> ElicitationPrompter:
    return ElicitationPrompter(_FakeServer(session), loop)


# --- answers ------------------------------------------------------------------------


def test_accept_approves(loop):
    session = _FakeSession(action="accept")
    assert _prompter(session, loop).confirm(_CHALLENGE) is True
    assert session.messages == [_CHALLENGE]  # the exact challenge text reaches the human


@pytest.mark.parametrize("action", ["decline", "cancel"])
def test_decline_and_cancel_deny(loop, action):
    session = _FakeSession(action=action)
    assert _prompter(session, loop).confirm(_CHALLENGE) is False


def test_no_form_fields_are_requested(loop):
    """Buttons only: the schema must request zero properties — nothing transits the client."""
    session = _FakeSession(action="accept")
    _prompter(session, loop).confirm(_CHALLENGE)
    assert session.schemas[0].get("properties") == {}


# --- the sensitive-data rule ---------------------------------------------------------


def test_read_code_is_never_offered_via_elicitation(loop):
    """The MCP spec forbids sensitive info via elicitation — codes skip this channel."""
    session = _FakeSession(action="accept")
    with pytest.raises(PrompterUnavailableError):
        _prompter(session, loop).read_code("Enter your 2FA code")
    assert session.messages == []  # the session was never even consulted


# --- channel availability ------------------------------------------------------------


def test_client_without_capability_is_unavailable(loop):
    session = _FakeSession(supports=False)
    with pytest.raises(PrompterUnavailableError):
        _prompter(session, loop).confirm(_CHALLENGE)
    assert session.messages == []


def test_no_active_request_context_is_unavailable(loop):
    with pytest.raises(PrompterUnavailableError):
        _prompter(None, loop).confirm(_CHALLENGE)


def test_method_not_found_is_unavailable(loop):
    session = _FakeSession(error=McpError(ErrorData(code=METHOD_NOT_FOUND, message="nope")))
    with pytest.raises(PrompterUnavailableError):
        _prompter(session, loop).confirm(_CHALLENGE)


def test_other_protocol_errors_propagate_so_provider_denies(loop):
    session = _FakeSession(error=McpError(ErrorData(code=INTERNAL_ERROR, message="boom")))
    with pytest.raises(McpError):
        _prompter(session, loop).confirm(_CHALLENGE)


def test_unanswered_challenge_times_out_to_a_denial(loop, monkeypatch):
    monkeypatch.setattr(ep_mod, "ANSWER_TIMEOUT_S", 0.05)
    session = _FakeSession(hang=True)
    with pytest.raises(EOFError):
        _prompter(session, loop).confirm(_CHALLENGE)


def test_refuses_to_run_on_the_event_loop_thread(loop):
    """Blocking the loop would deadlock the very session carrying the answer."""
    session = _FakeSession(action="accept")
    prompter = _prompter(session, loop)

    async def _on_loop():
        return prompter.confirm(_CHALLENGE)

    with pytest.raises(PrompterUnavailableError):
        asyncio.run_coroutine_threadsafe(_on_loop(), loop).result(timeout=5)
    assert session.messages == []


# --- chain behavior ------------------------------------------------------------------


class _RecorderPrompter:
    def __init__(self, *, confirm=True):
        self._confirm = confirm
        self.calls: list[str] = []

    def confirm(self, message: str) -> bool:
        self.calls.append(message)
        return self._confirm

    def read_code(self, message: str) -> str:
        self.calls.append(message)
        return "123456"


def test_unsupported_client_falls_through_to_the_next_channel(loop):
    gui = _RecorderPrompter(confirm=True)
    chain = FallbackPrompter([_prompter(_FakeSession(supports=False), loop), gui])
    assert chain.confirm(_CHALLENGE) is True
    assert gui.calls == [_CHALLENGE]


def test_an_elicitation_denial_is_final_in_the_chain(loop):
    gui = _RecorderPrompter(confirm=True)  # would approve — must never be consulted
    chain = FallbackPrompter([_prompter(_FakeSession(action="decline"), loop), gui])
    assert chain.confirm(_CHALLENGE) is False
    assert gui.calls == []


def test_code_requests_skip_elicitation_and_reach_the_next_channel(loop):
    gui = _RecorderPrompter()
    chain = FallbackPrompter([_prompter(_FakeSession(), loop), gui])
    assert chain.read_code("Enter your 2FA code") == "123456"
    assert gui.calls == ["Enter your 2FA code"]


# --- the executor must run challenges OFF the event loop ------------------------------


async def test_executor_runs_the_challenge_off_the_event_loop(monkeypatch):
    """An in-loop challenge would deadlock elicitation; the prompter must see a worker thread."""
    from doberman.models import (
        ActionType,
        Decision,
        GuardrailResult,
        ReasonCode,
        Risk,
        SecurityObject,
        Verdict,
    )
    from doberman.proxy import executor

    loop_thread = threading.current_thread()
    seen: dict = {}

    class _ThreadRecorder:
        def confirm(self, message: str) -> bool:
            seen["thread"] = threading.current_thread()
            return False  # deny — the downstream must never be needed

        def read_code(self, message: str) -> str:  # pragma: no cover — never reached
            raise AssertionError("code requested for a confirm-tier challenge")

    monkeypatch.setattr(executor, "AUTH_PROMPTER", _ThreadRecorder())
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    action = SecurityObject(
        id="act-thread-1",
        ts=now,
        agent_role="webdev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
    )
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="why",
    )
    decision = Decision(
        action_id="act-thread-1",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=objective,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="why",
        decided_at=now,
    )

    result = await executor._handle_auth(None, "fs_write", {}, action, decision, now)

    assert result.isError  # denied — nothing forwarded
    assert seen["thread"] is not loop_thread
