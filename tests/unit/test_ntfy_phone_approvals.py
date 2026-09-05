"""Phone approvals via ntfy — config, channel, method, and prompter.

No real network here: :class:`FakeUrlopen` records every ``urllib.request.Request``
and serves a scripted queue of responses (a plain object for ``publish``'s POST, or
one whose ``readline()`` yields scripted JSON lines then ``b""`` for the streamed
GET). Every security-critical property from the plan is pinned: only an exact
``approve <nonce>``/``deny <nonce>`` line resolves the wait; a deny is final even
when an approve follows it; any exception anywhere becomes a fail-closed outcome
(never an approval); the 2FA tiers are never double-notified (the approval method
already owns the phone there); and nothing here ever logs or transmits a raw secret.
"""

from __future__ import annotations

import json
import os
import stat
import urllib.error
from datetime import datetime, timezone

import pytest

from doberman.auth import approval_config, ntfy
from doberman.auth.approval import ApprovalOutcome, request_approval
from doberman.auth.challenge import run_auth_challenge
from doberman.auth.gui_prompter import FallbackPrompter, PrompterUnavailableError
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.proxy.normalize import REDACTED, challenge_copy

_NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Fakes — no real network                                                     #
# --------------------------------------------------------------------------- #
class _FakeResponse:
    """Stand-in for ``urlopen``'s context-manager return value."""

    def __init__(self, *, status=200, lines=None, raise_on_read=None):
        self.status = status
        self._lines = list(lines or [])
        self._raise_on_read = raise_on_read

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def readline(self):
        if self._lines:
            return self._lines.pop(0)
        if self._raise_on_read is not None:
            raise self._raise_on_read
        return b""


class FakeUrlopen:
    """Records every ``Request``; serves a scripted queue of responses/exceptions."""

    def __init__(self, responses):
        self.requests: list = []
        self._responses = list(responses)

    def __call__(self, req, timeout=None):  # noqa: ARG002 - timeout unused by the fake
        self.requests.append(req)
        if not self._responses:
            raise AssertionError("FakeUrlopen: no scripted response left")
        resp = self._responses.pop(0)
        if isinstance(resp, BaseException):
            raise resp
        return resp


def _cfg(*, server="https://ntfy.sh", token="", wait_s=60):
    return ntfy.NtfyConfig(
        server=server,
        topic="topicAAAAAAAAAAAAAAAAAAAA"[:24],
        reply_topic="replytopicBBBBBBBBBBBBBBB"[:24],
        token=token,
        wait_s=wait_s,
    )


def _msg_line(text: str) -> bytes:
    return json.dumps({"event": "message", "message": text}).encode("utf-8") + b"\n"


@pytest.fixture
def ntfy_cfg(tmp_path, monkeypatch):
    """Isolate BOTH the ntfy config and the opt-in approval_config file."""
    monkeypatch.setenv(ntfy.NTFY_FILE_ENV, str(tmp_path / "ntfy.json"))
    monkeypatch.setenv(approval_config.APPROVAL_FILE_ENV, str(tmp_path / "approval.json"))
    return tmp_path


def _action(action_id="act-1", risk=Risk.low):
    return SecurityObject(
        id=action_id,
        ts=_NOW,
        agent_role="tester",
        action_type=ActionType.shell_exec,
        tool_name="shell",
        target="ls -la",
        risk=risk,
    )


def _decision(risk=Risk.low, action_id="act-1"):
    reasons = [ReasonCode.destructive_command]
    objective = GuardrailResult(
        verdict=Verdict.AUTH, risk=risk, reason_codes=reasons, explanation="why"
    )
    return Decision(
        action_id=action_id,
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=objective,
        reason_codes=reasons,
        explanation="why",
        decided_at=_NOW,
    )


class _Recorder:
    """A Prompter that always answers (never PrompterUnavailableError) — the
    "next channel" every FallbackPrompter test falls through to."""

    def __init__(self, confirm=True, code="123456"):
        self._confirm = confirm
        self._code = code
        self.confirm_calls = 0
        self.read_code_calls = 0

    def confirm(self, message: str) -> bool:  # noqa: ARG002
        self.confirm_calls += 1
        return self._confirm

    def read_code(self, message: str) -> str:  # noqa: ARG002
        self.read_code_calls += 1
        return self._code


def _patch_channel(monkeypatch, outcome, calls=None):
    """Route ``ntfy.NtfyChannel(cfg)`` to a fake that returns ``outcome`` from ``ask``."""
    calls = calls if calls is not None else []

    class _FakeChannel:
        def __init__(self, cfg, **kw):  # noqa: ARG002
            self.cfg = cfg

        def ask(self, prompt, *, action_id, deadline_s):
            calls.append((prompt, action_id, deadline_s))
            return outcome

    monkeypatch.setattr(ntfy, "NtfyChannel", _FakeChannel)
    return calls


# --------------------------------------------------------------------------- #
# 1. Config — new/save/load round-trip, fail-safe reads                       #
# --------------------------------------------------------------------------- #
def test_new_config_topics_are_well_formed_and_distinct():
    cfg = ntfy.new_config()
    import re

    token_re = re.compile(r"^[A-Za-z0-9_-]{24}$")
    assert token_re.match(cfg.topic)
    assert token_re.match(cfg.reply_topic)
    assert cfg.topic != cfg.reply_topic
    # a second call never repeats either topic
    cfg2 = ntfy.new_config()
    assert {cfg.topic, cfg.reply_topic}.isdisjoint({cfg2.topic, cfg2.reply_topic})


def test_new_config_clamps_wait_s():
    assert ntfy.new_config(wait_s=1).wait_s == 10
    assert ntfy.new_config(wait_s=10_000).wait_s == 300
    assert ntfy.new_config(wait_s=45).wait_s == 45


def test_save_and_load_round_trip(ntfy_cfg):
    cfg = ntfy.new_config(token="tok123", wait_s=45)  # noqa: S106 - fake test token, not a secret
    path = ntfy.save_config(cfg)
    assert path == ntfy.config_path()
    loaded = ntfy.load_config()
    assert loaded == cfg
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_load_config_missing_file_returns_none(ntfy_cfg):
    assert ntfy.load_config() is None


def test_load_config_malformed_file_returns_none(ntfy_cfg):
    ntfy.config_path().parent.mkdir(parents=True, exist_ok=True)
    ntfy.config_path().write_text("}{ not json", encoding="utf-8")
    assert ntfy.load_config() is None


def test_delete_config(ntfy_cfg):
    ntfy.save_config(ntfy.new_config())
    assert ntfy.delete_config() is True
    assert ntfy.load_config() is None
    assert ntfy.delete_config() is False  # idempotent


# --------------------------------------------------------------------------- #
# 2. publish — payload shape, actions, auth headers                           #
# --------------------------------------------------------------------------- #
def test_publish_sends_one_post_with_the_expected_payload():
    cfg = _cfg(token="")
    fake = FakeUrlopen([_FakeResponse(status=200)])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake)

    channel.publish(
        title="Doberman: approve this action?", message="body\n\nid abcdef12", nonce="NONCE123"
    )

    assert len(fake.requests) == 1
    req = fake.requests[0]
    assert req.full_url == cfg.server
    assert req.get_method() == "POST"
    assert req.get_header("Content-type") == "application/json"
    assert req.get_header("Authorization") is None

    payload = json.loads(req.data)
    assert payload["topic"] == cfg.topic
    assert payload["title"] == "Doberman: approve this action?"
    assert payload["message"] == "body\n\nid abcdef12"
    assert payload["priority"] == 4
    assert payload["tags"] == ["dog"]
    actions = payload["actions"]
    assert len(actions) == 2
    assert all(a["action"] == "http" and a["clear"] is True for a in actions)
    assert {a["url"] for a in actions} == {f"{cfg.server}/{cfg.reply_topic}"}
    assert {a["body"] for a in actions} == {"approve NONCE123", "deny NONCE123"}
    assert all("headers" not in a for a in actions)


def test_publish_with_token_sets_auth_on_request_and_both_actions():
    cfg = _cfg(token="tk_secret_ABC")  # noqa: S106 - fake test token, not a secret
    fake = FakeUrlopen([_FakeResponse(status=200)])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake)

    channel.publish(title="T", message="m\n\nid deadbeef", nonce="N1")

    req = fake.requests[0]
    assert req.get_header("Authorization") == "Bearer tk_secret_ABC"
    payload = json.loads(req.data)
    for action in payload["actions"]:
        assert action["headers"] == {"Authorization": "Bearer tk_secret_ABC"}


def test_publish_raises_ntfy_unavailable_on_http_error(monkeypatch):
    cfg = _cfg()
    fake = FakeUrlopen([_FakeResponse(status=500)])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake)
    with pytest.raises(ntfy.NtfyUnavailable):
        channel.publish(title="T", message="m", nonce="N")


def test_publish_raises_ntfy_unavailable_on_urlerror():
    cfg = _cfg()
    fake = FakeUrlopen([urllib.error.URLError("boom")])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake)
    with pytest.raises(ntfy.NtfyUnavailable):
        channel.publish(title="T", message="m", nonce="N")


# --------------------------------------------------------------------------- #
# 3. publish — truncation never drops the id line, never leaks token/topics   #
# --------------------------------------------------------------------------- #
def test_publish_truncates_a_long_message_and_keeps_the_id_line():
    cfg = _cfg(token="tk_secret_XYZ")  # noqa: S106 - fake test token, not a secret
    fake = FakeUrlopen([_FakeResponse(status=200)])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake)

    prompt = "y" * 6000
    action_id_line = "id deadbeef"
    message = f"{prompt}\n\n{action_id_line}"

    channel.publish(title="T", message=message, nonce="N")

    sent = json.loads(fake.requests[0].data)["message"]
    assert len(sent.encode("utf-8")) <= 3500
    assert sent.endswith(action_id_line)
    assert cfg.token not in sent
    assert cfg.topic not in sent
    assert cfg.reply_topic not in sent


# --------------------------------------------------------------------------- #
# 4. wait — exact-match semantics, deny final, timeout on end/error           #
# --------------------------------------------------------------------------- #
def test_wait_matches_the_exact_approve_line_and_ignores_noise():
    cfg = _cfg()
    lines = [
        b'{"event":"open"}\n',
        b'{"event":"keepalive"}\n',
        _msg_line("approve OTHERNONCE"),
        _msg_line("APPROVE NONCE123"),
        _msg_line("approve NONCE123 extra"),
        _msg_line("approve NONCE123"),
        b"",
    ]
    fake = FakeUrlopen([_FakeResponse(lines=lines)])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    result = channel.wait("NONCE123", since=1000.0, deadline_s=30)

    assert result == "approved"
    assert len(fake.requests) == 1
    req = fake.requests[0]
    assert req.full_url == f"{cfg.server}/{cfg.reply_topic}/json?since=999"
    assert req.get_method() == "GET"


def test_wait_deny_is_final_even_when_an_approve_follows():
    cfg = _cfg()
    lines = [_msg_line("deny NONCE123"), _msg_line("approve NONCE123"), b""]
    fake = FakeUrlopen([_FakeResponse(lines=lines)])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    assert channel.wait("NONCE123", since=1000.0, deadline_s=30) == "denied"


def test_wait_times_out_when_the_stream_ends():
    cfg = _cfg()
    fake = FakeUrlopen([_FakeResponse(lines=[b'{"event":"keepalive"}\n', b""])])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    assert channel.wait("NONCE123", since=1000.0, deadline_s=30) == "timeout"


def test_wait_times_out_when_the_fake_raises_mid_stream():
    cfg = _cfg()
    fake = FakeUrlopen([_FakeResponse(raise_on_read=ConnectionResetError("boom"))])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    assert channel.wait("NONCE123", since=1000.0, deadline_s=30) == "timeout"


def test_wait_times_out_when_urlopen_itself_raises():
    cfg = _cfg()
    fake = FakeUrlopen([urllib.error.URLError("boom")])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    assert channel.wait("NONCE123", since=1000.0, deadline_s=30) == "timeout"


def test_wait_ignores_near_miss_lines_and_times_out():
    """Regression pin for review finding (a): a stream of ONLY near-miss lines —
    a suffixed approve, a case-different approve, and an approve for a different
    nonce — must never resolve to "approved". Catches a substring-match
    regression (exact `==` weakened to `in`) that a trailing exact line in the
    older test could mask."""
    cfg = _cfg()
    lines = [
        _msg_line("approve NONCE123 extra"),
        _msg_line("APPROVE NONCE123"),
        _msg_line("approve OTHERNONCE"),
        b"",
    ]
    fake = FakeUrlopen([_FakeResponse(lines=lines)])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    assert channel.wait("NONCE123", since=1000.0, deadline_s=30) == "timeout"


def test_wait_returns_timeout_without_opening_the_stream_when_deadline_already_passed():
    """Review finding (b): a deadline already in the past must fail fast, never
    fall back to the full stream timeout (the old `... or _STREAM_TIMEOUT_S`
    treated a computed remaining of exactly 0 as falsy)."""
    cfg = _cfg()
    fake = FakeUrlopen([])  # any call raises AssertionError -- the stream must never open
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    assert channel.wait("NONCE123", since=900.0, deadline_s=50) == "timeout"
    assert fake.requests == []


def test_wait_sends_bearer_token_when_configured_and_omits_it_otherwise():
    """Review finding (c): the reply-topic stream GET carries the bearer token
    when one is configured (needed to read a self-hosted `deny-all` server) and
    carries no Authorization header at all when it isn't."""
    cfg = _cfg(token="tk_secret_ABC")  # noqa: S106 - fake test token, not a secret
    fake = FakeUrlopen([_FakeResponse(lines=[b""])])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)
    channel.wait("NONCE123", since=1000.0, deadline_s=30)
    assert fake.requests[0].get_header("Authorization") == "Bearer tk_secret_ABC"

    cfg_no_token = _cfg(token="")
    fake2 = FakeUrlopen([_FakeResponse(lines=[b""])])
    channel2 = ntfy.NtfyChannel(cfg_no_token, urlopen=fake2, clock=lambda: 1000.0)
    channel2.wait("NONCE123", since=1000.0, deadline_s=30)
    assert fake2.requests[0].get_header("Authorization") is None


# --------------------------------------------------------------------------- #
# 5. ask — unavailable on publish failure, stream never opened                #
# --------------------------------------------------------------------------- #
def test_ask_returns_unavailable_when_publish_fails_and_never_opens_the_stream():
    cfg = _cfg()
    fake = FakeUrlopen([urllib.error.URLError("boom")])  # ONE scripted response only
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    result = channel.ask("do the thing", action_id="action-123", deadline_s=30)

    assert result == "unavailable"
    assert len(fake.requests) == 1  # only the publish attempt; a second call would AssertionError


def test_ask_returns_unavailable_on_http_500_and_never_opens_the_stream():
    cfg = _cfg()
    fake = FakeUrlopen([_FakeResponse(status=500)])
    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)

    result = channel.ask("do the thing", action_id="action-123", deadline_s=30)

    assert result == "unavailable"
    assert len(fake.requests) == 1


def test_ask_approves_end_to_end():
    cfg = _cfg()
    responses = [_FakeResponse(status=200)]
    fake = FakeUrlopen(responses)

    channel = ntfy.NtfyChannel(cfg, urlopen=fake, clock=lambda: 1000.0)
    # capture the nonce from the publish body, then script the matching reply
    orig_publish = channel.publish

    def _publish_and_script(*, title, message, nonce):
        since = orig_publish(title=title, message=message, nonce=nonce)
        fake._responses.append(_FakeResponse(lines=[_msg_line(f"approve {nonce}"), b""]))
        return since

    channel.publish = _publish_and_script  # type: ignore[method-assign]
    assert channel.ask("do it", action_id="a1", deadline_s=30) == "approved"


# --------------------------------------------------------------------------- #
# 6. NtfyApprovalMethod — availability + outcome mapping + deadline           #
# --------------------------------------------------------------------------- #
def test_method_unavailable_when_unconfigured(ntfy_cfg):
    assert ntfy.NtfyApprovalMethod().is_available() is False


def test_method_unavailable_when_configured_but_not_enabled(ntfy_cfg):
    ntfy.save_config(ntfy.new_config())
    assert ntfy.NtfyApprovalMethod().is_available() is False


def test_method_available_when_configured_and_enabled(ntfy_cfg):
    ntfy.save_config(ntfy.new_config())
    approval_config.enable(ntfy.METHOD_NAME)
    assert ntfy.NtfyApprovalMethod().is_available() is True


@pytest.mark.parametrize(
    "outcome,expected",
    [
        ("approved", ApprovalOutcome.approved),
        ("denied", ApprovalOutcome.denied),
        ("timeout", ApprovalOutcome.unavailable),
        ("unavailable", ApprovalOutcome.unavailable),
    ],
)
def test_method_request_maps_outcomes(ntfy_cfg, monkeypatch, outcome, expected):
    ntfy.save_config(ntfy.new_config(wait_s=20))
    approval_config.enable(ntfy.METHOD_NAME)
    calls = _patch_channel(monkeypatch, outcome)

    result = ntfy.NtfyApprovalMethod().request("prompt", action_id="act-1", timeout_s=5)

    assert result is expected
    assert calls == [("prompt", "act-1", 5)]  # min(timeout_s=5, wait_s=20) == 5


def test_method_deadline_is_min_of_timeout_and_wait(ntfy_cfg, monkeypatch):
    ntfy.save_config(ntfy.new_config(wait_s=10))
    approval_config.enable(ntfy.METHOD_NAME)
    calls = _patch_channel(monkeypatch, "approved")

    ntfy.NtfyApprovalMethod().request("p", action_id="a", timeout_s=999)

    assert calls[0][2] == 10  # wait_s wins


def test_method_not_configured_returns_unavailable_without_asking(ntfy_cfg, monkeypatch):
    calls = _patch_channel(monkeypatch, "approved")
    result = ntfy.NtfyApprovalMethod().request("p", action_id="a", timeout_s=5)
    assert result is ApprovalOutcome.unavailable
    assert calls == []  # never even constructed a channel


def test_method_channel_exception_is_denied_via_request_approval(ntfy_cfg, monkeypatch):
    ntfy.save_config(ntfy.new_config())
    approval_config.enable(ntfy.METHOD_NAME)

    class _RaisingChannel:
        def __init__(self, cfg, **kw):  # noqa: ARG002
            pass

        def ask(self, *a, **kw):  # noqa: ARG002
            raise RuntimeError("backend blew up")

    monkeypatch.setattr(ntfy, "NtfyChannel", _RaisingChannel)

    outcome = request_approval(ntfy.NtfyApprovalMethod(), "p", action_id="a")
    assert outcome is ApprovalOutcome.denied  # request_approval's fail-closed wrapper


# --------------------------------------------------------------------------- #
# 7. NtfyPrompter — unconfigured / 2FA step-aside / confirm-only / timeout    #
# --------------------------------------------------------------------------- #
def test_prompter_unconfigured_raises_unavailable(ntfy_cfg):
    with pytest.raises(PrompterUnavailableError):
        ntfy.NtfyPrompter().confirm("msg")


def test_prompter_read_code_always_raises_unavailable(ntfy_cfg):
    with pytest.raises(PrompterUnavailableError):
        ntfy.NtfyPrompter().read_code("msg")
    # even when fully configured and enabled
    ntfy.save_config(ntfy.new_config())
    approval_config.enable(ntfy.METHOD_NAME)
    with pytest.raises(PrompterUnavailableError):
        ntfy.NtfyPrompter().read_code("msg")


def test_prompter_steps_aside_for_2fa_tiers_with_no_request(ntfy_cfg, monkeypatch):
    # Updated for Task 2: builtin_methods() now registers NtfyApprovalMethod, so a
    # two_factor tier tries the PHONE METHOD first (single notification, exactly
    # once) — this test scripts it "unavailable" so the tier falls through to
    # confirm() + TOTP, same as before Task 2. What's still pinned here is the
    # PROMPTER's own step-aside: confirm() must NOT construct a second NtfyChannel
    # for a 2FA tier (that would double-notify the phone for one challenge) — only
    # the method's one channel construction is allowed.
    ntfy.save_config(ntfy.new_config())
    approval_config.enable(ntfy.METHOD_NAME)

    channel_constructions = []

    class _UnavailableChannel:
        def __init__(self, cfg, **kw):  # noqa: ARG002
            channel_constructions.append(cfg)

        def ask(self, *a, **kw):  # noqa: ARG002
            return "unavailable"

    monkeypatch.setattr(ntfy, "NtfyChannel", _UnavailableChannel)
    monkeypatch.setattr("doberman.auth.provider.totp.verify", lambda *a, **k: True)
    recorder = _Recorder(confirm=True)
    prompter = FallbackPrompter([ntfy.NtfyPrompter(), recorder])

    result = run_auth_challenge(
        _decision(risk=Risk.high), _action(risk=Risk.high), prompter=prompter, timeout_s=5
    )

    assert result.approved is True
    assert len(channel_constructions) == 1  # the method asked once; the prompter never asked again
    assert recorder.confirm_calls == 1  # phone method unavailable -> fell through to the recorder
    assert recorder.read_code_calls == 1  # confirm-only step-aside still needs the TOTP code


def test_prompter_confirm_only_tier_publishes_and_returns_true(ntfy_cfg, monkeypatch):
    ntfy.save_config(ntfy.new_config(wait_s=10))
    approval_config.enable(ntfy.METHOD_NAME)
    calls = _patch_channel(monkeypatch, "approved")
    recorder = _Recorder(confirm=False)  # would deny if ever reached
    prompter = FallbackPrompter([ntfy.NtfyPrompter(), recorder])

    result = run_auth_challenge(
        _decision(risk=Risk.low), _action(risk=Risk.low), prompter=prompter, timeout_s=30
    )

    assert result.approved is True
    assert len(calls) == 1
    assert recorder.confirm_calls == 0  # phone alone answered


def test_prompter_deny_is_final_the_recorder_is_never_asked(ntfy_cfg, monkeypatch):
    ntfy.save_config(ntfy.new_config(wait_s=10))
    approval_config.enable(ntfy.METHOD_NAME)
    _patch_channel(monkeypatch, "denied")
    recorder = _Recorder(confirm=True)
    prompter = FallbackPrompter([ntfy.NtfyPrompter(), recorder])

    result = run_auth_challenge(
        _decision(risk=Risk.low), _action(risk=Risk.low), prompter=prompter, timeout_s=30
    )

    assert result.approved is False
    assert recorder.confirm_calls == 0
    assert prompter.last_reason == "denied on phone"


def test_prompter_timeout_falls_through_to_the_next_channel(ntfy_cfg, monkeypatch):
    ntfy.save_config(ntfy.new_config(wait_s=10))
    approval_config.enable(ntfy.METHOD_NAME)
    calls = _patch_channel(monkeypatch, "timeout")
    recorder = _Recorder(confirm=True)
    prompter = FallbackPrompter([ntfy.NtfyPrompter(), recorder])

    result = run_auth_challenge(
        _decision(risk=Risk.low), _action(risk=Risk.low), prompter=prompter, timeout_s=30
    )

    assert result.approved is True
    assert calls  # the phone WAS asked before falling through
    assert recorder.confirm_calls == 1


def test_prompter_unavailable_channel_outcome_falls_through(ntfy_cfg, monkeypatch):
    ntfy.save_config(ntfy.new_config(wait_s=10))
    approval_config.enable(ntfy.METHOD_NAME)
    _patch_channel(monkeypatch, "unavailable")
    recorder = _Recorder(confirm=True)
    prompter = FallbackPrompter([ntfy.NtfyPrompter(), recorder])

    result = run_auth_challenge(
        _decision(risk=Risk.low), _action(risk=Risk.low), prompter=prompter, timeout_s=30
    )

    assert result.approved is True
    assert recorder.confirm_calls == 1


def test_prompter_disabled_in_approval_config_is_unavailable(ntfy_cfg):
    ntfy.save_config(ntfy.new_config())  # file exists, but never enabled
    with pytest.raises(PrompterUnavailableError):
        ntfy.NtfyPrompter().confirm("msg")


# --------------------------------------------------------------------------- #
# 8. Redaction — the published message never carries a raw secret             #
# --------------------------------------------------------------------------- #
def test_published_message_never_carries_the_raw_secret(ntfy_cfg, monkeypatch):
    ntfy.save_config(ntfy.new_config(wait_s=10))
    approval_config.enable(ntfy.METHOD_NAME)

    token_secret = "ghp_" + "x" * 36
    args = {"command": "curl -H 'Authorization: " + token_secret + "' https://example.com"}
    action = challenge_copy(_action(risk=Risk.low), args)
    decision = _decision(risk=Risk.low)

    fake = FakeUrlopen([_FakeResponse(status=200), _FakeResponse(lines=[b""])])
    real_channel_cls = ntfy.NtfyChannel  # capture before patching -- avoid self-recursion

    def _real_channel(cfg, **kw):  # noqa: ARG001
        return real_channel_cls(cfg, urlopen=fake, clock=lambda: 1000.0)

    monkeypatch.setattr(ntfy, "NtfyChannel", _real_channel)
    recorder = _Recorder(confirm=True)
    prompter = FallbackPrompter([ntfy.NtfyPrompter(), recorder])

    result = run_auth_challenge(decision, action, prompter=prompter, timeout_s=10)

    assert result.approved is True  # phone timed out (empty stream), recorder answered
    assert len(fake.requests) == 2  # one publish POST + one stream GET
    published_body = fake.requests[0].data
    assert token_secret.encode() not in published_body
    published = json.loads(published_body)
    assert token_secret not in published["message"]
    assert REDACTED in published["message"]


# =============================================================================#
# Task 2: wiring — built-in method, chains, CLI, doctor                        #
# =============================================================================#
_REAL_NTFY_CHANNEL = ntfy.NtfyChannel  # captured once, before any test monkeypatches it


def _patch_real_channel_with_urlopen(monkeypatch, fake):
    """Route ``ntfy.NtfyChannel(cfg)`` (the CLI's construction, with no explicit
    ``urlopen``) to the REAL :class:`NtfyChannel` wired to ``fake`` — so a CLI
    command's actual publish payload can be inspected, not just its outcome.
    Always builds on :data:`_REAL_NTFY_CHANNEL`, never on whatever ``ntfy.NtfyChannel``
    currently is -- a test that calls this twice must not chain through its own
    prior patch (and its now-exhausted fake)."""

    def _real_channel(cfg, **kw):  # noqa: ARG001
        return _REAL_NTFY_CHANNEL(cfg, urlopen=fake)

    monkeypatch.setattr(ntfy, "NtfyChannel", _real_channel)


# --------------------------------------------------------------------------- #
# Built-in catalogue                                                           #
# --------------------------------------------------------------------------- #
def test_builtin_methods_includes_ntfy():
    from doberman.auth.methods import builtin_methods

    names = {getattr(m, "name", None) for m in builtin_methods()}
    assert ntfy.METHOD_NAME in names


def test_cli_2fa_methods_enable_ntfy(ntfy_cfg):
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["2fa", "methods", "enable", ntfy.METHOD_NAME])
    assert result.exit_code == 0
    assert approval_config.is_enabled(ntfy.METHOD_NAME) is True


# --------------------------------------------------------------------------- #
# CLI — doberman phone setup|test|status|off                                  #
# --------------------------------------------------------------------------- #
def test_cli_phone_setup_writes_config_sends_test_notification_no_actions(ntfy_cfg, monkeypatch):
    fake = FakeUrlopen([_FakeResponse(status=200)])
    _patch_real_channel_with_urlopen(monkeypatch, fake)
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["phone", "setup", "--token", "tk_secret_ABC"])

    assert result.exit_code == 0
    cfg = ntfy.load_config()
    assert cfg is not None
    assert approval_config.is_enabled(ntfy.METHOD_NAME) is True
    # the public topic IS shown (the user must enter it into the ntfy app) --
    # the secret reply topic and the token never are.
    assert cfg.topic in result.output
    assert cfg.reply_topic not in result.output
    assert "tk_secret_ABC" not in result.output
    # exactly one publish, with no Approve/Deny actions (a plain connectivity test)
    assert len(fake.requests) == 1
    payload = json.loads(fake.requests[0].data)
    assert "actions" not in payload


def test_cli_phone_setup_twice_without_force_exits_1_and_leaves_file_untouched(
    ntfy_cfg, monkeypatch
):
    _patch_real_channel_with_urlopen(monkeypatch, FakeUrlopen([_FakeResponse(status=200)]))
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    assert runner.invoke(app, ["phone", "setup"]).exit_code == 0
    original = ntfy.load_config()

    result = runner.invoke(app, ["phone", "setup"])

    assert result.exit_code == 1
    assert ntfy.load_config() == original


def test_cli_phone_setup_force_overwrites(ntfy_cfg, monkeypatch):
    _patch_real_channel_with_urlopen(
        monkeypatch, FakeUrlopen([_FakeResponse(status=200), _FakeResponse(status=200)])
    )
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    assert runner.invoke(app, ["phone", "setup"]).exit_code == 0
    original = ntfy.load_config()

    result = runner.invoke(app, ["phone", "setup", "--force"])

    assert result.exit_code == 0
    assert ntfy.load_config() != original  # fresh topics


def test_cli_phone_setup_publish_failure_warns_and_exits_0_config_kept(ntfy_cfg, monkeypatch):
    _patch_real_channel_with_urlopen(monkeypatch, FakeUrlopen([_FakeResponse(status=500)]))
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["phone", "setup"])

    assert result.exit_code == 0
    assert "warning: test notification failed" in result.output
    assert "run doberman phone test after subscribing" in result.output
    assert ntfy.load_config() is not None  # config kept despite the failed test


def test_cli_phone_status_off_then_on(ntfy_cfg, monkeypatch):
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["phone", "status"])
    assert result.exit_code == 0
    assert "off" in result.output

    _patch_real_channel_with_urlopen(monkeypatch, FakeUrlopen([_FakeResponse(status=200)]))
    assert runner.invoke(app, ["phone", "setup"]).exit_code == 0

    result = runner.invoke(app, ["phone", "status"])
    cfg = ntfy.load_config()
    assert result.exit_code == 0
    assert "on" in result.output
    assert cfg.topic[:4] in result.output
    assert cfg.topic not in result.output  # never the full topic
    assert cfg.reply_topic not in result.output


def test_cli_phone_off_disables_and_deletes_idempotently(ntfy_cfg, monkeypatch):
    _patch_real_channel_with_urlopen(monkeypatch, FakeUrlopen([_FakeResponse(status=200)]))
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    assert runner.invoke(app, ["phone", "setup"]).exit_code == 0
    assert approval_config.is_enabled(ntfy.METHOD_NAME) is True

    result = runner.invoke(app, ["phone", "off"])
    assert result.exit_code == 0
    assert ntfy.load_config() is None
    assert approval_config.is_enabled(ntfy.METHOD_NAME) is False

    # idempotent -- a second "off" is not an error
    result2 = runner.invoke(app, ["phone", "off"])
    assert result2.exit_code == 0


def test_cli_phone_test_not_configured_exits_1(ntfy_cfg):
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["phone", "test"])
    assert result.exit_code == 1


def test_cli_phone_test_success_and_failure_exit_codes(ntfy_cfg, monkeypatch):
    ntfy.save_config(ntfy.new_config())
    approval_config.enable(ntfy.METHOD_NAME)
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()

    _patch_real_channel_with_urlopen(monkeypatch, FakeUrlopen([_FakeResponse(status=200)]))
    ok = runner.invoke(app, ["phone", "test"])
    assert ok.exit_code == 0

    _patch_real_channel_with_urlopen(monkeypatch, FakeUrlopen([_FakeResponse(status=500)]))
    fail = runner.invoke(app, ["phone", "test"])
    assert fail.exit_code == 1


# --------------------------------------------------------------------------- #
# Doctor check                                                                 #
# --------------------------------------------------------------------------- #
def test_check_phone_approvals_ok_and_warn_and_never_critical(ntfy_cfg):
    from doberman.cli.doctor import CheckStatus, _check_phone_approvals

    off = _check_phone_approvals()
    assert off.status == CheckStatus.WARN
    assert off.critical is False

    ntfy.save_config(ntfy.new_config())
    approval_config.enable(ntfy.METHOD_NAME)
    on = _check_phone_approvals()
    assert on.status == CheckStatus.OK
    assert on.critical is False


# --------------------------------------------------------------------------- #
# Prompter chains -- serve and hookio                                         #
# --------------------------------------------------------------------------- #
def test_build_auth_prompter_chain_order():
    from doberman.proxy.serve import build_auth_prompter

    prompter = build_auth_prompter(proxy=object(), loop=None, repo_root=".")

    kinds = [type(p).__name__ for p in prompter.prompters]
    assert kinds == [
        "DashboardPrompter",
        "NtfyPrompter",
        "ElicitationPrompter",
        "GuiPrompter",
        "TtyPrompter",
    ]


def test_default_auth_prompter_starts_with_ntfy_and_is_a_no_op_unconfigured(ntfy_cfg):
    from doberman.hosthooks.hookio import _default_auth_prompter

    prompter = _default_auth_prompter()

    kinds = [type(p).__name__ for p in prompter.prompters]
    assert kinds == ["NtfyPrompter", "GuiPrompter", "TtyPrompter"]
    # With no phone config, behaviour is byte-identical to the old [Gui, Tty]
    # chain: the phone step raises PrompterUnavailableError immediately -- no
    # network call, no popup -- so it never changes what the human sees.
    with pytest.raises(PrompterUnavailableError):
        prompter.prompters[0].confirm("msg")
