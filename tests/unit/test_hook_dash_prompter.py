"""Host-hook AUTH answered from the dashboard (schema v18).

A host hook's AUTH challenge now tries the dashboard first when one is running
for the hook's repo (``hookio._default_auth_prompter``): the hook queues a
redaction-safe row carrying the host session id, and a human answers it on
``doberman dash``. Everything that made an approval safe still holds, because
the dashboard only relays an answer: approval needs a resolved row bound to
this action, and a proof tier still runs ``totp.verify`` in the hook process.

The real GUI dialog and terminal prompt are replaced with recording fakes so
nothing here opens a window or reads a terminal, and the phone and approval
config files point at empty temp paths so a developer's own setup is never read.
"""

import asyncio
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from doberman.auth import (
    approval_config,
    dashboard_prompter,
    gui_prompter,
    ntfy,
    totp,
    tty_prompter,
)
from doberman.auth.gui_prompter import PrompterUnavailableError
from doberman.dash.app import create_app
from doberman.hosthooks import claude_code
from doberman.hosthooks.hookio import _default_auth_prompter
from doberman.models import AuthPath
from doberman.storage import approvals
from doberman.storage.heartbeat import touch_heartbeat
from doberman.storage.log import read_decisions

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret
_SESSION = "sess-hook-42"
_CANARY = "zx-canary-7731-unique"

#: A raw-IP fetch is a confirm-only (local_auth) AUTH in every mode.
_CONFIRM_CALL = {
    "tool_name": "WebFetch",
    "tool_input": {"url": "https://93.184.216.34/", "prompt": "x"},
}
#: An opaque shell payload is a two_factor AUTH: approval needs a TOTP code.
_PROOF_CALL = {"tool_name": "Bash", "tool_input": {"command": 'bash -c "echo hi"'}}


@pytest.fixture(autouse=True)
def _no_personal_channel_config(tmp_path, monkeypatch):
    monkeypatch.setenv(ntfy.NTFY_FILE_ENV, str(tmp_path / "ntfy.json"))
    monkeypatch.setenv(approval_config.APPROVAL_FILE_ENV, str(tmp_path / "approval.json"))


@pytest.fixture
def local_channels(monkeypatch):
    """Use the real default chain, with the GUI and terminal swapped for fakes.

    Returns the list of local channels asked, in order. ``gui_answer`` on the
    returned object sets what the fake dialog does: ``None`` = unavailable,
    ``"expired"`` = shown but nobody answered, ``True``/``False`` = a human click.
    """

    class _Asked(list):
        gui_answer: object = None

    asked = _Asked()

    class _Gui:
        last_reason: str | None = None

        def confirm(self, message):  # noqa: ARG002
            asked.append("gui")
            if asked.gui_answer is None:
                raise PrompterUnavailableError("test: no GUI")
            if asked.gui_answer == "expired":
                self.last_reason = "expired"
                return False
            return bool(asked.gui_answer)

        def read_code(self, message):  # noqa: ARG002
            asked.append("gui-code")
            raise PrompterUnavailableError("test: no GUI")

    class _Tty:
        def confirm(self, message):  # noqa: ARG002
            asked.append("tty")
            raise PrompterUnavailableError("test: no terminal")

        def read_code(self, message):  # noqa: ARG002
            asked.append("tty-code")
            raise PrompterUnavailableError("test: no terminal")

    monkeypatch.setattr(claude_code, "AUTH_PROMPTER", None)
    monkeypatch.setattr(gui_prompter, "GuiPrompter", _Gui)
    monkeypatch.setattr(tty_prompter, "TtyPrompter", _Tty)
    return asked


def _pre(root: str, call: dict, *, session_id: str | None = _SESSION) -> str:
    payload = {"hook_event_name": "PreToolUse", "cwd": root, **call}
    if session_id is not None:
        payload["session_id"] = session_id
    out = claude_code.evaluate_pre(payload)
    assert out is not None, "expected an AUTH decision, got abstain"
    return out["hookSpecificOutput"]["permissionDecision"]


def _all_rows(root: str) -> list[dict]:
    # A "now" long before any row was written lists expired rows too.
    return asyncio.run(
        approvals.list_pending(repo_root=root, now=datetime(2000, 1, 1, tzinfo=timezone.utc))
    )


def _latest_decision(root: str) -> dict:
    rows = asyncio.run(read_decisions(root))
    assert rows, "the host hook recorded nothing"
    return rows[0]


def _dashboard_answers(monkeypatch, root: str, *, decision="approved", code=None, seen=None):
    """Make the dashboard's poll wait resolve the queued row, as a human click would."""

    def _resolver(seconds):  # noqa: ARG001
        rows = asyncio.run(approvals.list_pending(repo_root=root))
        assert len(rows) == 1, "expected exactly one queued approval"
        if seen is not None:
            seen.append(rows[0])
        asyncio.run(
            approvals.resolve(rows[0]["id"], decision=decision, totp_code=code, repo_root=root)
        )

    monkeypatch.setattr(dashboard_prompter, "_sleep", _resolver)


def _nobody_at_the_dashboard(monkeypatch):
    """The dashboard is up but nobody answers: each poll wait jumps past its window."""
    clock = {"now": datetime.now(timezone.utc)}

    class _Clock(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ARG003
            return clock["now"]

    def _wait(seconds):  # noqa: ARG001
        clock["now"] += timedelta(seconds=dashboard_prompter.DEFAULT_TIMEOUT_S + 1)

    monkeypatch.setattr(dashboard_prompter, "datetime", _Clock)
    monkeypatch.setattr(dashboard_prompter, "_sleep", _wait)


def _no_wait_allowed(monkeypatch):
    def _fail(seconds):  # noqa: ARG001
        raise AssertionError("the dashboard channel must not wait here")

    monkeypatch.setattr(dashboard_prompter, "_sleep", _fail)


# --- the chain ------------------------------------------------------------------------------


def test_chain_puts_the_dashboard_first_when_the_hook_knows_its_repo(tmp_path):
    prompter = _default_auth_prompter(str(tmp_path), _SESSION)

    kinds = [type(p).__name__ for p in prompter.prompters]
    assert kinds == ["DashboardPrompter", "NtfyPrompter", "GuiPrompter", "TtyPrompter"]


def test_chain_without_a_repo_root_is_the_old_chain():
    prompter = _default_auth_prompter()

    kinds = [type(p).__name__ for p in prompter.prompters]
    assert kinds == ["NtfyPrompter", "GuiPrompter", "TtyPrompter"]


def test_dashboard_down_falls_to_the_old_chain_without_waiting_or_queuing(
    tmp_path, monkeypatch, local_channels
):
    root = str(tmp_path)  # no heartbeat: no dashboard has run here
    _no_wait_allowed(monkeypatch)
    local_channels.gui_answer = True

    assert _pre(root, _CONFIRM_CALL) == "allow"
    assert local_channels == ["gui"]
    assert _all_rows(root) == []


# --- the dashboard answers ------------------------------------------------------------------


def test_hook_auth_enqueues_with_the_session_id_and_allows_on_approve(
    tmp_path, monkeypatch, local_channels
):
    root = str(tmp_path)
    touch_heartbeat(root)
    seen: list[dict] = []
    _dashboard_answers(monkeypatch, root, seen=seen)

    assert _pre(root, _CONFIRM_CALL) == "allow"

    assert seen[0]["session_id"] == _SESSION
    assert local_channels == []  # nobody else was asked
    row = _latest_decision(root)
    assert row["final_verdict"] == "AUTH"
    assert row["auth_path"] == AuthPath.host_hook_challenge
    assert row["human_confirmed"] == 1


def test_a_deny_on_the_dashboard_denies_the_call(tmp_path, monkeypatch, local_channels):
    root = str(tmp_path)
    touch_heartbeat(root)
    _dashboard_answers(monkeypatch, root, decision="denied")

    assert _pre(root, _CONFIRM_CALL) == "deny"
    assert local_channels == []


@pytest.mark.parametrize(("code", "expected"), [("999000", "allow"), ("000000", "deny")])
def test_proof_tier_runs_totp_in_the_hook_process(
    tmp_path, monkeypatch, local_channels, code, expected
):
    root = str(tmp_path)
    touch_heartbeat(root)
    checked: list[str] = []
    monkeypatch.setattr(totp, "verify", lambda c, **_kw: (checked.append(c), c == "999000")[1])
    _dashboard_answers(monkeypatch, root, code=code)

    assert _pre(root, _PROOF_CALL) == expected
    assert checked == [code]
    assert local_channels == []


def test_proof_tier_denies_when_approved_without_a_code(tmp_path, monkeypatch, local_channels):
    root = str(tmp_path)
    touch_heartbeat(root)
    monkeypatch.setattr(totp, "verify", lambda c, **_kw: True)  # would pass any code
    seen: list[dict] = []
    _dashboard_answers(monkeypatch, root, code=None, seen=seen)

    assert _pre(root, _PROOF_CALL) == "deny"
    assert len(seen) == 1  # the dashboard did answer; the missing code is what denied


def test_a_forged_heartbeat_and_a_forged_approval_cannot_skip_the_proof(
    tmp_path, monkeypatch, local_channels
):
    # Any local process can write the heartbeat file and the row. Neither is proof: with no
    # authenticator enrolled (conftest), the guessed code fails the real totp.verify.
    root = str(tmp_path)
    touch_heartbeat(root)
    seen: list[dict] = []
    _dashboard_answers(monkeypatch, root, code="123456", seen=seen)

    assert _pre(root, _PROOF_CALL) == "deny"
    assert len(seen) == 1  # the forged approval was read, and still did not count
    assert _latest_decision(root)["human_confirmed"] == 0


def test_silence_everywhere_denies(tmp_path, monkeypatch, local_channels):
    root = str(tmp_path)
    touch_heartbeat(root)
    _nobody_at_the_dashboard(monkeypatch)
    local_channels.gui_answer = "expired"

    assert _pre(root, _CONFIRM_CALL) == "deny"
    assert local_channels == ["gui"]  # the dialog was the next channel, and it expired
    assert _latest_decision(root)["human_confirmed"] == 0
    # The dashboard row dies with its window, so a late click cannot approve anything.
    [row] = _all_rows(root)
    after_window = datetime.now(timezone.utc) + timedelta(
        seconds=dashboard_prompter.DEFAULT_TIMEOUT_S + 1
    )
    late = approvals.resolve(row["id"], decision="approved", repo_root=root, now=after_window)
    assert asyncio.run(late) is False


def test_approval_method_wins_before_the_dashboard_on_proof_tiers(
    tmp_path, monkeypatch, local_channels
):
    # With Windows Hello / Touch ID / phone enabled, a proof tier asks that method first and
    # no prompter runs at all, so nothing is queued on the dashboard.
    from doberman.auth import provider
    from doberman.auth.approval import ApprovalOutcome

    class _Method:
        name = "fake_biometric"

    root = str(tmp_path)
    touch_heartbeat(root)
    _no_wait_allowed(monkeypatch)
    monkeypatch.setattr(provider, "resolve_approval_method", lambda: _Method())
    monkeypatch.setattr(
        provider, "request_approval", lambda method, message, **_kw: ApprovalOutcome.approved
    )

    assert _pre(root, _PROOF_CALL) == "allow"
    assert _all_rows(root) == []
    assert local_channels == []


# --- redaction ------------------------------------------------------------------------------


def test_no_raw_input_reaches_the_row_or_the_api(tmp_path, monkeypatch, local_channels):
    root = str(tmp_path)
    touch_heartbeat(root)
    client = TestClient(create_app(_TOKEN, root))
    responses: list[str] = []

    def _resolver(seconds):  # noqa: ARG001
        resp = client.get("/api/pending", headers={"Authorization": f"Bearer {_TOKEN}"})
        responses.append(resp.text)
        [row] = resp.json()
        assert row["session_id"] == _SESSION
        client.post(
            f"/api/resolve/{row['id']}",
            headers={"Authorization": f"Bearer {_TOKEN}"},
            json={"decision": "approved"},
        )

    monkeypatch.setattr(dashboard_prompter, "_sleep", _resolver)
    call = {
        "tool_name": "WebFetch",
        "tool_input": {"url": f"https://93.184.216.34/?q={_CANARY}", "prompt": _CANARY},
    }

    assert _pre(root, call) == "allow"
    assert responses and all(_CANARY not in text for text in responses)
    assert _CANARY not in json.dumps(_all_rows(root))


# --- budget and hot path --------------------------------------------------------------------


def test_hook_chain_fits_the_challenge_budget_and_the_hook_timeout():
    """The hook-side twin of ``test_the_default_deadline_exceeds_the_worst_case_channel_chain``.

    One pass is the dashboard window, then the phone's wait, then the GUI dialog (its expiry
    is final, so the terminal never stacks on it). A proof tier runs two passes (confirm, then
    the code). Both must end inside the challenge ceiling, and that ceiling inside the
    host's hook timeout, or Claude Code kills the hook and the call fails open.
    """
    from doberman.auth.challenge import DEFAULT_CHALLENGE_TIMEOUT_S
    from doberman.hosthooks.install import HOOK_TIMEOUT_S

    one_pass = (
        dashboard_prompter.DEFAULT_TIMEOUT_S
        + ntfy.new_config().wait_s
        + gui_prompter.DEFAULT_DIALOG_TIMEOUT_S
    )
    assert one_pass * 2 <= DEFAULT_CHALLENGE_TIMEOUT_S < HOOK_TIMEOUT_S


def test_importing_and_passing_through_hookio_does_not_load_the_dashboard_prompter(tmp_path):
    code = (
        "import sys, json;"
        "from doberman.hosthooks.claude_code import run_pre_hook;"
        "run_pre_hook(json.dumps({'tool_name':'Bash','tool_input':{'command':'ls'},"
        f"'cwd':{str(tmp_path)!r}}}));"
        "print('doberman.auth.dashboard_prompter' in sys.modules)"
    )
    result = subprocess.run(  # noqa: S603 - our own interpreter and a fixed string
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
