"""#759: a save never overwrites a ``policies.yaml`` that failed to parse.

A corrupt ``.doberman/policies.yaml`` reads as an approval-memory TTL of 0 (fail
closed). Every save path loads the policy with a fallback to the recommended
defaults, so saving over the corrupt file would write the default TTL of 300
with no gate and no ledger row. ``save_policy`` refuses instead, naming the
file, and every command that saves the policy refuses before it runs the weaken
gate or writes a ledger row, exiting non-zero with the file left untouched.
"""

import asyncio

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.config import (
    PolicyFileUnreadableError,
    ensure_policy_saveable,
    load_approval_memory_seconds,
    load_policy,
    save_policy,
)
from doberman.policy.checklist import recommend_policy
from doberman.policy.drift import apply_mode_change, read_policy_changes

runner = CliRunner()

_CORRUPT = "mode: [unterminated\n"

_CORRUPT_CONTENTS = (
    ("invalid YAML", _CORRUPT),
    ("not a mapping", "- just\n- a list\n"),
    ("an invalid policy", "items: 7\n"),
)


def _write_policy_file(root, contents: str):
    policy_file = root / ".doberman" / "policies.yaml"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text(contents, encoding="utf-8")
    return policy_file


class _RecordingPrompter:
    """Approves everything, and records that the gate asked at all."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def confirm(self, message: str) -> bool:
        self.calls.append(message)
        return True

    def read_code(self, message: str) -> str:
        self.calls.append(message)
        return "000000"


@pytest.mark.parametrize(("_kind", "contents"), _CORRUPT_CONTENTS)
def test_save_refuses_to_overwrite_an_unreadable_policy_file(tmp_path, _kind, contents):
    policy_file = _write_policy_file(tmp_path, contents)
    assert load_approval_memory_seconds(str(tmp_path)) == 0  # the fail-closed reading

    with pytest.raises(PolicyFileUnreadableError, match="policies.yaml"):
        save_policy(recommend_policy(), str(tmp_path))

    assert policy_file.read_text(encoding="utf-8") == contents
    assert load_approval_memory_seconds(str(tmp_path)) == 0


def test_a_missing_or_readable_policy_is_saveable(tmp_path):
    ensure_policy_saveable(str(tmp_path))  # no file yet
    save_policy(recommend_policy(), str(tmp_path))
    ensure_policy_saveable(str(tmp_path))  # a readable file


def test_save_still_writes_a_first_policy(tmp_path):
    save_policy(recommend_policy().with_message_tone("technical"), str(tmp_path))
    assert load_policy(str(tmp_path)).message_tone == "technical"


def test_save_still_replaces_a_readable_policy(tmp_path):
    save_policy(recommend_policy(), str(tmp_path))
    save_policy(recommend_policy().with_message_tone("technical"), str(tmp_path))
    assert load_policy(str(tmp_path)).message_tone == "technical"


def _assert_refused_cleanly(result, policy_file, root) -> None:
    assert result.exit_code == 2, result.output
    assert isinstance(result.exception, SystemExit)  # a one-line error, not a traceback
    assert "policies.yaml" in result.stderr
    assert policy_file.read_text(encoding="utf-8") == _CORRUPT
    assert load_approval_memory_seconds(str(root)) == 0
    assert asyncio.run(read_policy_changes(str(root))) == []  # refused before the ledger


@pytest.mark.parametrize(
    "args",
    [
        ["message-tone", "technical"],
        ["mode", "strict"],
        ["review", "--yes"],
    ],
    ids=["message-tone", "raise-mode", "review-yes"],
)
def test_ungated_save_over_a_corrupt_policy_fails_and_leaves_it_unchanged(tmp_path, args):
    policy_file = _write_policy_file(tmp_path, _CORRUPT)

    result = runner.invoke(app, [*args, "--path", str(tmp_path)])

    _assert_refused_cleanly(result, policy_file, tmp_path)


@pytest.mark.parametrize(
    "args",
    [
        ["approvals", "ttl", "600"],
        ["mode", "light"],
        ["enforcement", "monitor"],
        ["role", "enable-default"],
        ["prefs", "confidentiality", "0.1"],
        ["egress-velocity", "burst", "100"],
        ["setup", "--yes", "--host", "claude"],
    ],
    ids=[
        "approvals-ttl",
        "lower-mode",
        "enforcement",
        "role-enable-default",
        "prefs",
        "egress-velocity",
        "setup",
    ],
)
def test_gated_save_over_a_corrupt_policy_refuses_before_the_gate(tmp_path, args):
    policy_file = _write_policy_file(tmp_path, _CORRUPT)

    # "y" would confirm a gate prompt; the command must refuse before reading it.
    result = runner.invoke(app, [*args, "--path", str(tmp_path)], input="y\n")

    _assert_refused_cleanly(result, policy_file, tmp_path)
    assert "weaken" not in result.output.lower()  # the gate's diff was never shown


def test_setup_dry_run_still_previews_over_a_corrupt_policy(tmp_path):
    policy_file = _write_policy_file(tmp_path, _CORRUPT)

    result = runner.invoke(
        app, ["setup", "--yes", "--dry-run", "--host", "claude", "--path", str(tmp_path)]
    )

    assert "refusing to overwrite" not in result.output
    assert policy_file.read_text(encoding="utf-8") == _CORRUPT


@pytest.mark.parametrize("establish_ok", [False, True], ids=["gated", "first-run"])
async def test_apply_mode_change_refuses_before_the_gate_and_the_ledger(tmp_path, establish_ok):
    # The shared chokepoint behind `doberman mode`, `setup` and the dashboard's
    # /api/mode. A corrupt file loads as None, which the first-run branch would
    # otherwise read as "no policy yet" and establish without the gate.
    policy_file = _write_policy_file(tmp_path, _CORRUPT)
    prompter = _RecordingPrompter()

    with pytest.raises(PolicyFileUnreadableError, match="policies.yaml"):
        await apply_mode_change(
            "light", str(tmp_path), "test", prompter=prompter, establish_ok=establish_ok
        )

    assert prompter.calls == []
    assert await read_policy_changes(str(tmp_path)) == []
    assert policy_file.read_text(encoding="utf-8") == _CORRUPT


def test_dashboard_mode_change_over_a_corrupt_policy_is_a_400(tmp_path):
    from starlette.testclient import TestClient

    from doberman.dash.app import create_app

    token = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret
    policy_file = _write_policy_file(tmp_path, _CORRUPT)
    client = TestClient(create_app(token, str(tmp_path)))

    resp = client.post(
        "/api/mode", headers={"Authorization": f"Bearer {token}"}, json={"mode": "strict"}
    )

    assert resp.status_code == 400
    assert "policies.yaml" in resp.json()["error"]
    assert policy_file.read_text(encoding="utf-8") == _CORRUPT
    assert asyncio.run(read_policy_changes(str(tmp_path))) == []
