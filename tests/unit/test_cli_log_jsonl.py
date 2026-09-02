"""`doberman log --jsonl` redaction-safe JSON Lines (#180)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import patch

from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage.log import record_decision

runner = CliRunner()

_NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)

# Planted in the raw target path below. `path_class()` drops the filename, so this
# value must never reach the JSONL stream — that is the whole redaction claim.
_SECRET = "AKIA-FAKE-JSONL-SECRET-4471"  # noqa: S105 — synthetic test value

# Mirrors `_DECISION_COLUMNS` in `doberman.storage.log`. Keeping the fake rows on the
# real column names is deliberate: an invented schema here hides field-name bugs in
# the command under test.
_ROWS = [
    {
        "id": 2,
        "ts": "2026-07-30T00:00:02Z",
        "action_id": "act-2",
        "agent_role": "backend",
        "action_type": "file_read",
        "target_path_class": "backend/secrets/*.env",
        "risk": "high",
        "source_context": "user",
        "final_verdict": "AUTH",
        "decided_layer": "objective",
        "reason_codes_json": '["sensitive_secret_access"]',
        "auth_required": 1,
        "auth_result": "denied",
        "elevation_id": None,
    },
    {
        "id": 1,
        "ts": "2026-07-30T00:00:01Z",
        "action_id": "act-1",
        "agent_role": "backend",
        "action_type": "file_read",
        "target_path_class": "src/**/*.py",
        "risk": "low",
        "source_context": "user",
        "final_verdict": "ALLOW",
        "decided_layer": "objective",
        "reason_codes_json": "[]",
        "auth_required": 0,
        "auth_result": None,
        "elevation_id": None,
    },
]


def _seed_secret_read(root: str) -> None:
    """Record one real decision whose raw target embeds `_SECRET`."""
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation="local secret access",
    )
    decision = Decision(
        action_id="act-1",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.high,
        objective=objective,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation="local secret access",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id="act-1",
        ts=_NOW,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="fs_read",
        target=f"backend/secrets/{_SECRET}.env",
        payload_fingerprints=["hmac:abc123"],
    )
    asyncio.run(record_decision(decision, action, repo_root=root, auth_result="denied"))


def test_log_jsonl_empty(tmp_path):
    import doberman.cli.main as main_mod

    async def _empty(*_a, **_k):
        return []

    with patch.object(main_mod, "read_decisions", _empty):
        result = runner.invoke(app, ["log", "--path", str(tmp_path), "--jsonl"])
    assert result.exit_code == 0
    assert result.stdout == ""


def test_log_jsonl_one_object_per_line_newest_first(tmp_path):
    import doberman.cli.main as main_mod

    async def _rows(*_a, **_k):
        return list(_ROWS)

    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path), "--jsonl", "--last", "20"])
    assert result.exit_code == 0
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    assert len(lines) == 2
    objs = [json.loads(ln) for ln in lines]
    assert objs[0]["ts"] == "2026-07-30T00:00:02Z"
    assert objs[0]["reason_codes"] == ["sensitive_secret_access"]
    assert "reason_codes_json" not in objs[0]
    assert objs[0]["target_path_class"] == "backend/secrets/*.env"


def test_log_jsonl_emits_the_risk_column(tmp_path):
    """`risk` is the real column name; a mismatched allowlist key drops it silently."""
    import doberman.cli.main as main_mod

    async def _rows(*_a, **_k):
        return list(_ROWS)

    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path), "--jsonl"])
    assert result.exit_code == 0
    objs = [json.loads(ln) for ln in result.stdout.splitlines() if ln.strip()]
    assert [o["risk"] for o in objs] == ["high", "low"]


def test_log_human_view_names_memory_approval(tmp_path):
    import doberman.cli.main as main_mod

    async def _rows(*_a, **_k):
        return [{**_ROWS[0], "auth_result": "soft_confirm+memory"}]

    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path)])

    assert result.exit_code == 0
    assert "approved via 5-minute memory (soft_confirm)" in result.stdout


def test_log_jsonl_never_emits_a_planted_secret(tmp_path):
    """Round-trip through the real storage layer with a secret in the raw target."""
    root = str(tmp_path)
    _seed_secret_read(root)

    result = runner.invoke(app, ["log", "--path", root, "--jsonl"])
    assert result.exit_code == 0

    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    assert len(lines) == 1
    obj = json.loads(lines[0])

    # The raw filename carried the secret; only its path CLASS may survive.
    assert _SECRET not in result.stdout
    assert obj["target_path_class"] == "backend/secrets/*.env"
    assert obj["final_verdict"] == "AUTH"
    assert obj["reason_codes"] == ["sensitive_secret_access"]
    assert obj["risk"] == "high"


def test_log_jsonl_omits_columns_outside_the_allowlist(tmp_path):
    """A column added to the table later must not leak into the stream by default."""
    import doberman.cli.main as main_mod

    async def _rows(*_a, **_k):
        return [{**_ROWS[0], "future_raw_column": "should-not-appear"}]

    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path), "--jsonl"])
    assert result.exit_code == 0
    assert "should-not-appear" not in result.stdout
    obj = json.loads(result.stdout.splitlines()[0])
    assert "future_raw_column" not in obj
    assert "source_context" not in obj


def test_log_last_zero_prints_no_rows(tmp_path):
    """`--last 0` asks for zero rows; truthiness used to turn it into ALL rows (#430)."""
    root = str(tmp_path)
    _seed_secret_read(root)

    result = runner.invoke(app, ["log", "--path", root, "--jsonl", "--last", "0"])
    assert result.exit_code == 0
    assert result.stdout == ""


def test_log_default_human_empty_message(tmp_path):
    import doberman.cli.main as main_mod

    async def _empty(*_a, **_k):
        return []

    with patch.object(main_mod, "read_decisions", _empty):
        result = runner.invoke(app, ["log", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "(no decisions recorded yet)" in result.stdout


def test_log_human_action_column_does_not_shift_for_long_types(tmp_path):
    """`network_request` is wider than `git_op`; both targets must align (#428)."""
    import doberman.cli.main as main_mod

    def _row(action_type: str, action_id: str, ts: str):
        return {
            "id": int(action_id.split("-")[1]),
            "ts": ts,
            "action_id": action_id,
            "agent_role": "backend",
            "action_type": action_type,
            "final_verdict": "ALLOW",
            "target_path_class": "src/**/*.py",
            "reason_codes_json": "[]",
            "auth_result": None,
        }

    async def _rows(*_a, **_k):
        return [
            _row("network_request", "act-2", "2026-07-30T00:00:02Z"),
            _row("git_op", "act-1", "2026-07-30T00:00:01Z"),
        ]

    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path)])

    assert result.exit_code == 0
    lines = [line for line in result.stdout.splitlines() if " src/**/*.py" in line]
    assert len(lines) == 2
    offsets = [line.index(" src/**/*.py") for line in lines]
    assert offsets[0] == offsets[1]


def test_log_why_prints_plain_summary_and_next_step_for_block_and_auth_rows(tmp_path):
    # round 4 design critique item 8: `doberman log --why` adds a
    # plain-language block and "Next" remedy the tui shows, under each
    # BLOCK/AUTH row only - `_ROWS[1]`'s "ALLOW" is neither, so it gets
    # nothing extra (an unrecognized/legacy verdict must never raise either).
    # Round 6 design critique item 7: that block is now `why_body` (what was
    # attempted + the reason description), not just the one-line
    # `first_sentence` - the row above already shows the verdict and the raw
    # reason code, so the old one-liner alone added nothing new.
    import doberman.cli.main as main_mod

    async def _rows(*_a, **_k):
        return list(_ROWS)

    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path), "--why"])
    assert result.exit_code == 0
    # Whitespace-normalized: `wrap_detail` wraps to the real terminal width, so
    # on a narrower CI runner "doberman dash" could otherwise land split across
    # two physical lines even though it now renders as one unbreakable phrase.
    normalized = " ".join(result.stdout.split())
    assert "Doberman decided AUTH after checking the rules." in normalized
    assert "backend attempted file_read on backend/secrets/*.env." in normalized
    assert "Reasons: the action touched a file recognized as holding secrets." in normalized
    # The trailing "(Checked by: ...)" aside is `template_explanation`'s, not
    # `why_body`'s - it adds nothing `doberman log`'s own row didn't already
    # say via the verdict/reason-code columns.
    assert "Checked by" not in normalized
    assert "Next: re-running the action asks again" in normalized
    assert "doberman dash" in normalized
    # Nothing is printed under the trailing "ALLOW" row.
    lines = result.stdout.splitlines()
    allow_index = next(i for i, ln in enumerate(lines) if ln.startswith("2026-07-30T00:00:01Z"))
    assert allow_index == len(lines) - 1


def test_log_why_on_a_block_row_includes_the_reason_description(tmp_path):
    # round 6 design critique item 7: `--why` must ADD information beyond
    # what `doberman log`'s own row already prints - specifically, the
    # human-readable reason description, not just the raw reason code the row
    # above already shows in brackets.
    import doberman.cli.main as main_mod

    block_row = {
        "id": 3,
        "ts": "2026-07-30T00:00:03Z",
        "action_id": "act-3",
        "agent_role": "cli",
        "action_type": "shell_exec",
        "target_path_class": None,
        "risk": "critical",
        "source_context": "user",
        "final_verdict": "BLOCK",
        "decided_layer": "objective",
        "reason_codes_json": '["destructive_command"]',
        "auth_required": 0,
        "auth_result": "blocked",
        "elevation_id": None,
    }

    async def _rows(*_a, **_k):
        return [block_row]

    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path), "--why"])
    assert result.exit_code == 0
    normalized = " ".join(result.stdout.split())
    assert "destructive_command" in normalized  # the row's own raw code, in brackets
    # The plain-English reason DESCRIPTION only comes from `--why`'s added block.
    assert "the command looked destructive" in normalized


def test_log_without_why_never_prints_the_extra_lines(tmp_path):
    import doberman.cli.main as main_mod

    async def _rows(*_a, **_k):
        return list(_ROWS)

    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Doberman decided" not in result.stdout
    assert "Next:" not in result.stdout
