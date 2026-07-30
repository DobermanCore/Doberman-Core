"""`doberman log --jsonl` redaction-safe JSON Lines (#180)."""

from __future__ import annotations

import json
from unittest.mock import patch

from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()

_ROWS = [
    {
        "ts": "2026-07-30T00:00:02Z",
        "final_verdict": "AUTH",
        "action_type": "file_read",
        "target_path_class": "backend/secrets/*.env",
        "reason_codes_json": '["sensitive_secret_access"]',
        "auth_result": "denied",
        "id": 2,
        "agent_role": "backend",
        "tool_name": "fs_read",
        "final_risk": "high",
        "explanation": "local secret access",
    },
    {
        "ts": "2026-07-30T00:00:01Z",
        "final_verdict": "ALLOW",
        "action_type": "file_read",
        "target_path_class": "src/**/*.py",
        "reason_codes_json": "[]",
        "auth_result": None,
        "id": 1,
        "agent_role": "backend",
        "tool_name": "fs_read",
        "final_risk": "low",
        "explanation": "ok",
    },
]


def test_log_jsonl_empty(tmp_path):
    with patch("doberman.cli.main.read_decisions", return_value=[]):
        # read_decisions is awaited via asyncio.run — patch at storage import site
        pass
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

    secret = "AKIA-FAKE-SECRET-SHOULD-NEVER-APPEAR"  # noqa: S105
    with patch.object(main_mod, "read_decisions", _rows):
        result = runner.invoke(app, ["log", "--path", str(tmp_path), "--jsonl", "--last", "20"])
    assert result.exit_code == 0
    assert secret not in result.stdout
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    assert len(lines) == 2
    objs = [json.loads(ln) for ln in lines]
    assert objs[0]["ts"] == "2026-07-30T00:00:02Z"
    assert objs[0]["reason_codes"] == ["sensitive_secret_access"]
    assert isinstance(objs[0]["reason_codes"], list)
    assert "reason_codes_json" not in objs[0]
    assert objs[0]["target_path_class"] == "backend/secrets/*.env"


def test_log_default_human_empty_message(tmp_path):
    import doberman.cli.main as main_mod

    async def _empty(*_a, **_k):
        return []

    with patch.object(main_mod, "read_decisions", _empty):
        result = runner.invoke(app, ["log", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "(no decisions recorded yet)" in result.stdout
