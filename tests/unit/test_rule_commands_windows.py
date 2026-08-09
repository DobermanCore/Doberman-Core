"""Windows/PowerShell destructive-command coverage (Codex-on-Windows live-test fix).

Live testing of the Codex CLI integration on Windows proved `Remove-Item
sentinel.txt` (and any PowerShell/cmd delete) passed unmediated — the
destructive-command vocabulary in ``commands.py`` was POSIX-only (``rm``,
``dd``, ``mkfs``, ``git``). These tests cover the Windows-verb classifier added
to close that gap: it maps Remove-Item/del/rd/... onto the SAME severity ladder
as ``rm`` (catastrophic BLOCK, bulk/unrecoverable-data AUTH) — never a second
policy — plus opaque PowerShell/cmd payload handling and the Windows disk-wipe
names. See ``tests/unit/test_rule_commands.py`` for the POSIX baseline this
mirrors.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

RULE = DestructiveCommandRule()


def _cmd(command, *, action_type=ActionType.shell_exec):
    action = SecurityObject(
        id="cmd-win-1",
        ts=datetime(2026, 8, 9, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="shell_exec",
        target=command,
    )
    ctx = EvalContext(metadata={"raw_arguments": {"command": command}})
    return RULE.evaluate(action, ctx)


# --- parity with rm: a single benign delete passes --------------------------


@pytest.mark.parametrize("command", ["Remove-Item sentinel.txt", "del a.txt"])
def test_single_benign_delete_passes(command):
    assert _cmd(command).verdict is Verdict.PASS


# --- unrecoverable, gitignored data -> AUTH ----------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "Remove-Item .env",
        r"Remove-Item .\.env",
        "del /q .env",
        "Clear-Content .env",
    ],
)
def test_unrecoverable_data_delete_requires_auth(command):
    result = _cmd(command)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.destructive_command in result.reason_codes


def test_rm_with_backslash_operand_matches_unrecoverable_basename():
    # Backslash-basename fix: `rm subdir\.env` must extract basename ".env",
    # not the shlex-mangled "subdir.env" (backslash silently eaten as a POSIX
    # escape char without the Windows-path normalization).
    result = _cmd(r"rm subdir\.env")
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.destructive_command in result.reason_codes


# --- catastrophic recursive+force at root/home -> BLOCK ----------------------


@pytest.mark.parametrize(
    "command",
    [
        "Remove-Item -Recurse -Force ~",
        "remove-item -r -fo C:\\",
        "rd /s /q C:\\",
    ],
)
def test_catastrophic_recursive_force_delete_blocks(command):
    result = _cmd(command)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.destructive_command in result.reason_codes


# --- opaque PowerShell/cmd payloads -------------------------------------


def test_powershell_command_payload_is_scanned_and_blocks():
    # -Command's body is scannable — a hidden catastrophic delete inside it
    # raises the opaque AUTH to BLOCK, mirroring `bash -c "rm -rf /"`.
    result = _cmd('powershell -Command "Remove-Item -Recurse -Force ~"')
    assert result.verdict is Verdict.BLOCK


def test_pwsh_short_command_flag_escalates_to_auth():
    result = _cmd('pwsh -c "echo hi"')
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.opaque_command in result.reason_codes


def test_powershell_encoded_command_is_opaque_with_no_body_scan():
    # -EncodedCommand is base64 — cannot decode/vet it, so it stays a plain
    # opaque AUTH (no body-scan escalation is possible here).
    result = _cmd("powershell -EncodedCommand AAAA")
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.opaque_command in result.reason_codes


# --- bulk delete ---------------------------------------------------------


def test_bulk_windows_delete_at_threshold_requires_auth():
    paths = " ".join(f"file{i}.txt" for i in range(30))
    result = _cmd(f"Remove-Item {paths}")
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.bulk_operation in result.reason_codes


# --- Windows disk-wipe ----------------------------------------------------


def test_format_volume_blocks():
    result = _cmd("Format-Volume -DriveLetter C")
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.destructive_command in result.reason_codes
