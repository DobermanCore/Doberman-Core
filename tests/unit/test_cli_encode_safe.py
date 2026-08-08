"""Windows onboarding fix: CLI output must never crash on a non-UTF-8 console.

The default Windows console is cp1252; printing a non-ASCII character (an arrow,
a box-drawing rule, an emoji) there raised ``UnicodeEncodeError`` and crashed
``doberman install-hooks`` / ``setup`` for any such user. Two guarantees:

1. ``_ensure_encode_safe_stdio`` reconfigures stdout/stderr so output can never
   crash on the console encoding (the universal safety net).
2. Onboarding output is ASCII, so it also *renders* cleanly on any console.
"""

import io
import sys

import pytest
from typer.testing import CliRunner

from doberman.cli.main import _ensure_encode_safe_stdio, app
from doberman.hosthooks.setup import parse_mode_choice

runner = CliRunner()


def test_encode_safe_stdio_prevents_cp1252_crash(monkeypatch):
    # A strict cp1252 stream raises on an arrow / box rule / emoji; after the
    # safe-guard reconfigures it, writing those must NOT raise.
    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    err = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)

    _ensure_encode_safe_stdio()

    sys.stdout.write("→ ─ \U0001f415")  # arrow, box rule, dog emoji
    sys.stderr.write("→")
    sys.stdout.flush()
    sys.stderr.flush()


def test_install_hooks_dry_run_output_is_ascii_and_cp1252_safe(tmp_path):
    # The onboarding command that crashed on Windows: its output must be ASCII
    # (renders everywhere) and cp1252-encodable (never raises on the default
    # Windows console).
    result = runner.invoke(app, ["install-hooks", "--dry-run", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.output.isascii(), f"non-ASCII in onboarding output: {result.output!r}"
    result.output.encode("cp1252")  # raises if any char is not cp1252-encodable


def test_setup_yes_output_is_ascii_and_cp1252_safe(tmp_path):
    # The setup wizard prints section separators that used box-drawing rules.
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.output.isascii(), f"non-ASCII in setup output: {result.output!r}"
    result.output.encode("cp1252")


def test_2fa_remove_warning_output_is_ascii(monkeypatch):
    """The post-removal warning must stay pure ASCII (cp1252 consoles)."""
    from doberman.cli import main as main_mod

    class FakePrompter:
        def confirm(self, message: str) -> bool:
            return True

        def read_code(self, label: str) -> str:
            return "123456"

    monkeypatch.setattr(main_mod.totp, "is_enrolled", lambda: True)
    monkeypatch.setattr(main_mod.totp, "unenroll", lambda current_code: None)
    monkeypatch.setattr(main_mod.password, "is_enrolled", lambda: False)
    monkeypatch.setattr(main_mod, "CliPrompter", lambda: FakePrompter())

    result = runner.invoke(app, ["2fa", "remove"])

    assert result.exit_code == 0, result.output
    assert result.output.isascii(), f"non-ASCII in 2fa remove output: {result.output!r}"


def test_bad_mode_choice_error_is_ascii():
    """The setup mode prompt error must remain pure ASCII."""
    with pytest.raises(ValueError) as excinfo:
        parse_mode_choice("99")

    assert str(excinfo.value).isascii()
