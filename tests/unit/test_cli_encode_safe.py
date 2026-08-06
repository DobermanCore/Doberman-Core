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

import pyotp
from typer.testing import CliRunner

from doberman.auth import totp
from doberman.cli.main import _ensure_encode_safe_stdio, app

runner = CliRunner()


def _current_code() -> str:
    """A code for the live enrollment on the real clock (same as test_2fa_remove)."""
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


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


def test_2fa_remove_warning_is_ascii_and_cp1252_safe():
    # The 2fa remove path warns when no possession factor remains; that warning
    # used an em-dash and must stay ASCII like the rest of onboarding.
    totp.enroll()

    result = runner.invoke(app, ["2fa", "remove"], input=f"y\n{_current_code()}\n")

    assert result.exit_code == 0, result.output
    assert "will be denied" in result.stderr
    output = result.output + result.stderr
    assert output.isascii(), f"non-ASCII in 2fa remove output: {output!r}"
    output.encode("cp1252")  # raises if any char is not cp1252-encodable


def test_setup_bad_mode_choice_error_is_ascii_and_cp1252_safe(tmp_path):
    # An out-of-range numeric mode choice surfaces parse_mode_choice's error
    # message (which used an en-dash); it must be ASCII too. Since #266 the
    # wizard re-prompts instead of dying, so feed a valid choice after the
    # invalid one and let the run complete.
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="9\nbalanced\nn\nn\n",
    )

    assert result.exit_code == 0, result.output
    assert "choose 1-4 or type a mode name" in result.output
    output = result.output + result.stderr
    assert output.isascii(), f"non-ASCII in setup error output: {output!r}"
    output.encode("cp1252")  # raises if any char is not cp1252-encodable
