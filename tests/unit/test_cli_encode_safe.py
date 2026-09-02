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


def test_setup_yes_output_is_ascii_and_cp1252_safe(tmp_path, monkeypatch):
    # The setup wizard prints section separators that used box-drawing rules.
    # Pin `doberman` as resolvable so the honest-end doctor pass reads this
    # wired-hooks run as complete (exit 0), same as test_cli_doctor.py's fixture.
    import shutil

    real_which = shutil.which
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name, *a, **k: (
            "/venv/bin/doberman" if name == "doberman" else real_which(name, *a, **k)
        ),
    )
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.output.isascii(), f"non-ASCII in setup output: {result.output!r}"
    result.output.encode("cp1252")


def test_setup_incomplete_output_is_ascii_and_cp1252_safe(tmp_path, monkeypatch):
    # The honest-end "-- Setup incomplete --" path prints different body text
    # (the doctor remediation, no activation claim); it must stay just as safe.
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 1, result.output
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


def test_doctor_output_is_ascii_and_cp1252_safe(tmp_path, monkeypatch):
    # doctor's own detail strings carried an em dash in several checks (2FA /
    # Password "not set" warnings, among others) - assert the whole checklist
    # stays ASCII/cp1252 safe, on both a bare (unhealthy) repo and one
    # `setup --yes` already wired (round 4 item 16).
    import shutil

    real_which = shutil.which
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name, *a, **k: (
            "/venv/bin/doberman" if name == "doberman" else real_which(name, *a, **k)
        ),
    )
    bare = runner.invoke(app, ["doctor", "--path", str(tmp_path)])
    assert bare.output.isascii(), f"non-ASCII in doctor output: {bare.output!r}"
    bare.output.encode("cp1252")

    wired = tmp_path / "wired"
    wired.mkdir()
    setup_result = runner.invoke(app, ["setup", "--yes", "--path", str(wired)])
    assert setup_result.exit_code == 0, setup_result.output
    result = runner.invoke(app, ["doctor", "--path", str(wired)])
    assert result.exit_code == 0, result.output
    assert result.output.isascii(), f"non-ASCII in doctor output: {result.output!r}"
    result.output.encode("cp1252")


def test_bad_mode_choice_error_is_ascii():
    """The setup mode prompt error must remain pure ASCII."""
    with pytest.raises(ValueError) as excinfo:
        parse_mode_choice("99")

    assert str(excinfo.value).isascii()
