"""Round 8 item P1 - `doberman mode <lower>` names the WHOLE remedy path in
one line when nothing is enrolled at all (a bare "then retry" would just fail
closed again with no factor to satisfy the gate). With a factor already
enrolled but the interactive prompt declined, a retry genuinely IS the whole
fix, so that message is unchanged.
"""

from typer.testing import CliRunner

from doberman.auth import password
from doberman.cli.main import app
from doberman.config import load_mode

runner = CliRunner()
_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover -- never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


def test_lowering_with_nothing_enrolled_names_the_whole_path(tmp_path):
    root = str(tmp_path)
    result = runner.invoke(app, ["mode", "light", "--path", root])

    assert result.exit_code == 1
    assert (
        "error: lowering needs a possession factor: run 'doberman password set', "
        "then 'doberman mode light'" in result.output
    )
    assert load_mode(root) == "balanced"


def test_lowering_with_a_factor_enrolled_but_declined_keeps_the_retry_message(
    tmp_path, monkeypatch
):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    monkeypatch.setattr("doberman.auth.provider.CliPrompter", _Decline)

    result = runner.invoke(app, ["mode", "light", "--path", root])

    assert result.exit_code == 1
    assert (
        "error: lowering needs a possession factor - run 'doberman password set' "
        "first, then retry" in result.output
    )
    assert "then 'doberman mode light'" not in result.output
    assert load_mode(root) == "balanced"


def test_raising_is_unaffected_and_never_mentions_a_possession_factor(tmp_path):
    """Sanity check: the refusal-message rework above only touches the
    denied-lowering branch - a raise still applies frictionlessly."""
    root = str(tmp_path)
    result = runner.invoke(app, ["mode", "strict", "--path", root])

    assert result.exit_code == 0, result.output
    assert "possession factor" not in result.output
    assert load_mode(root) == "strict"
