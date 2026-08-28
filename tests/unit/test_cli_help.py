"""Smoke-test help rendering for every public CLI command and group."""

import re

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from doberman.cli.main import app

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Keep this explicit matrix synchronized with every public command and group,
# including dynamically discovered commands that are absent from `.commands`.
CLI_HELP_TARGETS = (
    (),
    ("serve",),
    ("scan",),
    ("review",),
    ("mode",),
    ("enforcement",),
    ("prefs",),
    ("egress-velocity",),
    ("message-tone",),
    ("role",),
    ("role", "enable-default"),
    ("role", "disable-default"),
    ("status",),
    ("doctor",),
    ("revoke",),
    ("log",),
    ("decision-log-prune",),
    ("tui",),
    ("dash",),
    ("demo",),
    ("memory",),
    ("memory", "reset"),
    ("memory", "prune"),
    ("policy-history",),
    ("tune",),
    ("install-hooks",),
    ("uninstall-hooks",),
    ("uninstall",),
    ("setup",),
    ("telemetry",),
    ("telemetry", "on"),
    ("telemetry", "off"),
    ("telemetry", "status"),
    ("session-summary",),
    ("dashboard",),
    ("version",),
    ("approvals",),
    ("approvals", "status"),
    ("approvals", "clear"),
    ("approvals", "ttl"),
    ("2fa",),
    ("2fa", "setup"),
    ("2fa", "remove"),
    ("2fa", "reset-lockout"),
    ("2fa", "methods"),
    ("2fa", "methods", "list"),
    ("2fa", "methods", "enable"),
    ("2fa", "methods", "disable"),
    ("2fa", "methods", "status"),
    ("password",),
    ("password", "set"),
    ("hook",),
    ("hook", "pre"),
    ("hook", "post"),
    ("hook", "openclaw"),
    ("hook", "codex-pre"),
    ("taint",),
    ("taint", "clear"),
    ("tools",),
    ("tools", "approve"),
)

runner = CliRunner()


def _eager_command_paths(command, prefix=()):
    yield prefix
    for name, child in getattr(command, "commands", {}).items():
        yield from _eager_command_paths(child, (*prefix, name))


def _target_id(command_path):
    return "root" if not command_path else " ".join(command_path)


def _expected_usage(command_path):
    return "Usage: root" + "".join(f" {name}" for name in command_path)


def _normalize_help_output(output):
    return " ".join(ANSI_ESCAPE.sub("", output).split())


def test_cli_help_targets_cover_every_eager_command_and_group():
    registered = set(_eager_command_paths(get_command(app)))

    assert len(CLI_HELP_TARGETS) == len(set(CLI_HELP_TARGETS))
    assert registered <= set(CLI_HELP_TARGETS)


@pytest.mark.parametrize("command_path", CLI_HELP_TARGETS, ids=_target_id)
def test_cli_help_renders_without_a_traceback(command_path):
    result = runner.invoke(
        app,
        [*command_path, "--help"],
        env={"FORCE_COLOR": "1"},
    )
    normalized_output = _normalize_help_output(result.output)

    assert result.exit_code == 0, result.output
    assert _expected_usage(command_path) in normalized_output
    assert "Traceback" not in result.output


def test_dashboard_alias_is_hidden_from_root_help():
    root_command = get_command(app)

    assert root_command.commands["session-summary"].hidden is False
    assert root_command.commands["dashboard"].hidden is True
