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
    ("policy-file",),
    ("enforcement",),
    ("prefs",),
    ("egress-velocity",),
    ("message-tone",),
    ("role",),
    ("role", "enable-default"),
    ("role", "disable-default"),
    ("status",),
    ("doctor",),
    ("update",),
    ("revoke",),
    ("log",),
    ("decision-log-prune",),
    ("tui",),
    ("dash",),
    ("demo",),
    ("memory",),
    ("memory", "reset"),
    ("memory", "prune"),
    ("memory", "seed"),
    ("policy-history",),
    ("policy-versions",),
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
    ("plugins",),
    ("plugins", "list"),
    ("plugins", "enable"),
    ("plugins", "disable"),
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
    ("hook", "cursor"),
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


def test_no_unlabeled_commands_panel_and_getting_started_leads():
    """Every command has an explicit `rich_help_panel` (item 3) - the unlabeled
    "Commands" panel Typer/Rich prints first is empty, so the first panel
    actually rendered is "Getting started", not a grab-bag of groups."""
    root_output = _normalize_help_output(
        runner.invoke(app, ["--help"], env={"FORCE_COLOR": "1"}).output
    )
    assert "Getting started" in root_output
    getting_started_idx = root_output.index("Getting started")
    for later in ("Advanced", "2fa", "taint", "plugins"):
        assert getting_started_idx < root_output.index(later), (
            f"Getting started should render before {later!r}"
        )


def test_getting_started_panel_leads_with_setup_then_demo():
    """`setup` (the guided path) leads "Getting started", `demo` (the best
    onboarding asset) follows it - both ahead of doctor/install-hooks/update."""
    root_output = _normalize_help_output(
        runner.invoke(app, ["--help"], env={"FORCE_COLOR": "1"}).output
    )
    ordered_names = ["setup", "demo", "doctor", "install-hooks", "update"]
    positions = [root_output.index(name) for name in ordered_names]

    assert positions == sorted(positions)


def test_demo_is_filed_under_getting_started():
    demo_panel = next(
        c.rich_help_panel for c in app.registered_commands if c.callback.__name__ == "demo"
    )

    assert demo_panel == "Getting started"


def test_removal_commands_get_their_own_leaving_panel():
    panels_by_name = {
        (c.name or c.callback.__name__.replace("_", "-")): c.rich_help_panel
        for c in app.registered_commands
    }

    assert panels_by_name["uninstall-hooks"] == "Leaving"
    assert panels_by_name["uninstall"] == "Leaving"


def test_install_hooks_help_points_back_to_setup():
    result = runner.invoke(app, ["install-hooks", "--help"], env={"FORCE_COLOR": "1"})

    assert "doberman setup" in _normalize_help_output(result.output)


def test_policy_panel_split_from_policy_internals():
    """round 5 item 10: the old "Policy" panel held every policy-shaped
    command (10+ items) in one wall of text - it now splits into the few
    essentials (`mode`/`review`/`role`) and a "Policy internals" panel for
    the rest, `taint`/`tools` included (moved out of the equally overloaded
    "Advanced" panel)."""
    panels_by_name = {
        (c.name or c.callback.__name__.replace("_", "-")): c.rich_help_panel
        for c in app.registered_commands
    }
    assert panels_by_name["mode"] == "Policy"
    assert panels_by_name["review"] == "Policy"
    assert panels_by_name["enforcement"] == "Policy internals"
    assert panels_by_name["prefs"] == "Policy internals"
    assert panels_by_name["egress-velocity"] == "Policy internals"
    assert panels_by_name["message-tone"] == "Policy internals"
    assert panels_by_name["policy-history"] == "Policy internals"
    assert panels_by_name["policy-versions"] == "Policy internals"

    groups_by_name = {g.name: g.rich_help_panel for g in app.registered_groups}
    assert groups_by_name["role"] == "Policy"
    assert groups_by_name["taint"] == "Policy internals"
    assert groups_by_name["tools"] == "Policy internals"


def test_root_help_shows_both_policy_panels_with_getting_started_still_first():
    root_output = _normalize_help_output(
        runner.invoke(app, ["--help"], env={"FORCE_COLOR": "1"}).output
    )
    getting_started_idx = root_output.index("Getting started")
    assert getting_started_idx < root_output.index("Policy internals")
    assert "Policy internals" in root_output
    # The plain "Policy" panel heading, not just its "Policy internals" cousin.
    policy_heading_idx = root_output.index("Policy ─")
    assert getting_started_idx < policy_heading_idx
