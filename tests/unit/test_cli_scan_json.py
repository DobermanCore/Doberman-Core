"""`doberman scan --json` and `--quiet` (#178, #187)."""

from __future__ import annotations

import json
from unittest.mock import patch

from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.discovery.scan import Capability
from doberman.models import Risk

runner = CliRunner()


def _caps() -> list[Capability]:
    return [
        Capability(name="shell", category="tool", present=True, evidence=("bash",), risk=Risk.high),
        Capability(
            name="dotenv_visible",
            category="surface",
            present=True,
            evidence=(".env",),
            risk=Risk.medium,
        ),
        # Sorts before "dotenv_visible" by name but after it by category, so a
        # name-only sort and the documented (category, name) sort disagree here.
        Capability(
            name="aws_cli", category="tool", present=True, evidence=("aws",), risk=Risk.high
        ),
    ]


def test_scan_json_is_one_document_and_sorted(tmp_path):
    with (
        patch("doberman.cli.main.enumerate_capabilities", return_value=_caps()),
        patch("doberman.cli.main.rate_capabilities", side_effect=lambda c: c),
    ):
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["version"] == 1
    # docs/CLI.md promises "sorted by (category, name)" — assert that exact key.
    pairs = [(c["category"], c["name"]) for c in payload["capabilities"]]
    assert pairs == sorted(pairs), f"capabilities not sorted by (category, name): {pairs}"
    assert all("evidence" in c for c in payload["capabilities"])
    # deterministic separators / keys
    with (
        patch("doberman.cli.main.enumerate_capabilities", return_value=_caps()),
        patch("doberman.cli.main.rate_capabilities", side_effect=lambda c: c),
    ):
        again = runner.invoke(app, ["scan", "--path", str(tmp_path), "--json"])
    assert again.stdout == result.stdout


def test_scan_quiet_empty_stdout(tmp_path):
    with (
        patch("doberman.cli.main.enumerate_capabilities", return_value=[]),
        patch("doberman.cli.main.rate_capabilities", side_effect=lambda c: c),
    ):
        quiet = runner.invoke(app, ["scan", "--path", str(tmp_path), "--quiet"])
        loud = runner.invoke(app, ["scan", "--path", str(tmp_path)])
    assert quiet.exit_code == loud.exit_code == 0
    assert quiet.stdout == ""
    assert loud.stdout != ""


def test_scan_default_not_json(tmp_path):
    with (
        patch("doberman.cli.main.enumerate_capabilities", return_value=[]),
        patch("doberman.cli.main.rate_capabilities", side_effect=lambda c: c),
    ):
        result = runner.invoke(app, ["scan", "--path", str(tmp_path)])
    assert result.exit_code == 0
    # human map is not JSON
    try:
        json.loads(result.stdout)
    except json.JSONDecodeError:
        pass
    else:
        raise AssertionError("default scan should not be raw JSON")


def test_scan_json_wins_over_quiet(tmp_path):
    """`--json` still prints JSON when combined with `--quiet` (#225)."""
    with (
        patch("doberman.cli.main.enumerate_capabilities", return_value=_caps()),
        patch("doberman.cli.main.rate_capabilities", side_effect=lambda c: c),
    ):
        both = runner.invoke(app, ["scan", "--path", str(tmp_path), "--json", "--quiet"])
        json_only = runner.invoke(app, ["scan", "--path", str(tmp_path), "--json"])
    assert both.exit_code == json_only.exit_code == 0
    payload = json.loads(both.stdout)
    assert payload["version"] == 1
    assert isinstance(payload["capabilities"], list)
    # Quiet must not suppress machine-readable output.
    assert both.stdout.strip() != ""
    assert json.loads(both.stdout) == json.loads(json_only.stdout)
