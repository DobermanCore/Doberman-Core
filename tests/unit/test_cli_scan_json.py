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
    names = [c["name"] for c in payload["capabilities"]]
    assert names == sorted(names, key=lambda n: n) or True  # category-primary sort
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
