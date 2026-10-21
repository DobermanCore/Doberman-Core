"""Run the shipped OrcaRouter evidence capture through the project's test runner.

``scripts/orcarouter_evidence.py`` starts the real dashboard, drives it in
headless Chromium and writes ``orca-evidence/manifest.json`` plus the three
screenshots. It is a script, not a test, so this module is the pytest entry
point: it executes the script as a subprocess in a fresh interpreter, then
reads the artifacts the run produced and checks them. Nothing here writes the
manifest itself — a fabricated manifest must never be able to pass this test.

``orca-evidence/`` is generated output and is never committed; this test is
what produces it (CI uploads the directory as a build artifact). The module is
skipped when the optional GUI toolchain (Playwright plus a Chromium binary) is
absent, which is the case for the standard CI install; the release validator
installs both and runs the module for real.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess  # noqa: S404 - running the repo's own script, fixed argv
import sys
from pathlib import Path

import pytest

pytest.importorskip("playwright", reason="the GUI evidence run needs Playwright")

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = REPO_ROOT / "orca-evidence"
SCRIPT = REPO_ROOT / "scripts" / "orcarouter_evidence.py"
CHROMIUM = "/usr/bin/chromium"
SHOTS = ("auth-methods.png", "text-model-dropdown.png", "multimodal-model-dropdown.png")

pytestmark = pytest.mark.skipif(
    not Path(CHROMIUM).exists(), reason=f"no Chromium binary at {CHROMIUM}"
)


def _png_size(path: Path) -> tuple[int, int]:
    header = path.read_bytes()[:24]
    assert header[:8] == b"\x89PNG\r\n\x1a\n", path.name
    width, height = struct.unpack(">II", header[16:24])
    return width, height


def _child_env() -> dict[str, str]:
    """Give the fresh interpreter the import path this process is using.

    The suite's ``isolated_user_home`` fixture moves HOME to a throwaway
    directory, so a child started with the inherited environment no longer
    sees dependencies installed in the real HOME's user site-packages (the
    dashboard's ``uvicorn``/``starlette``) and dies on import. Exporting the
    parent's ``sys.path`` keeps the child on exactly the install this test
    run is validated against, whatever interpreter prefix or venv it is in.
    """
    env = dict(os.environ)
    entries = [entry for entry in sys.path if entry]
    env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(entries))
    return env


def test_the_repository_regenerates_its_dashboard_evidence():
    result = subprocess.run(  # noqa: S603 - our interpreter, a fixed script path
        [sys.executable, str(SCRIPT)],
        cwd=str(REPO_ROOT),
        env=_child_env(),
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, result.stderr[-4000:]

    manifest = json.loads((EVIDENCE / "manifest.json").read_text())
    automation = manifest["automation"]
    assert automation["framework"] == "playwright"
    assert automation["passed"] is True, manifest["artifacts"]
    assert automation["catalog_source"] == "https://api.orcarouter.ai/v1/models?capability=chat"
    assert automation["catalog_state"] == "live"
    assert automation["catalog_model_count"] > 0
    assert automation["image_model_count"] > 0

    by_kind = {item["kind"]: item for item in manifest["artifacts"]}
    assert set(by_kind) == {"auth-methods", "text-model-dropdown", "multimodal-model-dropdown"}

    auth = by_kind["auth-methods"]["ui"]
    assert auth["api_key_visible"] is True
    assert auth["secret_masked"] is True
    assert auth["controls_enabled"] is True
    assert auth["provider_selected"] == "orcarouter"

    for kind, expected in (
        ("text-model-dropdown", automation["catalog_model_count"]),
        ("multimodal-model-dropdown", automation["image_model_count"]),
    ):
        ui = by_kind[kind]["ui"]
        assert ui["dropdown_open"] is True, kind
        assert ui["item_count"] == expected, kind
        assert ui["opaque_background"] is True, kind
        assert ui["visible_border"] is True, kind
        assert ui["trigger_panel_right_delta"] <= 2, kind

    for name in SHOTS:
        path = EVIDENCE / name
        assert path.is_file(), name
        record = next(item for item in manifest["artifacts"] if item["path"] == name)
        assert len(record["sha256"]) == 64, name
        assert record["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        width, height = _png_size(path)
        assert (width, height) >= (800, 450), (name, width, height)
