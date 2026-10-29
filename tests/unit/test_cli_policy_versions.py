"""`doberman policy-versions`: list, --show, --verify (ADR 0088)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.config import save_policy
from doberman.policy.checklist import recommend_policy
from doberman.storage.policy_catalogue import VERSION_PREFIX, read_versions

runner = CliRunner()


def _two_versions(tmp_path) -> list[str]:
    save_policy(
        recommend_policy().with_mode("strict"), str(tmp_path), ledger_ts="2026-08-30T10:00:00+00:00"
    )
    save_policy(
        recommend_policy().with_mode("balanced"),
        str(tmp_path),
        ledger_ts="2026-08-30T10:00:00+00:00",
    )
    return [v["version"] for v in read_versions(str(tmp_path))]


def test_listing_observes_the_current_policy_and_lists_newest_first(tmp_path):
    result = runner.invoke(app, ["policy-versions", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Doberman policy versions" in result.stdout
    assert result.stdout.count("pv1:") == 1  # defaults observed on first run
    versions = _two_versions(tmp_path)
    result = runner.invoke(app, ["policy-versions", "--path", str(tmp_path)])
    assert result.exit_code == 0
    for v in versions:
        assert v[:16] in result.stdout
    assert "via change" in result.stdout


def test_json_listing_is_an_allowlist_without_content(tmp_path):
    _two_versions(tmp_path)
    result = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--json"])
    assert result.exit_code == 0
    rows = json.loads(result.stdout)
    assert rows and all(
        set(r) == {"version", "first_seen", "engine", "schema", "in_force_since", "origin"}
        for r in rows
    )
    assert "canonical" not in result.stdout
    assert "items" not in result.stdout


def test_show_resolves_a_prefix_and_prints_the_snapshot(tmp_path):
    (v, *_) = _two_versions(tmp_path)
    prefix = v[len(VERSION_PREFIX) :][:8]
    result = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--show", prefix])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["version"] == v
    assert data["snapshot"]["schema"] == 1
    assert "mode" in data["snapshot"]["doc"]
    assert "\n  " in result.stdout

    full = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--show", v])
    assert full.exit_code == 0
    assert json.loads(full.stdout)["version"] == v
    assert "\n  " in full.stdout


def test_show_json_is_compact_and_deterministic(tmp_path):
    (v, *_) = _two_versions(tmp_path)
    prefix = v[len(VERSION_PREFIX) :][:8]
    result = runner.invoke(
        app, ["policy-versions", "--path", str(tmp_path), "--show", prefix, "--json"]
    )
    assert result.exit_code == 0
    assert len(result.stdout.strip().splitlines()) == 1
    data = json.loads(result.stdout)
    assert data["version"] == v
    assert data["snapshot"]["schema"] == 1
    assert '", "' not in result.stdout
    assert '": "' not in result.stdout

    second = runner.invoke(
        app, ["policy-versions", "--path", str(tmp_path), "--show", prefix, "--json"]
    )
    assert result.stdout == second.stdout


def test_show_exit_codes(tmp_path):
    _two_versions(tmp_path)
    bad = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--show", "zz"])
    assert bad.exit_code == 2
    short = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--show", "abcd"])
    assert short.exit_code == 2
    missing = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--show", "0" * 8])
    assert missing.exit_code == 1


def test_verify_is_read_only_and_reports_drift(tmp_path):
    _two_versions(tmp_path)
    ok = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--verify"])
    assert ok.exit_code == 0 and ok.stdout.startswith("ok")
    policy = tmp_path / ".doberman" / "policies.yaml"
    policy.write_text(policy.read_text().replace("balanced", "paranoid"))
    drift = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--verify"])
    assert drift.exit_code == 1 and drift.stdout.startswith("drift")
    assert len(read_versions(str(tmp_path))) == 2  # verify recorded nothing
    as_json = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--verify", "--json"])
    assert as_json.exit_code == 1
    assert json.loads(as_json.stdout)["status"] == "drift"


def test_verify_reports_unledgered(tmp_path):
    save_policy(recommend_policy().with_mode("strict"), str(tmp_path))
    result = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--verify"])
    assert result.exit_code == 1
    assert result.stdout.startswith("unledgered:")
    as_json = runner.invoke(app, ["policy-versions", "--path", str(tmp_path), "--verify", "--json"])
    assert as_json.exit_code == 1
    report = json.loads(as_json.stdout)
    assert report["status"] == "unledgered"
    assert report["unledgered"]


@pytest.mark.parametrize("change", ["missing", "strengthen", "weaken"])
def test_verify_preserves_policy_pins_and_runtime_cache(tmp_path, change):
    from doberman.policy import sources
    from doberman.storage.policy_catalogue import read_observations, verify_catalogue

    root = str(tmp_path)
    policy_file = tmp_path / "doberman.policy.yaml"
    pin_path = tmp_path / ".doberman" / "policy_file_pin.json"
    if change != "missing":
        policy_file.write_text('blocked: ["kept/**"]\n')
        sources.effective_policy(root)  # establish the runtime's approved floor
    save_policy(recommend_policy(), root)
    policy_file.write_text(
        "blocked: []\n" if change == "weaken" else 'blocked: ["kept/**", "new/**"]\n'
    )
    before_pin = pin_path.read_bytes() if pin_path.exists() else None
    before_cache = dict(sources._effective_policy_cache)
    before_versions = read_versions(root)
    before_observations = read_observations(root)

    verify_catalogue(root)
    runner.invoke(app, ["policy-versions", "--path", root, "--verify", "--json"])

    assert (pin_path.read_bytes() if pin_path.exists() else None) == before_pin
    assert sources._effective_policy_cache == before_cache
    assert read_versions(root) == before_versions
    assert read_observations(root) == before_observations
    # Verification must not cache a result under an unpinned state and prevent
    # a subsequent real evaluation from establishing/tightening its pin.
    active = sources.effective_policy(root)
    expected = {"kept/**"} if change == "weaken" else {"kept/**", "new/**"}
    assert set(active.blocked_globs) == expected
    assert set(sources.read_pin(root)["blocked"]) == expected
