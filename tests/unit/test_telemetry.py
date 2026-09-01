"""Tests for default-on, opt-out, anonymous CLI telemetry."""

from __future__ import annotations

import getpass
import json
import platform
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.error import URLError

import pytest
from typer.testing import CliRunner

import doberman.cli.main as cli_module
from doberman.storage.device_metrics import record_decision_metric

runner = CliRunner()
_NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)
_KEY = "phc_test_key"


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _ready(telemetry, tmp_path, monkeypatch):
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.delenv("DOBERMAN_TELEMETRY", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("DOBERMAN_HOME", str(tmp_path))
    telemetry.enable(home=tmp_path)
    monkeypatch.setenv(telemetry.ENV_KEY, _KEY)


def _capture_requests(telemetry, monkeypatch):
    requests = []

    def urlopen(request, timeout):
        requests.append((request, timeout))
        return _Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    return requests


def _bodies(telemetry, requests):
    telemetry._join_sender_threads(timeout=1.0)
    return [json.loads(request.data) for request, _timeout in requests]


def _clear_kill_switches(monkeypatch):
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.delenv("DOBERMAN_TELEMETRY", raising=False)
    monkeypatch.delenv("CI", raising=False)


def test_default_on_first_capture_creates_id_and_posts(tmp_path, monkeypatch):
    from doberman import telemetry

    _clear_kill_switches(monkeypatch)
    monkeypatch.setenv(telemetry.ENV_KEY, _KEY)
    requests = _capture_requests(telemetry, monkeypatch)

    assert telemetry.is_enabled(home=tmp_path) is True
    assert telemetry.status(home=tmp_path).distinct_id == ""  # nothing persisted before a send
    telemetry.capture("cli_command", {"command": "doctor"}, home=tmp_path)

    bodies = _bodies(telemetry, requests)
    assert [body["event"] for body in bodies] == ["cli_command"]
    uuid.UUID(bodies[0]["distinct_id"], version=4)
    persisted = telemetry.status(home=tmp_path)
    assert persisted.distinct_id == bodies[0]["distinct_id"]
    assert persisted.consent_at is None  # default-on is not a recorded choice


def test_kill_switch_wins_over_the_default(tmp_path, monkeypatch):
    from doberman import telemetry

    _clear_kill_switches(monkeypatch)
    monkeypatch.setenv("DOBERMAN_TELEMETRY", "0")
    monkeypatch.setenv(telemetry.ENV_KEY, _KEY)
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("HTTP called")),
    )
    assert telemetry.is_enabled(home=tmp_path) is False
    telemetry.capture("cli_command", {"command": "doctor"}, home=tmp_path)
    telemetry._join_sender_threads(timeout=1.0)


def test_opted_out_state_blocks_http(tmp_path, monkeypatch):
    from doberman import telemetry

    _clear_kill_switches(monkeypatch)
    telemetry.disable(home=tmp_path)  # placeholder key here, so the final event is a no-op
    monkeypatch.setenv(telemetry.ENV_KEY, _KEY)
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("HTTP called")),
    )
    assert telemetry.is_enabled(home=tmp_path) is False
    assert telemetry.status(home=tmp_path).consent_at is not None
    telemetry.capture("cli_command", {"command": "doctor"}, home=tmp_path)
    telemetry._join_sender_threads(timeout=1.0)


def test_first_run_notice_prints_once_and_never_after_a_choice(tmp_path, monkeypatch):
    from doberman import telemetry

    _clear_kill_switches(monkeypatch)
    monkeypatch.setenv(telemetry.ENV_KEY, _KEY)
    assert telemetry.first_run_notice(home=tmp_path) == telemetry.FIRST_RUN_NOTICE
    assert telemetry.first_run_notice(home=tmp_path) is None
    assert telemetry.status(home=tmp_path).notice_shown is True

    opted_out = tmp_path / "opted-out"
    monkeypatch.delenv(telemetry.ENV_KEY, raising=False)
    telemetry.disable(home=opted_out)
    monkeypatch.setenv(telemetry.ENV_KEY, _KEY)
    assert telemetry.first_run_notice(home=opted_out) is None

    forced = tmp_path / "forced"
    monkeypatch.setenv("CI", "1")
    assert telemetry.first_run_notice(home=forced) is None  # cannot send, so nothing to announce


def test_first_cli_command_prints_the_notice_to_stderr_once(tmp_path, monkeypatch):
    from doberman import telemetry

    _clear_kill_switches(monkeypatch)
    monkeypatch.setenv("DOBERMAN_HOME", str(tmp_path))
    monkeypatch.setenv(telemetry.ENV_KEY, _KEY)
    _capture_requests(telemetry, monkeypatch)

    first = runner.invoke(cli_module.app, ["status", "--path", str(tmp_path)])
    second = runner.invoke(cli_module.app, ["status", "--path", str(tmp_path)])
    assert telemetry.FIRST_RUN_NOTICE in first.stderr
    assert telemetry.FIRST_RUN_NOTICE not in first.stdout
    assert telemetry.FIRST_RUN_NOTICE not in second.stderr
    telemetry._join_sender_threads(timeout=1.0)


def test_enable_and_capture_posts_allowlisted_payload(tmp_path, monkeypatch):
    from doberman import telemetry

    _ready(telemetry, tmp_path, monkeypatch)
    requests = _capture_requests(telemetry, monkeypatch)
    telemetry.capture(
        "setup_completed",
        {
            "mode": "balanced",
            "host": "claude",
            "hooks_installed": True,
            "global_install": False,
            "source": "wizard",
        },
        home=tmp_path,
        now=_NOW,
    )

    bodies = _bodies(telemetry, requests)
    assert len(bodies) == 1
    body = bodies[0]
    assert requests[0][0].full_url == f"{telemetry.POSTHOG_HOST}/i/v0/e/"
    assert requests[0][1] == 3
    assert body["api_key"] == _KEY
    assert body["event"] == "setup_completed"
    uuid.UUID(body["distinct_id"], version=4)
    assert body["timestamp"].endswith("Z")
    assert set(body["properties"]) == {
        "$process_person_profile",
        "$geoip_disable",
        "$lib",
        "version",
        "os",
        "python",
        "mode",
        "host",
        "hooks_installed",
        "global_install",
        "source",
    }
    assert all(
        value is None or isinstance(value, str | int | float | bool)
        for value in body["properties"].values()
    )


def test_enable_emits_enabled_event_and_disable_emits_final_event(tmp_path, monkeypatch):
    from doberman import telemetry

    _ready(telemetry, tmp_path, monkeypatch)
    requests = _capture_requests(telemetry, monkeypatch)
    enabled = telemetry.enable(home=tmp_path)
    disabled = telemetry.disable(home=tmp_path)

    assert enabled.enabled is True
    assert disabled.enabled is False
    assert disabled.distinct_id == enabled.distinct_id
    assert [body["event"] for body in _bodies(telemetry, requests)] == [
        "telemetry_enabled",
        "telemetry_disabled",
    ]


def test_redaction_guard_drops_unknown_properties_and_identity_strings(tmp_path, monkeypatch):
    from doberman import telemetry

    _ready(telemetry, tmp_path, monkeypatch)
    requests = _capture_requests(telemetry, monkeypatch)
    telemetry.capture(
        "cli_command",
        {"command": "doctor", "path": "/home/me/secret.env", "token": "sk-live-abc"},
        home=tmp_path,
    )

    raw = json.dumps(_bodies(telemetry, requests)[0])
    assert "/repo/.env" not in raw
    assert "/home/me/secret.env" not in raw
    assert "sk-live-abc" not in raw
    assert "path" not in json.loads(raw)["properties"]
    assert "token" not in json.loads(raw)["properties"]
    assert platform.node() not in raw
    assert getpass.getuser() not in raw


@pytest.mark.parametrize(
    ("name", "value", "reason"),
    [
        ("DO_NOT_TRACK", "1", "DO_NOT_TRACK"),
        ("DOBERMAN_TELEMETRY", "false", "DOBERMAN_TELEMETRY"),
        ("CI", "true", "CI"),
    ],
)
def test_kill_switches_prevent_http_and_status_names_reason(
    tmp_path, monkeypatch, name, value, reason
):
    from doberman import telemetry

    _ready(telemetry, tmp_path, monkeypatch)
    monkeypatch.setenv(name, value)
    requests = _capture_requests(telemetry, monkeypatch)
    telemetry.capture("cli_command", {"command": "doctor"}, home=tmp_path)
    result = runner.invoke(cli_module.app, ["telemetry", "status"])

    assert requests == []
    assert result.exit_code == 0, result.output
    assert reason in result.output


def test_placeholder_key_prevents_http(tmp_path, monkeypatch):
    from doberman import telemetry

    _clear_kill_switches(monkeypatch)
    telemetry.enable(home=tmp_path)
    monkeypatch.setenv(telemetry.ENV_KEY, "phc_REPLACE_ME")
    requests = _capture_requests(telemetry, monkeypatch)
    telemetry.capture("cli_command", {"command": "doctor"}, home=tmp_path)
    assert requests == []


@pytest.mark.parametrize("failure", [URLError("offline"), socket.timeout("slow")])
def test_transport_failure_never_raises(tmp_path, monkeypatch, failure):
    from doberman import telemetry

    _ready(telemetry, tmp_path, monkeypatch)

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr("urllib.request.urlopen", fail)
    telemetry.capture("cli_command", {"command": "doctor"}, home=tmp_path)
    result = runner.invoke(cli_module.app, ["version"])
    telemetry._join_sender_threads(timeout=1.0)
    assert result.exit_code == 0, result.output


def test_invalid_allowed_value_drops_whole_event(tmp_path, monkeypatch):
    from doberman import telemetry

    _ready(telemetry, tmp_path, monkeypatch)
    requests = _capture_requests(telemetry, monkeypatch)
    telemetry.capture("cli_command", {"command": "/repo/.env"}, home=tmp_path)
    assert requests == []


def test_usage_summary_sends_at_most_once_per_day(tmp_path, monkeypatch):
    from doberman import telemetry

    _ready(telemetry, tmp_path, monkeypatch)
    for verdict in ("PASS", "PASS", "AUTH", "BLOCK"):
        record_decision_metric(verdict, home=tmp_path)
    requests = _capture_requests(telemetry, monkeypatch)

    assert telemetry.maybe_send_usage_summary(home=tmp_path, now=_NOW) is True
    assert (
        telemetry.maybe_send_usage_summary(home=tmp_path, now=_NOW + timedelta(hours=23)) is False
    )
    assert telemetry.maybe_send_usage_summary(home=tmp_path, now=_NOW + timedelta(hours=24)) is True

    bodies = _bodies(telemetry, requests)
    assert len(bodies) == 2
    assert bodies[0]["event"] == "usage_summary"
    expected = {
        "total": 4,
        "pass": 2,
        "auth": 1,
        "block": 1,
        "days_since_first_seen": 0,
    }
    assert {key: bodies[0]["properties"][key] for key in expected} == expected
    assert telemetry.status(home=tmp_path).last_summary_at == _NOW + timedelta(hours=24)


def test_cli_command_emitted_for_doctor_but_not_hook(tmp_path, monkeypatch):
    from doberman import telemetry

    _ready(telemetry, tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(
        telemetry,
        "capture",
        lambda event, properties=None, **_kw: events.append((event, properties)),
    )
    monkeypatch.setattr(telemetry, "maybe_send_usage_summary", lambda **_kw: False)

    runner.invoke(cli_module.app, ["doctor", "--path", str(tmp_path)])
    assert ("cli_command", {"command": "doctor"}) in events
    events.clear()
    runner.invoke(cli_module.app, ["hook", "pre"], input="{}")
    assert events == []


def test_importing_cli_does_not_load_telemetry_hot_path_module():
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import doberman.cli.main; assert 'doberman.telemetry' not in sys.modules",
        ],
        capture_output=True,
        text=True,
        timeout=60,  # a cold interpreter + CLI import on a loaded Windows runner can exceed 10 s
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_nested_cli_command_uses_group_and_subcommand(monkeypatch):
    from doberman import telemetry

    events = []
    monkeypatch.setattr(
        telemetry,
        "capture",
        lambda event, properties=None, **_kw: events.append((event, properties)),
    )
    monkeypatch.setattr(telemetry, "maybe_send_usage_summary", lambda **_kw: False)
    result = runner.invoke(cli_module.app, ["taint", "clear"])

    assert result.exit_code in {0, 1}
    assert events == [("cli_command", {"command": "taint.clear"})]


def test_join_sender_threads_has_one_second_total_budget():
    from doberman import telemetry

    thread = threading.Thread(target=time.sleep, args=(5,), daemon=True)
    thread.start()
    started = time.monotonic()
    telemetry._join_sender_threads([thread], timeout=1.0)
    assert time.monotonic() - started < 1.5
