"""Issue #147 — policy-as-code: a repo-committed ``doberman.policy.yaml``
resolved through ``PolicySource``, layered raise-only over a local pin.

Covers: the seam stays dormant with no file/plugin (byte-identical to
today); a file's blocked/sensitive globs reach real BLOCK/AUTH end to end,
combined with a role that independently blocks the same target; adding a
glob applies immediately and rewrites the pin; dropping a glob keeps the
dropped glob enforced, leaves the pin untouched, and warns exactly once
across repeated loads of the same file state; a deleted/malformed file
after adoption behaves the same way, never raises; a file under
``.doberman/`` is ignored; ``effective_policy`` memoizes discovery; and the
``doberman policy-file --accept`` gate (mirrors ``doberman mode`` /
``doberman memory reset``).
"""

from __future__ import annotations

import asyncio
import json
import logging

import pyotp
import pytest
import yaml
from typer.testing import CliRunner

from doberman.auth import password, totp
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.hosthooks import spine
from doberman.models import ReasonCode, Verdict
from doberman.policy.drift import read_policy_changes
from doberman.policy.sources import (
    PIN_CORRUPT,
    PolicySnapshot,
    effective_policy,
    glob_state_map,
    load_file_policy,
    load_raw_file,
    read_pin,
)

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


def _write_policy_file(repo_root, *, blocked=(), sensitive=(), version=1, text=None) -> None:
    path = repo_root / "doberman.policy.yaml"
    if text is not None:
        path.write_text(text, encoding="utf-8")
        return
    doc: dict = {}
    if version is not None:
        doc["version"] = version
    if blocked:
        doc["blocked"] = list(blocked)
    if sensitive:
        doc["sensitive"] = list(sensitive)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _pin_path(repo_root):
    return repo_root / ".doberman" / "policy_file_pin.json"


# --- 1. dormant with nothing configured -------------------------------------


def test_no_file_no_plugins_neither_builder_sets_resolved_policy(tmp_path):
    assert effective_policy(str(tmp_path)).is_empty
    result = spine.evaluate_action(
        "fs_write", {"path": "app/notes.txt"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.PASS
    assert ReasonCode.policy_source_blocked not in result.decision.reason_codes
    assert ReasonCode.policy_source_sensitive not in result.decision.reason_codes


# --- 2. end-to-end BLOCK/AUTH, plus a role combined with the file -----------


def test_file_blocked_glob_reaches_block_end_to_end(tmp_path):
    _write_policy_file(tmp_path, blocked=["myteamsecrets/**"])
    result = spine.evaluate_action(
        "fs_read", {"path": "myteamsecrets/key.txt"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.BLOCK
    assert ReasonCode.policy_source_blocked in result.decision.reason_codes


def test_file_sensitive_glob_reaches_auth_end_to_end(tmp_path):
    _write_policy_file(tmp_path, sensitive=["myteaminfra/**"])
    result = spine.evaluate_action(
        "fs_read", {"path": "myteaminfra/network.conf"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.AUTH
    assert ReasonCode.policy_source_sensitive in result.decision.reason_codes


def test_role_block_plus_file_sensitive_on_same_path_is_block(tmp_path):
    # The role hard-blocks the path; the file only marks it sensitive (AUTH).
    # max_verdict()/combine() must still land on the stricter BLOCK.
    (tmp_path / ".doberman").mkdir()
    (tmp_path / ".doberman" / "role.yaml").write_text(
        yaml.safe_dump({"blocked": ["myteamshared/**"]}), encoding="utf-8"
    )
    _write_policy_file(tmp_path, sensitive=["myteamshared/**"])
    result = spine.evaluate_action(
        "fs_read", {"path": "myteamshared/secret.txt"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.BLOCK


# --- 2b. a category change is a pure tighten/weaken, never "mixed" ---------


def test_sensitive_to_blocked_is_a_pure_tighten_applies_immediately(tmp_path):
    _write_policy_file(tmp_path, sensitive=["catmove/**"])
    load_file_policy(str(tmp_path))  # adopt: pinned as sensitive

    _write_policy_file(tmp_path, blocked=["catmove/**"])  # promote to blocked
    src = load_file_policy(str(tmp_path))
    assert src.snapshot().blocked_globs == ("catmove/**",)
    assert "catmove/**" not in src.snapshot().sensitive_globs

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["catmove/**"]  # pin rewritten -- auto-tighten, no gate
    assert pin["sensitive"] == []

    result = runner.invoke(app, ["policy-file", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Pending" not in result.stdout  # nothing pending: it already applied


def test_blocked_to_sensitive_is_held_until_accept_block_still_wins(tmp_path):
    _write_policy_file(tmp_path, blocked=["catmove/**"])
    load_file_policy(str(tmp_path))  # adopt: pinned as blocked

    _write_policy_file(tmp_path, sensitive=["catmove/**"])  # demote to sensitive
    src = load_file_policy(str(tmp_path))
    # The pin's blocked entry stays in force -- BLOCK still wins even though
    # the file itself now only asks for AUTH.
    assert "catmove/**" in src.snapshot().blocked_globs

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["catmove/**"]  # unchanged -- held, not auto-applied

    result = spine.evaluate_action(
        "fs_read", {"path": "catmove/secret.txt"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.BLOCK

    # --accept still sees this as a pending weaken (never a no-op).
    from doberman.policy.drift import Classification, classify_change

    pin_snapshot = PolicySnapshot(blocked_globs=pin["blocked"], sensitive_globs=pin["sensitive"])
    file_snapshot, _digest, _rejected, _reason = load_raw_file(str(tmp_path))
    assert (
        classify_change(glob_state_map(pin_snapshot), glob_state_map(file_snapshot))
        is Classification.weaken
    )


# --- 3. adding a glob applies immediately and rewrites the pin --------------


def test_adding_a_glob_applies_immediately_and_rewrites_pin(tmp_path):
    _write_policy_file(tmp_path, blocked=["a/**"])
    src1 = load_file_policy(str(tmp_path))
    assert src1.snapshot().blocked_globs == ("a/**",)
    pin1 = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin1["blocked"] == ["a/**"]

    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    src2 = load_file_policy(str(tmp_path))
    assert set(src2.snapshot().blocked_globs) == {"a/**", "b/**"}
    pin2 = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin2["blocked"]) == {"a/**", "b/**"}


# --- 4. dropping a glob: still enforced, pin unchanged, one warning --------


def test_dropping_a_glob_keeps_it_blocked_pin_unchanged_warns_once(tmp_path, caplog):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))  # adopt both

    _write_policy_file(tmp_path, blocked=["a/**"])  # drop b/**
    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        src1 = load_file_policy(str(tmp_path))
        src2 = load_file_policy(str(tmp_path))  # repeated load of the SAME file state

    assert "b/**" in src1.snapshot().blocked_globs  # still enforced
    assert "b/**" in src2.snapshot().blocked_globs

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}  # unchanged

    drop_warnings = [r for r in caplog.records if "drops" in r.message]
    assert len(drop_warnings) == 1


# --- 5. deleted/malformed file after adoption: pin still applies, no crash -


def _corrupt_file(tmp_path, corrupt: str) -> None:
    path = tmp_path / "doberman.policy.yaml"
    if corrupt == "deleted":
        path.unlink()
    else:
        path.write_text(corrupt, encoding="utf-8")


@pytest.mark.parametrize(
    "corrupt",
    [
        "deleted",
        "not: valid: yaml: [",
        "- just\n- a\n- list\n",
        'version: 2\nblocked: ["a/**"]\n',
        'blocked: "a/**"\n',
    ],
    ids=["deleted", "malformed-yaml", "non-mapping", "bad-version", "blocked-not-a-list"],
)
def test_bad_file_state_after_adoption_pin_still_applies_one_warning(tmp_path, caplog, corrupt):
    _write_policy_file(tmp_path, blocked=["a/**"])
    load_file_policy(str(tmp_path))  # adopt

    _corrupt_file(tmp_path, corrupt)

    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        src = load_file_policy(str(tmp_path))

    assert src is not None
    assert "a/**" in src.snapshot().blocked_globs  # pin still applies
    assert len(caplog.records) == 1  # no exception, exactly one warning


def test_unknown_top_level_key_warns_but_known_keys_still_apply(tmp_path, caplog):
    _write_policy_file(
        tmp_path, text=yaml.safe_dump({"version": 1, "blocked": ["a/**"], "mystery": "x"})
    )
    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        src = load_file_policy(str(tmp_path))
    assert src.snapshot().blocked_globs == ("a/**",)
    assert any("unknown key" in r.message for r in caplog.records)


def test_utf16_file_is_rejected_not_raised_pin_still_applies(tmp_path, caplog):
    _write_policy_file(tmp_path, blocked=["a/**"])
    load_file_policy(str(tmp_path))  # adopt

    # A UTF-16/binary file raises UnicodeDecodeError out of a naive
    # read_text(encoding="utf-8") -- it must be REJECTED, not propagate out
    # of the ctx builders that call this on every action.
    (tmp_path / "doberman.policy.yaml").write_text("blocked: ['x/**']\n", encoding="utf-16")

    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        src = load_file_policy(str(tmp_path))  # must not raise

    assert src is not None
    assert "a/**" in src.snapshot().blocked_globs  # pin still applies

    file_snapshot, _digest, rejected, reason = load_raw_file(str(tmp_path))
    assert file_snapshot.blocked_globs == ()
    assert rejected
    assert "could not be read" in reason


# --- 5b. rejected is distinct from emptied ----------------------------------


def test_status_reports_rejected_file_not_applied_or_pending(tmp_path):
    _write_policy_file(tmp_path, blocked=["a/**"], sensitive=["s/**"])
    load_file_policy(str(tmp_path))  # adopt: pin now holds a/** + s/**

    # A one-character typo -- "version 1" with the colon missing -- parses
    # as a YAML STRING, not a mapping. This must read as REJECTED, never as
    # "Applied: 0" (a legitimately empty file) with the pin's globs listed
    # as "Pending" (an intentional drop a human is being asked to accept).
    _write_policy_file(tmp_path, text="version 1\n")

    result = runner.invoke(app, ["policy-file", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "rejected" in result.stdout
    assert "Applied" not in result.stdout
    assert "Pending" not in result.stdout


def test_accept_refuses_a_rejected_file_writes_nothing(tmp_path):
    _write_policy_file(tmp_path, blocked=["a/**"], sensitive=["s/**"])
    load_file_policy(str(tmp_path))  # adopt
    pin_before = _pin_path(tmp_path).read_text(encoding="utf-8")

    _write_policy_file(tmp_path, text="version 1\n")

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "rejected" in result.output
    # Nothing was actually decided -- the pin (in particular) must not have
    # been overwritten with an EMPTY snapshot, which would disarm
    # enforcement after a one-character typo.
    assert _pin_path(tmp_path).read_text(encoding="utf-8") == pin_before


# --- 5c. a corrupt pin means "unknown", never "never adopted" --------------


def test_corrupt_pin_applies_file_as_is_leaves_pin_untouched(tmp_path, caplog):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))  # adopt both -- pin now holds a/** + b/**

    # Corrupt the pin -- the prior approved state is now UNKNOWN, not "never
    # adopted".
    _pin_path(tmp_path).write_text("{not json", encoding="utf-8")
    corrupt_bytes = _pin_path(tmp_path).read_text(encoding="utf-8")
    assert read_pin(str(tmp_path)) is PIN_CORRUPT

    _write_policy_file(tmp_path, blocked=["a/**"])  # drop b/** in the same turn

    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        src = load_file_policy(str(tmp_path))

    # The file's own globs apply as-is (never less protective than the file
    # itself), but the corrupt pin bytes are left completely untouched -- no
    # silent re-adoption of the smaller set as a fresh, ungated baseline.
    assert src.snapshot().blocked_globs == ("a/**",)
    assert _pin_path(tmp_path).read_text(encoding="utf-8") == corrupt_bytes
    assert any("unreadable" in r.message for r in caplog.records)


def test_accept_rewrites_a_corrupt_pin_when_gated(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**"])
    load_file_policy(str(tmp_path))

    _pin_path(tmp_path).write_text("{not json", encoding="utf-8")
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 0

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["a/**"]  # re-pinned from the file's current content

    rows = asyncio.run(read_policy_changes(str(tmp_path)))  # newest first
    assert rows[0]["classification"] == "weaken"
    assert rows[0]["approved"] == 1


# --- 6. `doberman policy-file --accept` ------------------------------------


class _Approve:
    def __init__(self, code="999999"):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover — never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


def _use_prompter(monkeypatch, prompter_factory):
    # `policy_file()` constructs the already-imported top-level `CliPrompter`
    # name in `cli.main`, not a lazy re-import -- patch that binding directly
    # (mirrors test_cli_memory_reset.py / test_cli_taint_clear.py).
    monkeypatch.setattr(cli_main, "CliPrompter", prompter_factory)


def _enrolled_code() -> str:
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


def test_accept_nothing_pending_exits_zero(tmp_path):
    _write_policy_file(tmp_path, blocked=["a/**"])
    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "nothing to accept" in result.stdout


def test_accept_with_enrolled_totp_valid_code_passes_wrong_code_denied(tmp_path, monkeypatch):
    # TOTP must win when both factors are enrolled (mirrors
    # test_cli_lowering_gate.py's `mode`/`prefs` coverage of this same gate).
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))  # adopt both

    _write_policy_file(tmp_path, blocked=["a/**"])  # drop b/**
    password.enroll(_PASSWORD)
    code = _enrolled_code()

    # A non-TOTP-shaped code is denied -- no accidental accept.
    _use_prompter(monkeypatch, lambda: _Approve("wrong password"))
    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 1
    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}  # unchanged

    # The correct current TOTP code passes and rewrites the pin.
    _use_prompter(monkeypatch, lambda: _Approve(code))
    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 0
    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["a/**"]

    rows = asyncio.run(read_policy_changes(str(tmp_path)))  # newest first
    assert rows[0]["approval_method"] == "two_factor"
    assert rows[0]["approved"] == 1


def test_accept_with_valid_factor_rewrites_pin_and_ledgers_weaken(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))  # adopt both

    _write_policy_file(tmp_path, blocked=["a/**"])  # drop b/**
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 0

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["a/**"]  # b/** accepted as dropped

    rows = asyncio.run(read_policy_changes(str(tmp_path)))
    assert rows[0]["classification"] == "weaken"
    assert rows[0]["approved"] == 1
    assert rows[0]["approval_method"] == "password"


def test_accept_denied_leaves_pin_unchanged_and_ledgers_denial(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))

    _write_policy_file(tmp_path, blocked=["a/**"])  # drop b/**
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve("wrong password"))

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 1

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}  # unchanged

    rows = asyncio.run(read_policy_changes(str(tmp_path)))
    assert rows[0]["approved"] == 0
    assert rows[0]["classification"] == "weaken"


def test_accept_declined_confirm_leaves_pin_unchanged(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))

    _write_policy_file(tmp_path, blocked=["a/**"])
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, _Decline)

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 1
    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}


def test_accept_with_no_factor_enrolled_fails_closed(tmp_path):
    # Neither TOTP nor password enrolled (conftest isolates both to empty temp
    # paths): the accept must fail closed, no confirm-only fallback.
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))
    _write_policy_file(tmp_path, blocked=["a/**"])

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "enrolled possession factor" in result.output
    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}


def test_status_shows_pending_drop(tmp_path):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))
    _write_policy_file(tmp_path, blocked=["a/**"])

    result = runner.invoke(app, ["policy-file", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Pending" in result.stdout
    assert "b/**" in result.stdout


# --- 7. a file under .doberman/ is ignored ----------------------------------


def test_file_under_dot_doberman_is_ignored(tmp_path):
    ddir = tmp_path / ".doberman"
    ddir.mkdir()
    (ddir / "doberman.policy.yaml").write_text(
        yaml.safe_dump({"version": 1, "blocked": ["a/**"]}), encoding="utf-8"
    )
    assert load_file_policy(str(tmp_path)) is None
    assert effective_policy(str(tmp_path)).is_empty


# --- 8. memoization ----------------------------------------------------------


def test_effective_policy_memoizes_discovery(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**"])

    from doberman.engine import registry

    calls = {"n": 0}
    real = registry.discover_policy_sources

    def _counting():
        calls["n"] += 1
        return real()

    monkeypatch.setattr(registry, "discover_policy_sources", _counting)

    effective_policy(str(tmp_path))
    effective_policy(str(tmp_path))
    assert calls["n"] == 1

    # Changing the file busts the cache: discovery runs again.
    _write_policy_file(tmp_path, blocked=["a/**", "c/**"])
    effective_policy(str(tmp_path))
    assert calls["n"] == 2


def test_deleting_the_pin_is_a_genuine_cache_miss_and_recreates_it(tmp_path):
    # A cache entry must only ever be looked up by the digests actually READ
    # after load_file_policy() runs -- never by a pre-call guess. Storing a
    # result under a pre-call key too let a later lookup with the SAME
    # pre-call shape (pin missing) hit that stale entry after the pin was
    # deleted, so the pin was never recreated on disk.
    _write_policy_file(tmp_path, blocked=["a/**"])
    effective_policy(str(tmp_path))  # first-ever call: adopts, writes the pin
    assert _pin_path(tmp_path).exists()

    _pin_path(tmp_path).unlink()
    rp = effective_policy(str(tmp_path))

    assert "a/**" in rp.blocked_globs
    assert _pin_path(tmp_path).exists()  # recreated -- not served from a stale cache hit
    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["a/**"]
