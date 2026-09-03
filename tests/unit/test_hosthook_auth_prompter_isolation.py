"""Regression test for the autouse hosthook auth-prompter neutralizer.

``tests/conftest.py``'s ``_neutralize_hosthook_auth_prompter`` autouse fixture used to
patch only ``claude_code.AUTH_PROMPTER``. ``codex.AUTH_PROMPTER`` is a separate
module-level seam (mirrors ``claude_code``'s — see ``codex.py``'s docstring on it) that
the fixture never touched, so any test driving ``codex.evaluate_pre`` into an AUTH-tier
decision without injecting its own fake prompter fell through to
``hookio._default_auth_prompter()`` — which opens a REAL GUI dialog and blocks up to
``DEFAULT_CHALLENGE_TIMEOUT_S`` (10 minutes) on any machine with an active desktop
session. This hit several existing tests (``test_hosthook_codex.py``'s
``test_windows_powershell_delete_is_gated`` and ``test_reason_never_echoes_raw_command``,
``test_hosthook_taint_floor.py``'s ``test_codex_taint_floor_multistep_exfil_denied``) that
were written assuming a fast headless deny, per their own "headless test = fail-closed
deny" comments.

This proves the fixture now covers ``codex`` too — with NO test-local monkeypatch of its
own. If this regresses, this test would hang and pop a real window instead of failing
fast, exactly like the tests above did before this fix.
"""

import json
from pathlib import Path

from doberman.hosthooks import claude_code, codex

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "codex"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_codex_auth_prompter_is_neutralized_without_a_test_local_monkeypatch(tmp_path):
    # A Write to a CI/CD config is DEFAULT_SENSITIVE -> AUTH tier (same trigger used by
    # test_hosthook_codex.py::test_auth_runs_dobermans_own_challenge, which explicitly
    # monkeypatches codex.AUTH_PROMPTER itself; this test deliberately does not, to prove
    # the autouse fixture alone is enough).
    payload = _load("pre_bash.json")
    payload["cwd"] = str(tmp_path)
    payload["tool_name"] = "Write"
    payload["tool_input"] = {"file_path": ".github/workflows/ci.yml", "content": "x"}

    out = codex.evaluate_pre(payload)

    assert out is not None, "an AUTH-tier action must not abstain"
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    # This specific "channel could not be shown" wording only comes from the
    # PrompterUnavailableError path (see hookio._auth_denied_reason's channel_error
    # branch) - proof this went through the neutralized _NoChannel stub, a fast and
    # deterministic fail-closed path, rather than a real GUI/TTY channel actually
    # being tried and eventually timing out.
    assert "could not be shown" in hso["permissionDecisionReason"]


def test_codex_and_claude_code_get_the_same_kind_of_neutralized_prompter():
    # Both hosthook modules' AUTH_PROMPTER seams must be patched to the same no-channel
    # behavior by the one autouse fixture - not just "codex has *a* patch" but "the
    # same protection claude_code already had".
    assert type(codex.AUTH_PROMPTER) is type(claude_code.AUTH_PROMPTER)
