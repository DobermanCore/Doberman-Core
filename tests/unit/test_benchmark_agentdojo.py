"""Unit tests for the AgentDojo / AgentDyn suite adapters.

These cover the deterministic *mapping* (tool -> ActionType, arg -> destination/
target, label -> source_context, egress -> attacker_goal_index) and the
``load()`` flow, **without** requiring the optional ``agentdojo`` package: the
package is faked in ``sys.modules`` where a task source is needed. The security-
critical guarantee — **no payload text in ``case_id`` / ``note``** — is asserted
against a marker that is only ever placed in ``raw_arguments``.
"""

from __future__ import annotations

import sys
import types

import pytest

from doberman.models import ActionType, SourceContext
from tests.benchmarks.adapter import SuiteAdapter
from tests.benchmarks.suites.agentdojo import (
    AgentDojoAdapter,
    AgentDynAdapter,
    _action_type,
    _first,
    _goal_index,
    _to_candidate,
)

#: A sentinel that must only ever live in ``raw_arguments`` — never in a case id
#: or note (the redaction guarantee the adapter promises).
PAYLOAD_MARKER = "AGENTDOJO_PAYLOAD_MARKER_DO_NOT_LEAK"


# --- fakes (stand in for the agentdojo package, no install needed) ----------
class _FakeCall:
    """A stand-in for agentdojo's ``FunctionCall`` (``.function`` + ``.args``)."""

    def __init__(self, function: str, args: dict) -> None:
        self.function = function
        self.args = args


class _FakeTask:
    def __init__(self, calls: list[_FakeCall], *, raises: bool = False) -> None:
        self._calls = calls
        self._raises = raises

    def ground_truth(self, env):
        if self._raises:
            raise RuntimeError("task needs a richer env")
        return self._calls


class _FakeSuite:
    def __init__(self, user_tasks: dict, injection_tasks: dict) -> None:
        self.user_tasks = user_tasks
        self.injection_tasks = injection_tasks

    def load_and_inject_default_environment(self, injections):
        assert injections == {}  # adapter must inject nothing
        return {"env": True}


def _install_fake_agentdojo(monkeypatch, suite: _FakeSuite) -> None:
    pkg = types.ModuleType("agentdojo")
    sub = types.ModuleType("agentdojo.task_suite")
    mod = types.ModuleType("agentdojo.task_suite.load_suites")
    mod.get_suite = lambda version, name: suite  # noqa: ARG005
    monkeypatch.setitem(sys.modules, "agentdojo", pkg)
    monkeypatch.setitem(sys.modules, "agentdojo.task_suite", sub)
    monkeypatch.setitem(sys.modules, "agentdojo.task_suite.load_suites", mod)


# --- action-type mapping ----------------------------------------------------
def test_action_type_explicit_table():
    assert _action_type("send_email") is ActionType.network_request
    assert _action_type("read_file") is ActionType.file_read
    assert _action_type("create_file") is ActionType.file_write
    assert _action_type("delete_file") is ActionType.file_delete


def test_action_type_prefix_fallback_and_unknown():
    # AgentDyn tools resolve via the prefix table, not the explicit map.
    assert _action_type("git_push") is ActionType.git_op
    assert _action_type("download_invoice") is ActionType.network_request
    assert _action_type("view_product") is ActionType.file_read
    # Truly unknown -> conservative ``other`` (never silently network/exec).
    assert _action_type("frobnicate_widget") is ActionType.other


# --- destination / target extraction ----------------------------------------
def test_first_priority_and_list_join():
    # ``url`` outranks ``recipient`` (priority order in _DEST_KEYS).
    assert _first({"url": "h.test", "recipient": "x"}, ("url", "recipient")) == "h.test"
    # A recipient list is joined deterministically.
    assert _first({"recipients": ["a", "b"]}, ("recipients",)) == "a,b"
    # Nothing present -> None (not "").
    assert _first({}, ("url", "recipient")) is None
    # Falsy values are skipped.
    assert _first({"url": "", "to": "you"}, ("url", "to")) == "you"


# --- label -> provenance + field passthrough --------------------------------
def test_to_candidate_attack_is_tool_output_and_keeps_raw_args():
    cand = _to_candidate(
        "send_email",
        {"recipient": "[email protected]", "body": f"{PAYLOAD_MARKER} x"},
        "attack",
    )
    assert cand.action_type is ActionType.network_request
    assert cand.tool_name == "send_email"
    assert cand.external_destination == "[email protected]"
    # Injected actions are flagged as arriving via tool output.
    assert cand.source_context is SourceContext.tool_output
    # The payload survives ONLY in raw_arguments (the engine's content path).
    assert PAYLOAD_MARKER in cand.raw_arguments["body"]


def test_to_candidate_benign_is_user_sourced():
    cand = _to_candidate("read_file", {"file_path": "/repo/a.txt"}, "benign")
    assert cand.source_context is SourceContext.user
    assert cand.target == "/repo/a.txt"
    assert cand.external_destination is None


# --- attacker_goal_index = last egress --------------------------------------
def test_goal_index_points_at_last_network_egress():
    actions = (
        _to_candidate("read_file", {"file_path": "/a"}, "attack"),
        _to_candidate("send_email", {"recipient": "a@b"}, "attack"),
        _to_candidate("send_email", {"recipient": "c@d"}, "attack"),
    )
    assert _goal_index(actions) == 2


def test_goal_index_none_when_no_egress():
    actions = (_to_candidate("read_file", {"file_path": "/a"}, "attack"),)
    assert _goal_index(actions) is None


# --- load(): full mapping + redaction ---------------------------------------
def test_load_maps_user_and_injection_tasks_and_redacts(monkeypatch):
    suite = _FakeSuite(
        user_tasks={
            "user_task_0": _FakeTask([_FakeCall("read_file", {"file_path": "/repo/a.txt"})]),
        },
        injection_tasks={
            "injection_task_0": _FakeTask(
                [
                    _FakeCall(
                        "send_email",
                        {"recipient": "[email protected]", "body": f"{PAYLOAD_MARKER} exfil"},
                    )
                ]
            ),
        },
    )
    _install_fake_agentdojo(monkeypatch, suite)

    cases = list(AgentDojoAdapter(suites=["banking"]).load())
    by_label = {c.label: c for c in cases}

    # Both a benign (user task) and an attack (injection task) case were produced.
    assert by_label["benign"].case_id == "banking/user_task_0"
    assert by_label["attack"].case_id == "banking/injection_task_0"
    # The attacker goal = the single egress send_email (index 0).
    assert by_label["attack"].attacker_goal_index == 0

    # REDACTION: the payload marker never appears in any case_id or note ...
    for c in cases:
        assert PAYLOAD_MARKER not in c.case_id
        assert PAYLOAD_MARKER not in c.note
    # ... but it IS preserved in raw_arguments (the engine evaluation path).
    attack_args = by_label["attack"].actions[0].raw_arguments
    assert PAYLOAD_MARKER in attack_args["body"]


def test_load_skips_task_whose_ground_truth_raises(monkeypatch):
    # Fail-closed at the case level: a task that can't produce ground truth is
    # dropped, not crashed on.
    suite = _FakeSuite(
        user_tasks={"user_task_0": _FakeTask([], raises=True)},
        injection_tasks={},
    )
    _install_fake_agentdojo(monkeypatch, suite)
    assert list(AgentDojoAdapter(suites=["banking"]).load()) == []


def test_load_without_agentdojo_raises_runtimeerror(monkeypatch):
    # Deterministically force the lazy import to fail regardless of the env.
    monkeypatch.setitem(sys.modules, "agentdojo.task_suite.load_suites", None)
    with pytest.raises(RuntimeError, match="AgentDojo is not installed"):
        list(AgentDojoAdapter().load())


# --- adapters conform to the contract ---------------------------------------
def test_adapters_satisfy_suite_adapter_protocol():
    assert isinstance(AgentDojoAdapter(), SuiteAdapter)
    assert isinstance(AgentDynAdapter(), SuiteAdapter)


def test_agentdyn_defaults_to_its_dynamic_suites():
    dyn = AgentDynAdapter()
    assert dyn.suite_name == "agentdyn"
    # AgentDyn's distinctive multi-step suites (not the original four).
    assert dyn._suites == ("shopping", "github", "dailylife")
