"""AgentDojo adapter — maps the ETH Zurich agent-security suite onto core types.

Source: https://github.com/ethz-spylab/agentdojo (installed as the ``agentdojo``
package; no third-party data is vendored in this repo). AgentDojo organizes tasks
into four **suites** (``banking``, ``slack``, ``travel``, ``workspace``) each with
**user tasks** (benign) and **injection tasks** (attack). Every task exposes a
``ground_truth(env)`` returning the ordered ``FunctionCall``s that accomplish it —
that is exactly the labeled candidate-action stream this harness needs.

Mapping (per ``tests/benchmarks/README.md``):

* each *user task* ground-truth call  → a ``benign`` ``CandidateAction``,
* each *injection task* ground-truth call → an ``attack`` ``CandidateAction``;
  the consummating egress call is flagged via ``attacker_goal_index``.

We run the real ``decide()`` engine over these — Doberman is the *filter*, not the
agent, so we never execute AgentDojo's agent or any live model. The suite version
is pinned (``_BENCHMARK_VERSION``) for reproducibility, and **no payload text** is
placed in ``case_id``/``note`` (only the AgentDojo task id and its suite name).
"""

from __future__ import annotations

from collections.abc import Iterable

from doberman.models import ActionType, SourceContext

from ..adapter import BenchmarkCase, CandidateAction

#: Pinned AgentDojo benchmark version for reproducibility.
_BENCHMARK_VERSION = "v1"

#: The four suites AgentDojo ships under ``v1``.
_SUITES = ("banking", "slack", "travel", "workspace")

#: AgentDojo tool name -> the closest core ``ActionType``. Tools that ship data
#: *outward* to a recipient/host (the egress surface Doberman cares about) map to
#: ``network_request``; reads/searches to ``file_read``; mutations to
#: ``file_write``; removals to ``file_delete``. Unknowns fall back to ``other``
#: (README: "pick the closest; use ActionType.other if unsure").
_ACTION_TYPE: dict[str, ActionType] = {
    # --- egress / outbound (drives the external-destination rule) ---
    "send_email": ActionType.network_request,
    "send_money": ActionType.network_request,
    "schedule_transaction": ActionType.network_request,
    "update_scheduled_transaction": ActionType.network_request,
    "send_direct_message": ActionType.network_request,
    "send_channel_message": ActionType.network_request,
    "share_file": ActionType.network_request,
    "post_webpage": ActionType.network_request,
    "get_webpage": ActionType.network_request,
    "invite_user_to_slack": ActionType.network_request,
    "add_user_to_channel": ActionType.network_request,
    "add_calendar_event_participants": ActionType.network_request,
    "reserve_hotel": ActionType.network_request,
    # --- mutations / writes ---
    "create_file": ActionType.file_write,
    "append_to_file": ActionType.file_write,
    "create_calendar_event": ActionType.file_write,
    "reschedule_calendar_event": ActionType.file_write,
    "update_user_info": ActionType.file_write,
    "update_password": ActionType.file_write,
    # --- deletions ---
    "delete_file": ActionType.file_delete,
    "delete_email": ActionType.file_delete,
    "remove_user_from_slack": ActionType.file_delete,
    # --- reads / searches (everything else falls back below) ---
    "read_file": ActionType.file_read,
    "list_files": ActionType.file_read,
    "search_files": ActionType.file_read,
    "search_files_by_filename": ActionType.file_read,
    "read_inbox": ActionType.file_read,
    "get_unread_emails": ActionType.file_read,
    "search_emails": ActionType.file_read,
    "read_channel_messages": ActionType.file_read,
}

#: Arg keys that name an outbound destination (host/URL/recipient), in priority
#: order — the first present, non-empty value becomes ``external_destination``.
_DEST_KEYS = ("url", "recipient", "recipients", "email", "to", "address", "repo", "remote")

#: Arg keys that name a local resource/path -> ``target``.
_TARGET_KEYS = ("file_path", "file_id", "filename", "path", "file")


#: Prefix fallbacks (checked after the explicit table). Ordered most- to
#: least-specific. Covers AgentDyn's extra suites (shopping/github/dailylife)
#: without enumerating every tool: git_* are git operations, download_/browse_/
#: input_to_ reach the network, create_/move_/cart_/update_ mutate, etc.
_PREFIX_ACTION_TYPE: tuple[tuple[str, ActionType], ...] = (
    ("git_", ActionType.git_op),
    ("download_", ActionType.network_request),
    ("browse_", ActionType.network_request),
    ("input_to_", ActionType.network_request),
    ("checkout_", ActionType.network_request),
    ("refund_", ActionType.network_request),
    ("delete_", ActionType.file_delete),
    ("create_", ActionType.file_write),
    ("move_", ActionType.file_write),
    ("cart_", ActionType.file_write),
    ("update_", ActionType.file_write),
    ("login_", ActionType.network_request),
    ("verify_", ActionType.network_request),
    ("get_", ActionType.file_read),
    ("list_", ActionType.file_read),
    ("search_", ActionType.file_read),
    ("read_", ActionType.file_read),
    ("view_", ActionType.file_read),
    ("check_", ActionType.file_read),
)


def _action_type(function: str) -> ActionType:
    if function in _ACTION_TYPE:
        return _ACTION_TYPE[function]
    for prefix, action_type in _PREFIX_ACTION_TYPE:
        if function.startswith(prefix):
            return action_type
    return ActionType.other


def _first(args: dict, keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = args.get(k)
        if v:
            # A recipient list -> join deterministically; scalars -> str.
            if isinstance(v, (list, tuple)):
                return ",".join(str(x) for x in v) or None
            return str(v)
    return None


def _to_candidate(function: str, args: dict, label: str) -> CandidateAction:
    return CandidateAction(
        action_type=_action_type(function),
        tool_name=function,
        target=_first(args, _TARGET_KEYS),
        external_destination=_first(args, _DEST_KEYS),
        # Injected instructions reach the agent through tool results in AgentDojo
        # (documents, emails, webpages); benign actions originate from the user.
        source_context=(SourceContext.tool_output if label == "attack" else SourceContext.user),
        raw_arguments=dict(args),
    )


def _goal_index(actions: tuple[CandidateAction, ...]) -> int | None:
    """The consummating egress call is the attacker's goal; else count all."""
    egress = [i for i, a in enumerate(actions) if a.action_type == ActionType.network_request]
    return egress[-1] if egress else None


class AgentDojoAdapter:
    """Map the installed AgentDojo suites into labeled benchmark cases.

    Needs the optional ``agentdojo`` package; it is imported lazily so the rest of
    the harness (and CI) never depends on it. ``load`` is deterministic: suites,
    tasks, and calls are emitted in a fixed, sorted order.
    """

    suite_name = "agentdojo"

    def __init__(self, version: str = _BENCHMARK_VERSION, suites: Iterable[str] = _SUITES) -> None:
        self._version = version
        self._suites = tuple(suites)

    def load(self) -> Iterable[BenchmarkCase]:
        try:
            from agentdojo.task_suite.load_suites import get_suite
        except ImportError as exc:  # pragma: no cover - environment guard
            raise RuntimeError(
                "AgentDojo is not installed; `pip install agentdojo` to run this suite."
            ) from exc

        cases: list[BenchmarkCase] = []
        for suite_name in sorted(self._suites):
            suite = get_suite(self._version, suite_name)
            env = suite.load_and_inject_default_environment(injections={})

            for task_id in sorted(suite.user_tasks):
                task = suite.user_tasks[task_id]
                actions = self._actions(task, env, "benign")
                if actions:
                    cases.append(
                        BenchmarkCase(
                            case_id=f"{suite_name}/{task_id}",
                            label="benign",
                            note=f"{self.suite_name} {suite_name} user task",
                            actions=actions,
                        )
                    )

            for task_id in sorted(suite.injection_tasks):
                task = suite.injection_tasks[task_id]
                actions = self._actions(task, env, "attack")
                if actions:
                    cases.append(
                        BenchmarkCase(
                            case_id=f"{suite_name}/{task_id}",
                            label="attack",
                            note=f"{self.suite_name} {suite_name} injection task",
                            actions=actions,
                            attacker_goal_index=_goal_index(actions),
                        )
                    )
        return tuple(cases)

    @staticmethod
    def _actions(task, env, label: str) -> tuple[CandidateAction, ...]:
        try:
            calls = task.ground_truth(env)
        except Exception:  # noqa: BLE001 - some tasks need a richer env; skip them
            return ()
        return tuple(_to_candidate(fc.function, dict(fc.args or {}), label) for fc in calls)


class AgentDynAdapter(AgentDojoAdapter):
    """Map the AgentDyn suite (https://github.com/SaFo-Lab/AgentDyn) — an MIT,
    AgentDojo-derived *dynamic* benchmark — into labeled cases.

    AgentDyn ships the **same** ``agentdojo`` package API as upstream, adding three
    dynamic, multi-step suites (``shopping``/``github``/``dailylife``); those are
    AgentDyn's distinctive contribution (the original four already run under the
    ``agentdojo`` adapter). To resolve to AgentDyn's data put its checkout on the
    path, e.g. ``PYTHONPATH=/path/to/AgentDyn/src``. Multi-step tasks are emitted
    as ordered ``CandidateAction``s in one case with ``attacker_goal_index`` at
    the consummating egress step (inherited), exercising multi-step correlation.
    """

    suite_name = "agentdyn"

    def __init__(
        self,
        version: str = "v1",
        suites: Iterable[str] = ("shopping", "github", "dailylife"),
    ) -> None:
        super().__init__(version=version, suites=suites)
