"""LLMail-Inject adapter — maps Microsoft's email prompt-injection challenge
dataset onto core types.

Source: https://huggingface.co/datasets/microsoft/llmail-inject-challenge
(MIT). No data is vendored — point ``DOBERMAN_BENCH_LLMAIL_DIR`` at a checkout
root (the directory containing ``data/scenarios.json``).

Ground truth used (see the PR description for why): a submission counts as a
scored **attack** case when its ``labelled_unique_submissions_phase{1,2}.json``
entry has ``attack_attempt == "True"`` and ``reason == "api_triggered"`` — the
send_email tool call **actually fired** for that exact text during the real
challenge (the strongest, cleanest signal on disk; the weaker
``reason == "judge"`` content-only opinion is excluded). Each qualifying
submission becomes a two-action ``BenchmarkCase``: action 0 = the email
arriving (``source_context=email``, the literal submission text under
``raw_arguments``), action 1 = the consummating ``send_email`` call the
challenge's own objective flags call ``exfil.sent``/``exfil.destination``/
``exfil.content`` (``attacker_goal_index=1``). All four LLMail-Inject scenarios
target the fixed attacker address ``contact@contact.com`` (a structural
constant of the published challenge, not attack payload); three of the four
use body ``"confirmation"`` — this adapter fixes the consummating body to that
value since the labelled file carries no per-submission scenario/level field
to disambiguate scenario 4's numeric-value variant.

Doberman evaluates the **action**, not the LLM's obedience: this measures
whether Doberman's taint/egress floors would stop the send a successful
injection tried to cause, not whether an LLM would have generated it.

``decide()`` is called statelessly, once per action — this suite (like every
other suite here) does not run the proxy's/host-hook spine's POST-decide
follow-up (``doberman.engine.taint_floor``'s taint floor and echo tripwire key
off the persisted decision log across calls, not a single ``decide()``
invocation). So what this suite measures by default is narrower than "was the
injection caught end to end": it is whether the real, static objective egress
rules stop the consummating send on its own content/destination, independent
of the taint floors. ``tests/benchmarks/session_replay.py``'s
``--replay-session`` closes that gap for suites registered here.

Benign counterpart: ``data/emails_for_fp_tests.json`` (a plain JSON array of
203 "should NOT trigger a send" emails) — a read-only case per email (no send
action; the correct behavior on these is to do nothing) PLUS a second,
synthetic benign SEND case per email (``BENIGN_SEND_DESTINATION``): the
dataset carries no real sender/reply addresses, so this is a fixed,
clearly-synthetic recipient, not derived from any record. Its purpose is
measuring FPR on an ordinary legitimate send, which the read-only cases alone
never exercise. Expect non-zero friction here (a bare ``user@host``
destination reads as embedded credentials to the real objective destination
rule and AUTHs — ``ReasonCode.unknown_external_destination`` — in every mode,
never a hard BLOCK); report it honestly rather than trimming it away.
"""

from __future__ import annotations

import json
import os
import pathlib
import random
from collections.abc import Iterable

from doberman.models import ActionType, SourceContext

from ..adapter import BenchmarkCase, CandidateAction

DATA_DIR_ENV = "DOBERMAN_BENCH_LLMAIL_DIR"
ATTACKER_EMAIL = "contact@contact.com"
#: Fixed, clearly-synthetic recipient for the benign SEND variant below — the
#: dataset carries no real sender/reply addresses, so this is not derived from
#: any record.
BENIGN_SEND_DESTINATION = "reply@example.com"
_GOAL_BODY = "confirmation"
_DEFAULT_PHASES: tuple[str, ...] = ("phase2",)
_DEFAULT_SAMPLE_SIZE = 500
_DEFAULT_SEED = 20260902


def _successful_injections(data_dir: pathlib.Path, phases: tuple[str, ...]) -> list[str]:
    """Prompts whose recorded outcome shows the injection actually triggered the
    target tool call (``attack_attempt == "True"`` and ``reason ==
    "api_triggered"``); ``reason == "judge"`` is a content-only opinion,
    independent of whether the tool call fired, and is excluded."""
    prompts: list[str] = []
    for phase in phases:
        path = data_dir / f"labelled_unique_submissions_{phase}.json"
        if not path.is_file():
            continue
        labelled = json.loads(path.read_text(encoding="utf-8"))
        prompts.extend(
            prompt
            for prompt, label in labelled.items()
            if label.get("attack_attempt") == "True" and label.get("reason") == "api_triggered"
        )
    return sorted(prompts)


class LlmailInjectAdapter:
    suite_name = "llmail_inject"

    def __init__(
        self,
        data_dir: str | pathlib.Path | None = None,
        *,
        phases: tuple[str, ...] = _DEFAULT_PHASES,
        sample_size: int = _DEFAULT_SAMPLE_SIZE,
        seed: int = _DEFAULT_SEED,
    ) -> None:
        raw = data_dir or os.environ.get(DATA_DIR_ENV, "")
        self._data_dir = pathlib.Path(raw) if raw else None
        self._phases = phases
        self._sample_size = sample_size
        self._seed = seed

    def load(self) -> Iterable[BenchmarkCase]:
        if self._data_dir is None or not self._data_dir.is_dir():
            raise RuntimeError(
                f"LLMail-Inject dataset not found; set {DATA_DIR_ENV} to a checkout "
                "root (the directory containing data/scenarios.json)."
            )

        data_dir = self._data_dir / "data"
        prompts = _successful_injections(data_dir, self._phases)
        rng = random.Random(self._seed)  # noqa: S311 — deterministic sample seed, not cryptographic
        sample = sorted(rng.sample(prompts, min(self._sample_size, len(prompts))))

        cases: list[BenchmarkCase] = []
        for i, prompt in enumerate(sample):
            read_action = CandidateAction(
                action_type=ActionType.file_read,
                tool_name="read_email",
                source_context=SourceContext.email,
                raw_arguments={"body": prompt},
            )
            send_action = CandidateAction(
                action_type=ActionType.network_request,
                tool_name="send_email",
                external_destination=ATTACKER_EMAIL,
                source_context=SourceContext.email,
                raw_arguments={"to": ATTACKER_EMAIL, "body": _GOAL_BODY},
            )
            cases.append(
                BenchmarkCase(
                    case_id=f"llmail-attack-{i:05d}",
                    label="attack",
                    note="api_triggered",
                    actions=(read_action, send_action),
                    attacker_goal_index=1,
                )
            )

        fp_path = data_dir / "emails_for_fp_tests.json"
        if fp_path.is_file():
            for i, email in enumerate(json.loads(fp_path.read_text(encoding="utf-8"))):
                cases.append(
                    BenchmarkCase(
                        case_id=f"llmail-benign-{i:05d}",
                        label="benign",
                        note="fp_test_email",
                        actions=(
                            CandidateAction(
                                action_type=ActionType.file_read,
                                tool_name="read_email",
                                source_context=SourceContext.email,
                                raw_arguments={"body": email},
                            ),
                        ),
                    )
                )
                # A2 (benign SEND variant): the dataset only ships "should not
                # trigger a send" emails, never a benign send action, so the
                # suite could not measure friction on an ordinary, legitimate
                # send at all. Emit one per fp email so FPR is measured on a
                # real send, not just a read. Synthetic (no real sender/reply
                # addresses exist in this dataset) — say so in the docs, not
                # here in the code comment alone.
                cases.append(
                    BenchmarkCase(
                        case_id=f"llmail-benign-send-{i:05d}",
                        label="benign",
                        note="fp_test_send_synthetic",
                        actions=(
                            CandidateAction(
                                action_type=ActionType.network_request,
                                tool_name="send_email",
                                external_destination=BENIGN_SEND_DESTINATION,
                                source_context=SourceContext.email,
                                raw_arguments={"to": BENIGN_SEND_DESTINATION, "body": email},
                            ),
                        ),
                    )
                )
        cases.sort(key=lambda c: c.case_id)
        return tuple(cases)
