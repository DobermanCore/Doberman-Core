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

Benign counterpart: ``data/emails_for_fp_tests.json`` (a plain JSON array of
203 "should NOT trigger a send" emails) — read-only cases (no send action; the
correct behavior on these is to do nothing).
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
_GOAL_BODY = "confirmation"
_DEFAULT_PHASES: tuple[str, ...] = ("phase2",)
_DEFAULT_SAMPLE_SIZE = 500
_DEFAULT_SEED = 20260902


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
        return ()
