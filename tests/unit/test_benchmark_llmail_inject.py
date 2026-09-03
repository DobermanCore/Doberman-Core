"""Unit tests for the LLMail-Inject suite adapter.

LLMail-Inject (https://huggingface.co/datasets/microsoft/llmail-inject-challenge,
MIT) is operator-supplied via ``DOBERMAN_BENCH_LLMAIL_DIR``. These tests build a
tiny synthetic ``data/labelled_unique_submissions_phase2.json`` +
``data/emails_for_fp_tests.json`` pair under ``tmp_path`` in the real on-disk
shape (a single JSON object keyed by submission text; a plain JSON array of
benign email strings) and never touch the real, multi-hundred-MB files.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from doberman.models import ActionType, SourceContext
from tests.benchmarks.adapter import SuiteAdapter
from tests.benchmarks.suites.llmail_inject import ATTACKER_EMAIL, DATA_DIR_ENV, LlmailInjectAdapter

PAYLOAD_MARKER = "LLMAIL_PAYLOAD_MARKER_DO_NOT_LEAK"


def test_load_without_data_dir_raises(monkeypatch):
    monkeypatch.delenv(DATA_DIR_ENV, raising=False)
    with pytest.raises(RuntimeError, match=DATA_DIR_ENV):
        list(LlmailInjectAdapter().load())


def test_adapter_satisfies_suite_adapter_protocol():
    assert isinstance(LlmailInjectAdapter(data_dir="/nonexistent"), SuiteAdapter)
