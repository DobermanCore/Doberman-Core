"""Unit tests for the MSB tool-response-poisoning suite adapter.

MSB (https://github.com/dongsenzhang/MSB, MIT) is operator-supplied via
``DOBERMAN_BENCH_MSB_DIR``. These tests build a tiny synthetic
``data/attack_task.jsonl`` / ``data/attack_type.jsonl`` / ``data/prompt_template.py``
trio under ``tmp_path`` — the three static files this adapter reads — and
never touch the real checkout or any ``attack_tools/*.py`` file.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from doberman.models import ActionType, SourceContext
from tests.benchmarks.adapter import SuiteAdapter
from tests.benchmarks.suites.msb_poisoning import DATA_DIR_ENV, MsbPoisoningAdapter

PAYLOAD_MARKER = "MSB_PAYLOAD_MARKER_DO_NOT_LEAK"


def test_load_without_data_dir_raises(monkeypatch):
    monkeypatch.delenv(DATA_DIR_ENV, raising=False)
    with pytest.raises(RuntimeError, match=DATA_DIR_ENV):
        list(MsbPoisoningAdapter().load())


def test_adapter_satisfies_suite_adapter_protocol():
    assert isinstance(MsbPoisoningAdapter(data_dir="/nonexistent"), SuiteAdapter)
